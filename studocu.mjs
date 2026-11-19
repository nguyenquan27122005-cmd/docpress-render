/**
 * Studocu document inspection and PDF rendering via Playwright Chromium.
 *
 * Document access normalization, hex background vs decimal text fragment URL
 * resolution, locked-page detection, fragment sanitization, and per-page @page
 * sizing are adapted from StudocuHack (MIT License, revision
 * fbb2ba270450ec26a55a75448070fa13ebb641a9). See THIRD_PARTY_NOTICES.md.
 */

import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'

export const DOC_ASSETS_ORIGIN = 'https://doc-assets.studocu.com/'
export const MAX_PAGES_HARD_CAP = 20
export const MAX_PDF_BYTES_DEFAULT = 8 * 1024 * 1024
export const MAX_ASSET_BYTES = 4 * 1024 * 1024
export const MAX_TOTAL_IMAGE_BYTES = 24 * 1024 * 1024
export const DEFAULT_RENDER_TIMEOUT_MS = 90_000
export const MAX_REDIRECT_HOPS = 3

const STUDOCU_HOST_RE = /(?:^|\.)(?:studocu\.com|studeersnel\.nl|studocu\.id|studocu\.vn)$/i
const STUDOCU_PATH_RE = /^\/(?:[a-z]{2}(?:-[a-z]{2})?\/)?document\/.+/i
const BLOCKED_TRACKER_HOST_RE =
  /(?:^|\.)(?:doubleclick\.net|googlesyndication\.com|google-analytics\.com|googletagmanager\.com|facebook\.net|adagio\.io|refinery89\.com|amazon-adsystem\.com|criteo\.com|taboola\.com|outbrain\.com|hotjar\.com)$/i

const CHALLENGE_MARKER_RE =
  /just a moment|access blocked|attention required|temporarily restricted your access|verify you are human|cf-challenge|\/_fs-ch-|captcha/i

const DEFAULT_CHROME_MAJOR = '156'
const SOURCE_PAGE_BLOCKED_RESOURCE_TYPES = new Set([
  'image',
  'media',
  'font',
  'stylesheet',
  'script',
  'websocket',
  'eventsource',
  'manifest',
])

function buildUserAgent(browserVersion) {
  const major = /^(\d+)/.exec(String(browserVersion || ''))?.[1] || DEFAULT_CHROME_MAJOR
  const platformToken =
    process.platform === 'linux' ? 'X11; Linux x86_64' : 'Windows NT 10.0; Win64; x64'
  return `Mozilla/5.0 (${platformToken}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`
}

export class RenderServiceError extends Error {
  constructor(code, message, details = undefined) {
    super(message || code)
    this.name = 'RenderServiceError'
    this.code = code
    if (details !== undefined) this.details = details
  }
}

function normalizeLoopbackOrigin(allowLoopbackOrigin) {
  if (!allowLoopbackOrigin) return null
  let parsed
  try {
    parsed = new URL(allowLoopbackOrigin)
  } catch {
    return null
  }
  if (parsed.protocol !== 'http:') return null
  if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') return null
  return parsed.origin
}

function isAllowedOrigin(parsed, loopbackOrigin) {
  if (loopbackOrigin && parsed.origin === loopbackOrigin) {
    return !parsed.username && !parsed.password
  }
  if (parsed.protocol !== 'https:') return false
  if (parsed.username || parsed.password || parsed.port) return false
  return STUDOCU_HOST_RE.test(parsed.hostname)
}

export function validateStudocuUrl(rawUrl, options = {}) {
  const loopbackOrigin = normalizeLoopbackOrigin(options.allowLoopbackOrigin)
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new RenderServiceError('INVALID_URL', 'Missing sourceUrl.')
  }
  let parsed
  try {
    parsed = new URL(rawUrl.trim())
  } catch {
    throw new RenderServiceError('INVALID_URL', 'Malformed sourceUrl.')
  }
  if (!isAllowedOrigin(parsed, loopbackOrigin)) {
    throw new RenderServiceError('INVALID_URL', 'URL host or protocol is not allowed.')
  }
  if (!STUDOCU_PATH_RE.test(parsed.pathname)) {
    throw new RenderServiceError('INVALID_URL', 'URL is not a Studocu document path.')
  }
  return parsed
}

function isAllowedAssetUrl(rawUrl, loopbackOrigin) {
  let parsed
  try {
    parsed = new URL(rawUrl)
  } catch {
    return false
  }
  return isAllowedOrigin(parsed, loopbackOrigin)
}

function isPrivateOrLocalHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '')
  if (!host) return true
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true
  if (host === '::1' || host === '0:0:0:0:0:0:0:1' || host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) {
    return true
  }
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (!m) return false
  const a = Number(m[1])
  const b = Number(m[2])
  if (a === 10 || a === 127 || a === 0) return true
  if (a === 169 && b === 254) return true
  if (a === 192 && b === 168) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

function pickParam(sp, keys) {
  if (!sp || typeof sp !== 'object') return ''
  for (const key of keys) {
    if (typeof sp[key] === 'string' && sp[key]) return sp[key]
  }
  return ''
}

function normalizeBaseUrl(rawUrl, objectKey, loopbackOrigin) {
  if (typeof rawUrl === 'string' && rawUrl.trim()) {
    const candidate = rawUrl.trim().endsWith('/') ? rawUrl.trim() : `${rawUrl.trim()}/`
    if (isAllowedAssetUrl(candidate, loopbackOrigin)) return candidate
    throw new RenderServiceError('NO_PAGES_FOUND', 'Document asset base URL is outside the allowlist.')
  }
  return `${DOC_ASSETS_ORIGIN}${encodeURIComponent(objectKey)}/html/`
}

export function inspectStudocuAccess(documentAccess, selectedPages, options = {}) {
  const loopbackOrigin = normalizeLoopbackOrigin(options.allowLoopbackOrigin)
  if (!documentAccess || typeof documentAccess !== 'object') {
    throw new RenderServiceError('NO_PAGES_FOUND', 'Missing documentAccess metadata.')
  }
  const objectKey =
    typeof documentAccess.objectKey === 'string' ? documentAccess.objectKey.trim() : ''
  const sp = documentAccess.signedQueryParams
  if (!objectKey || !sp || typeof sp !== 'object' || Array.isArray(sp)) {
    throw new RenderServiceError('NO_PAGES_FOUND', 'Incomplete documentAccess metadata.')
  }

  const normalizedPages = Array.isArray(selectedPages)
    ? selectedPages
        .map((n) => Number(n))
        .filter((n) => Number.isSafeInteger(n) && n >= 1)
    : []
  if (!normalizedPages.length) {
    throw new RenderServiceError('NO_PAGES_FOUND', 'No valid pages selected.')
  }

  const hasPerPageArray = Array.isArray(sp.pages)
  const wildcardHtmlParam = pickParam(sp, ['html'])
  const bgParams = pickParam(sp, ['png', 'global'])
  const cssParams = pickParam(sp, ['css', 'global'])
  const globalParam = pickParam(sp, ['global'])

  const pageParams = {}
  if (hasPerPageArray) {
    for (const entry of sp.pages) {
      if (
        entry &&
        typeof entry === 'object' &&
        Number.isSafeInteger(Number(entry.pageNumber)) &&
        Number(entry.pageNumber) >= 1 &&
        typeof entry.signedQueryParams === 'string' &&
        entry.signedQueryParams.length > 0
      ) {
        pageParams[Number(entry.pageNumber)] = entry.signedQueryParams
      }
    }
  }

  // Keyed off presence of signedQueryParams.pages (not its length):
  // pages: [] means every page is text-gated, NOT a scanned document.
  const hasTextLayer = hasPerPageArray || Boolean(wildcardHtmlParam)
  if (!hasTextLayer && !bgParams) {
    throw new RenderServiceError('NO_PAGES_FOUND', 'Missing signed asset query parameters.')
  }

  const assetsBaseUrl = normalizeBaseUrl(documentAccess.url, objectKey, loopbackOrigin)
  const accessiblePages = []
  const lockedPages = []

  if (hasTextLayer) {
    for (const pageNum of normalizedPages) {
      const signed = hasPerPageArray ? pageParams[pageNum] : wildcardHtmlParam
      if (signed) accessiblePages.push(pageNum)
      else lockedPages.push(pageNum)
    }
  } else {
    const scanRestricted = Boolean(documentAccess.hasBlurredPages) && !globalParam
    for (const pageNum of normalizedPages) {
      if (scanRestricted) lockedPages.push(pageNum)
      else accessiblePages.push(pageNum)
    }
  }

  return {
    objectKey,
    assetsBaseUrl,
    hasTextLayer,
    mode: hasTextLayer ? 'text' : 'scan',
    hasPerPageArray,
    wildcardHtmlParam,
    bgParams,
    cssParams,
    globalParam,
    pageParams,
    hasBlurredPages: Boolean(documentAccess.hasBlurredPages),
    selectedPages: normalizedPages,
    accessiblePages,
    lockedPages,
  }
}

export function buildStudocuAssetUrls(access, pageNum) {
  const hexPage = Number(pageNum).toString(16)
  const bgUrl = access.bgParams
    ? `${access.assetsBaseUrl}bg${hexPage}.png${access.bgParams}`
    : null
  const textParam = access.hasTextLayer
    ? access.hasPerPageArray
      ? access.pageParams[pageNum] || ''
      : access.wildcardHtmlParam
    : ''
  const pageTextUrl = textParam
    ? `${access.assetsBaseUrl}${access.objectKey}${pageNum}.page${textParam}`
    : null
  const candidatePageTextUrl =
    pageTextUrl ||
    (access.globalParam
      ? `${access.assetsBaseUrl}${access.objectKey}${pageNum}.page${access.globalParam}`
      : null)
  const cssUrl = access.cssParams
    ? `${access.assetsBaseUrl}${access.objectKey}.css${access.cssParams}`
    : null
  return { bgUrl, pageTextUrl, candidatePageTextUrl, cssUrl }
}

export function sanitizePageHtml(html) {
  return String(html ?? '')
    .replace(/<\s*(script|iframe|object|embed|applet|base|meta|form|link|style)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, '')
    .replace(/<\s*(script|iframe|object|embed|applet|base|meta|link|style)\b[^>]*\/?>/gi, '')
    .replace(/\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/\b(href|src|xlink:href)\s*=\s*(["'])\s*(?:javascript|vbscript):[^"']*\2/gi, '$1=$2#$2')
}

export function downloadFilename(title, ext = 'pdf') {
  let base = String(title ?? 'document')
    .replace(/\.[a-z0-9]{1,5}$/i, '')
    .replace(/[<>:"/\\|?*\u0000-\u001f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/^[.\s]+|[.\s]+$/g, '')
    .slice(0, 80)
  if (!base) base = 'document'
  return `${base}.${ext}`
}

function decodeSlugTitle(pathname) {
  const segments = String(pathname || '').split('/').filter(Boolean)
  const docIdx = segments.findIndex((s) => s.toLowerCase() === 'document')
  const tail = docIdx >= 0 ? segments.slice(docIdx + 1) : segments
  const titleSeg = tail.find((s) => !/^\d+$/.test(s) && s.length > 2) || tail[0] || 'Studocu Document'
  try {
    return decodeURIComponent(titleSeg).replace(/[-_]+/g, ' ').replace(/\s+/g, ' ').trim()
  } catch {
    return titleSeg.replace(/[-_]+/g, ' ').replace(/\s+/g, ' ').trim()
  }
}

function computeRange(rangeFrom, rangeTo, totalPages, maxPages) {
  const cap = Math.max(1, Math.min(MAX_PAGES_HARD_CAP, Math.floor(maxPages || MAX_PAGES_HARD_CAP)))
  const safeTotal = Math.max(1, Math.floor(totalPages))

  let from = 1
  if (rangeFrom !== undefined && rangeFrom !== null) {
    const parsedFrom = Number(rangeFrom)
    if (!Number.isSafeInteger(parsedFrom) || parsedFrom < 1) {
      throw new RenderServiceError('INVALID_URL', 'rangeFrom must be a positive integer.')
    }
    if (parsedFrom > safeTotal) {
      throw new RenderServiceError('NO_PAGES_FOUND', `Requested start page ${parsedFrom} exceeds total pages (${safeTotal}).`)
    }
    from = parsedFrom
  }

  let to = safeTotal
  if (rangeTo !== undefined && rangeTo !== null) {
    const parsedTo = Number(rangeTo)
    if (!Number.isSafeInteger(parsedTo) || parsedTo < 1) {
      throw new RenderServiceError('INVALID_URL', 'rangeTo must be a positive integer.')
    }
    to = Math.min(parsedTo, safeTotal)
  }

  if (from > to) {
    throw new RenderServiceError('INVALID_URL', 'rangeFrom must not exceed rangeTo.')
  }
  if (to - from + 1 > cap) {
    to = from + cap - 1
  }

  const selectedPages = []
  for (let p = from; p <= to; p++) selectedPages.push(p)
  return { from, to, selectedPages }
}

/**
 * Inspect PDF binary outside stream payloads to verify header and page count.
 */
export function inspectPdfBytes(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || 0)
  if (buf.byteLength < 32) {
    throw new RenderServiceError('RENDER_FAILED', 'Generated PDF is empty or truncated.')
  }
  const header = Buffer.from(buf.subarray(0, 5)).toString('ascii')
  if (header !== '%PDF-') {
    throw new RenderServiceError('RENDER_FAILED', 'Output does not start with %PDF- magic header.')
  }

  const latin = Buffer.from(buf).toString('latin1')
  // Strip binary stream payloads so image/font streams cannot confuse PDF object parsing.
  const withoutStreams = latin.replace(/stream\r?\n[\s\S]*?\r?\n?endstream/g, 'stream\nendstream')

  const leafMatches = withoutStreams.match(/\/Type\s*\/Page\b(?!s)/g) || []
  let maxTreeCount = 0
  const objRe = /<<[\s\S]*?>>/g
  let m
  while ((m = objRe.exec(withoutStreams))) {
    const dict = m[0]
    if (/\/Type\s*\/Pages\b/.test(dict)) {
      const countMatch = /\/Count\s+(\d+)/.exec(dict)
      if (countMatch) {
        const count = Number(countMatch[1])
        if (count > maxTreeCount) maxTreeCount = count
      }
    }
  }

  const pageCount = maxTreeCount > 0 ? maxTreeCount : leafMatches.length
  if (pageCount <= 0) {
    throw new RenderServiceError('RENDER_FAILED', 'Generated PDF contains zero pages.')
  }
  return {
    pageCount,
    leafPageObjects: leafMatches.length,
    treeCount: maxTreeCount,
    byteLength: buf.byteLength,
  }
}

async function readResponseWithLimit(response, maxBytes) {
  const cl = Number(response.headers.get('content-length') || '')
  if (Number.isFinite(cl) && cl > maxBytes) {
    throw new RenderServiceError('OUTPUT_TOO_LARGE', 'Asset response exceeded maximum size.')
  }
  if (!response.body) {
    const arr = new Uint8Array(await response.arrayBuffer())
    if (arr.byteLength > maxBytes) {
      throw new RenderServiceError('OUTPUT_TOO_LARGE', 'Asset response exceeded maximum size.')
    }
    return arr
  }
  const reader = response.body.getReader()
  const chunks = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) continue
    total += value.byteLength
    if (total > maxBytes) {
      try {
        await reader.cancel()
      } catch {
        // ignore cancel error
      }
      throw new RenderServiceError('OUTPUT_TOO_LARGE', 'Asset response exceeded maximum size.')
    }
    chunks.push(value)
  }
  const merged = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    merged.set(chunk, offset)
    offset += chunk.byteLength
  }
  return merged
}

async function safeFetchAsset(initialUrl, loopbackOrigin, maxBytes, signal, userAgent) {
  let currentUrl = initialUrl
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    if (!isAllowedAssetUrl(currentUrl, loopbackOrigin)) {
      throw new RenderServiceError('RENDER_FAILED', 'Asset redirect target is outside allowlist.')
    }
    const res = await fetch(currentUrl, {
      method: 'GET',
      credentials: 'omit',
      redirect: 'manual',
      headers: {
        'User-Agent': userAgent || buildUserAgent(''),
        Accept: '*/*',
      },
      signal,
    })
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location')
      if (!loc || hop === MAX_REDIRECT_HOPS) {
        throw new RenderServiceError('RENDER_FAILED', 'Too many asset redirects.')
      }
      currentUrl = new URL(loc, currentUrl).href
      continue
    }
    const bytes = await readResponseWithLimit(res, maxBytes)
    return {
      status: res.status,
      contentType: (res.headers.get('content-type') || '').toLowerCase(),
      bytes,
      finalUrl: currentUrl,
    }
  }
  throw new RenderServiceError('RENDER_FAILED', 'Failed to fetch asset.')
}

function detectImageMime(bytes, contentType) {
  if (bytes.byteLength >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return 'image/png'
  }
  if (bytes.byteLength >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return 'image/jpeg'
  }
  if (
    bytes.byteLength >= 12 &&
    Buffer.from(bytes.subarray(0, 4)).toString('ascii') === 'RIFF' &&
    Buffer.from(bytes.subarray(8, 12)).toString('ascii') === 'WEBP'
  ) {
    return 'image/webp'
  }
  if (contentType.startsWith('image/')) return contentType.split(';')[0].trim()
  return null
}

function rewriteCssRelativeUrls(cssText, cssBaseUrl, loopbackOrigin, fallbackQuery = '') {
  const cleaned = String(cssText || '').replace(/@import\b[^;]+;?/gi, '')
  let baseOrigin = ''
  try {
    baseOrigin = new URL(cssBaseUrl).origin
  } catch {
    baseOrigin = ''
  }
  return cleaned.replace(/url\(\s*(['"]?)([^)'"]+)\1\s*\)/gi, (full, _quote, rawTarget) => {
    const target = rawTarget.trim()
    if (!target || target.startsWith('data:') || target.startsWith('#')) return full
    const isRelative = !/^[a-z][a-z0-9+.-]*:/i.test(target) && !target.startsWith('//')
    let resolved
    try {
      resolved = new URL(target, cssBaseUrl)
    } catch {
      return 'url("")'
    }
    if (!isAllowedAssetUrl(resolved.href, loopbackOrigin)) return 'url("")'
    if (isRelative && !resolved.search && fallbackQuery && resolved.origin === baseOrigin) {
      resolved.search = fallbackQuery.startsWith('?') ? fallbackQuery : `?${fallbackQuery}`
    }
    return `url("${resolved.href}")`
  })
}

function escapeHtmlAttr(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function isAbortLikeError(err) {
  if (!err) return false
  if (err.code === 'RENDER_TIMEOUT') return true
  if (err.name === 'AbortError' || err.name === 'TimeoutError') return true
  return /timeout|aborted/i.test(String(err.message || ''))
}

function checkDeadline(deadlineMs, abortController) {
  if (Date.now() >= deadlineMs || abortController.signal.aborted) {
    throw new RenderServiceError('RENDER_TIMEOUT', 'Render job exceeded timeout limit.')
  }
}

function remainingMs(deadlineMs, capMs) {
  const left = deadlineMs - Date.now()
  if (left <= 0) {
    throw new RenderServiceError('RENDER_TIMEOUT', 'Render job exceeded timeout limit.')
  }
  return Math.max(100, Math.min(left, capMs))
}

function isChallengeResponse(status, title, bodySnippet) {
  if (status === 403 || status === 429) return true
  const combined = `${title || ''}\n${bodySnippet || ''}`.slice(0, 6000)
  return CHALLENGE_MARKER_RE.test(combined)
}

function extractInlineNextData(rawText) {
  try {
    return JSON.parse(rawText)
  } catch {
    return null
  }
}

async function mapPool(items, concurrency, fn) {
  const results = new Array(items.length)
  let nextIdx = 0
  async function worker() {
    while (true) {
      const idx = nextIdx++
      if (idx >= items.length) return
      results[idx] = await fn(items[idx], idx)
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, Math.max(1, items.length)) }, worker)
  await Promise.all(workers)
  return results
}

function readContainerMemoryBytes() {
  if (process.platform !== 'linux') return {}
  const readNum = (filePath) => {
    try {
      const raw = readFileSync(filePath, 'utf8').trim()
      const n = Number(raw)
      return Number.isFinite(n) && n > 0 ? n : undefined
    } catch {
      return undefined
    }
  }
  const peakBytes =
    readNum('/sys/fs/cgroup/memory.peak') ??
    readNum('/sys/fs/cgroup/memory/memory.max_usage_in_bytes')
  const currentBytes =
    readNum('/sys/fs/cgroup/memory.current') ??
    readNum('/sys/fs/cgroup/memory/memory.usage_in_bytes')
  return {
    ...(currentBytes !== undefined ? { containerCurrentBytes: currentBytes } : {}),
    ...(peakBytes !== undefined ? { containerPeakBytes: peakBytes } : {}),
  }
}

function stripUrlQuery(rawUrl) {
  try {
    const parsed = new URL(rawUrl)
    return `${parsed.origin}${parsed.pathname}`
  } catch {
    return ''
  }
}

function withCleanupTimeout(promise, ms = 2000) {
  let timer
  return Promise.race([
    Promise.resolve(promise).catch(() => {}),
    new Promise((resolve) => {
      timer = setTimeout(resolve, ms)
      if (typeof timer.unref === 'function') timer.unref()
    }),
  ]).finally(() => clearTimeout(timer))
}

export async function renderStudocuPdf(input, options = {}) {
  const startedAt = Date.now()
  let peakRssBytes = process.memoryUsage().rss
  const recordMemory = () => {
    const rss = process.memoryUsage().rss
    if (rss > peakRssBytes) peakRssBytes = rss
  }

  const loopbackOrigin = normalizeLoopbackOrigin(options.allowLoopbackOrigin)
  const parsedSource = validateStudocuUrl(input?.sourceUrl, { allowLoopbackOrigin: loopbackOrigin })
  const maxPages = Math.max(
    1,
    Math.min(MAX_PAGES_HARD_CAP, Math.floor(Number(input?.maxPages || MAX_PAGES_HARD_CAP)))
  )
  const maxPdfBytes = Math.max(128, Math.floor(Number(options.maxPdfBytes || MAX_PDF_BYTES_DEFAULT)))
  const timeoutMs = Math.max(500, Math.floor(Number(options.timeoutMs || DEFAULT_RENDER_TIMEOUT_MS)))
  const deadlineMs = startedAt + timeoutMs

  const abortController = new AbortController()
  const externalSignal = options.signal
  const onExternalAbort = () => abortController.abort()
  if (externalSignal) {
    if (externalSignal.aborted) abortController.abort()
    else externalSignal.addEventListener('abort', onExternalAbort, { once: true })
  }

  let browser = null
  let context = null
  let closeBrowserPromise = null
  let timedOut = false
  let disallowedRedirectError = null
  const closeBrowserOnce = () => {
    if (!browser) return Promise.resolve()
    if (!closeBrowserPromise) {
      closeBrowserPromise = withCleanupTimeout(browser.close(), 3000)
    }
    return closeBrowserPromise
  }
  const hardTimer = setTimeout(() => {
    timedOut = true
    abortController.abort()
    closeBrowserOnce()
  }, timeoutMs)

  try {
    checkDeadline(deadlineMs, abortController)

    const chromiumSandbox =
      options.chromiumSandbox !== undefined
        ? Boolean(options.chromiumSandbox)
        : process.env.PLAYWRIGHT_CHROMIUM_SANDBOX === 'true'

    browser = await chromium.launch({
      headless: true,
      chromiumSandbox,
      args: [
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-background-networking',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-sync',
        '--metrics-recording-only',
        '--no-first-run',
        '--mute-audio',
      ],
    })
    recordMemory()
    const userAgent = buildUserAgent(browser.version())

    context = await browser.newContext({
      userAgent,
      locale: 'en-US',
      viewport: { width: 1280, height: 900 },
      acceptDownloads: false,
      serviceWorkers: 'block',
    })

    let sourcePage = null
    let mainNavRedirects = 0
    await context.route('**/*', async (route) => {
      const req = route.request()
      const urlStr = req.url()
      if (urlStr === 'about:blank' || urlStr.startsWith('data:')) {
        await route.continue()
        return
      }
      let parsed
      try {
        parsed = new URL(urlStr)
      } catch {
        await route.abort('blockedbyclient')
        return
      }
      const isMainNav = Boolean(sourcePage && req.isNavigationRequest() && req.frame() === sourcePage.mainFrame())
      if (parsed.protocol !== 'https:' && !(loopbackOrigin && parsed.origin === loopbackOrigin)) {
        if (isMainNav) {
          disallowedRedirectError = new RenderServiceError(
            'RENDER_FAILED',
            'Blocked navigation to disallowed protocol or origin.'
          )
        }
        await route.abort('blockedbyclient')
        return
      }
      if (isMainNav) {
        if (!isAllowedOrigin(parsed, loopbackOrigin)) {
          disallowedRedirectError = new RenderServiceError(
            'RENDER_FAILED',
            'Blocked redirect to disallowed origin.'
          )
          await route.abort('blockedbyclient')
          return
        }
        // Let Chromium perform main navigation with its native TLS/HTTP2 stack;
        // HTTP 3xx redirect locations are validated via CDP Fetch Response stage below.
        await route.continue()
        return
      }
      if (BLOCKED_TRACKER_HOST_RE.test(parsed.hostname)) {
        await route.abort('blockedbyclient')
        return
      }
      // On sourcePage we only need SSR HTML (#__NEXT_DATA__), never React hydration
      // bundles, media, fonts, or 100+ page viewer assets (critical for 512 MiB RAM).
      if (sourcePage && SOURCE_PAGE_BLOCKED_RESOURCE_TYPES.has(req.resourceType())) {
        await route.abort('blockedbyclient')
        return
      }
      // Once sourcePage is closed (print phase), allow only explicitly allowlisted origins.
      if (!sourcePage && !isAllowedOrigin(parsed, loopbackOrigin)) {
        await route.abort('blockedbyclient')
        return
      }
      if (!loopbackOrigin && isPrivateOrLocalHost(parsed.hostname)) {
        await route.abort('blockedbyclient')
        return
      }
      if (loopbackOrigin && isPrivateOrLocalHost(parsed.hostname) && parsed.origin !== loopbackOrigin) {
        await route.abort('blockedbyclient')
        return
      }
      await route.continue()
    })

    // Step 1: Open Studocu document page to read __NEXT_DATA__ and loaded CSS references.
    sourcePage = await context.newPage()
    const cdp = await context.newCDPSession(sourcePage)
    await cdp.send('Fetch.enable', {
      patterns: [{ urlPattern: '*', requestStage: 'Response', resourceType: 'Document' }],
    })
    cdp.on('Fetch.requestPaused', async (event) => {
      try {
        const status = event.responseStatusCode || 0
        if (status >= 300 && status < 400) {
          const headers = event.responseHeaders || []
          const locHeader = headers.find((h) => String(h.name || '').toLowerCase() === 'location')
          const loc = locHeader?.value
          mainNavRedirects += 1
          if (!loc || mainNavRedirects > MAX_REDIRECT_HOPS) {
            disallowedRedirectError = new RenderServiceError(
              'RENDER_FAILED',
              'Too many or invalid document redirects.'
            )
            await cdp
              .send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' })
              .catch(() => {})
            return
          }
          let nextUrl
          try {
            nextUrl = new URL(loc, event.request.url)
          } catch {
            disallowedRedirectError = new RenderServiceError(
              'RENDER_FAILED',
              'Malformed redirect location.'
            )
            await cdp
              .send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' })
              .catch(() => {})
            return
          }
          if (!isAllowedOrigin(nextUrl, loopbackOrigin)) {
            disallowedRedirectError = new RenderServiceError(
              'RENDER_FAILED',
              'Blocked redirect to disallowed origin.'
            )
            await cdp
              .send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' })
              .catch(() => {})
            return
          }
        }
        await cdp.send('Fetch.continueResponse', { requestId: event.requestId }).catch(() => {})
      } catch {
        await cdp
          .send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' })
          .catch(() => {})
      }
    })

    let sourceStatus = 0
    let finalUrl = parsedSource.href
    let safeFinalUrl = stripUrlQuery(parsedSource.href)
    let pageTitle = ''
    let bodySnippet = ''
    let rawNextData = ''
    let pageStylesheetLinks = []
    let inlineP2hvCss = ''

    try {
      const response = await sourcePage.goto(parsedSource.href, {
        waitUntil: 'domcontentloaded',
        timeout: remainingMs(deadlineMs, 30_000),
      })
      if (disallowedRedirectError) throw disallowedRedirectError

      sourceStatus = response ? response.status() : 0
      finalUrl = sourcePage.url()
      safeFinalUrl = stripUrlQuery(finalUrl)
      recordMemory()

      const finalParsed = new URL(finalUrl)
      if (!isAllowedOrigin(finalParsed, loopbackOrigin)) {
        throw new RenderServiceError('RENDER_FAILED', 'Final document URL is outside allowlist.')
      }

      if (sourceStatus === 404 || sourceStatus === 410) {
        throw new RenderServiceError('NOT_FOUND', `Source returned HTTP ${sourceStatus}.`, {
          sourceStatus,
          finalUrl: safeFinalUrl,
        })
      }

      if (!STUDOCU_PATH_RE.test(finalParsed.pathname)) {
        throw new RenderServiceError(
          'NOT_FOUND',
          'Document URL redirected away from a document page.',
          { sourceStatus, finalUrl: safeFinalUrl }
        )
      }

      const initialSnapshot = await sourcePage.evaluate(() => {
        const el = document.getElementById('__NEXT_DATA__')
        const h1 = document.querySelector('h1')
        const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
          .map((l) => l.getAttribute('href') || '')
          .filter(Boolean)
        const inlineCss = Array.from(document.querySelectorAll('style'))
          .map((s) => s.textContent || '')
          .filter((css) => css.includes('.p2hv'))
          .join('\n')
        return {
          title: document.title || '',
          h1: h1 ? h1.textContent.trim() : '',
          bodyText: (document.body?.innerText || '').slice(0, 4000),
          nextData: el ? (el.textContent || '').trim() : '',
          links,
          inlineCss,
        }
      })

      pageTitle = initialSnapshot.title
      bodySnippet = initialSnapshot.bodyText
      rawNextData = initialSnapshot.nextData
      pageStylesheetLinks = initialSnapshot.links
      inlineP2hvCss = initialSnapshot.inlineCss

      if (isChallengeResponse(sourceStatus, pageTitle, bodySnippet)) {
        throw new RenderServiceError(
          'SOURCE_BLOCKED',
          `Source blocked automated access (HTTP ${sourceStatus || 'unknown'}).`,
          { sourceStatus, title: pageTitle, finalUrl: safeFinalUrl }
        )
      }

      if (!rawNextData) {
        try {
          await sourcePage.waitForSelector('#__NEXT_DATA__', {
            state: 'attached',
            timeout: remainingMs(deadlineMs, 5_000),
          })
          rawNextData = await sourcePage.evaluate(() => {
            const el = document.getElementById('__NEXT_DATA__')
            return el ? (el.textContent || '').trim() : ''
          })
        } catch {
          // handled below
        }
      }

      if (sourceStatus >= 400) {
        throw new RenderServiceError('RENDER_FAILED', `Source returned HTTP ${sourceStatus}.`, {
          sourceStatus,
          title: pageTitle,
          finalUrl: safeFinalUrl,
        })
      }

      if (!rawNextData) {
        if (isChallengeResponse(sourceStatus, pageTitle, bodySnippet)) {
          throw new RenderServiceError('SOURCE_BLOCKED', 'Source returned a challenge page.', {
            sourceStatus,
            title: pageTitle,
            finalUrl: safeFinalUrl,
          })
        }
        throw new RenderServiceError('NO_PAGES_FOUND', 'Page did not contain __NEXT_DATA__.', {
          sourceStatus,
          title: pageTitle,
          finalUrl: safeFinalUrl,
        })
      }
    } finally {
      // Release CDP session and heavy Studocu React page before fetching assets and printing.
      if (!timedOut && browser?.isConnected()) {
        await withCleanupTimeout(cdp.send('Fetch.disable'), 1000)
        await withCleanupTimeout(sourcePage.close(), 1500)
      }
      sourcePage = null
    }

    checkDeadline(deadlineMs, abortController)
    recordMemory()

    // Step 2: Parse metadata and inspect page-level access strictly.
    const nextData = extractInlineNextData(rawNextData)
    const pageProps = nextData?.props?.pageProps
    if (!pageProps || typeof pageProps !== 'object') {
      throw new RenderServiceError('NO_PAGES_FOUND', 'Invalid __NEXT_DATA__ structure.', {
        sourceStatus,
      })
    }
    if (pageProps.notFound || pageProps.statusCode === 404) {
      throw new RenderServiceError('NOT_FOUND', 'Document not found in source metadata.', {
        sourceStatus,
      })
    }

    const docMeta = pageProps.document || {}
    const pageDataList = Array.isArray(pageProps.pageDataList) ? pageProps.pageDataList : []
    const totalPages = Math.max(
      Number(docMeta.numberOfPages) || 0,
      Number(docMeta.pageCount) || 0,
      pageDataList.length
    )
    if (!Number.isSafeInteger(totalPages) || totalPages <= 0) {
      throw new RenderServiceError('NO_PAGES_FOUND', 'Document reports zero pages.', {
        sourceStatus,
      })
    }

    const { from, to, selectedPages } = computeRange(
      input?.rangeFrom,
      input?.rangeTo,
      totalPages,
      maxPages
    )

    const allPages = Array.from({ length: totalPages }, (_, i) => i + 1)
    const fullAccess = inspectStudocuAccess(pageProps.documentAccess, allPages, {
      allowLoopbackOrigin: loopbackOrigin,
    })
    const access = inspectStudocuAccess(pageProps.documentAccess, selectedPages, {
      allowLoopbackOrigin: loopbackOrigin,
    })

    if (access.lockedPages.length > 0) {
      throw new RenderServiceError(
        'SOURCE_RESTRICTED',
        `Selected range includes ${access.lockedPages.length} premium-locked page(s): ${access.lockedPages.join(', ')}.`,
        {
          sourceStatus,
          totalPages,
          accessiblePages: fullAccess.accessiblePages.length,
          lockedPages: access.lockedPages,
          from,
          to,
        }
      )
    }

    const cleanedHtmlTitle = pageTitle.replace(/\s*\|\s*Studocu.*$/i, '').trim()
    const title =
      (typeof docMeta.title === 'string' && docMeta.title.trim()) ||
      cleanedHtmlTitle ||
      decodeSlugTitle(parsedSource.pathname)

    const pageDataByNum = new Map()
    for (const row of pageDataList) {
      const num = Number(row?.pageNumber)
      if (Number.isSafeInteger(num) && num >= 1) pageDataByNum.set(num, row)
    }

    // Free native text documents on Studocu also use signedQueryParams: { global }
    // without a per-page `pages` array. Detect text-layer availability via inline
    // pageHtml or probing the first selected page's .page fragment before falling
    // back to scan mode.
    let effectiveMode = access.mode
    const prefetchedFragments = new Map()
    if (effectiveMode === 'scan' && access.globalParam) {
      const hasInlineHtml = pageDataList.some(
        (r) =>
          (typeof r?.pageHtml === 'string' && r.pageHtml.includes('<')) ||
          (typeof r?.html === 'string' && r.html.includes('<'))
      )
      if (hasInlineHtml) {
        effectiveMode = 'text'
      } else {
        const probePageNum = selectedPages[0]
        const probeUrls = buildStudocuAssetUrls(access, probePageNum)
        if (probeUrls.candidatePageTextUrl && isAllowedAssetUrl(probeUrls.candidatePageTextUrl, loopbackOrigin)) {
          try {
            const probeRes = await safeFetchAsset(
              probeUrls.candidatePageTextUrl,
              loopbackOrigin,
              MAX_ASSET_BYTES,
              abortController.signal,
              userAgent
            )
            if (probeRes.status >= 200 && probeRes.status < 300) {
              const probeHtml = new TextDecoder().decode(probeRes.bytes)
              if (probeHtml.includes('<span') || probeHtml.includes('class="pc')) {
                effectiveMode = 'text'
                prefetchedFragments.set(probePageNum, probeHtml)
              }
            }
          } catch (err) {
            if (err instanceof RenderServiceError && (err.code === 'OUTPUT_TOO_LARGE' || err.code === 'RENDER_TIMEOUT')) {
              throw err
            }
          }
        }
      }
    }

    // Step 3: Fetch pdf2htmlEX CSS and selected page assets with strict allowlist & byte limits.
    let docCss = inlineP2hvCss
      ? rewriteCssRelativeUrls(inlineP2hvCss, access.assetsBaseUrl, loopbackOrigin, access.globalParam)
      : ''
    const cssCandidates = []
    for (const href of pageStylesheetLinks) {
      try {
        const resolved = new URL(href, finalUrl).href
        if (resolved.includes(access.objectKey) && resolved.includes('.css')) {
          cssCandidates.push(resolved)
        }
      } catch {
        // ignore invalid href
      }
    }
    const { cssUrl } = buildStudocuAssetUrls(access, selectedPages[0])
    if (cssUrl && !cssCandidates.includes(cssUrl)) cssCandidates.push(cssUrl)

    for (const candidateCss of cssCandidates) {
      if (!isAllowedAssetUrl(candidateCss, loopbackOrigin)) continue
      try {
        const cssRes = await safeFetchAsset(
          candidateCss,
          loopbackOrigin,
          MAX_ASSET_BYTES,
          abortController.signal,
          userAgent
        )
        if (cssRes.status >= 200 && cssRes.status < 300) {
          const text = new TextDecoder().decode(cssRes.bytes)
          docCss += '\n' + rewriteCssRelativeUrls(text, cssRes.finalUrl, loopbackOrigin, access.globalParam)
          break
        }
      } catch (err) {
        if (err instanceof RenderServiceError && (err.code === 'OUTPUT_TOO_LARGE' || err.code === 'RENDER_TIMEOUT')) {
          throw err
        }
      }
    }

    let totalImageBytes = 0
    const assembledPages = await mapPool(selectedPages, 4, async (pageNum) => {
      checkDeadline(deadlineMs, abortController)
      const row = pageDataByNum.get(pageNum) || {}
      const width = Number(row.width) > 0 ? Math.round(Number(row.width)) : 794
      const height = Number(row.height) > 0 ? Math.round(Number(row.height)) : 1123
      const urls = buildStudocuAssetUrls(access, pageNum)

      const fetchEmbeddedBg = async (required) => {
        if (!urls.bgUrl) {
          if (required) {
            throw new RenderServiceError('NO_PAGES_FOUND', `Missing image URL for page ${pageNum}.`)
          }
          return null
        }
        const imgRes = await safeFetchAsset(
          urls.bgUrl,
          loopbackOrigin,
          MAX_ASSET_BYTES,
          abortController.signal,
          userAgent
        )
        if (imgRes.status === 403 || imgRes.status === 401) {
          throw new RenderServiceError(
            'SOURCE_RESTRICTED',
            `Source denied image asset for page ${pageNum} (HTTP ${imgRes.status}).`,
            { sourceStatus: imgRes.status, pageNumber: pageNum }
          )
        }
        if (imgRes.status < 200 || imgRes.status >= 300) {
          if (required) {
            throw new RenderServiceError(
              'NO_PAGES_FOUND',
              `Image asset for page ${pageNum} returned HTTP ${imgRes.status}.`,
              { sourceStatus: imgRes.status, pageNumber: pageNum }
            )
          }
          return null
        }
        const mime = detectImageMime(imgRes.bytes, imgRes.contentType)
        if (!mime) {
          if (required) {
            throw new RenderServiceError('RENDER_FAILED', `Invalid image bytes for page ${pageNum}.`)
          }
          return null
        }
        totalImageBytes += imgRes.bytes.byteLength
        if (totalImageBytes > MAX_TOTAL_IMAGE_BYTES) {
          throw new RenderServiceError('OUTPUT_TOO_LARGE', 'Embedded page images exceeded memory budget.')
        }
        return `data:${mime};base64,${Buffer.from(imgRes.bytes).toString('base64')}`
      }

      if (effectiveMode === 'scan') {
        const bgDataUri = await fetchEmbeddedBg(true)
        return {
          pageNum,
          width,
          height,
          markup: `<div class="pf" data-page-no="${pageNum.toString(16)}" style="width:${width}px;height:${height}px"><div class="pc" style="width:${width}px;height:${height}px"><img class="bi x0 y0 w1 h1" alt="" src="${bgDataUri}" style="display:block;width:100%;height:100%;object-fit:contain"></div></div>`,
        }
      }

      // Text-layer mode: fetch real .page fragment (or inline row HTML).
      let rawFragment =
        (typeof row.pageHtml === 'string' && row.pageHtml) ||
        (typeof row.html === 'string' && row.html) ||
        prefetchedFragments.get(pageNum) ||
        ''

      if (!rawFragment) {
        const textFetchUrl = urls.pageTextUrl || urls.candidatePageTextUrl
        if (!textFetchUrl) {
          throw new RenderServiceError(
            'SOURCE_RESTRICTED',
            `Missing signed text fragment URL for page ${pageNum}.`,
            { lockedPages: [pageNum] }
          )
        }
        const pageRes = await safeFetchAsset(
          textFetchUrl,
          loopbackOrigin,
          MAX_ASSET_BYTES,
          abortController.signal,
          userAgent
        )
        if (pageRes.status === 403 || pageRes.status === 401) {
          throw new RenderServiceError(
            'SOURCE_RESTRICTED',
            `Text layer for page ${pageNum} was denied (HTTP ${pageRes.status}).`,
            { sourceStatus: pageRes.status, lockedPages: [pageNum] }
          )
        }
        if (pageRes.status < 200 || pageRes.status >= 300) {
          throw new RenderServiceError(
            'NO_PAGES_FOUND',
            `Text layer for page ${pageNum} returned HTTP ${pageRes.status}.`,
            { sourceStatus: pageRes.status, pageNumber: pageNum }
          )
        }
        rawFragment = new TextDecoder().decode(pageRes.bytes)
      }

      const sanitized = sanitizePageHtml(rawFragment).trim()
      if (!sanitized) {
        throw new RenderServiceError('NO_PAGES_FOUND', `Page ${pageNum} text fragment was empty.`)
      }

      const bgDataUri = await fetchEmbeddedBg(false)
      let fragmentWithBg = sanitized
      if (bgDataUri) {
        fragmentWithBg = fragmentWithBg
          .replace(/\s+\b(?:data-src|srcset)\s*=\s*(["'])[^"']*\1/gi, '')
          .replace(
            /\bsrc\s*=\s*(["'])([^"']*bg[0-9a-f]+\.png(?:\?[^"']*)?)\1/gi,
            `src="${bgDataUri}"`
          )
      } else {
        fragmentWithBg = fragmentWithBg.replace(
          /<img\b[^>]*\bsrc\s*=\s*(["'])[^"']*bg[0-9a-f]+\.png(?:\?[^"']*)?\1[^>]*>/gi,
          ''
        )
      }

      const alreadyWrappedPf = /^<div\b[^>]*\bclass\s*=\s*(["'])[^"']*\bpf\b/i.test(fragmentWithBg)
      if (alreadyWrappedPf) {
        return { pageNum, width, height, markup: fragmentWithBg }
      }

      const wrapper = typeof row.pageHtmlWrapper === 'string' ? sanitizePageHtml(row.pageHtmlWrapper).trim() : ''
      if (wrapper && /^<div\b/i.test(wrapper)) {
        return { pageNum, width, height, markup: `${wrapper}${fragmentWithBg}</div>` }
      }

      return {
        pageNum,
        width,
        height,
        markup: `<div class="pf" data-page-no="${pageNum.toString(16)}" style="width:${width}px;height:${height}px">${fragmentWithBg}</div>`,
      }
    })

    checkDeadline(deadlineMs, abortController)
    recordMemory()

    // Step 4: Render clean print document in a fresh Playwright page and print to PDF.
    const cspFontSrc = loopbackOrigin ? `data: https: ${loopbackOrigin}` : 'data: https:'
    const cspStyleSrc = loopbackOrigin ? `'unsafe-inline' https: ${loopbackOrigin}` : `'unsafe-inline' https:`
    const cspImgSrc = loopbackOrigin ? `data: https: ${loopbackOrigin}` : 'data: https:'

    const printHtml = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src ${cspStyleSrc}; font-src ${cspFontSrc}; img-src ${cspImgSrc};">
<title>${escapeHtmlAttr(title)}</title>
<style>
html, body { margin: 0; padding: 0; background: #fff; }
.p2hv { margin: 0; padding: 0; }
${docCss}
.p2hv .pf { position: relative !important; margin: 0 !important; padding: 0 !important; overflow: hidden !important; background: #fff !important; break-after: page; page-break-after: always; }
.p2hv .pf:last-child { break-after: auto; page-break-after: auto; }
.p2hv .pc { display: block !important; visibility: visible !important; opacity: 1 !important; filter: none !important; }
</style>
</head>
<body>
<div class="p2hv">
${assembledPages.map((p) => p.markup).join('\n')}
</div>
</body>
</html>`

    const printPage = await context.newPage()
    try {
      await printPage.setContent(printHtml, {
        waitUntil: 'networkidle',
        timeout: remainingMs(deadlineMs, 25_000),
      })

      const layoutReport = await printPage.evaluate(async () => {
        if (document.fonts && document.fonts.ready) {
          await document.fonts.ready.catch(() => {})
        }
        const imgs = Array.from(document.querySelectorAll('img'))
        await Promise.all(
          imgs.map(
            (img) =>
              new Promise((resolve) => {
                if (img.complete) {
                  resolve()
                  return
                }
                img.addEventListener('load', resolve, { once: true })
                img.addEventListener('error', resolve, { once: true })
                setTimeout(resolve, 4000)
              })
          )
        )

        const pfs = Array.from(document.querySelectorAll('.p2hv .pf'))
        const rules = []
        const names = Object.create(null)
        const sizes = []

        for (const pf of pfs) {
          const rect = pf.getBoundingClientRect()
          const w = Math.max(1, Math.round(rect.width))
          const h = Math.max(1, Math.round(rect.height))
          sizes.push({ w, h })
          const key = `${w}x${h}`
          if (!names[key]) {
            names[key] = `dp-page-${rules.length + 1}`
            rules.push(`@page ${names[key]} { size: ${w}px ${h}px; margin: 0; }`)
          }
          pf.style.setProperty('page', names[key])
        }

        if (rules.length) {
          const styleEl = document.createElement('style')
          styleEl.id = 'dp-page-sizes'
          styleEl.textContent = rules.join('\n')
          document.head.appendChild(styleEl)
        }

        const loadedImages = imgs.filter((img) => img.complete && img.naturalWidth > 0).length
        const brokenImages = imgs.length - loadedImages
        const renderedTextChars = (document.body?.innerText || '').replace(/\s+/g, ' ').trim().length

        return {
          pfCount: pfs.length,
          loadedImages,
          brokenImages,
          renderedTextChars,
          sizes,
        }
      })

      if (layoutReport.pfCount !== selectedPages.length) {
        throw new RenderServiceError(
          'RENDER_FAILED',
          `Rendered DOM page count (${layoutReport.pfCount}) did not match selected pages (${selectedPages.length}).`
        )
      }
      if (effectiveMode === 'text' && layoutReport.renderedTextChars === 0) {
        throw new RenderServiceError(
          'NO_PAGES_FOUND',
          'Text-mode document rendered zero text characters.'
        )
      }
      if (effectiveMode === 'scan' && layoutReport.loadedImages < selectedPages.length) {
        throw new RenderServiceError(
          'RENDER_FAILED',
          `Scan document loaded only ${layoutReport.loadedImages} of ${selectedPages.length} page images.`
        )
      }

      checkDeadline(deadlineMs, abortController)
      const pdfBuffer = await printPage.pdf({
        printBackground: true,
        preferCSSPageSize: true,
        margin: { top: '0', right: '0', bottom: '0', left: '0' },
      })
      recordMemory()

      const bytes = new Uint8Array(pdfBuffer)
      if (bytes.byteLength > maxPdfBytes) {
        throw new RenderServiceError(
          'OUTPUT_TOO_LARGE',
          `Generated PDF (${bytes.byteLength} bytes) exceeds ${maxPdfBytes} byte limit.`,
          { pdfBytes: bytes.byteLength, maxPdfBytes }
        )
      }

      const pdfInfo = inspectPdfBytes(bytes)
      if (pdfInfo.pageCount !== selectedPages.length) {
        throw new RenderServiceError(
          'RENDER_FAILED',
          `PDF page count mismatch: expected ${selectedPages.length}, got ${pdfInfo.pageCount}.`,
          { expectedPages: selectedPages.length, pdfPageCount: pdfInfo.pageCount }
        )
      }

      const durationMs = Date.now() - startedAt
      const containerMem = readContainerMemoryBytes()
      return {
        metadata: {
          title,
          totalPages,
          from,
          to,
          pageCount: selectedPages.length,
          filename: downloadFilename(title, 'pdf'),
        },
        diagnostics: {
          sourceStatus,
          finalUrl: safeFinalUrl,
          mode: effectiveMode,
          accessiblePages: fullAccess.accessiblePages.length,
          selectedPagesCount: selectedPages.length,
          pdfPageCount: pdfInfo.pageCount,
          pdfBytes: bytes.byteLength,
          renderedTextChars: layoutReport.renderedTextChars,
          loadedImages: layoutReport.loadedImages,
          brokenImages: layoutReport.brokenImages,
          durationMs,
          peakRssBytes,
          ...containerMem,
        },
        bytes,
      }
    } finally {
      await printPage.close().catch(() => {})
    }
  } catch (err) {
    recordMemory()
    const timingDetails = {
      durationMs: Date.now() - startedAt,
      peakRssBytes,
      ...readContainerMemoryBytes(),
    }
    if (err instanceof RenderServiceError) {
      err.details = { ...(err.details || {}), ...timingDetails }
      throw err
    }
    if (disallowedRedirectError) {
      disallowedRedirectError.details = { ...(disallowedRedirectError.details || {}), ...timingDetails }
      throw disallowedRedirectError
    }
    if (timedOut || isAbortLikeError(err)) {
      throw new RenderServiceError('RENDER_TIMEOUT', 'Render job timed out.', timingDetails)
    }
    throw new RenderServiceError(
      'RENDER_FAILED',
      err instanceof Error ? err.message : 'Unexpected render failure.',
      timingDetails
    )
  } finally {
    clearTimeout(hardTimer)
    if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort)
    if (context && !timedOut && browser?.isConnected()) {
      await withCleanupTimeout(context.close(), 2000)
    }
    await closeBrowserOnce()
  }
}
