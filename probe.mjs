import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import {
  MAX_PAGES_HARD_CAP,
  RenderServiceError,
  inspectPdfBytes,
  renderStudocuPdf,
  validateStudocuUrl,
} from './studocu.mjs'

const REMOTE_TIMEOUT_MS = 180_000
const MAX_REMOTE_RESPONSE_BYTES = 9 * 1024 * 1024

function parseArgs(argv) {
  const positional = []
  const opts = {
    rangeFrom: undefined,
    rangeTo: undefined,
    maxPages: MAX_PAGES_HARD_CAP,
    manifestPath: undefined,
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--from' && i + 1 < argv.length) {
      opts.rangeFrom = Number(argv[++i])
    } else if (arg === '--to' && i + 1 < argv.length) {
      opts.rangeTo = Number(argv[++i])
    } else if (arg === '--max-pages' && i + 1 < argv.length) {
      opts.maxPages = Number(argv[++i])
    } else if (arg === '--manifest' && i + 1 < argv.length) {
      opts.manifestPath = argv[++i]
    } else if (arg.startsWith('--')) {
      throw new RenderServiceError('INVALID_URL', `Unknown flag: ${arg}`)
    } else {
      positional.push(arg)
    }
  }
  if (positional.length < 2) {
    throw new RenderServiceError(
      'INVALID_URL',
      'Usage: node probe.mjs <studocu-url> <output.pdf> [--from N] [--to N] [--max-pages N] [--manifest file.json]'
    )
  }
  return {
    sourceUrl: positional[0],
    outputPath: path.resolve(positional[1]),
    manifestPath: path.resolve(opts.manifestPath || `${positional[1]}.manifest.json`),
    rangeFrom: opts.rangeFrom,
    rangeTo: opts.rangeTo,
    maxPages: opts.maxPages,
  }
}

async function readLimitedResponse(response, maxBytes) {
  const cl = Number(response.headers.get('content-length') || '')
  if (Number.isFinite(cl) && cl > maxBytes) {
    throw new RenderServiceError('OUTPUT_TOO_LARGE', 'Remote probe response exceeded 9 MiB.')
  }
  if (!response.body) {
    const buf = new Uint8Array(await response.arrayBuffer())
    if (buf.byteLength > maxBytes) {
      throw new RenderServiceError('OUTPUT_TOO_LARGE', 'Remote probe response exceeded 9 MiB.')
    }
    return buf
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
        // ignore
      }
      throw new RenderServiceError('OUTPUT_TOO_LARGE', 'Remote probe response exceeded 9 MiB.')
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

async function runRemoteProbe(originRaw, secret, args) {
  let originUrl
  try {
    originUrl = new URL(originRaw)
  } catch {
    throw new RenderServiceError('INVALID_URL', 'Invalid DOCPRESS_PROBE_ORIGIN.')
  }
  const isLoopback = originUrl.hostname === '127.0.0.1' || originUrl.hostname === 'localhost'
  if (originUrl.protocol !== 'https:' && !(isLoopback && originUrl.protocol === 'http:')) {
    throw new RenderServiceError('INVALID_URL', 'DOCPRESS_PROBE_ORIGIN must use https (or loopback http in local tests).')
  }
  if (!secret) {
    throw new RenderServiceError('RENDER_FAILED', 'DOCPRESS_RENDER_SECRET is required when DOCPRESS_PROBE_ORIGIN is set.')
  }

  const endpoint = new URL('/v1/probe', originUrl.origin).href
  const startedAt = Date.now()

  // redirect: 'manual' prevents forwarding Authorization Bearer secret to any redirected origin.
  let res
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        Authorization: `Bearer ${secret}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sourceUrl: args.sourceUrl,
        ...(args.rangeFrom !== undefined ? { rangeFrom: args.rangeFrom } : {}),
        ...(args.rangeTo !== undefined ? { rangeTo: args.rangeTo } : {}),
        maxPages: args.maxPages,
      }),
      signal: AbortSignal.timeout(REMOTE_TIMEOUT_MS),
    })
  } catch (err) {
    if (err?.name === 'TimeoutError' || err?.name === 'AbortError') {
      throw new RenderServiceError('RENDER_TIMEOUT', 'Remote probe timed out after 180 seconds.')
    }
    throw new RenderServiceError('RENDER_FAILED', 'Failed to reach remote probe service.')
  }

  if (res.status >= 300 && res.status < 400) {
    throw new RenderServiceError(
      'RENDER_FAILED',
      `Remote probe refused redirect (HTTP ${res.status}) to prevent secret forwarding.`
    )
  }

  const bodyBytes = await readLimitedResponse(res, MAX_REMOTE_RESPONSE_BYTES)
  const ct = (res.headers.get('content-type') || '').toLowerCase()

  if (!res.ok) {
    let parsedErr = null
    try {
      parsedErr = JSON.parse(new TextDecoder().decode(bodyBytes))
    } catch {
      // ignore non-JSON body
    }
    throw new RenderServiceError(
      parsedErr?.code || 'RENDER_FAILED',
      parsedErr?.message || `Remote probe returned HTTP ${res.status}.`,
      { httpStatus: res.status, ...(parsedErr?.details || {}) }
    )
  }

  if (!ct.includes('application/pdf')) {
    throw new RenderServiceError('RENDER_FAILED', `Expected application/pdf response, got ${ct || 'unknown'}.`)
  }

  const pdfInfo = inspectPdfBytes(bodyBytes)
  const totalPages = Number(res.headers.get('x-docpress-total-pages') || '0')
  const from = Number(res.headers.get('x-docpress-from') || '0')
  const to = Number(res.headers.get('x-docpress-to') || '0')
  const pageCount = Number(res.headers.get('x-docpress-page-count') || '0')
  const accessiblePages = Number(res.headers.get('x-docpress-accessible-pages') || '0')
  const titleHeader = res.headers.get('x-docpress-title') || ''
  let title = 'document'
  if (titleHeader) {
    try {
      title = decodeURIComponent(titleHeader)
    } catch {
      title = titleHeader
    }
  }

  if (pageCount <= 0 || pdfInfo.pageCount !== pageCount) {
    throw new RenderServiceError(
      'RENDER_FAILED',
      `Remote PDF page count (${pdfInfo.pageCount}) did not match header (${pageCount}).`
    )
  }

  return {
    metadata: {
      title,
      totalPages,
      from,
      to,
      pageCount,
      filename: path.basename(args.outputPath),
    },
    diagnostics: {
      remoteOrigin: originUrl.origin,
      sourceStatus: Number(res.headers.get('x-docpress-source-status') || '200'),
      mode: res.headers.get('x-docpress-mode') || 'unknown',
      accessiblePages: accessiblePages || undefined,
      pdfPageCount: pdfInfo.pageCount,
      pdfBytes: bodyBytes.byteLength,
      durationMs: Number(res.headers.get('x-docpress-duration-ms') || '0') || Date.now() - startedAt,
      roundTripMs: Date.now() - startedAt,
      peakRssBytes: Number(res.headers.get('x-docpress-peak-rss-bytes') || '0') || undefined,
      containerPeakBytes: Number(res.headers.get('x-docpress-container-peak-bytes') || '0') || undefined,
    },
    bytes: bodyBytes,
  }
}

async function writeManifest(manifestPath, payload) {
  await mkdir(path.dirname(manifestPath), { recursive: true })
  await writeFile(manifestPath, JSON.stringify(payload, null, 2) + '\n', 'utf8')
}

async function main() {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
    validateStudocuUrl(args.sourceUrl)
  } catch (err) {
    console.error(`Error [${err?.code || 'INVALID_URL'}]: ${err?.message || 'Invalid arguments'}`)
    process.exitCode = 1
    return
  }

  const probeOrigin = (process.env.DOCPRESS_PROBE_ORIGIN || '').trim()
  const secret = (process.env.DOCPRESS_RENDER_SECRET || '').trim()
  const mode = probeOrigin ? 'remote' : 'local'
  const timestamp = new Date().toISOString()

  try {
    const result = probeOrigin
      ? await runRemoteProbe(probeOrigin, secret, args)
      : await renderStudocuPdf({
          sourceUrl: args.sourceUrl,
          rangeFrom: args.rangeFrom,
          rangeTo: args.rangeTo,
          maxPages: args.maxPages,
        })

    await mkdir(path.dirname(args.outputPath), { recursive: true })
    await writeFile(args.outputPath, result.bytes)

    const manifest = {
      ok: true,
      mode,
      timestamp,
      sourceUrl: args.sourceUrl,
      outputPath: args.outputPath,
      metadata: result.metadata,
      diagnostics: result.diagnostics,
    }
    await writeManifest(args.manifestPath, manifest)

    console.log(
      `OK mode=${mode} title="${result.metadata.title}" totalPages=${result.metadata.totalPages} range=${result.metadata.from}-${result.metadata.to} pdfPages=${result.diagnostics.pdfPageCount} bytes=${result.diagnostics.pdfBytes} durationMs=${result.diagnostics.durationMs}`
    )
    process.exitCode = 0
  } catch (err) {
    const code = err instanceof RenderServiceError ? err.code : 'RENDER_FAILED'
    const message = err instanceof RenderServiceError ? err.message : String(err?.message || 'Unknown error')
    const details = err instanceof RenderServiceError ? err.details : undefined
    const manifest = {
      ok: false,
      mode,
      timestamp,
      sourceUrl: args.sourceUrl,
      code,
      message,
      ...(details ? { details } : {}),
    }
    await writeManifest(args.manifestPath, manifest).catch(() => {})
    console.error(`FAILED mode=${mode} code=${code} message="${message}"`)
    process.exitCode = 1
  }
}

await main()
