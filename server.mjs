import crypto from 'node:crypto'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  MAX_PAGES_HARD_CAP,
  RenderServiceError,
  renderStudocuPdf,
  validateStudocuUrl,
} from './studocu.mjs'

const MAX_JSON_BODY_BYTES = 16 * 1024

function timingSafeBearerMatch(authHeader, expectedSecret) {
  if (!expectedSecret || typeof authHeader !== 'string') return false
  const prefix = 'Bearer '
  if (!authHeader.startsWith(prefix)) return false
  const provided = authHeader.slice(prefix.length)
  const a = Buffer.from(provided, 'utf8')
  const b = Buffer.from(expectedSecret, 'utf8')
  if (a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  })
  res.end(body)
}

function readJsonBody(req, maxBytes = MAX_JSON_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    let done = false

    req.on('data', (chunk) => {
      if (done) return
      total += chunk.byteLength
      if (total > maxBytes) {
        done = true
        reject(new RenderServiceError('BODY_TOO_LARGE', 'Request body exceeded 16 KiB limit.'))
        req.resume()
        return
      }
      chunks.push(chunk)
    })

    req.on('end', () => {
      if (done) return
      done = true
      const raw = Buffer.concat(chunks).toString('utf8')
      try {
        const parsed = JSON.parse(raw || '{}')
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          reject(new RenderServiceError('INVALID_JSON', 'Request body must be a JSON object.'))
          return
        }
        resolve(parsed)
      } catch {
        reject(new RenderServiceError('INVALID_JSON', 'Malformed JSON body.'))
      }
    })

    req.on('error', () => {
      if (done) return
      done = true
      reject(new RenderServiceError('RENDER_FAILED', 'Failed to read request body.'))
    })
  })
}

function statusForFailureCode(code) {
  switch (code) {
    case 'INVALID_URL':
    case 'INVALID_JSON':
      return 400
    case 'BODY_TOO_LARGE':
    case 'OUTPUT_TOO_LARGE':
      return 413
    case 'SOURCE_BLOCKED':
    case 'SOURCE_RESTRICTED':
      return 403
    case 'NOT_FOUND':
      return 404
    case 'NO_PAGES_FOUND':
      return 422
    case 'RENDER_TIMEOUT':
      return 504
    default:
      return 500
  }
}

function sanitizeFilenameHeader(filename) {
  return String(filename || 'document.pdf')
    .replace(/["\\\r\n;]/g, '_')
    .replace(/[^\x20-\x7e]/g, '_')
    .slice(0, 100) || 'document.pdf'
}

export function createRenderServer(options = {}) {
  const secret = options.secret ?? process.env.DOCPRESS_RENDER_SECRET ?? ''
  const enableProbe =
    options.enableProbe !== undefined
      ? Boolean(options.enableProbe)
      : process.env.DOCPRESS_ENABLE_PROBE !== 'false'
  const renderPdf = options.renderPdf ?? renderStudocuPdf

  let busy = false
  let activeAbortController = null

  const server = http.createServer(async (req, res) => {
    const method = req.method || 'GET'
    let pathname = '/'
    try {
      pathname = new URL(req.url || '/', 'http://localhost').pathname
    } catch {
      sendJson(res, 400, { code: 'INVALID_URL', message: 'Malformed request path.' })
      return
    }

    if (method === 'GET' && pathname === '/health') {
      sendJson(res, 200, { ok: true, busy })
      return
    }

    if (enableProbe && method === 'POST' && pathname === '/v1/probe') {
      if (!secret) {
        sendJson(res, 503, { code: 'NOT_CONFIGURED', message: 'DOCPRESS_RENDER_SECRET is not set.' })
        return
      }
      if (!timingSafeBearerMatch(req.headers.authorization, secret)) {
        sendJson(res, 401, { code: 'UNAUTHORIZED', message: 'Missing or invalid Bearer token.' })
        return
      }

      let body
      try {
        body = await readJsonBody(req, MAX_JSON_BODY_BYTES)
      } catch (err) {
        const code = err instanceof RenderServiceError ? err.code : 'INVALID_JSON'
        sendJson(res, statusForFailureCode(code), { code, message: err.message })
        return
      }

      try {
        validateStudocuUrl(body.sourceUrl)
      } catch (err) {
        sendJson(res, 400, { code: 'INVALID_URL', message: err.message })
        return
      }

      const rawMaxPages = body.maxPages !== undefined ? Number(body.maxPages) : MAX_PAGES_HARD_CAP
      if (!Number.isSafeInteger(rawMaxPages) || rawMaxPages < 1) {
        sendJson(res, 400, { code: 'INVALID_URL', message: 'maxPages must be a positive integer.' })
        return
      }
      const maxPages = Math.min(MAX_PAGES_HARD_CAP, rawMaxPages)
      const rangeFrom = body.rangeFrom !== undefined ? Number(body.rangeFrom) : undefined
      const rangeTo = body.rangeTo !== undefined ? Number(body.rangeTo) : undefined
      if (
        (rangeFrom !== undefined && (!Number.isSafeInteger(rangeFrom) || rangeFrom < 1)) ||
        (rangeTo !== undefined && (!Number.isSafeInteger(rangeTo) || rangeTo < 1)) ||
        (rangeFrom !== undefined && rangeTo !== undefined && rangeFrom > rangeTo)
      ) {
        sendJson(res, 400, { code: 'INVALID_URL', message: 'Invalid page range parameters.' })
        return
      }

      if (busy) {
        sendJson(res, 429, { code: 'BUSY', message: 'Renderer is currently processing another job.' })
        return
      }

      busy = true
      activeAbortController = new AbortController()
      try {
        const result = await renderPdf(
          {
            sourceUrl: body.sourceUrl,
            rangeFrom,
            rangeTo,
            maxPages,
          },
          { signal: activeAbortController.signal }
        )

        const pdfBuf = Buffer.from(result.bytes)
        const headers = {
          'Content-Type': 'application/pdf',
          'Content-Length': pdfBuf.byteLength,
          'Content-Disposition': `attachment; filename="${sanitizeFilenameHeader(result.metadata.filename)}"`,
          'Cache-Control': 'no-store',
          'X-DocPress-Title': encodeURIComponent(result.metadata.title || 'document'),
          'X-DocPress-Total-Pages': String(result.metadata.totalPages),
          'X-DocPress-From': String(result.metadata.from),
          'X-DocPress-To': String(result.metadata.to),
          'X-DocPress-Page-Count': String(result.metadata.pageCount),
        }
        if (result.diagnostics) {
          if (result.diagnostics.accessiblePages !== undefined) {
            headers['X-DocPress-Accessible-Pages'] = String(result.diagnostics.accessiblePages)
          }
          if (result.diagnostics.mode) headers['X-DocPress-Mode'] = String(result.diagnostics.mode)
          if (result.diagnostics.sourceStatus !== undefined) {
            headers['X-DocPress-Source-Status'] = String(result.diagnostics.sourceStatus)
          }
          if (result.diagnostics.durationMs !== undefined) {
            headers['X-DocPress-Duration-Ms'] = String(result.diagnostics.durationMs)
          }
          if (result.diagnostics.peakRssBytes !== undefined) {
            headers['X-DocPress-Peak-Rss-Bytes'] = String(result.diagnostics.peakRssBytes)
          }
          if (result.diagnostics.containerPeakBytes !== undefined) {
            headers['X-DocPress-Container-Peak-Bytes'] = String(result.diagnostics.containerPeakBytes)
          }
        }
        res.writeHead(200, headers)
        res.end(pdfBuf)
      } catch (err) {
        const code = err instanceof RenderServiceError ? err.code : 'RENDER_FAILED'
        const message = err instanceof RenderServiceError ? err.message : 'Render failed.'
        const safeDetails =
          err instanceof RenderServiceError && err.details && typeof err.details === 'object'
            ? {
                sourceStatus: err.details.sourceStatus,
                title: err.details.title,
                totalPages: err.details.totalPages,
                accessiblePages: err.details.accessiblePages,
                lockedPages: err.details.lockedPages,
                from: err.details.from,
                to: err.details.to,
                durationMs: err.details.durationMs,
                peakRssBytes: err.details.peakRssBytes,
                containerPeakBytes: err.details.containerPeakBytes,
              }
            : undefined
        sendJson(res, statusForFailureCode(code), {
          code,
          message,
          ...(safeDetails ? { details: safeDetails } : {}),
        })
      } finally {
        busy = false
        activeAbortController = null
      }
      return
    }

    sendJson(res, 404, { code: 'NOT_FOUND', message: 'Route not found.' })
  })

  function shutdown() {
    if (activeAbortController) activeAbortController.abort()
    return new Promise((resolve) => server.close(() => resolve()))
  }

  return { server, shutdown, isBusy: () => busy }
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))

if (isMain) {
  const port = Number(process.env.PORT) || 10000
  const host = '0.0.0.0'
  const { server, shutdown } = createRenderServer()
  server.listen(port, host, () => {
    console.log(`[docpress-render] listening on ${host}:${port}`)
  })
  const onSignal = (sig) => {
    console.log(`[docpress-render] received ${sig}, shutting down`)
    shutdown().finally(() => process.exit(0))
  }
  process.on('SIGTERM', () => onSignal('SIGTERM'))
  process.on('SIGINT', () => onSignal('SIGINT'))
}
