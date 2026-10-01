const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]'])
const unsafeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const loopbackAuthority = /^(localhost|127\.0\.0\.1|\[::1\]):([0-9]{1,5})$/i

/** Defines the sole browser origin admitted by an owner-local console process. */
export function parseOwnerOrigin(value) {
  let url
  try { url = new URL(value) } catch { invalid() }
  if (!['http:', 'https:'].includes(url.protocol)
    || !loopbackHosts.has(url.hostname) || !url.port || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash) invalid()
  const port = Number(url.port)
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) invalid()
  return Object.freeze({ origin: url.origin, host: url.host, port: url.port,
    protocol: url.protocol })
}

export function assessRequestBoundary(owner, request) {
  if (!isOwnerLoopbackHost(owner, request.host)) return 'crowsi-browser-security-host-rejected'
  if (request.origin && request.origin !== owner.origin) {
    return 'crowsi-browser-security-origin-rejected'
  }
  if (unsafeMethods.has(request.method.toUpperCase())
    && request.origin !== owner.origin) return 'crowsi-browser-security-origin-required'
  if (request.fetchSite === 'cross-site') {
    return 'crowsi-browser-security-fetch-site-rejected'
  }
  return null
}

/** Allows only loopback spelling changes introduced by a local OS/WSL bridge. */
function isOwnerLoopbackHost(owner, value) {
  if (typeof value !== 'string' || value.trim() !== value) return false
  const match = loopbackAuthority.exec(value)
  if (!match || !loopbackHosts.has(match[1].toLowerCase())) return false
  const port = Number(match[2])
  return Number.isSafeInteger(port) && String(port) === match[2] && String(port) === owner.port
}

export function securityHeaders() {
  return Object.freeze({
    'content-security-policy': [
      "default-src 'self'", "base-uri 'none'", "object-src 'none'",
      "frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'",
      "img-src 'self' data:", "font-src 'self'", "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline'"
    ].join('; '),
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'cache-control': 'no-store'
  })
}

function invalid() { throw new Error('crowsi-browser-security-origin-invalid') }
