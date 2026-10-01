import { randomBytes, timingSafeEqual } from 'node:crypto'

/** A launch credential is a local browser bootstrap, not an owner identity. */
export function createLaunchAccess(origin) {
  const url = new URL(origin)
  if (url.origin !== origin || url.username || url.password
    || !['http:', 'https:'].includes(url.protocol)
    || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
    throw new Error('crowsi-browser-security-origin-invalid')
  }
  const credential = randomBytes(32).toString('base64url')
  url.hash = `launch=${credential}`
  return Object.freeze({ credential, url: url.href })
}

const tokenPattern = /^[A-Za-z0-9_-]{43,128}$/u
const noncePattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu

/** Keeps launch and browser authority in process memory only. */
export class SessionAuthority {
  constructor({ launchToken = null, ttlMs = 8 * 60 * 60 * 1000,
    maxSessions = 32, now = Date.now, random = randomBytes } = {}) {
    if (launchToken !== null && !tokenPattern.test(launchToken) || !Number.isSafeInteger(ttlMs) || ttlMs < 60_000
      || ttlMs > 86_400_000 || !Number.isSafeInteger(maxSessions) || maxSessions < 1 || maxSessions > 256) {
      throw new Error('crowsi-browser-security-launch-configuration-invalid')
    }
    this.launchToken = launchToken
    this.maxSessions = maxSessions
    this.ttlMs = ttlMs
    this.now = now
    this.random = random
    this.sessions = new Map()
  }

  launch(token) {
    if (!this.launchToken) throw new Error('crowsi-browser-security-launch-token-consumed')
    if (!constantEquals(token, this.launchToken)) {
      throw new Error('crowsi-browser-security-launch-token-rejected')
    }
    const session = this.issue()
    this.launchToken = null
    return session
  }

  /** Caller enforces its boundary; a session does not assert a human identity. */
  issue() {
    for (const [id, session] of this.sessions) if (session.expiresAt <= this.now()) this.sessions.delete(id)
    if (this.sessions.size >= this.maxSessions) throw new Error('crowsi-browser-security-session-capacity-reached')
    const sessionId = encode(this.random(32))
    const csrfToken = encode(this.random(32))
    const expiresAt = this.now() + this.ttlMs
    this.sessions.set(sessionId, { csrfToken, expiresAt, nonces: new Set() })
    return { sessionId, csrfToken, expiresAt }
  }

  authenticate(sessionId) {
    const value = typeof sessionId === 'string' ? this.sessions.get(sessionId) : null
    if (!value) throw new Error('crowsi-browser-security-session-rejected')
    if (value.expiresAt <= this.now()) {
      this.sessions.delete(sessionId)
      throw new Error('crowsi-browser-security-session-expired')
    }
    return value
  }

  authorizeMutation(sessionId, csrfToken, nonce) {
    const session = this.authenticate(sessionId)
    if (!constantEquals(csrfToken, session.csrfToken)) {
      throw new Error('crowsi-browser-security-csrf-rejected')
    }
    if (!noncePattern.test(nonce)) throw new Error('crowsi-browser-security-request-nonce-invalid')
    if (session.nonces.has(nonce)) throw new Error('crowsi-browser-security-request-replayed')
    if (session.nonces.size >= 65_536) {
      throw new Error('crowsi-browser-security-request-nonce-capacity-reached')
    }
    session.nonces.add(nonce)
  }

  revoke(sessionId) { this.sessions.delete(sessionId) }
}

function encode(value) { return Buffer.from(value).toString('base64url') }
function constantEquals(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}
