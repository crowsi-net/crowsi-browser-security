import assert from 'node:assert/strict'
import test from 'node:test'
import { SessionAuthority } from '../src/access.mjs'
import { connectBrowser } from '../src/client.mjs'
test('bounds live sessions, reclaims expired entries and rejects invalid browser responses', async () => {
  let now = 0
  const authority = new SessionAuthority({ launchToken: 'a'.repeat(43), maxSessions: 1,
    ttlMs: 60_000, now: () => now })
  const first = authority.issue()
  assert.throws(() => authority.issue(), /session-capacity-reached/u)
  now = 60_001
  const second = authority.issue()
  assert.notEqual(second.sessionId, first.sessionId)
  assert.equal(authority.sessions.size, 1)
  assert.throws(() => authority.authenticate(first.sessionId), /session-rejected/u)
  for (const value of [{ authenticated: true }, { authenticated: true, csrf: 'secret' }]) {
    await assert.rejects(connectBrowser({ request: async () => value }), /session-response-invalid/u)
  }
})
