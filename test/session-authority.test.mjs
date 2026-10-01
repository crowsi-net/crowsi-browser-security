import assert from 'node:assert/strict'
import test from 'node:test'
import { SessionAuthority } from '../src/access.mjs'

const launchToken = 'A'.repeat(43)

test('consumes a launch token once and expires its session', () => {
  let now = 1_000
  let sequence = 1
  const authority = new SessionAuthority({ launchToken, ttlMs: 60_000,
    now: () => now, random: () => Buffer.alloc(32, sequence++) })
  const session = authority.launch(launchToken)
  assert.equal(authority.authenticate(session.sessionId).csrfToken, session.csrfToken)
  assert.throws(() => authority.launch(launchToken), /launch-token-consumed/)
  now += 60_001
  assert.throws(() => authority.authenticate(session.sessionId), /session-expired/)
})

test('binds mutations to CSRF and one-use nonces', () => {
  const authority = new SessionAuthority({ launchToken,
    now: () => 1_000, random: () => Buffer.alloc(32, 7) })
  const session = authority.launch(launchToken)
  assert.throws(() => authority.authorizeMutation(
    session.sessionId, 'wrong', '00000000-0000-4000-8000-000000000001'
  ), /csrf-rejected/)
  authority.authorizeMutation(
    session.sessionId, session.csrfToken, '00000000-0000-4000-8000-000000000001'
  )
  assert.throws(() => authority.authorizeMutation(
    session.sessionId, session.csrfToken, '00000000-0000-4000-8000-000000000001'
  ), /request-replayed/)
})

test('issues the same bounded session after an external Passkey authority succeeds', () => {
  const authority = new SessionAuthority({ launchToken,
    now: () => 2_000, random: () => Buffer.alloc(32, 9) })
  const session = authority.issue()
  assert.equal(authority.authenticate(session.sessionId).csrfToken, session.csrfToken)
  assert.equal(session.expiresAt, 2_000 + 8 * 60 * 60 * 1_000)
})
