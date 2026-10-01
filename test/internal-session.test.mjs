import assert from 'node:assert/strict'
import test from 'node:test'
import { SessionAuthority } from '../src/access.mjs'
test('an internal session has no URL credential and never enables launch authentication', () => {
  const authority = new SessionAuthority()
  const issued = authority.issue()
  assert.equal(authority.authenticate(issued.sessionId).csrfToken, issued.csrfToken)
  assert.throws(() => authority.launch('x'.repeat(43)), /launch-token-consumed/)
  authority.revoke(issued.sessionId)
  assert.throws(() => authority.authenticate(issued.sessionId), /session-rejected/)
})
