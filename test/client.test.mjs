import assert from 'node:assert/strict'
import test from 'node:test'
import { createLaunchAccess, SessionAuthority } from '../src/access.mjs'
import { consumeLaunchCredential, connectBrowser } from '../src/client.mjs'

test('generic browser bootstrap clears history, correlates credentials, rejects replay and external origins', async () => {
  const launch = createLaunchAccess('http://localhost:4317')
  const location = new URL(launch.url)
  let cleared
  const credential = consumeLaunchCredential({ location, history: {
    replaceState: (_state, _title, value) => { cleared = value }
  } })
  assert.equal(credential, launch.credential)
  assert.equal(cleared, '/')
  const authority = new SessionAuthority({ launchToken: credential })
  const session = await connectBrowser({ credential, request: async (path, options) => {
    if (path === '/api/session') return { authenticated: false }
    assert.equal(path, '/api/session/connect')
    assert.equal(options.method, 'POST')
    const value = authority.launch(options.body.credential)
    return { authenticated: true, csrf: value.csrfToken, expiresAtUnixMs: value.expiresAt }
  } })
  assert.equal(session.authenticated, true)
  assert.throws(() => authority.launch(credential), /launch-token-consumed/u)
  assert.throws(() => createLaunchAccess('https://example.com'), /origin-invalid/u)
  assert.equal(await connectBrowser({ request: async () => session }), session)
  await assert.rejects(connectBrowser({ request: async () => ({ authenticated: false }) }), /session-unavailable/u)
})
