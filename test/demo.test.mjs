import assert from 'node:assert/strict'
import test from 'node:test'
import { randomUUID } from 'node:crypto'
import { startDemo } from '../bin/demo.mjs'

test('standalone HTTP access enforces origin, one-use bootstrap, mutation proof and logout without an application', async t => {
  const demo = await startDemo({ port: 0 }); t.after(() => demo.close())
  const url = new URL(demo.url); const origin = url.origin
  const post = (path, body, headers = {}) => fetch(origin + path, { method: 'POST',
    headers: { origin, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) })
  assert.equal((await post('/connect', {}, { origin: 'http://example.com' })).status, 403)
  assert.equal((await fetch(origin + '/status')).status, 400)
  const credential = new URLSearchParams(url.hash.slice(1)).get('launch')
  const connected = await post('/connect', { credential })
  assert.equal(connected.status, 200)
  const cookie = connected.headers.get('set-cookie').split(';')[0]
  const session = await connected.json()
  assert.equal((await post('/connect', { credential })).status, 400)
  const status = await fetch(origin + '/status', { headers: { cookie } })
  assert.equal(status.status, 200)
  assert.equal((await status.json()).state, 'foundation-required')
  assert.equal((await post('/logout', {}, { cookie })).status, 400)
  assert.equal((await post('/logout', {}, { cookie, 'x-csrf': session.csrf, 'x-nonce': randomUUID() })).status, 200)
  assert.equal((await fetch(origin + '/status', { headers: { cookie } })).status, 400)
})
