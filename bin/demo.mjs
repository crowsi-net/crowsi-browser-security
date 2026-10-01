#!/usr/bin/env node
import { createServer } from 'node:http'
import { once } from 'node:events'
import { pathToFileURL } from 'node:url'
import { SessionAuthority, createLaunchAccess } from '../src/access.mjs'
import { parseOwnerOrigin, assessRequestBoundary, securityHeaders } from '../src/boundary.mjs'
import { OwnerSecurity } from '../src/owner-security.mjs'

/** Real loopback HTTP demo; cryptographic ceremonies require explicit native providers. */
export async function startDemo({ port = 4317, paths = {} } = {}) {
  let authority, boundary, owner
  const server = createServer(async (request, response) => {
    const headers = { ...securityHeaders(), 'content-type': 'application/json' }
    const send = (status, value, extra = {}) => {
      response.writeHead(status, { ...headers, ...extra }); response.end(JSON.stringify(value))
    }
    try {
      const reason = assessRequestBoundary(boundary, {
        host: request.headers.host, origin: request.headers.origin,
        fetchSite: request.headers['sec-fetch-site'], method: request.method
      })
      if (reason) return send(403, { reason })
      if (request.method === 'GET' && request.url === '/') {
        response.writeHead(200, { ...headers, 'content-type': 'text/html' })
        response.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>Local access demo</title><h1>Local browser access</h1><p>This standalone endpoint exposes /connect, /status, /passkey/start, /passkey/stage, /passkey/confirm, /authentication/start, /authentication/confirm, /recovery/inspect and /logout. Use the CLI test client documented in README. No application state is loaded.</p></html>')
        return
      }
      let body = {}
      if (request.method === 'POST') {
        let size = 0; const chunks = []
        for await (const chunk of request) {
          size += chunk.length
          if (size > 1_048_576) return send(413, { reason: 'request-too-large' })
          chunks.push(chunk)
        }
        body = JSON.parse(Buffer.concat(chunks).toString() || '{}')
      }
      const issue = session => send(200, { csrf: session.csrfToken, expiresAt: session.expiresAt }, {
        'set-cookie': `local_access=${session.sessionId}; HttpOnly; SameSite=Strict; Path=/`
      })
      if (request.method === 'POST' && request.url === '/connect') return issue(authority.launch(body.credential))
      if (request.method === 'POST' && request.url === '/authentication/start') return send(200, await owner.startAuthentication())
      if (request.method === 'POST' && request.url === '/authentication/confirm') {
        await owner.confirmAuthentication(body); return issue(authority.issue())
      }
      const sessionId = request.headers.cookie?.split('; ').find(item => item.startsWith('local_access='))?.slice(13)
      authority.authenticate(sessionId)
      if (request.method === 'GET' && ['/status', '/recovery/inspect'].includes(request.url)) return send(200, await owner.inspect())
      if (request.method !== 'POST') return send(404, { reason: 'route-not-found' })
      authority.authorizeMutation(sessionId, request.headers['x-csrf'], request.headers['x-nonce'])
      const actions = { '/passkey/start': () => owner.start(), '/passkey/stage': () => owner.stage(body),
        '/passkey/confirm': () => owner.confirm(body), '/passkey/cancel': () => owner.cancel(body.registrationRef),
        '/logout': () => authority.revoke(sessionId) }
      const action = actions[request.url]
      if (!action) return send(404, { reason: 'route-not-found' })
      return send(200, await action() ?? { completed: true })
    } catch (error) {
      const reason = /^crowsi-browser-security-[a-z0-9-]+$/u.test(error?.message)
        ? error.message : 'request-rejected'
      send(400, { reason })
    }
  })
  server.requestTimeout = 15_000; server.headersTimeout = 10_000
  server.listen(port, '127.0.0.1'); await once(server, 'listening')
  const origin = `http://localhost:${server.address().port}`
  const launch = createLaunchAccess(origin)
  authority = new SessionAuthority({ launchToken: launch.credential })
  boundary = parseOwnerOrigin(origin); owner = new OwnerSecurity({ origin, paths })
  return { url: launch.url, async close() {
    owner.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve))
  } }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const demo = await startDemo({ paths: {
    securityRoot: process.env.CROWSI_SECURITY_ROOT, paAgent: process.env.CROWSI_PA_AGENT,
    credentialAgent: process.env.CROWSI_CREDENTIAL_AGENT,
    ownerRecoveryProvider: process.env.CROWSI_RECOVERY_PROVIDER
  } })
  process.stdout.write(`${demo.url}\n`)
  const close = () => { void demo.close().then(() => { process.exitCode = 0 }) }
  process.once('SIGINT', close); process.once('SIGTERM', close)
}
