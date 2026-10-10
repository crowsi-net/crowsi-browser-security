import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import test from 'node:test'
import {SessionAuthority} from '../src/access.mjs'
import {parseOwnerOrigin,securityHeaders} from '../src/boundary.mjs'

test('coercible nonce objects cannot evade replay detection',()=>{
 const authority=new SessionAuthority(), session=authority.issue(), nonce=randomUUID()
 for(const value of [[nonce],{toString:()=>nonce}]) {
  assert.throws(()=>authority.authorizeMutation(session.sessionId,session.csrfToken,value),/request-nonce-invalid/u)
 }
 authority.authorizeMutation(session.sessionId,session.csrfToken,nonce)
 assert.throws(()=>authority.authorizeMutation(session.sessionId,session.csrfToken,nonce),/request-replayed/u)
 assert.throws(()=>new SessionAuthority({launchToken:['a'.repeat(43)]}),/configuration-invalid/u)
 assert.throws(()=>parseOwnerOrigin(['http://localhost:4317']),/origin-invalid/u)
})

test('CSP blocks unrestricted inline execution and binds only explicit valid nonces',()=>{
 const defaults=securityHeaders()['content-security-policy']
 assert.doesNotMatch(defaults,/unsafe-inline/u)
 const nonce='a'.repeat(22)
 const selected=securityHeaders({scriptNonce:nonce})['content-security-policy']
 assert.ok(selected.includes(`script-src 'self' 'nonce-${nonce}'`))
 assert.throws(()=>securityHeaders({scriptNonce:"unsafe' injected"}),/csp-nonce-invalid/u)
 assert.throws(()=>securityHeaders({styleNonce:'short'}),/csp-nonce-invalid/u)
})
