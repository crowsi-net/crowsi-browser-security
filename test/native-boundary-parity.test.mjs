import { readFileSync } from 'node:fs'
import assert from 'node:assert/strict'
import test from 'node:test'
import { parseOwnerOrigin, assessRequestBoundary } from '../src/boundary.mjs'
const cases = JSON.parse(readFileSync(new URL('../native/browser-boundary/test-data/boundary-cases.json', import.meta.url), 'utf8'))
test('native and JavaScript browser boundary share the same owner contract vectors', () => {
  assert.equal(cases.schemaVersion, 'crowsi-browser-boundary-cases/v1')
  for (const item of cases.ownerCases) {
    if (item.origin === null) assert.throws(() => parseOwnerOrigin(item.input))
    else assert.equal(parseOwnerOrigin(item.input).origin, item.origin)
  }
  const owner = parseOwnerOrigin('http://127.0.0.1:4317')
  for (const item of cases.requestCases) assert.equal(assessRequestBoundary(owner, item), item.error)
})
