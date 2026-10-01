import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { custodyRuntime, installPrivateExecutable, installPrivateJson } from '../src/provision.mjs'

test('Generic custody pin contains no credential or secret value', () => {
  const value = custodyRuntime('/release/provider.exe', `sha256:${'a'.repeat(64)}`, 'example.credentials')
  assert.deepEqual(Object.keys(value).sort(), [
    'helper_path', 'helper_sha256', 'kind', 'namespace', 'protocol_version', 'schema'])
  assert.equal(value.namespace, 'example.credentials')
  assert.doesNotMatch(JSON.stringify(value), /token|password|private.key|secret/iu)
})

test('private JSON install is owner-only and refuses implicit replacement', async t => {
  const temporary = await mkdtemp(join(tmpdir(), 'crowsi-browser-state-'))
  t.after(() => rm(temporary, { recursive: true, force: true }))
  chmodSync(temporary, 0o700)
  const target = join(temporary, 'runtime.json')
  installPrivateJson(target, { schema: 'test' })
  assert.equal(statSync(target).mode & 0o777, 0o600)
  assert.throws(() => installPrivateJson(target, { schema: 'replacement' }),
    /already exists/u)
})

test('custody executable is copied out of the recyclable build generation', async t => {
  const temporary = await mkdtemp(join(tmpdir(), 'crowsi-browser-binary-'))
  t.after(() => rm(temporary, { recursive: true, force: true }))
  chmodSync(temporary, 0o700)
  const source = join(temporary, 'source.exe')
  const target = join(temporary, 'installed.exe')
  await writeFile(source, 'reviewed-binary', { mode: 0o700 })
  const value = installPrivateExecutable(source, target)
  assert.equal(statSync(target).mode & 0o777, 0o700)
  assert.match(value.digest, /^sha256:[0-9a-f]{64}$/u)
})
