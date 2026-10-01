import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, mkdirSync, rmSync, statSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { initializeSecurityRoot } from '../src/provision.mjs'
import { privateDirectory } from '../src/crowsi-native-files.mjs'
test('provisioning never changes parent permissions or follows a directory link', t => {
  const root = mkdtempSync(join(tmpdir(), 'crowsi-boundary-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  chmodSync(root, 0o755)
  initializeSecurityRoot(join(root, 'security'))
  assert.equal(statSync(root).mode & 0o777, 0o755)
  assert.equal(statSync(join(root, 'security')).mode & 0o777, 0o700)
  const target = join(root, 'target'); mkdirSync(target, { mode: 0o755 })
  const link = join(root, 'link'); symlinkSync(target, link)
  assert.throws(() => privateDirectory(link), /directory-invalid/u)
  assert.equal(statSync(target).mode & 0o777, 0o755)
})
