import assert from 'node:assert/strict'
import { mkdtemp, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
test('packed artifact starts without Hatter, source neighbours, installation scripts or runtime dependencies', async t => {
  const root = await mkdtemp(join(tmpdir(), 'crowsi-package-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const archive = join(root, 'browser-security.tgz')
  const pack = spawnSync('pnpm', ['pack', '--out', archive], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 30_000 })
  assert.equal(pack.status, 0, pack.stderr)
  const unpack = spawnSync('tar', ['-xzf', archive, '-C', root], { encoding: 'utf8' })
  assert.equal(unpack.status, 0, unpack.stderr)
  const manifest = JSON.parse(await readFile(join(root, 'package/package.json')))
  assert.equal(manifest.version, '0.10.0')
  assert.equal(Object.keys(manifest.dependencies ?? {}).length, 0)
  assert.equal('postinstall' in manifest.scripts, false)
  const { startDemo } = await import(pathToFileURL(join(root, 'package/bin/demo.mjs')).href)
  const demo = await startDemo({ port: 0 }); t.after(() => demo.close())
  const url = new URL(demo.url)
  const connected = await fetch(url.origin + '/connect', { method: 'POST',
    headers: { origin: url.origin, 'content-type': 'application/json' },
    body: JSON.stringify({ credential: new URLSearchParams(url.hash.slice(1)).get('launch') }) })
  assert.equal(connected.status, 200)
  assert.match((await connected.json()).csrf, /^[A-Za-z0-9_-]{43}$/u)
})
