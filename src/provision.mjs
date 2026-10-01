import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync, closeSync, copyFileSync, existsSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync
} from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'

export function initializeSecurityRoot(root) {
  for (const path of [root,
    join(root, 'platform-custody'), join(root, 'credential-agent'),
    join(root, 'policy-authority'), join(root, 'identity')]) ownerDirectory(path)
}

export function custodyRuntime(executable, digest, namespace) {
  if (typeof namespace !== 'string' || !/^[a-z][a-z0-9.-]{2,127}$/u.test(namespace)) fail('custody-namespace-invalid')
  return { schema: 'crowsi://platform-custody/runtime/v1',
    kind: 'windows-dpapi-user', namespace,
    helper_path: executable, helper_sha256: digest,
    protocol_version: 'crowsi-windows-custody-v1' }
}

export function installPrivateJson(path, value, overwrite = false) {
  const temporary = join(dirname(path), `.install-${process.pid}-${randomUUID()}.json`)
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`,
      { encoding: 'utf8', flag: 'wx', mode: 0o600 })
    chmodSync(temporary, 0o600)
    const descriptor = openSync(temporary, 'r')
    try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
    if (existsSync(path)) {
      requireOwnerFile(path, 65_536)
      if (!overwrite) fail(`${path} already exists; review it instead of replacing trust state.`)
    }
    renameSync(temporary, path)
    const directory = openSync(dirname(path), 'r')
    try { fsyncSync(directory) } finally { closeSync(directory) }
  } finally { rmSync(temporary, { force: true }) }
}

export function installPrivateExecutable(source, target) {
  const temporary = join(dirname(target), `.install-${process.pid}-${randomUUID()}.bin`)
  try {
    copyFileSync(source, temporary, 1); chmodSync(temporary, 0o700)
    const descriptor = openSync(temporary, 'r')
    try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
    if (existsSync(target)) requireOwnerFile(target, 134_217_728, true)
    renameSync(temporary, target)
    const directory = openSync(dirname(target), 'r')
    try { fsyncSync(directory) } finally { closeSync(directory) }
  } finally { rmSync(temporary, { force: true }) }
  return { executable: target, digest: digestFile(target) }
}

export function ownerFile(path, maximum = 1_048_576, executable = false) {
  try { requireOwnerFile(path, maximum, executable); return true } catch { return false }
}

export function readPrivateJson(path, maximum = 65_536) {
  requireOwnerFile(path, maximum)
  return JSON.parse(readFileSync(path, 'utf8'))
}

function ownerDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 })
  const value = lstatSync(path)
  if (!value.isDirectory() || value.isSymbolicLink() || value.uid !== process.getuid?.()
    || (value.mode & 0o777) !== 0o700 || realpathSync(path) !== path) {
    fail('Crowsi state directory is unsafe.')
  }
}

function requireOwnerFile(path, maximum, executable = false) {
  const value = lstatSync(path)
  if (!value.isFile() || value.isSymbolicLink() || value.uid !== process.getuid?.()
    || (value.mode & 0o022) !== 0 || value.size < 1 || value.size > maximum
    || realpathSync(path) !== path || (executable && (value.mode & 0o111) === 0)) {
    fail(`Owner-only file is unsafe: ${path}`)
  }
}

function digestFile(path) {
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`
}
function fail(message) { throw new Error(message) }
