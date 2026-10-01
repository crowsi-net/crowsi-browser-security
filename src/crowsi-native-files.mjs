import { lstatSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'

export function crowsiPaths(value) {
  const root = safeRoot(value?.securityRoot)
  const paAgent = safeExecutable(value?.paAgent)
  const credentialAgent = safeExecutable(value?.credentialAgent)
  const ownerRecoveryProvider = safeExecutable(value?.ownerRecoveryProvider)
  const base = root ?? '/browser-crowsi-unavailable'
  const paths = { securityRoot: root, paAgent, credentialAgent, ownerRecoveryProvider,
    state: join(base, 'policy-authority/public-state.json'),
    passkey: join(base, 'policy-authority/passkey.json'),
    custody: join(base, 'platform-custody/runtime.json'),
    runtime: join(base, 'credential-agent/runtime.json'),
    sessions: join(base, 'credential-agent/browser-sessions'),
    identityAssertion: join(base, 'identity/device-identity-assertion.json'),
    identityStatus: join(base, 'identity/current-device-status.json'),
    identityTrust: join(base, 'identity/policy-authority-trust.json') }
  paths.ownerRecoveryRoot = join(base, 'identity/owner-recovery-root.json')
  const checks = Object.freeze([
    check('passkey-authority', Boolean(paAgent)),
    check('credential-agent', Boolean(credentialAgent)),
    check('security-root', Boolean(root)),
    check('policy-authority', ownerFile(paths.state)),
    check('passkey', ownerFile(paths.passkey)),
    check('platform-custody', ownerFile(paths.custody)),
    check('credential-runtime', Boolean(credentialAgent) && ownerFile(paths.runtime)),
    check('device-identity', ownerFile(paths.identityAssertion)),
    check('current-device-status', ownerFile(paths.identityStatus)),
    check('identity-trust', ownerFile(paths.identityTrust)),
    check('owner-recovery-provider', Boolean(ownerRecoveryProvider)),
    check('owner-recovery-root', ownerFile(paths.ownerRecoveryRoot)),
  ])
  const optional = new Set(['owner-recovery-provider', 'owner-recovery-root'])
  return Object.freeze({ ...paths, checks,
    ready: checks.filter(item => !optional.has(item.id)).every(item => item.available) })
}

export function privateDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 })
  const value = lstatSync(path)
  if (!value.isDirectory() || value.isSymbolicLink() || value.uid !== process.getuid?.()
    || (value.mode & 0o777) !== 0o700 || realpathSync(path) !== path) invalid('directory')
}

export function writePrivateJson(path, value) {
  writeFileSync(path, JSON.stringify(value), { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  if (!ownerFile(path)) invalid('file')
}

function safeRoot(value) {
  if (!isAbsolute(value ?? '')) return null
  try {
    const entry = lstatSync(value)
    return entry.isDirectory() && !entry.isSymbolicLink()
      && entry.uid === process.getuid?.() && (entry.mode & 0o077) === 0
      && realpathSync(value) === value ? value : null
  } catch { return null }
}
function safeExecutable(value) {
  if (!isAbsolute(value ?? '')) return null
  try {
    const entry = lstatSync(value)
    return entry.isFile() && !entry.isSymbolicLink() && (entry.mode & 0o111) !== 0
      && (entry.mode & 0o022) === 0 && [0, process.getuid?.()].includes(entry.uid)
      && realpathSync(value) === value ? value : null
  } catch { return null }
}
function ownerFile(path) {
  try {
    const value = lstatSync(path)
    return value.isFile() && !value.isSymbolicLink() && value.uid === process.getuid?.()
      && (value.mode & 0o777) === 0o600 && value.size > 0 && realpathSync(path) === path
  } catch { return false }
}
function check(id, available) { return Object.freeze({ id, available }) }
function invalid(code) { throw new Error(`crowsi-browser-security-${code}-invalid`) }
