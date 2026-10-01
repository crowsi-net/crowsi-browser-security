import { randomBytes } from 'node:crypto'
import { rmSync } from 'node:fs'
import { join } from 'node:path'
import { crowsiPaths, privateDirectory, writePrivateJson } from './crowsi-native-files.mjs'
import { runNativeJson } from './crowsi-native-process.mjs'

const encoded = /^[A-Za-z0-9_-]{1,131072}$/u
const maximumSessions = 2

/** Orchestrates owner-visible Passkey setup while Crowsi retains all trust material. */
export class OwnerSecurity {
  #options
  #run
  #origin
  #onDiagnostic
  #sessions = new Map()
  #authenticationSessions = new Map()
  #rebindSessions = new Map()

  constructor(options = {}) {
    this.#options = options.paths ?? {}
    this.#run = options.run ?? runNativeJson
    this.#origin = ownerOrigin(options.origin)
    this.#onDiagnostic = typeof options.onDiagnostic === 'function'
      ? options.onDiagnostic : () => undefined
  }

  projection() {
    const paths = crowsiPaths(this.#options)
    const available = id => paths.checks.find(item => item.id === id)?.available === true
    const foundation = available('passkey-authority') && available('security-root')
      && available('platform-custody')
    const passkey = available('passkey')
    const recoveryProvider = available('owner-recovery-provider')
    const recoveryRoot = available('owner-recovery-root')
    const continuity = ownerKeyContinuity({ foundation, passkey,
      passkeyAuthority: available('passkey-authority'), custody: available('platform-custody') })
    return { schema: 'crowsi://browser-security/owner/v1',
      state: foundation && passkey ? 'ready' : foundation ? 'passkey-registration-required'
        : 'foundation-required',
      passkeyRegistered: passkey,
      passkeyUsable: foundation && passkey,
      checks: [
        { id: 'local-protection', available: foundation },
        { id: 'owner-verification', available: passkey },
        { id: 'passkey-authority', available: available('passkey-authority') },
        { id: 'credential-runtime', available: available('credential-runtime') },
        { id: 'owner-recovery-provider', available: recoveryProvider },
        { id: 'owner-recovery-root', available: recoveryRoot },
      ], continuity, recovery: { providerAvailable: recoveryProvider,
        rootRegistered: recoveryRoot,
        continuity: ownerRecoveryContinuity({ recoveryProvider, recoveryRoot }) },
      registration: null }
  }

  /** Verifies persisted Passkey state through the Crowsi authority before presenting recovery. */
  async inspect() {
    const paths = crowsiPaths(this.#options)
    const projected = await this.#inspectRecovery(this.projection(), paths)
    if (!projected.passkeyUsable) return projected
    try {
      const status = await this.#passkeyStatus(paths)
      if (status.state === 'ready' && status.rp_id === 'localhost'
        && status.origin === this.#origin
        && encoded.test(status.credential_id_b64url ?? '')) return projected
      if (status.state === 'stale' && status.rp_id === 'localhost'
        && status.origin === this.#origin
        && encoded.test(status.credential_id_b64url ?? '')) {
        return unavailablePasskey(projected, 'recovery_available', 'rebind',
          'owner-key-policy-binding-stale')
      }
      if (['invalid', 'not-registered'].includes(status.state)) {
        return unavailablePasskey(projected, 'reregistration_required', 'reregister',
          'owner-key-registration-invalid')
      }
      return unavailablePasskey(projected, 'blocked', 'review_conflict',
        'owner-key-status-invalid')
    } catch (error) {
      this.#diagnose(error, 'inspection')
      return unavailablePasskey(projected, 'blocked', 'review_conflict',
        'owner-key-status-unavailable')
    }
  }

  async start() {
    for (const [reference, value] of this.#sessions) {
      if (value.expiresAtUnixMs <= Date.now()) this.cancel(reference)
    }
    const paths = crowsiPaths(this.#options)
    requireFoundation(paths)
    if (paths.checks.find(item => item.id === 'passkey')?.available) fail('already-registered')
    if (this.#sessions.size >= maximumSessions) fail('registration-capacity-reached')
    privateDirectory(join(paths.securityRoot, 'policy-authority'))
    privateDirectory(join(paths.securityRoot, 'policy-authority/browser-registration-sessions'))
    if (!paths.checks.find(item => item.id === 'policy-authority')?.available) {
      await this.#run(paths.paAgent, ['initialize', '--state', paths.state,
        '--custody', paths.custody])
    }
    const registrationRef = `passkey-${randomBytes(24).toString('base64url')}`
    const directory = join(paths.securityRoot,
      `policy-authority/browser-registration-sessions/${registrationRef}`)
    privateDirectory(directory)
    const files = Object.fromEntries(['challenge', 'response', 'candidate', 'proof', 'assertion']
      .map(name => [name, join(directory, `${name}.json`)]))
    try {
      const challenge = await this.#run(paths.paAgent, [
        'passkey-register-challenge', '--state', paths.state,
        '--challenge', files.challenge, '--rp-id', 'localhost', '--origin', this.#origin,
        '--custody', paths.custody])
      validChallenge(challenge, 'register', this.#origin)
      const userHandle = randomBytes(32).toString('base64url')
      this.#sessions.set(registrationRef, { paths, files, directory,
        expiresAtUnixMs: challenge.expires_at_epoch_s * 1_000 })
      return { ...this.projection(), registration: publicChallenge(
        registrationRef, challenge, userHandle, null) }
    } catch (error) {
      this.#diagnose(error, 'start')
      rmSync(directory, { recursive: true, force: true }); throw error
    }
  }

  async stage(value) {
    const session = this.#session(value?.registrationRef)
    try {
      const response = registrationResponse(value)
      writePrivateJson(session.files.response, response)
      const proof = await this.#run(session.paths.paAgent, [
        'passkey-register-stage', '--state', session.paths.state,
        '--challenge', session.files.challenge, '--response', session.files.response,
        '--candidate', session.files.candidate, '--proof-challenge', session.files.proof,
        '--credential', session.paths.passkey, '--custody', session.paths.custody])
      validChallenge(proof, 'passkey-registration-proof', this.#origin)
      return { ...this.projection(), registration: publicChallenge(
        value.registrationRef, proof, null, response.credential_id_b64url) }
    } catch (error) {
      this.#diagnose(error, 'stage')
      this.cancel(value?.registrationRef); throw error
    }
  }

  async confirm(value) {
    const session = this.#session(value?.registrationRef)
    try {
      writePrivateJson(session.files.assertion, passkeyAssertion(value))
      const credential = await this.#run(session.paths.paAgent, [
        'passkey-register-confirm', '--state', session.paths.state,
        '--candidate', session.files.candidate, '--proof-challenge', session.files.proof,
        '--assertion', session.files.assertion, '--credential', session.paths.passkey,
        '--custody', session.paths.custody])
      if (credential?.schema !== 'crowsi://policy-authority/passkey-credential/v1'
        || credential.rp_id !== 'localhost' || credential.origin !== this.#origin) {
        fail('credential-invalid')
      }
      this.#sessions.delete(value.registrationRef)
      rmSync(session.directory, { recursive: true, force: true })
      return this.projection()
    } catch (error) {
      this.#diagnose(error, 'confirm')
      this.cancel(value?.registrationRef); throw error
    }
  }

  async startAuthentication() {
    this.#purgeAuthentication()
    const paths = crowsiPaths(this.#options)
    requireFoundation(paths)
    if (!paths.checks.find(item => item.id === 'passkey')?.available) {
      fail('passkey-not-registered')
    }
    if (this.#authenticationSessions.size >= maximumSessions) {
      fail('authentication-capacity-reached')
    }
    privateDirectory(join(paths.securityRoot, 'policy-authority'))
    privateDirectory(join(paths.securityRoot,
      'policy-authority/browser-authentication-sessions'))
    const authenticationRef = `authentication-${randomBytes(24).toString('base64url')}`
    const directory = join(paths.securityRoot,
      `policy-authority/browser-authentication-sessions/${authenticationRef}`)
    privateDirectory(directory)
    const files = Object.fromEntries(['challenge', 'assertion']
      .map(name => [name, join(directory, `${name}.json`)]))
    try {
      const challenge = await this.#run(paths.paAgent, [
        'passkey-authentication-challenge', '--state', paths.state,
        '--credential', paths.passkey, '--challenge', files.challenge,
        '--custody', paths.custody])
      const passkey = await this.#run(paths.paAgent, [
        'passkey-status', '--state', paths.state,
        '--credential', paths.passkey, '--custody', paths.custody])
      validChallenge(challenge, 'passkey-authentication', this.#origin)
      if (passkey?.schema !== 'crowsi://policy-authority/passkey-status/v1'
        || passkey.state !== 'ready' || passkey.rp_id !== 'localhost'
        || passkey.origin !== this.#origin || !encoded.test(passkey.credential_id_b64url ?? '')) {
        fail('passkey-unavailable')
      }
      this.#authenticationSessions.set(authenticationRef, { paths, files, directory,
        expiresAtUnixMs: challenge.expires_at_epoch_s * 1_000 })
      return publicAuthenticationChallenge(authenticationRef, challenge,
        passkey.credential_id_b64url)
    } catch (error) {
      this.#diagnose(error, 'authentication-start')
      rmSync(directory, { recursive: true, force: true }); throw error
    }
  }

  async confirmAuthentication(value) {
    const session = this.#authenticationSession(value?.authenticationRef)
    try {
      writePrivateJson(session.files.assertion, passkeyAssertion(value))
      const receipt = await this.#run(session.paths.paAgent, [
        'passkey-authenticate', '--state', session.paths.state,
        '--credential', session.paths.passkey, '--challenge', session.files.challenge,
        '--assertion', session.files.assertion, '--custody', session.paths.custody])
      if (receipt?.schema
        !== 'crowsi://policy-authority/passkey-authentication-receipt/v1'
        || receipt.contains_secret_values !== false
        || !Number.isSafeInteger(receipt.authenticated_at_epoch_s)) {
        fail('authentication-receipt-invalid')
      }
      this.#authenticationSessions.delete(value.authenticationRef)
      rmSync(session.directory, { recursive: true, force: true })
      return true
    } catch (error) {
      this.#diagnose(error, 'authentication-confirm')
      this.#cancelAuthentication(value?.authenticationRef); throw error
    }
  }

  async startRebind() {
    this.#purgeRebind()
    const paths = crowsiPaths(this.#options)
    requireFoundation(paths)
    if (this.#rebindSessions.size >= maximumSessions) fail('rebind-capacity-reached')
    const status = await this.#passkeyStatus(paths)
    if (status.state !== 'stale' || status.rp_id !== 'localhost'
      || status.origin !== this.#origin
      || !encoded.test(status.credential_id_b64url ?? '')) fail('rebind-unavailable')
    const rebindRef = `rebind-${randomBytes(24).toString('base64url')}`
    const directory = join(paths.securityRoot,
      `policy-authority/browser-rebind-sessions/${rebindRef}`)
    privateDirectory(directory)
    const files = { challenge: join(directory, 'challenge.json'),
      assertion: join(directory, 'assertion.json') }
    try {
      const challenge = await this.#run(paths.paAgent, [
        'passkey-rebind-challenge', '--state', paths.state,
        '--credential', paths.passkey, '--challenge', files.challenge,
        '--custody', paths.custody])
      validChallenge(challenge, 'passkey-rebind', this.#origin)
      this.#rebindSessions.set(rebindRef, { paths, files, directory,
        expiresAtUnixMs: challenge.expires_at_epoch_s * 1_000 })
      return publicAuthenticationChallenge(rebindRef, challenge,
        status.credential_id_b64url)
    } catch (error) {
      this.#diagnose(error, 'rebind-start')
      rmSync(directory, { recursive: true, force: true }); throw error
    }
  }

  async confirmRebind(value) {
    const session = this.#rebindSession(value?.authenticationRef)
    try {
      writePrivateJson(session.files.assertion, passkeyAssertion(value))
      const credential = await this.#run(session.paths.paAgent, [
        'passkey-rebind', '--state', session.paths.state,
        '--credential', session.paths.passkey, '--challenge', session.files.challenge,
        '--assertion', session.files.assertion, '--custody', session.paths.custody])
      if (credential?.schema !== 'crowsi://policy-authority/passkey-credential/v1'
        || credential.rp_id !== 'localhost' || credential.origin !== this.#origin) {
        fail('rebind-receipt-invalid')
      }
      this.#rebindSessions.delete(value.authenticationRef)
      rmSync(session.directory, { recursive: true, force: true })
      return await this.inspect()
    } catch (error) {
      this.#diagnose(error, 'rebind-confirm')
      this.#cancelRebind(value?.authenticationRef); throw error
    }
  }

  async resetInvalidRegistration() {
    const inspected = await this.inspect()
    if (inspected.continuity.state !== 'reregistration_required'
      || inspected.continuity.action !== 'reregister') fail('reregistration-unavailable')
    const paths = crowsiPaths(this.#options)
    requireFoundation(paths)
    const authority = await this.#run(paths.paAgent, [
      'status', '--state', paths.state, '--custody', paths.custody])
    if (authority?.schema !== 'crowsi://policy-authority/public-state/v1'
      || !/^[0-9a-f]{64}$/u.test(authority.public_key_hex ?? '')) {
      fail('authority-status-invalid')
    }
    const receipt = await this.#run(paths.paAgent, [
      'passkey-recovery-revoke', '--state', paths.state,
      '--credential', paths.passkey, '--confirm-public-key', authority.public_key_hex,
      '--confirmation', 'revoke-lost-passkey-registration', '--custody', paths.custody])
    if (receipt?.schema !== 'crowsi://policy-authority/lost-passkey-recovery-receipt/v1'
      || receipt.state !== 'completed' || receipt.pa_key !== 'retained'
      || receipt.public_state !== 'retained'
      || !['revoked', 'absent'].includes(receipt.passkey_registration)
      || receipt.authenticator_credential !== 'unchanged'
      || receipt.contains_secret_values !== false) {
      fail('reregistration-receipt-invalid')
    }
    return this.projection()
  }

  cancel(reference) {
    const session = this.#sessions.get(reference)
    if (!session) return
    this.#sessions.delete(reference)
    rmSync(session.directory, { recursive: true, force: true })
  }

  /** Removes incomplete ceremonies when the host process shuts down. */
  close() {
    for (const reference of [...this.#sessions.keys()]) this.cancel(reference)
    for (const reference of [...this.#authenticationSessions.keys()]) {
      this.#cancelAuthentication(reference)
    }
    for (const reference of [...this.#rebindSessions.keys()]) this.#cancelRebind(reference)
  }

  #session(reference) {
    const value = typeof reference === 'string' ? this.#sessions.get(reference) : null
    if (!value || value.expiresAtUnixMs <= Date.now()) {
      if (value) this.cancel(reference)
      fail('registration-unavailable')
    }
    return value
  }

  #authenticationSession(reference) {
    this.#purgeAuthentication()
    const value = typeof reference === 'string'
      ? this.#authenticationSessions.get(reference) : null
    if (!value) fail('authentication-unavailable')
    return value
  }

  #cancelAuthentication(reference) {
    const value = this.#authenticationSessions.get(reference)
    if (!value) return
    this.#authenticationSessions.delete(reference)
    rmSync(value.directory, { recursive: true, force: true })
  }

  #purgeAuthentication() {
    const now = Date.now()
    for (const [reference, value] of this.#authenticationSessions) {
      if (value.expiresAtUnixMs <= now) this.#cancelAuthentication(reference)
    }
  }

  #rebindSession(reference) {
    this.#purgeRebind()
    const value = typeof reference === 'string' ? this.#rebindSessions.get(reference) : null
    if (!value) fail('rebind-unavailable')
    return value
  }

  #cancelRebind(reference) {
    const value = this.#rebindSessions.get(reference)
    if (!value) return
    this.#rebindSessions.delete(reference)
    rmSync(value.directory, { recursive: true, force: true })
  }

  #purgeRebind() {
    const now = Date.now()
    for (const [reference, value] of this.#rebindSessions) {
      if (value.expiresAtUnixMs <= now) this.#cancelRebind(reference)
    }
  }

  async #passkeyStatus(paths) {
    const value = await this.#run(paths.paAgent, [
      'passkey-status', '--state', paths.state,
      '--credential', paths.passkey, '--custody', paths.custody])
    if (value?.schema !== 'crowsi://policy-authority/passkey-status/v1') {
      fail('passkey-status-invalid')
    }
    return value
  }

  async #inspectRecovery(projected, paths) {
    if (!projected.recovery.providerAvailable || !projected.recovery.rootRegistered) {
      return projected
    }
    try {
      const value = await this.#run(paths.ownerRecoveryProvider,
        ['inspect-descriptor', paths.ownerRecoveryRoot])
      if (value?.schema !== 'crowsi://owner-recovery/root-descriptor/v1'
        || value.profile !== 'ihat://identity/owner-recovery-profile/bip39-ed25519-v1'
        || !/^[0-9a-f]{64}$/u.test(value.key_fingerprint ?? '')) {
        fail('owner-recovery-descriptor-invalid')
      }
      return projected
    } catch (error) {
      this.#diagnose(error, 'recovery-inspection')
      return { ...projected,
        checks: projected.checks.map(item => item.id === 'owner-recovery-root'
          ? { ...item, available: false } : item),
        recovery: { ...projected.recovery, rootRegistered: false, continuity: {
          state: 'blocked', action: 'review_conflict',
          reason: 'owner-recovery-root-invalid' } } }
    }
  }

  #diagnose(error, phase) {
    const code = error instanceof Error ? error.message : ''
    if (!/^crowsi-browser-security-[a-z0-9-]{3,96}$/u.test(code)
      || !['start', 'stage', 'confirm', 'authentication-start',
        'authentication-confirm', 'inspection', 'rebind-start',
        'rebind-confirm', 'recovery-inspection'].includes(phase)) return
    try { this.#onDiagnostic({ code, phase }) } catch { /* diagnostics cannot alter the result */ }
  }
}

function ownerRecoveryContinuity({ recoveryProvider, recoveryRoot }) {
  if (recoveryProvider && recoveryRoot) return {
    state: 'retained', action: 'none', reason: 'owner-recovery-root-retained' }
  if (!recoveryProvider) return { state: 'blocked', action: 'restore_exact_release',
    reason: 'owner-recovery-provider-unavailable' }
  return { state: 'registration_required', action: 'register',
    reason: 'owner-recovery-root-not-registered' }
}

function ownerKeyContinuity({ foundation, passkey, passkeyAuthority, custody }) {
  if (foundation && passkey) return { state: 'retained', action: 'none',
    reason: 'owner-key-retained-in-platform-custody' }
  if (passkey && custody && !passkeyAuthority) return { state: 'recovery_available',
    action: 'restore_exact_release', reason: 'owner-key-retained-release-component-missing' }
  if (passkey && !custody) return { state: 'blocked',
    action: 'review_conflict', reason: 'owner-key-custody-unavailable' }
  if (foundation) return { state: 'registration_required', action: 'register',
    reason: 'owner-key-not-registered' }
  return { state: 'blocked', action: 'review_conflict',
    reason: 'owner-key-foundation-unavailable' }
}

function unavailablePasskey(projected, state, action, reason) {
  return { ...projected, state: state === 'blocked' ? 'foundation-required'
    : 'passkey-registration-required', passkeyUsable: false,
  continuity: { state, action, reason } }
}

function requireFoundation(paths) {
  for (const id of ['passkey-authority', 'security-root', 'platform-custody']) {
    if (!paths.checks.find(item => item.id === id)?.available) fail('foundation-required')
  }
}
function publicChallenge(reference, value, userHandle, credentialId) {
  const remaining = Math.max(1, value.expires_at_epoch_s * 1_000 - Date.now())
  return { registrationRef: reference, challenge: value.challenge_b64url,
    rpId: 'localhost', origin: value.origin, timeout: Math.min(180_000, remaining),
    expiresAtUnixMs: value.expires_at_epoch_s * 1_000,
    userHandle, credentialId }
}
function publicAuthenticationChallenge(reference, value, credentialId) {
  const remaining = Math.max(1, value.expires_at_epoch_s * 1_000 - Date.now())
  return { authenticationRef: reference, challenge: value.challenge_b64url,
    rpId: 'localhost', origin: value.origin, credentialId,
    timeout: Math.min(180_000, remaining),
    expiresAtUnixMs: value.expires_at_epoch_s * 1_000 }
}
function validChallenge(value, operation, origin) {
  const now = Math.floor(Date.now() / 1_000)
  if (value?.schema !== 'crowsi://policy-authority/passkey-challenge/v1'
    || value.operation !== operation || value.rp_id !== 'localhost' || value.origin !== origin
    || !encoded.test(value.challenge_b64url)
    || !Number.isSafeInteger(value.expires_at_epoch_s)
    || value.expires_at_epoch_s <= now || value.expires_at_epoch_s > now + 300) {
    fail('challenge-invalid')
  }
}
function registrationResponse(value) {
  const fields = ['credentialId', 'clientDataJSON', 'authenticatorData', 'publicKeySpki']
  if (!fields.every(key => encoded.test(value?.[key] ?? ''))) fail('registration-invalid')
  return { credential_id_b64url: value.credentialId,
    client_data_json_b64url: value.clientDataJSON,
    authenticator_data_b64url: value.authenticatorData,
    public_key_spki_b64url: value.publicKeySpki }
}
function passkeyAssertion(value) {
  const fields = ['credentialId', 'clientDataJSON', 'authenticatorData', 'signature']
  if (!fields.every(key => encoded.test(value?.[key] ?? ''))) fail('assertion-invalid')
  return { credential_id_b64url: value.credentialId,
    client_data_json_b64url: value.clientDataJSON,
    authenticator_data_b64url: value.authenticatorData,
    signature_b64url: value.signature }
}
function ownerOrigin(value) {
  if (typeof value !== 'string' || !/^http:\/\/localhost:[1-9][0-9]{0,4}$/u.test(value)) {
    fail('origin-invalid')
  }
  const port = Number(new URL(value).port)
  if (!Number.isSafeInteger(port) || port > 65_535) fail('origin-invalid')
  return value
}
function fail(code) { throw new Error(`crowsi-browser-security-${code}`) }
