import assert from 'node:assert/strict'
import { chmod, mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { OwnerSecurity } from '../src/owner-security.mjs'

test('initializes owner protection and completes an exact two-ceremony Passkey registration',
  async t => {
    const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
    t.after(() => rm(root, { recursive: true, force: true }))
    const agent = join(root, 'pa-agent')
    const credentialAgent = join(root, 'credential-agent')
    await writeFile(agent, '#!/bin/sh\n', { mode: 0o700 })
    await writeFile(credentialAgent, '#!/bin/sh\n', { mode: 0o700 })
    await mkdir(join(root, 'platform-custody'), { mode: 0o700 })
    await writeFile(join(root, 'platform-custody/runtime.json'), '{}', { mode: 0o600 })
    await chmod(root, 0o700)
    const calls = []
    const run = async (_executable, arguments_) => {
      calls.push(arguments_[0])
      if (arguments_[0] === 'initialize') {
        await writePrivate(arguments_[arguments_.indexOf('--state') + 1], { state: 'ready' })
        return { schema: 'crowsi://policy-authority/public-state/v1' }
      }
      if (arguments_[0] === 'passkey-register-challenge') {
        const value = challenge('register')
        await writePrivate(arguments_[arguments_.indexOf('--challenge') + 1], value)
        return value
      }
      if (arguments_[0] === 'passkey-register-stage') return challenge('passkey-registration-proof')
      const credential = { schema: 'crowsi://policy-authority/passkey-credential/v1',
        rp_id: 'localhost', origin: 'http://localhost:4213' }
      await writePrivate(arguments_[arguments_.indexOf('--credential') + 1], credential)
      return credential
    }
    const security = new OwnerSecurity({ origin: 'http://localhost:4213', run,
      paths: { securityRoot: root, paAgent: agent, credentialAgent } })
    assert.equal(security.projection().state, 'passkey-registration-required')
    const started = await security.start()
    const reference = started.registration.registrationRef
    const staged = await security.stage({ registrationRef: reference,
      credentialId: encoded('c'), clientDataJSON: encoded('d'),
      authenticatorData: encoded('e'), publicKeySpki: encoded('f') })
    assert.equal(staged.registration.credentialId, encoded('c'))
    const completed = await security.confirm({ registrationRef: reference,
      credentialId: encoded('c'), clientDataJSON: encoded('g'),
      authenticatorData: encoded('h'), signature: encoded('i') })
    assert.equal(completed.state, 'ready')
    assert.equal(completed.passkeyRegistered, true)
    assert.equal(completed.passkeyUsable, true)
    assert.deepEqual(completed.continuity, { state: 'retained', action: 'none',
      reason: 'owner-key-retained-in-platform-custody' })
    assert.deepEqual(calls, ['initialize', 'passkey-register-challenge',
      'passkey-register-stage', 'passkey-register-confirm'])
    assert.equal(JSON.stringify(completed).includes(root), false)
  })

test('does not start registration without the local owner-protection boundary', async () => {
  const security = new OwnerSecurity({ origin: 'http://localhost:4213',
    paths: {}, run: async () => assert.fail('must not execute') })
  assert.equal(security.projection().state, 'foundation-required')
  assert.equal(security.projection().continuity.state, 'blocked')
  await assert.rejects(security.start(), /crowsi-browser-security-foundation-required/u)
})

test('trusts an offline recovery root only after the native provider verifies its descriptor',
  async t => {
    const root = await mkdtemp(join(tmpdir(), 'browser-owner-recovery-'))
    t.after(() => rm(root, { recursive: true, force: true }))
    const provider = join(root, 'owner-recovery-provider')
    await writeFile(provider, '#!/bin/sh\n', { mode: 0o700 })
    await mkdir(join(root, 'identity'), { mode: 0o700 })
    await writePrivate(join(root, 'identity/owner-recovery-root.json'), {})
    await chmod(root, 0o700)
    const valid = new OwnerSecurity({ origin: 'http://localhost:4213',
      paths: { securityRoot: root, ownerRecoveryProvider: provider }, run: async () => ({
        schema: 'crowsi://owner-recovery/root-descriptor/v1',
        profile: 'ihat://identity/owner-recovery-profile/bip39-ed25519-v1',
        key_fingerprint: 'ab'.repeat(32) }) })
    assert.equal((await valid.inspect()).recovery.continuity.state, 'retained')
    const invalid = new OwnerSecurity({ origin: 'http://localhost:4213',
      paths: { securityRoot: root, ownerRecoveryProvider: provider }, run: async () => ({
        schema: 'crowsi://owner-recovery/root-descriptor/v1', profile: 'substituted' }) })
    const inspected = await invalid.inspect()
    assert.equal(inspected.recovery.rootRegistered, false)
    assert.deepEqual(inspected.recovery.continuity, { state: 'blocked',
      action: 'review_conflict', reason: 'owner-recovery-root-invalid' })
  })

test('retains a key for release repair but blocks substitution when custody is lost', async t => {
  const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  await mkdir(join(root, 'policy-authority'), { recursive: true, mode: 0o700 })
  await mkdir(join(root, 'platform-custody'), { recursive: true, mode: 0o700 })
  await writePrivate(join(root, 'policy-authority/passkey.json'), {})
  await writePrivate(join(root, 'platform-custody/runtime.json'), {})
  await chmod(root, 0o700)
  const repair = new OwnerSecurity({ origin: 'http://localhost:4213',
    paths: { securityRoot: root }, run: async () => assert.fail('must not execute') }).projection()
  assert.equal(repair.passkeyRegistered, true)
  assert.equal(repair.passkeyUsable, false)
  assert.equal(repair.continuity.state, 'recovery_available')
  await rm(join(root, 'platform-custody/runtime.json'))
  const reregister = new OwnerSecurity({ origin: 'http://localhost:4213',
    paths: { securityRoot: root }, run: async () => assert.fail('must not execute') }).projection()
  assert.equal(reregister.continuity.state, 'blocked')
  assert.equal(reregister.continuity.action, 'review_conflict')
})

test('inspects and rebinds a retained stale Passkey without replacing its credential', async t => {
  const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const agent = join(root, 'pa-agent')
  const credentialAgent = join(root, 'credential-agent')
  await writeFile(agent, '#!/bin/sh\n', { mode: 0o700 })
  await writeFile(credentialAgent, '#!/bin/sh\n', { mode: 0o700 })
  await mkdir(join(root, 'platform-custody'), { mode: 0o700 })
  await mkdir(join(root, 'policy-authority'), { mode: 0o700 })
  await writePrivate(join(root, 'platform-custody/runtime.json'), {})
  await writePrivate(join(root, 'policy-authority/public-state.json'), {})
  await writePrivate(join(root, 'policy-authority/passkey.json'), {})
  await chmod(root, 0o700)
  let rebound = false
  const calls = []
  const run = async (_executable, arguments_) => {
    calls.push(arguments_[0])
    if (arguments_[0] === 'passkey-status') return {
      schema: 'crowsi://policy-authority/passkey-status/v1',
      state: rebound ? 'ready' : 'stale', rp_id: 'localhost',
      origin: 'http://localhost:4213', credential_id_b64url: encoded('c')
    }
    if (arguments_[0] === 'passkey-rebind-challenge') {
      const value = challenge('passkey-rebind')
      await writePrivate(arguments_[arguments_.indexOf('--challenge') + 1], value)
      return value
    }
    rebound = true
    return { schema: 'crowsi://policy-authority/passkey-credential/v1',
      rp_id: 'localhost', origin: 'http://localhost:4213' }
  }
  const security = new OwnerSecurity({ origin: 'http://localhost:4213', run,
    paths: { securityRoot: root, paAgent: agent, credentialAgent } })
  const before = await security.inspect()
  assert.equal(before.passkeyUsable, false)
  assert.deepEqual(before.continuity, { state: 'recovery_available', action: 'rebind',
    reason: 'owner-key-policy-binding-stale' })
  const started = await security.startRebind()
  assert.equal(started.credentialId, encoded('c'))
  const after = await security.confirmRebind({
    authenticationRef: started.authenticationRef, credentialId: encoded('c'),
    clientDataJSON: encoded('d'), authenticatorData: encoded('e'), signature: encoded('f')
  })
  assert.equal(after.passkeyUsable, true)
  assert.deepEqual(after.continuity, { state: 'retained', action: 'none',
    reason: 'owner-key-retained-in-platform-custody' })
  assert.deepEqual(calls, ['passkey-status', 'passkey-status',
    'passkey-rebind-challenge', 'passkey-rebind', 'passkey-status'])
})

test('removes only an invalid local registration before explicit registration', async t => {
  const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const agent = join(root, 'pa-agent')
  const credentialAgent = join(root, 'credential-agent')
  const passkey = join(root, 'policy-authority/passkey.json')
  await writeFile(agent, '#!/bin/sh\n', { mode: 0o700 })
  await writeFile(credentialAgent, '#!/bin/sh\n', { mode: 0o700 })
  await mkdir(join(root, 'platform-custody'), { mode: 0o700 })
  await mkdir(join(root, 'policy-authority'), { mode: 0o700 })
  await writePrivate(join(root, 'platform-custody/runtime.json'), {})
  await writePrivate(join(root, 'policy-authority/public-state.json'), {})
  await writePrivate(passkey, {})
  await chmod(root, 0o700)
  const calls = []
  const publicKey = 'ab'.repeat(32)
  const run = async (_executable, arguments_) => {
    calls.push(arguments_[0])
    if (arguments_[0] === 'passkey-status') return {
      schema: 'crowsi://policy-authority/passkey-status/v1', state: 'invalid',
      reason_code: 'pa-passkey-registration-invalid'
    }
    if (arguments_[0] === 'status') return {
      schema: 'crowsi://policy-authority/public-state/v1', public_key_hex: publicKey
    }
    assert.equal(arguments_[arguments_.indexOf('--confirm-public-key') + 1], publicKey)
    await rm(passkey)
    return { schema: 'crowsi://policy-authority/lost-passkey-recovery-receipt/v1',
      state: 'completed', pa_key: 'retained', public_state: 'retained',
      passkey_registration: 'revoked', authenticator_credential: 'unchanged',
      contains_secret_values: false }
  }
  const security = new OwnerSecurity({ origin: 'http://localhost:4213', run,
    paths: { securityRoot: root, paAgent: agent, credentialAgent } })
  assert.equal((await security.inspect()).continuity.action, 'reregister')
  const reset = await security.resetInvalidRegistration()
  assert.equal(reset.continuity.state, 'registration_required')
  assert.equal(reset.passkeyRegistered, false)
  assert.deepEqual(calls, ['passkey-status', 'passkey-status', 'status',
    'passkey-recovery-revoke'])
})

test('fails closed when re-registration would not retain the authenticator credential', async t => {
  const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const agent = join(root, 'pa-agent')
  const credentialAgent = join(root, 'credential-agent')
  const passkey = join(root, 'policy-authority/passkey.json')
  await writeFile(agent, '#!/bin/sh\n', { mode: 0o700 })
  await writeFile(credentialAgent, '#!/bin/sh\n', { mode: 0o700 })
  await mkdir(join(root, 'platform-custody'), { mode: 0o700 })
  await mkdir(join(root, 'policy-authority'), { mode: 0o700 })
  await writePrivate(join(root, 'platform-custody/runtime.json'), {})
  await writePrivate(join(root, 'policy-authority/public-state.json'), {})
  await writePrivate(passkey, {})
  await chmod(root, 0o700)
  const run = async (_executable, arguments_) => {
    if (arguments_[0] === 'passkey-status') return {
      schema: 'crowsi://policy-authority/passkey-status/v1', state: 'invalid',
      reason_code: 'pa-passkey-registration-invalid'
    }
    if (arguments_[0] === 'status') return {
      schema: 'crowsi://policy-authority/public-state/v1', public_key_hex: 'ab'.repeat(32)
    }
    return { schema: 'crowsi://policy-authority/lost-passkey-recovery-receipt/v1',
      state: 'completed', pa_key: 'retained', public_state: 'retained',
      passkey_registration: 'revoked', authenticator_credential: 'removed',
      contains_secret_values: false }
  }
  const security = new OwnerSecurity({ origin: 'http://localhost:4213', run,
    paths: { securityRoot: root, paAgent: agent, credentialAgent } })
  await assert.rejects(security.resetInvalidRegistration(),
    /crowsi-browser-security-reregistration-receipt-invalid/u)
})

test('opens a browser session only after the registered Passkey proves possession', async t => {
  const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const agent = join(root, 'pa-agent')
  const credentialAgent = join(root, 'credential-agent')
  await writeFile(agent, '#!/bin/sh\n', { mode: 0o700 })
  await writeFile(credentialAgent, '#!/bin/sh\n', { mode: 0o700 })
  await mkdir(join(root, 'platform-custody'), { mode: 0o700 })
  await mkdir(join(root, 'policy-authority'), { mode: 0o700 })
  await writePrivate(join(root, 'platform-custody/runtime.json'), {})
  await writePrivate(join(root, 'policy-authority/public-state.json'), {})
  await writePrivate(join(root, 'policy-authority/passkey.json'), {})
  await chmod(root, 0o700)
  const calls = []
  const run = async (_executable, arguments_) => {
    calls.push(arguments_[0])
    if (arguments_[0] === 'passkey-authentication-challenge') {
      const value = challenge('passkey-authentication')
      await writePrivate(arguments_[arguments_.indexOf('--challenge') + 1], value)
      return value
    }
    if (arguments_[0] === 'passkey-status') return {
      schema: 'crowsi://policy-authority/passkey-status/v1', state: 'ready',
      rp_id: 'localhost', origin: 'http://localhost:4213',
      credential_id_b64url: encoded('c')
    }
    return { schema: 'crowsi://policy-authority/passkey-authentication-receipt/v1',
      authenticated_at_epoch_s: Math.floor(Date.now() / 1000),
      contains_secret_values: false }
  }
  const security = new OwnerSecurity({ origin: 'http://localhost:4213', run,
    paths: { securityRoot: root, paAgent: agent, credentialAgent } })
  const started = await security.startAuthentication()
  assert.equal(started.credentialId, encoded('c'))
  assert.equal(started.origin, 'http://localhost:4213')
  assert.equal(await security.confirmAuthentication({
    authenticationRef: started.authenticationRef, credentialId: encoded('c'),
    clientDataJSON: encoded('d'), authenticatorData: encoded('e'), signature: encoded('f')
  }), true)
  assert.deepEqual(calls, ['passkey-authentication-challenge', 'passkey-status',
    'passkey-authenticate'])
  await assert.rejects(security.confirmAuthentication({
    authenticationRef: started.authenticationRef
  }), /crowsi-browser-security-authentication-unavailable/u)
})

test('opens a Passkey browser session without requiring the external credential runtime',
  async t => {
    const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
    t.after(() => rm(root, { recursive: true, force: true }))
    const agent = join(root, 'pa-agent')
    await writeFile(agent, '#!/bin/sh\n', { mode: 0o700 })
    await mkdir(join(root, 'platform-custody'), { mode: 0o700 })
    await mkdir(join(root, 'policy-authority'), { mode: 0o700 })
    await writePrivate(join(root, 'platform-custody/runtime.json'), {})
    await writePrivate(join(root, 'policy-authority/public-state.json'), {})
    await writePrivate(join(root, 'policy-authority/passkey.json'), {})
    await chmod(root, 0o700)
    const calls = []
    const run = async (_executable, arguments_) => {
      calls.push(arguments_[0])
      if (arguments_[0] === 'passkey-authentication-challenge') {
        const value = challenge('passkey-authentication')
        await writePrivate(arguments_[arguments_.indexOf('--challenge') + 1], value)
        return value
      }
      if (arguments_[0] === 'passkey-status') return {
        schema: 'crowsi://policy-authority/passkey-status/v1', state: 'ready',
        rp_id: 'localhost', origin: 'http://localhost:4213',
        credential_id_b64url: encoded('c')
      }
      return { schema: 'crowsi://policy-authority/passkey-authentication-receipt/v1',
        authenticated_at_epoch_s: Math.floor(Date.now() / 1000),
        contains_secret_values: false }
    }
    const security = new OwnerSecurity({ origin: 'http://localhost:4213', run,
      paths: { securityRoot: root, paAgent: agent } })
    assert.equal(security.projection().passkeyUsable, true)
    assert.equal(security.projection().checks.find(item =>
      item.id === 'credential-runtime')?.available, false)
    const started = await security.startAuthentication()
    assert.equal(await security.confirmAuthentication({
      authenticationRef: started.authenticationRef, credentialId: encoded('c'),
      clientDataJSON: encoded('d'), authenticatorData: encoded('e'), signature: encoded('f')
    }), true)
    assert.deepEqual(calls, ['passkey-authentication-challenge', 'passkey-status',
      'passkey-authenticate'])
  })

test('retains a bounded reason code when possession proof fails and removes ceremony files',
  async t => {
    const root = await mkdtemp(join(tmpdir(), 'browser-device-security-'))
    t.after(() => rm(root, { recursive: true, force: true }))
    const agent = join(root, 'pa-agent')
    const credentialAgent = join(root, 'credential-agent')
    await writeFile(agent, '#!/bin/sh\n', { mode: 0o700 })
    await writeFile(credentialAgent, '#!/bin/sh\n', { mode: 0o700 })
    await mkdir(join(root, 'platform-custody'), { mode: 0o700 })
    await writeFile(join(root, 'platform-custody/runtime.json'), '{}', { mode: 0o600 })
    await chmod(root, 0o700)
    const diagnostics = []
    const run = async (_executable, arguments_) => {
      if (arguments_[0] === 'initialize') {
        await writePrivate(arguments_[arguments_.indexOf('--state') + 1], { state: 'ready' })
        return { schema: 'crowsi://policy-authority/public-state/v1' }
      }
      if (arguments_[0] === 'passkey-register-challenge') {
        const value = challenge('register')
        await writePrivate(arguments_[arguments_.indexOf('--challenge') + 1], value)
        return value
      }
      if (arguments_[0] === 'passkey-register-stage') {
        return challenge('passkey-registration-proof')
      }
      throw Error('crowsi-browser-security-pa-passkey-proof-signature-rejected')
    }
    const security = new OwnerSecurity({ origin: 'http://localhost:4213', run,
      onDiagnostic: value => diagnostics.push(value),
      paths: { securityRoot: root, paAgent: agent, credentialAgent } })
    const started = await security.start()
    const reference = started.registration.registrationRef
    await security.stage({ registrationRef: reference,
      credentialId: encoded('c'), clientDataJSON: encoded('d'),
      authenticatorData: encoded('e'), publicKeySpki: encoded('f') })
    await assert.rejects(security.confirm({ registrationRef: reference,
      credentialId: encoded('c'), clientDataJSON: encoded('g'),
      authenticatorData: encoded('h'), signature: encoded('i') }),
    /pa-passkey-proof-signature-rejected/u)
    assert.deepEqual(diagnostics, [{
      code: 'crowsi-browser-security-pa-passkey-proof-signature-rejected',
      phase: 'confirm'
    }])
    await assert.rejects(security.confirm({ registrationRef: reference }),
      /crowsi-browser-security-registration-unavailable/u)
  })

function challenge(operation) { return {
  schema: 'crowsi://policy-authority/passkey-challenge/v1', operation,
  challenge_b64url: encoded('a'), rp_id: 'localhost', origin: 'http://localhost:4213',
  expires_at_epoch_s: Math.floor(Date.now() / 1000) + 180,
} }
function encoded(character) { return character.repeat(43) }
async function writePrivate(path, value) {
  await writeFile(path, JSON.stringify(value), { mode: 0o600 })
  await chmod(path, 0o600)
}
