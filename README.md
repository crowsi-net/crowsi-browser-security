# Crowsi browser security

Version 0.10.0. Standalone local browser bootstrap, bounded session/CSRF authority,
and orchestration of Crowsi native Passkey registration, authentication, rebind,
and recovery-status inspection. Callers supply state and compose the documented interfaces.
The browser bootstrap proves possession of a process-issued capability, not the
identity of a human. Applications decide which operations need owner proof.

```sh
npm test
npm run demo
```

The demo listens on localhost:4317 and prints a one-use launch URL. Its HTTP API
is exercised with a real server by `test/demo.test.mjs`: exchange the fragment's
credential with `POST /connect {"credential":"..."}`, retain the HttpOnly cookie,
then use the returned CSRF value in `X-CSRF` and a fresh UUID in `X-Nonce` for
mutations. Requests require the exact Origin. `/status` and `/recovery/inspect`
return bounded state; `/logout` revokes the session. Do not expose this local
demo to a network or treat a bootstrap token as a Passkey verification.

To exercise actual owner ceremonies, supply CROWSI_SECURITY_ROOT, CROWSI_PA_AGENT,
CROWSI_CREDENTIAL_AGENT and CROWSI_RECOVERY_PROVIDER. Missing providers remain
unavailable, never replaced with test credentials. Zixcel's `@zixcel/webauthn`
builds browser options; Crowsi's native authority verifies the signatures.
The Node owner tests inject native responses to test orchestration only, not to
claim OS authenticator acceptance. Native Passkey tests live in crowsi-pa-key-agent.

Seed phrase generation and proof stay in crowsi-owner-recovery-provider;
zixcel-owner-recovery owns the secret-free recovery/move sequence. This package
neither copies their cryptography nor adds a browser field for the phrase.
Secrets and existing registrations are never imported or deleted on installation.

Applications reference the access/client/boundary exports through versioned
package artifacts and own their UI composition.
