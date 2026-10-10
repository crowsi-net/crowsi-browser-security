# @crowsi/browser-security

Guard a caller-owned loopback HTTP service against cross-origin requests, replayed mutations and expired browser sessions. Optional owner ceremonies delegate cryptographic decisions to explicitly supplied native providers.

## Install and protect a loopback service

```sh
npm install @crowsi/browser-security@0.10.0
```

```typescript
import { createLaunchAccess, SessionAuthority } from '@crowsi/browser-security/access'
import { parseOwnerOrigin, assessRequestBoundary } from '@crowsi/browser-security/boundary'

const origin = parseOwnerOrigin('http://localhost:4317')
const launch = createLaunchAccess(origin.origin)
const sessions = new SessionAuthority({ launchToken: launch.credential })
const reason = assessRequestBoundary(origin, {
  host: 'localhost:4317', origin: origin.origin, method: 'POST', fetchSite: 'same-origin'
})
if (reason) throw new Error(reason)
const session = sessions.launch(launch.credential)
sessions.authorizeMutation(session.sessionId, session.csrfToken, crypto.randomUUID())
```

Deliver the launch URL only to its intended local browser. Its one-use credential is in the fragment and must not be logged, persisted or sent in a query string. The application must issue an HttpOnly, SameSite cookie, enforce the boundary before every request, and authenticate the session before returning protected data. Reusing a mutation nonce is rejected.

## Public interfaces

| Export | Responsibility |
| --- | --- |
| `/access` | Bounded, in-memory bootstrap, sessions, CSRF and nonce replay checks |
| `/boundary` | Loopback Host/Origin/Fetch-Site admission and security headers |
| `/client` | Browser fragment consumption and explicit session endpoint calls |
| `/owner` | Passkey ceremony coordination with caller-supplied native authority paths |
| `/provision` | Private state installation and owner-only file validation |
| `/demo` | An explicitly started loopback example; importing it starts no server |

Node.js 22 or later and ESM are required. Each export ships separate TypeScript declarations; the browser client additionally requires DOM types. There are no runtime npm dependencies.

Native authority and credential executables are supplied by the host, including the provider implementations managed under vpremises. Stable `crowsi://` wire identifiers identify existing protocols; they do not cause native components to download or start on import. Ceremonies fail closed without the required providers. Local files require Linux owner permissions; WSL-mounted files that cannot establish those permissions are rejected.

## Example server and verification

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm run typecheck
pnpm test
pnpm run demo
```

The demo binds only `127.0.0.1`. Its port defaults to 4317; callers of `startDemo` can select another port. Demo headers permit inline content and are an example policy: a production host must choose a CSP appropriate to its own frontend.

[Usage](docs/getting-started.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Notices](NOTICE)
