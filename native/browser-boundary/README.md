# crowsi-browser-boundary

Source-only Rust metadata admission and bounded opaque browser sessions for a caller-owned loopback HTTP service.
Use a fixed public Git commit; this crate is not on crates.io. Apache-2.0.

`OwnerOrigin` and `assess_request` implement the existing JavaScript `/boundary`
owner-origin/Host/unsafe-method/Fetch-Site contract. The same checked-in vectors
run against both implementations. Existing npm exports and version are unchanged.
The native configuration parser also bounds input at 256 bytes.

This is not human authentication, a passkey ceremony, custody, peer verification,
CSP generation or a network listener. Opaque browser sessions do not assert
iHAT identity, product roles, commercial entitlements or external execution grants.
Applications must supply the actual trusted peer/headers from their server, refuse
ambiguous duplicate headers, enforce their numeric-loopback/proxy policy and map
verified identities to product grants separately. Never treat a matching origin
or a SPIFFE-shaped name as authority to use a secret or execute an operation.

NERP currently has an explicitly local bootstrap mode; real iHAT/Crowsi grant and
held host acceptance are distinct. This crate does not resume those trials.

Verification: shared JS/native vectors, whole Node contract suite, native tests,
Clippy and packaged-crate build. Consumer HTTP acceptance remains required.


## Native browser sessions (source-only 0.2.0)

`SessionAuthority` implements the existing JavaScript access-owner responsibilities
for Rust consumers: OS-random 256-bit opaque session/CSRF tokens, explicit one-use
local launch credentials, expiry, revocation and UUIDv4 mutation replay checks.
A caller can issue browser access after an independently verified external auth
ceremony; issuing access never manufactures identity. No private keys, OS store,
network service, persistent sessions or automatic activation are introduced.
Restart invalidates sessions. Tokens are neither serialized nor Debug-formatted
by the owner. Local bootstrap credentials must be shown only in the caller's
explicit owner ceremony and removed from the browser fragment immediately.

Configuration limits live sessions to 1..256, TTL to 60 seconds..24 hours, and the
**total across all sessions** retained mutation nonces to 1..65536. Capacity errors
never evict a live session or permit replay; revoke/expiry frees its nonce budget.
The global nonce bound is stricter than the JavaScript owner's per-session bound.
Issued token and browser response wire fields remain compatible (64 lowercase
hex characters are within the browser token contract). Monotonic time enforces
expiry; Unix milliseconds are presentation metadata only. CSRF comparisons use
`subtle`; randomness uses `getrandom`; UUID parsing uses `uuid`. There is no custom
cryptographic algorithm, background task, entropy retry or unbounded queue.

A Rust consumer must still enforce HTTP metadata/duplicate-header admission,
cookie transport, identity freshness, account/workspace roles and business
idempotency. CSRF success is not authorization, and a consumed transport nonce
never authorizes replay of an outcome-unknown business operation. Source tests
use actual OS randomness and disposable process state; no personal host or
key-store trial is required or resumed.
