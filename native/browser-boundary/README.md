# crowsi-browser-boundary

Source-only Rust metadata admission for a caller-owned loopback HTTP service.
Use a fixed public Git commit; this crate is not on crates.io. Apache-2.0.

`OwnerOrigin` and `assess_request` implement the existing JavaScript `/boundary`
owner-origin/Host/unsafe-method/Fetch-Site contract. The same checked-in vectors
run against both implementations. Existing npm exports and version are unchanged.
The native configuration parser also bounds input at 256 bytes.

This is not authentication, a session authority, a passkey ceremony, custody,
CSRF-token/session checking, peer verification, CSP generation or a network listener.
Applications must supply the actual trusted peer/headers from their server, refuse
ambiguous duplicate headers, enforce their numeric-loopback/proxy policy and map
verified identities to product grants separately. Never treat a matching origin
or a SPIFFE-shaped name as authority to use a secret or execute an operation.

NERP currently has an explicitly local bootstrap mode; real iHAT/Crowsi grant and
held host acceptance are distinct. This crate does not resume those trials.

Verification: shared JS/native vectors, whole Node contract suite, native tests,
Clippy and packaged-crate build. Consumer HTTP acceptance remains required.
