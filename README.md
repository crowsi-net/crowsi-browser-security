# @crowsi/browser-security

Compose browser bootstrap, session and CSRF checks for a caller-owned authentication flow.

## What you can do

- Validate session and request context.
- Coordinate explicitly requested passkey steps.

## Current scope

The application owns identity records, credential custody and its authentication endpoints.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Use the package manager matching the checked-in lockfile and the Node.js version declared in `engines` in `package.json`. Run from this repository:

```sh
npm install
npm run test
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](test) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
