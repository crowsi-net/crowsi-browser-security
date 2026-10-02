# Using @crowsi/browser-security

Compose browser bootstrap, session and CSRF checks for a caller-owned authentication flow.

## Before you start

The application owns identity records, credential custody and its authentication endpoints.

## First steps

Run from the repository root:

```sh
npm install
npm run test
```

## How to assess the result

- Validate session and request context.
- Coordinate explicitly requested passkey steps.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
