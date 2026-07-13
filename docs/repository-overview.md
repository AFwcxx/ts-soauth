# Repository Overview

`ts-soauth` is a small TypeScript authentication and encrypted-messaging toolkit built directly on libsodium. It supports human/browser authentication through registration and login negotiation, as well as deterministic machine-to-machine encrypted communication.

## Architecture

The published Node API exposes two singleton-style modules:

- `Host`: server-side negotiation, token verification, encryption, and decryption.
- `Machine`: deterministic machine identity, encryption/decryption, and machine fingerprinting.

There is also a separate browser implementation in `browser/soauth.js`. It is not part of the TypeScript package exports.

The main human authentication flow is:

1. A host derives a deterministic keypair from its secret and host ID.
2. A browser sends a sealed, signed registration or login request.
3. The host verifies the signature and intended host key.
4. The host deterministically derives session key material and a token from the client box key.
5. Subsequent messages use authenticated public-key encryption and require that token.

Machine clients skip negotiation because their keypair is deterministically derived from a pre-shared secret and host ID.

## Implementation Characteristics

- Cryptography is provided by `libsodium-wrappers`.
- Runtime input validation is handled with Zod.
- Keys, nonces, ciphertexts, and tokens cross API boundaries as hexadecimal strings.
- Host and machine configuration lives in module-global mutable state. This effectively makes each module a singleton and limits a process to one active configuration.
- Authentication state is mostly deterministic rather than stored internally:
  - Host signing keys come from `host secret + hostId`.
  - Host session box keys come from `host secret + hostId + client public key`.
  - Tokens are derived from that box key and host ID.
- Actual authorization and account persistence are left to the consuming application. The demo host keeps users and machines in memory.

## Repository Maturity

The repository currently resembles a working reference implementation or early-stage security library more than a production-ready authentication framework.

- The Node library compiles successfully with strict TypeScript.
- The programs under `src/test/` are executable demonstrations rather than automated unit or integration tests.
- There is no `npm test` script, CI configuration, linting, or coverage setup.
- The Express demo has a one-hour in-memory human-session TTL and demonstrates token-protected resources.
- Machine registration is hardcoded in the demo.
- The package uses CommonJS, targets ES2021, and emits declarations into `dist`.
- Browser code is plain JavaScript and is maintained separately from the typed Node implementation.

## Security Interpretation

The protocol provides confidentiality and proof of possession of derived signing or private keys, but it is not a conventional OAuth implementation despite the name. It does not implement OAuth grants, scopes, authorization-server concepts, or standard token formats.

Its security depends heavily on:

- High-entropy host and machine secrets.
- Clients securely pinning the correct host public key.
- Credential-derived browser keys being sufficiently resistant to guessing.
- Application code correctly persisting registrations and enforcing login and account policy.
- Nonce uniqueness and secure handling of tokens and saved browser state.

Before production use, the project would benefit from:

- A protocol-level security review and documented threat model.
- Explicit password-hardening analysis.
- Automated cryptographic test vectors and integration tests.
- Replay protection and authentication throttling.
- Clearly documented session expiration, rotation, and revocation behavior.

## Summary

`ts-soauth` is a compact custom secure-channel and identity-negotiation protocol with runnable browser, server, and machine demonstrations. It has strict TypeScript compilation and runtime boundary validation, but it is not a complete production authentication platform or an OAuth implementation.
