# ts-soauth

`ts-soauth` is a libsodium-based authentication and encrypted messaging toolkit for TypeScript/JavaScript projects.

It supports two practical deployment patterns:

- **Node/server-side**: run as a **Host** service and/or as a **Machine** client for server-to-server communication.
- **Browser/human-side**: use `browser/soauth.js` for human registration/login negotiation and encrypted message exchange from the browser.

The design assumes untrusted networks (including potential man-in-the-middle interception) and uses signed negotiation plus per-session encryption keys/tokens.

---

## What this package is

`ts-soauth` provides cryptographic building blocks and reference flows for:

1. **Negotiation / authentication** (register or login intent).
2. **Session-bound encrypted communication** after successful negotiation.
3. **Token-gated access** to private host resources.

The repository includes:

- Node library modules (`src/host.ts`, `src/machine.ts`).
- Node demo/test programs (`src/test/*`).
- Browser client implementation and demo (`browser/soauth.js`, `browser/test/*`).

---

## Supported usage modes

### 1) Host (Node/server)

Use `Host` in your backend to:

- initialize host configuration (`secret`, list of served host IDs),
- process negotiation requests,
- verify issued session tokens,
- encrypt/decrypt host↔client messages.

Reference implementation: `src/test/host.ts`.

### 2) Machine (Node/server-to-server)

Use `Machine` in backend clients/services to:

- derive deterministic machine identity/public key from `secret + hostId`,
- encrypt payloads to a Host,
- decrypt Host responses,
- optionally compute a machine fingerprint.

Reference flow: `src/test/machine.ts` against Host `/machine` route in `src/test/host.ts`.

### 3) Browser / human client

Use `browser/soauth.js` for human flows:

- `setup(...)` to configure host details and fingerprint provider,
- `negotiate('register' | 'login', ...)` for authentication,
- `exchange(...)` for encrypted post-login communication,
- `save/load` for encrypted client-side session persistence.

Reference demo: `browser/test/index.html` + `browser/test/index.js`.

---

## Core concepts

### Host identity

The Host has a deterministic signing keypair per `hostId`, derived from Host `secret + hostId`. Clients pin/know the Host signing public key ahead of time.

### Signing keys (identity)

Client negotiation messages are signed. In the browser flow, signing keys are deterministically derived from user credential material and the host signing public key.

### Box keys (encryption)

Encrypted transport uses libsodium box primitives. Negotiation and message exchange rely on box keypairs and nonces for confidentiality.

### Token/session behavior

After successful negotiation, Host returns a token tied to host/client key material. That token is required for protected Host operations in the demo flow (for example `/message` and `/private/*`).

### Fingerprinting

A fingerprint header (`SoAuth-Fingerprint`) is used by demo server logic to correlate client/device context (browser demo via WebGL provider; machine demo uses a fixed sample fingerprint).

### MITM security framing

The protocol is designed for hostile networks:

- Negotiation request authenticity is validated via signature checks.
- Negotiation response secrecy is protected with sealed boxes.
- Post-negotiation traffic is encrypted with per-session keying material.
- Tokens are verified before allowing private operations.

---

## High-level communication flow

1. **Host bootstrap**
   - Host calls `Host.setup({ secret, serves: [...] })`.
   - Host can derive/publish signing public keys for served host IDs.

2. **Client negotiation request**
   - Client prepares signed data including intention (`register`/`login`) and its box public key.
   - Client seals that payload to Host signing public key and sends `{ hostId, sealed }`.

3. **Host negotiation validation**
   - Host opens sealed payload with host signing keypair.
   - Host validates client signature and expected host signing key reference.
   - Host derives auth material, creates token + host box public key, seals response to client box public key.

4. **Post-negotiation exchange**
   - Client sends encrypted payload + nonce + token.
   - Host validates token, derives peer box key context, decrypts request, encrypts response.

5. **Token-gated private resource access (demo)**
   - Demo Host route `/private/{*path}` requires token (`?soauth=...`) and serves from `private/` only when valid.

---

## Installation

### Use as a package

```bash
npm install github:AFwcxx/ts-soauth
```

### Work in this repository

```bash
npm install
npm run build
```

---

## Quick start (repo demos)

> Open separate terminals for Host and clients.

### 1) Run Host demo

```bash
npm run test:host
```

Starts Express Host on port `3000` by default.

### 2) Run browser/human demo

```bash
npm run test:human
```

Starts static server (`http-server`) and opens `/browser/test`.

### 3) Run machine demo

```bash
npm run test:machine
```

Sends encrypted machine message to Host `/machine` route and decrypts Host response.

---

## Package API overview

## Exports

```ts
import { Host, Machine } from 'ts-soauth'
```

or default export:

```ts
import Soauth from 'ts-soauth'
// Soauth.Host, Soauth.Machine
```

### `Host` API (`src/host.ts`)

- `setup(options)`
  - Requires `secret` and `serves` (array of host IDs).
- `negotiate(request)`
  - Input envelope typically `{ hostId, sealed }`.
  - Returns `{ success, message, sealed, data }`.
- `verify_token(hostId, boxPublicKey, token)`
- `encrypt(message, hostId, boxPublicKey)`
- `decrypt(data, hostId, boxPublicKey)`
- `get_box_pubkey(hostId, boxPublicKey)`
- `check_store_data(definition, data)`
- constants:
  - `SOAUTH_HUMAN_STOREDATA`
  - `SOAUTH_MACHINE_STOREDATA`

### `Machine` API (`src/machine.ts`)

- `setup(options)`
  - Requires `secret`, `hostId`, `hostPublicKey`.
- `get_pubkey()`
- `encrypt(message)`
- `decrypt({ ciphertext, nonce })`
- `fingerprint(raw?)`
- `serialize_message(message)`

### Browser client API (`browser/soauth.js`)

- `setup(options)`
- `negotiate(intention, credential, pathname, meta?)`
- `exchange(message, pathname, requestId?)`
- `cancel_exchange(requestId)`
- `save(secret, manual?)`
- `load(secret, options, data?)`
- `clear_local_storage(hostSignPublicKey?)`

---

## Usage examples

## Minimal Host (Node)

```ts
import sodium from 'libsodium-wrappers'
import { Host } from 'ts-soauth'

await sodium.ready

Host.setup({
  secret: 'your-secret',
  serves: ['my-host-id'],
})

// inside your route handler:
// const result = Host.negotiate(req.body)
```

See complete server flow in `src/test/host.ts`.

## Minimal Machine client (Node)

```ts
import sodium from 'libsodium-wrappers'
import { Machine } from 'ts-soauth'

await sodium.ready

Machine.setup({
  secret: 'your-secret',
  hostId: 'my-host-id',
  hostPublicKey: '<host-box-public-key-hex>',
})

const encrypted = Machine.encrypt({ hello: 'world' })
// POST encrypted to host, then:
// const response = Machine.decrypt({ ciphertext, nonce })
```

See runnable sample in `src/test/machine.ts`.

## Browser integration sketch

```js
import soauth from '../soauth.js'
import { webgl } from './webgl.js'

await soauth.setup({
  hostId,
  hostSignPublicKey,
  hostEndpoint,
  webgl,
})

await soauth.negotiate('login', { username, password }, '/negotiate', { username })
const reply = await soauth.exchange('hello', '/message')
```

See full demo in `browser/test/index.js`.

---

## Project structure

```text
.
├── browser/
│   ├── soauth.js            # Browser client implementation
│   └── test/                # Browser demo assets
├── private/                 # Demo private resources served behind token check
├── src/
│   ├── host.ts              # Host API
│   ├── machine.ts           # Machine API
│   ├── index.ts             # Package exports
│   └── test/
│       ├── host.ts          # Express host demo
│       └── machine.ts       # Machine demo client
├── package.json
└── README.md
```

---

## Security notes and caveats

- Keep Host `secret` protected; key derivation depends on it.
- Use HTTPS in non-local environments (browser client enforces this for non-local hosts).
- Treat tokens as session transport credentials; do not rely on them alone as durable identity.
- Browser persistence (`save/load`) stores encrypted session state; do **not** persist human signing private keys.
- Fingerprinting is signal/correlation data, not a standalone authentication factor.

---

## Development and demo commands

```bash
npm install
npm run build
npm run test:host
npm run test:human
npm run test:machine
```

Scripts are defined in `package.json`.

---

## Practical troubleshooting

- **"SoAuth: libsodium is not ready yet."**
  - Ensure `await sodium.ready` before calling Node APIs.
- **Browser setup fails with host endpoint error**
  - Use `https://` for non-local hosts; `http://127.0.0.1` is allowed for local dev.
- **`exchange` fails after reload**
  - Re-negotiate or verify `load(...)` succeeded and session/token is still valid.

