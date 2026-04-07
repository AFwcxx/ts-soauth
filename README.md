# ts-soauth

```sh
 ____          _         _   _     
/ ___|  ___   / \  _   _| |_| |__  
\___ \ / _ \ / _ \| | | | __| '_ \ 
 ___) | (_) / ___ \ |_| | |_| | | |
|____/ \___/_/   \_\__,_|\__|_| |_|
```

A Libsodium based authentication framework.\
Set it up either as a centralised service that allows single host or multiple hosts management.\
Where the clients can be either human (browser) or machine (computer).\
Built with the assumption that there is a man-in-the-middle.\
Easy. Secure. Private.

## Communication topology

> No issue with multiple layer of proxies.

```js
          /---> Client Browser(s)
Host <---X                                       /---> Proxy <---> Client Machine
          \---> Client Machine, also a Host <---X
                                                 \---> Client Machine
```

## Demo

### As host
```js
// This will create an Express server
$ npm run test:host
```

### As human on browser
```js
// Note: Require Host to run
// This will spin up a simple webserver, open you default browser and present a form - use this to test registration, login, communication encryption and retrieving private sensitive data
$ npm run test:human
```

### As machine
```js
// Note: Require Host to run
// This will test s2s communication with the host
$ npm run test:machine
```


## Concept

1. The clients know the public identity of the host.
2. The host should never store any client private credentials.

Main keypoints:

- **Signing keys:** Deterministic. Used for human identity. Password not required, as long as the human memory is intact.
- **Box keys:** Random on every negotation. Used for encrypted communications.
- **Token:** Random on every negotation. Used for sessions to retrieve private readonly data.
- **Fingerprint:** Unique hash of the client resource information.

## Flow

|  CLIENT   | MAN IN THE MIDDLE |   HOST  |
| ------------- | ------------- |------------- |
|  |  | - Generate Signing key pairs and share the Signing public key to respective clients. |
| - Has the host Signing public key. <br />- Generate Signing key pairs and Box key pairs.<br />- Create a message that consists of the Box public key.<br />- Sign the message with Signing private key.<br />-Seal the message <br />- Send the signature and Signing public key as negotiation. | Has nothing useful here. |  |
|  |  | - Receives the negotation request, unseal and validate the signature and Signing public key.<br />- If valid, generate Box key pairs and Token.<br />- Create a message that consists of the Box public key and Token.<br />- Seal the message with client Box private key and respond to the client with only the seal. |
| Receives the negotiation respond, unseal and keep the host Box public key. | Has nothing useful here.  |  |
| Negotation ends. Communication begins. |
| - Use Box private key and host's Box public key to encrypt message.<br />- Send the ciphertext, nonce and Token.|  | Use the Token session to obtain client's Box public key and decrypt it with host own Box private key.|
| | **In total, it may hold:**<br/><br />- Nothing useful | |

The Man in the Middle:

- Replaying the client signing process with it's own signature to provide it's own
Box public key will only become a new identity since it cannot provide the
client's Signing public key (identity) and have a valid signature.
- Replaying the signing process as the host will only generate invalid
signature when the client validates it.
- Passing the client's Token with it's own ciphertext and nonce
(using it's own Box key pairs) in the communication will only point the host
to retrieve the invalid or non-exist public key and will not able to decrypt the ciphertext.
- Since the Token lifetime remains alive until the next negotation process, Tokens
should NEVER be used to retrieve sensitive information. Useful for static files such as javascript, json, stylesheet or html in private scope. 
Useful to isolate contents that should only be retrievable after authenticated.

About the Persistent mode:

- Client uses local storage (or any secured storage method) to store only the Box key pairs.
Never the signing key pairs.
- Box key pairs lifetime is until the next signing process or
when the local storage is cleared.
- If the local storage is compromised or Box key pairs is copied,
destroy the client Box public key or re-negotiate.
- <b>DO NOT</b> store Signing private key as that is the client identity.

## Specifications

### File structure

```
├── src
| └── test : Source files for Host and Machine test
| └── index.ts : Barrel source file for library consumption
| └── host.ts : Host source file
| └── machine.ts : Machine source file
|
├── private : Static sensitive resources that requires token
|
└── browser : Human resource
  └── test : Source files for browser to use
  └── soauth.js : Human source file for browser to use
```

### WebGL Fingerprint

The fingerprint is a hash of the client device user-agent and client device
graphical capabilities. User-agent as a sole unique device identifier is
insufficient as it only has the CPU make model, browser type, and version.
However, different machines would not have similar graphical rendering
criteria, and using this information helps generate even more unique device id.

[WebGL Repository](https://github.com/AFwcxx/webgl-detect)


### Dependencies

- [Libsodium](https://github.com/jedisct1/libsodium.js)
  - [NPM](https://www.npmjs.com/package/libsodium-wrappers)
  - [Browser](https://github.com/jedisct1/libsodium.js/tree/master/dist/browsers)

