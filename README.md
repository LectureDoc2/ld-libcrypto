# ld-libcrypto

Provides basic, but secure functionality to encrypt and decrypt strings. The library can be used in Node as well as web projects and has no runtime dependencies.

Encryption is AES-GCM with a 256 bit key derived from the password using PBKDF2 (SHA-256), with a random 32 byte salt and a random 12 byte IV per message.

## Installation

```sh
npm install @lecturedoc2/libcrypto
```

## Usage

```js
import { encryptAESGCMPBKDF, decryptAESGCMPBKDF } from "@lecturedoc2/libcrypto";

const encrypted = await encryptAESGCMPBKDF(
  "secret message",
  "password",
  250000,
);
// => "MjUwMDAw:<salt>:<iv>:<ciphertext>"  (base64 fields, ":" separated)

const plaintext = await decryptAESGCMPBKDF(encrypted, "password");
// => "secret message"
```

### API

`encryptAESGCMPBKDF(plaintext, password, iterations)` → `Promise<string>`

Returns a self-describing string of four base64 fields joined by `:` — the PBKDF2 iteration count, the salt, the IV, and the ciphertext (which includes the GCM authentication tag). Throws if the password is not a non-empty string.

`decryptAESGCMPBKDF(encrypted, password)` → `Promise<string>`

Takes the string produced by `encryptAESGCMPBKDF`. The iteration count, salt and IV are read back out of it, so they do not need to be supplied. Rejects if the password is wrong or the message has been tampered with.

Choose `iterations` to suit the threat model — OWASP currently suggests 600,000 for PBKDF2-HMAC-SHA256. Low values are fast but weaken the protection of the derived key.

## Requirements

Node 24+, or any browser with the Web Crypto API. In browsers, `crypto.subtle` is only available in [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (HTTPS or localhost).

## Development

```sh
pnpm install
pnpm test        # runs the Jest suite against src/
pnpm build       # writes dist/libcrypto.min.js + sourcemap
pnpm test:dist   # smoke-tests the built bundle
```

The published package exposes the minified bundle by default. The unminified source is also shipped and can be imported explicitly:

```js
import { encryptAESGCMPBKDF } from "@lecturedoc2/libcrypto/src/libcrypto.js";
```
