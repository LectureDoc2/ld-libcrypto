# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08-11

### Added

- TypeScript declarations (`dist/libcrypto.d.ts`) generated from the JSDoc
  comments, so consumers get autocomplete and type checking.
- API documentation published to
  [lecturedoc2.github.io/ld-libcrypto](https://lecturedoc2.github.io/ld-libcrypto/).
- JSDoc comments on both exported functions, covering parameters, return
  values, thrown errors, and the encoding of the returned message.

## [1.0.0] - 2026-08-11

### Added

- `encryptAESGCMPBKDF(plaintext, password, iterations)` — encrypts a string
  with AES-256-GCM using a key derived via PBKDF2 (HMAC-SHA-256), a random
  32 byte salt, and a random 12 byte IV.
- `decryptAESGCMPBKDF(encrypted, password)` — recovers the plaintext, reading
  the iteration count, salt, and IV back out of the message.

[unreleased]: https://github.com/LectureDoc2/ld-libcrypto/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/LectureDoc2/ld-libcrypto/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/LectureDoc2/ld-libcrypto/releases/tag/v1.0.0
