/**
 * A small library to encrypt and decrypt strings using AES-GCM and PBKDF2 which
 * can be used in Web projects (i.e., modern browsers) and also in Node projects.
 *
 * The key is derived from the password with PBKDF2 (HMAC-SHA-256) using a
 * random 32 byte salt; the message is then encrypted with AES-256-GCM using a
 * random 12 byte initialization vector. Salt and IV are freshly generated for
 * every call, so encrypting the same plaintext twice yields different results.
 *
 * Requires the Web Crypto API (`crypto.subtle`). In browsers this is only
 * available in {@link https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts secure contexts}
 * (HTTPS or localhost).
 *
 * Based on code found at: https://github.com/themikefuller/Web-Cryptography
 *
 * @module @lecturedoc2/libcrypto
 */

export { decrypt as decryptAESGCMPBKDF, encrypt as encryptAESGCMPBKDF };

/**
 * Encrypts a string with a password.
 *
 * The result is self-describing: it carries the iteration count, salt and IV
 * needed to decrypt it, so {@link decryptAESGCMPBKDF} needs nothing but the
 * returned string and the password. The four fields are base64 encoded and
 * joined with `":"`:
 *
 * ```text
 * <iterations>:<salt>:<iv>:<ciphertext>
 * ```
 *
 * The ciphertext field includes the 16 byte GCM authentication tag, which is
 * what makes tampering detectable at decryption time.
 *
 * @param {string} plaintext - The text to encrypt. May be empty.
 * @param {string} password - The password to derive the key from. Must be a
 *   non-empty string.
 * @param {number} iterations - PBKDF2 iteration count. Higher is slower to
 *   compute and slower to attack; OWASP currently recommends 600000 for
 *   PBKDF2-HMAC-SHA256. Low values leave the derived key easier to brute-force.
 * @returns {Promise<string>} The encrypted message, as described above.
 * @throws {Error} If `password` is not a string, or is empty.
 *
 * @example
 * const encrypted = await encryptAESGCMPBKDF("secret message", "password", 600000);
 * // => "NjAwMDAw:9Xk2...:pQ7f...:Lm4z..."
 */
async function encrypt(plaintext, password, iterations) {
  if (typeof password != "string")
    throw new Error(
      `password is not a string: (typeof ${password}) == ${typeof password}`,
    );

  if (typeof password != "string" || password.length == 0)
    throw new Error(`password too short: ${password.length} < 1`);

  const encodedPlaintext = new TextEncoder().encode(plaintext);
  const encodedPassword = new TextEncoder().encode(password);

  const pass = await crypto.subtle.importKey(
    "raw",
    encodedPassword,
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const keyBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: { name: "SHA-256" },
    },
    pass,
    256,
  );

  const key = await crypto.subtle.importKey(
    "raw",
    keyBits,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  const enc = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    encodedPlaintext,
  );

  const iterationsB64 = btoa(iterations.toString());

  const saltB64 = btoa(
    Array.from(new Uint8Array(salt))
      .map((val) => {
        return String.fromCharCode(val);
      })
      .join(""),
  );

  const ivB64 = btoa(
    Array.from(new Uint8Array(iv))
      .map((val) => {
        return String.fromCharCode(val);
      })
      .join(""),
  );

  const encB64 = btoa(
    Array.from(new Uint8Array(enc))
      .map((val) => {
        return String.fromCharCode(val);
      })
      .join(""),
  );

  return iterationsB64 + ":" + saltB64 + ":" + ivB64 + ":" + encB64;
}

/**
 * Decrypts a message produced by {@link encryptAESGCMPBKDF}.
 *
 * The iteration count, salt and IV are read back out of the message itself, so
 * only the password has to be supplied. Because AES-GCM is authenticated,
 * decryption fails rather than returning garbage if the password is wrong or
 * the message was modified.
 *
 * @param {string} encrypted - A message returned by
 *   {@link encryptAESGCMPBKDF}, i.e. four base64 fields joined with `":"`.
 * @param {string} password - The password used to encrypt the message.
 * @returns {Promise<string>} The recovered plaintext.
 * @throws {Error} If the password is wrong, the message has been tampered
 *   with, or it is not in the expected format.
 *
 * @example
 * const plaintext = await decryptAESGCMPBKDF(encrypted, "password");
 * // => "secret message"
 *
 * @example <caption>A wrong password rejects rather than returning garbage.</caption>
 * try {
 *   await decryptAESGCMPBKDF(encrypted, "wrong password");
 * } catch {
 *   // authentication failed
 * }
 */
async function decrypt(encrypted, password) {
  const parts = encrypted.split(":");
  const rounds = parseInt(atob(parts[0]));

  const salt = new Uint8Array(
    atob(parts[1])
      .split("")
      .map((val) => {
        return val.charCodeAt(0);
      }),
  );

  const iv = new Uint8Array(
    atob(parts[2])
      .split("")
      .map((val) => {
        return val.charCodeAt(0);
      }),
  );

  const enc = new Uint8Array(
    atob(parts[3])
      .split("")
      .map((val) => {
        return val.charCodeAt(0);
      }),
  );

  const encodedPassword = new TextEncoder().encode(password);
  const pass = await crypto.subtle.importKey(
    "raw",
    encodedPassword,
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const keyBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: rounds,
      hash: {
        name: "SHA-256",
      },
    },
    pass,
    256,
  );

  let key = await crypto.subtle.importKey(
    "raw",
    keyBits,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  let dec = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    enc,
  );

  return new TextDecoder().decode(dec);
}
