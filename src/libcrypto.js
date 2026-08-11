/* A small library to encrypt and decrypt strings using AES-GCM and PBKDF2 which
 * can be used in Web projects (i.e., modern browsers) and also in Node projects.
 *
 * Based on code found at: https://github.com/themikefuller/Web-Cryptography
 */
export { decrypt as decryptAESGCMPBKDF, encrypt as encryptAESGCMPBKDF };

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
