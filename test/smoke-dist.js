/* Smoke test for the published artifact.
 *
 * Jest exercises src/, this exercises dist/ exactly as a consumer would import
 * it (via the package's "exports" entry). Run with: node test/smoke-dist.js
 */
import assert from "node:assert/strict";

import { encryptAESGCMPBKDF, decryptAESGCMPBKDF } from "@lecturedoc2/libcrypto";

const plaintext = "This is a test.";
const password = "Password";

const encrypted = await encryptAESGCMPBKDF(plaintext, password, 1000);
assert.equal(typeof encrypted, "string");
assert.notEqual(encrypted, plaintext);
assert.equal(encrypted.split(":").length, 4);

const decrypted = await decryptAESGCMPBKDF(encrypted, password);
assert.equal(decrypted, plaintext);

await assert.rejects(() => decryptAESGCMPBKDF(encrypted, "wrong password"));

console.log("dist smoke test: ok");
