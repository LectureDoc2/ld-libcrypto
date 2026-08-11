import { jest, test, expect } from "@jest/globals";

import { encryptAESGCMPBKDF, decryptAESGCMPBKDF } from "../src/libcrypto";

test("encrypt and decrypt regular string", async () => {
  const x = "This is a test.";
  const pwd = "Password";
  const iterations = 1;
  const y = await encryptAESGCMPBKDF(x, pwd, iterations);
  expect(typeof y).toBe("string");
  expect(y).not.toBe(x);
  const decrypted_y = await decryptAESGCMPBKDF(y, pwd, iterations);
  expect(x).toBe(decrypted_y);
});

test("encrypt and decrypt empty string", async () => {
  const x = "";
  const pwd = "Password";
  const iterations = 1;
  const y = await encryptAESGCMPBKDF(x, pwd, iterations);
  expect(typeof y).toBe("string");
  expect(y).not.toBe(x);
  const decrypted_y = await decryptAESGCMPBKDF(y, pwd, iterations);
  expect(x).toBe(decrypted_y);
});

test("password has unexpected type", async () => {
  const x = "This is a test.";
  const pwd = 1.0;
  const iterations = 2;
  try {
    await encryptAESGCMPBKDF(x, pwd, iterations);
  } catch (error) {
    expect(error.message).toMatch("password is not a string");
  }
});

test("password too short", async () => {
  const x = "This is a test.";
  const pwd = "";
  const iterations = 2;
  try {
    await encryptAESGCMPBKDF(x, pwd, iterations);
  } catch (error) {
    expect(error.message).toMatch("password too short");
  }
});

test("no iterations", async () => {
  const x = "This is a test.";
  const pwd = "a valid password";
  const iterations = 0;
  try {
    await encryptAESGCMPBKDF(x, pwd, iterations);
  } catch (error) {
    expect(error.message).toMatch("iterations cannot be zero");
  }
});

test("iterations affect the encryption and the encoding", async () => {
  const x = "";
  const pwd = "Password";
  const iterations_1 = 1;
  const iterations_2 = 100_000;
  const y_1 = await encryptAESGCMPBKDF(x, pwd, iterations_1);
  const y_2 = await encryptAESGCMPBKDF(x, pwd, iterations_2);
  expect(y_1).not.toBe(y_2);
  const iterations_1B64Matcher = new RegExp(
    String.raw`^${btoa(iterations_1)}:`,
  );
  const iterations_2B64Matcher = new RegExp(
    String.raw`^${btoa(iterations_2)}:`,
  );
  expect(y_1).toMatch(iterations_1B64Matcher);
  expect(y_2).toMatch(iterations_2B64Matcher);
});
