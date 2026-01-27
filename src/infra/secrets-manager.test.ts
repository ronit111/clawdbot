import { describe, expect, test, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  encryptData,
  decryptData,
  storeSecret,
  getSecret,
  deleteSecret,
  listSecretKeys,
  hasSecret,
  generateSecureToken,
  hashSecret,
  verifySecretHash,
  getDefaultEncryptedSecretsPath,
  detectAvailableBackends,
} from "./secrets-manager.js";

describe("secrets-manager encryption", () => {
  test("encrypts and decrypts data correctly", () => {
    const original = "super secret password 123!@#";
    const encrypted = encryptData(original);
    const decrypted = decryptData(encrypted);
    expect(decrypted).toBe(original);
  });

  test("encrypts to different ciphertext each time (random IV)", () => {
    const original = "same data";
    const encrypted1 = encryptData(original);
    const encrypted2 = encryptData(original);
    expect(encrypted1.equals(encrypted2)).toBe(false);
  });

  test("decrypts with correct password", () => {
    const original = "password protected data";
    const password = "my-custom-password";
    const encrypted = encryptData(original, password);
    const decrypted = decryptData(encrypted, password);
    expect(decrypted).toBe(original);
  });

  test("fails to decrypt with wrong password", () => {
    const original = "password protected data";
    const encrypted = encryptData(original, "correct-password");
    expect(() => decryptData(encrypted, "wrong-password")).toThrow();
  });

  test("handles empty string", () => {
    // Empty string encryption produces just headers (salt+iv+authTag) with no ciphertext
    // The decryption should handle this edge case
    const original = "";
    const encrypted = encryptData(original);
    // Encrypted buffer should have at least salt(32) + iv(16) + authTag(16) = 64 bytes
    expect(encrypted.length).toBeGreaterThanOrEqual(64);
    const decrypted = decryptData(encrypted);
    expect(decrypted).toBe(original);
  });

  test("handles unicode characters", () => {
    const original = "日本語テスト 🔐 émojis";
    const encrypted = encryptData(original);
    const decrypted = decryptData(encrypted);
    expect(decrypted).toBe(original);
  });

  test("handles large data", () => {
    const original = "x".repeat(100_000);
    const encrypted = encryptData(original);
    const decrypted = decryptData(encrypted);
    expect(decrypted).toBe(original);
  });

  test("rejects tampered ciphertext", () => {
    const original = "sensitive data";
    const encrypted = encryptData(original);
    // Tamper with the encrypted data
    encrypted[encrypted.length - 1] ^= 0xff;
    expect(() => decryptData(encrypted)).toThrow();
  });

  test("rejects truncated ciphertext", () => {
    const original = "sensitive data";
    const encrypted = encryptData(original);
    const truncated = encrypted.subarray(0, 50);
    expect(() => decryptData(truncated)).toThrow();
  });
});

describe("secrets-manager file storage", () => {
  let testDir: string;
  let testFilePath: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secrets-test-"));
    testFilePath = path.join(testDir, "test-secrets.enc");
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  test("stores and retrieves secret from encrypted file", () => {
    const key = "test-api-key";
    const value = "sk-test-1234567890";

    const storeResult = storeSecret(key, value, {
      preferKeychain: false,
      enableEncryptedFallback: true,
      encryptedFilePath: testFilePath,
    });

    expect(storeResult.success).toBe(true);
    expect(storeResult.storage).toBe("encrypted-file");

    const getResult = getSecret(key, {
      preferKeychain: false,
      enableEncryptedFallback: true,
      encryptedFilePath: testFilePath,
    });

    expect(getResult.success).toBe(true);
    expect(getResult.value).toBe(value);
    expect(getResult.storage).toBe("encrypted-file");
  });

  test("returns error for non-existent secret", () => {
    const result = getSecret("non-existent-key", {
      preferKeychain: false,
      enableEncryptedFallback: true,
      encryptedFilePath: testFilePath,
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("not found");
  });

  test("deletes secret from encrypted file", () => {
    const key = "delete-me";
    const value = "temporary secret";

    storeSecret(key, value, {
      preferKeychain: false,
      encryptedFilePath: testFilePath,
    });

    expect(hasSecret(key, { preferKeychain: false, encryptedFilePath: testFilePath })).toBe(true);

    deleteSecret(key, {
      preferKeychain: false,
      encryptedFilePath: testFilePath,
    });

    expect(hasSecret(key, { preferKeychain: false, encryptedFilePath: testFilePath })).toBe(false);
  });

  test("lists stored secret keys", () => {
    storeSecret("key1", "value1", { preferKeychain: false, encryptedFilePath: testFilePath });
    storeSecret("key2", "value2", { preferKeychain: false, encryptedFilePath: testFilePath });
    storeSecret("key3", "value3", { preferKeychain: false, encryptedFilePath: testFilePath });

    const keys = listSecretKeys({ preferKeychain: false, encryptedFilePath: testFilePath });

    expect(keys).toContain("key1");
    expect(keys).toContain("key2");
    expect(keys).toContain("key3");
    expect(keys.length).toBe(3);
  });

  test("overwrites existing secret", () => {
    const key = "overwrite-test";

    storeSecret(key, "original", { preferKeychain: false, encryptedFilePath: testFilePath });
    storeSecret(key, "updated", { preferKeychain: false, encryptedFilePath: testFilePath });

    const result = getSecret(key, { preferKeychain: false, encryptedFilePath: testFilePath });
    expect(result.value).toBe("updated");
  });

  test("creates directory if it doesn't exist", () => {
    const nestedPath = path.join(testDir, "nested", "dir", "secrets.enc");

    const result = storeSecret("nested-key", "nested-value", {
      preferKeychain: false,
      encryptedFilePath: nestedPath,
    });

    expect(result.success).toBe(true);
    expect(fs.existsSync(nestedPath)).toBe(true);
  });

  test("sets restrictive file permissions", () => {
    storeSecret("perm-test", "value", {
      preferKeychain: false,
      encryptedFilePath: testFilePath,
    });

    const stats = fs.statSync(testFilePath);
    // Check that only owner has read/write (0o600)
    const mode = stats.mode & 0o777;
    expect(mode).toBe(0o600);
  });
});

describe("secrets-manager utilities", () => {
  test("generateSecureToken returns correct length", () => {
    const token32 = generateSecureToken(32);
    const token64 = generateSecureToken(64);

    // Base64url encoding: 4 chars per 3 bytes
    expect(token32.length).toBeGreaterThan(40);
    expect(token64.length).toBeGreaterThan(80);
  });

  test("generateSecureToken is unique each time", () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 100; i++) {
      tokens.add(generateSecureToken());
    }
    expect(tokens.size).toBe(100);
  });

  test("hashSecret produces consistent hash", () => {
    const secret = "my-secret-value";
    const hash1 = hashSecret(secret);
    const hash2 = hashSecret(secret);
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64); // SHA-256 hex is 64 chars
  });

  test("hashSecret produces different hashes for different inputs", () => {
    const hash1 = hashSecret("secret1");
    const hash2 = hashSecret("secret2");
    expect(hash1).not.toBe(hash2);
  });

  test("verifySecretHash returns true for matching secret", () => {
    const secret = "verify-me";
    const hash = hashSecret(secret);
    expect(verifySecretHash(secret, hash)).toBe(true);
  });

  test("verifySecretHash returns false for wrong secret", () => {
    const hash = hashSecret("correct-secret");
    expect(verifySecretHash("wrong-secret", hash)).toBe(false);
  });

  test("hasSecret returns true when secret exists", () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), "has-secret-test-"));
    const testFilePath = path.join(testDir, "secrets.enc");

    try {
      storeSecret("exists", "value", { preferKeychain: false, encryptedFilePath: testFilePath });
      expect(hasSecret("exists", { preferKeychain: false, encryptedFilePath: testFilePath })).toBe(
        true,
      );
      expect(
        hasSecret("not-exists", { preferKeychain: false, encryptedFilePath: testFilePath }),
      ).toBe(false);
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  test("getDefaultEncryptedSecretsPath returns expected path", () => {
    const defaultPath = getDefaultEncryptedSecretsPath();
    expect(defaultPath).toContain(".clawdbot");
    expect(defaultPath).toContain("secrets.enc");
  });
});

describe("secrets-manager backend detection", () => {
  test("detectAvailableBackends returns object with correct shape", () => {
    const backends = detectAvailableBackends();
    expect(typeof backends.keychain).toBe("boolean");
    expect(typeof backends.secretService).toBe("boolean");
    expect(typeof backends.credentialManager).toBe("boolean");
  });

  test("detectAvailableBackends reports keychain on macOS", () => {
    const backends = detectAvailableBackends();
    if (process.platform === "darwin") {
      // On macOS, keychain should generally be available
      expect(backends.keychain).toBe(true);
    }
  });

  test("detectAvailableBackends reports credential manager on Windows", () => {
    const backends = detectAvailableBackends();
    if (process.platform === "win32") {
      expect(backends.credentialManager).toBe(true);
    }
  });
});
