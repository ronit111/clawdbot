/**
 * Secrets Manager
 *
 * Cross-platform secure storage for sensitive credentials using system keychains.
 * Falls back to AES-256-GCM encrypted files when keychain is unavailable.
 *
 * Supported platforms:
 * - macOS: Keychain Access via `security` command
 * - Linux: Secret Service API via `secret-tool` (libsecret)
 * - Windows: Credential Manager via PowerShell (future)
 * - Fallback: AES-256-GCM encrypted JSON files
 */

import crypto from "node:crypto";
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("secrets");

/** Service name prefix for keychain entries */
const KEYCHAIN_SERVICE_PREFIX = "Clawdbot";

/** Encryption algorithm for file fallback */
const ENCRYPTION_ALGORITHM = "aes-256-gcm";

/** Key derivation iterations */
const PBKDF2_ITERATIONS = 100_000;

/** Salt length in bytes */
const SALT_LENGTH = 32;

/** IV length in bytes */
const IV_LENGTH = 16;

/** Auth tag length in bytes */
const AUTH_TAG_LENGTH = 16;

/** Result of a secrets operation */
export type SecretsResult<T> = {
  success: boolean;
  value?: T;
  error?: string;
  storage: "keychain" | "encrypted-file" | "plain-file" | "none";
};

/** Configuration for secrets storage */
export type SecretsConfig = {
  /** Prefer keychain over file storage */
  preferKeychain: boolean;
  /** Enable encrypted file fallback when keychain unavailable */
  enableEncryptedFallback: boolean;
  /** Path to encrypted secrets file (for fallback) */
  encryptedFilePath?: string;
  /** Machine-specific key for file encryption (derived from hardware ID if not provided) */
  encryptionKey?: string;
};

const DEFAULT_CONFIG: SecretsConfig = {
  preferKeychain: true,
  enableEncryptedFallback: true,
};

/**
 * Detects available secret storage backends on the current platform.
 */
export function detectAvailableBackends(): {
  keychain: boolean;
  secretService: boolean;
  credentialManager: boolean;
} {
  const platform = process.platform;

  let keychain = false;
  let secretService = false;
  let credentialManager = false;

  if (platform === "darwin") {
    // Check if security command is available
    try {
      execSync("which security", { encoding: "utf8", timeout: 2000, stdio: "pipe" });
      keychain = true;
    } catch {
      keychain = false;
    }
  }

  if (platform === "linux") {
    // Check if secret-tool is available (libsecret)
    try {
      execSync("which secret-tool", { encoding: "utf8", timeout: 2000, stdio: "pipe" });
      secretService = true;
    } catch {
      secretService = false;
    }
  }

  if (platform === "win32") {
    // Windows Credential Manager is always available via PowerShell
    credentialManager = true;
  }

  return { keychain, secretService, credentialManager };
}

/**
 * Derives an encryption key from a password using PBKDF2.
 */
function deriveKey(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256");
}

/**
 * Gets a machine-specific identifier for encryption key derivation.
 * Uses hardware IDs that are stable across reboots but unique per machine.
 */
function getMachineId(): string {
  const platform = process.platform;
  let machineId = "";

  try {
    if (platform === "darwin") {
      // Use macOS hardware UUID
      const output = execSync("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID", {
        encoding: "utf8",
        timeout: 5000,
        stdio: "pipe",
      });
      const match = output.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
      machineId = match?.[1] ?? "";
    } else if (platform === "linux") {
      // Use machine-id
      if (fs.existsSync("/etc/machine-id")) {
        machineId = fs.readFileSync("/etc/machine-id", "utf8").trim();
      } else if (fs.existsSync("/var/lib/dbus/machine-id")) {
        machineId = fs.readFileSync("/var/lib/dbus/machine-id", "utf8").trim();
      }
    } else if (platform === "win32") {
      // Use MachineGuid from registry
      const output = execSync(
        'reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
        { encoding: "utf8", timeout: 5000, stdio: "pipe" },
      );
      const match = output.match(/MachineGuid\s+REG_SZ\s+(\S+)/);
      machineId = match?.[1] ?? "";
    }
  } catch (err) {
    log.warn("Failed to get machine ID", { error: String(err) });
  }

  // Fallback to hostname + username if no machine ID available
  if (!machineId) {
    machineId = `${os.hostname()}-${os.userInfo().username}`;
  }

  return machineId;
}

/**
 * Encrypts data using AES-256-GCM with a machine-derived key.
 */
export function encryptData(data: string, password?: string): Buffer {
  const key = password ?? getMachineId();
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const derivedKey = deriveKey(key, salt);

  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Format: salt (32) + iv (16) + authTag (16) + encrypted
  return Buffer.concat([salt, iv, authTag, encrypted]);
}

/**
 * Decrypts data encrypted with encryptData.
 */
export function decryptData(encryptedBuffer: Buffer, password?: string): string {
  const key = password ?? getMachineId();

  // Minimum size is salt + iv + authTag (empty ciphertext is valid for empty string)
  if (encryptedBuffer.length < SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error("Invalid encrypted data: too short");
  }

  const salt = encryptedBuffer.subarray(0, SALT_LENGTH);
  const iv = encryptedBuffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = encryptedBuffer.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH,
  );
  const encrypted = encryptedBuffer.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

  const derivedKey = deriveKey(key, salt);
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, derivedKey, iv);
  decipher.setAuthTag(authTag);

  return decipher.update(encrypted) + decipher.final("utf8");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MACOS KEYCHAIN OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Stores a secret in macOS Keychain.
 */
function storeInKeychain(service: string, account: string, secret: string): boolean {
  try {
    // First try to update existing entry
    try {
      execSync(
        `security add-generic-password -U -s "${service}" -a "${account}" -w '${secret.replace(/'/g, "'\"'\"'")}'`,
        { encoding: "utf8", timeout: 5000, stdio: "pipe" },
      );
      return true;
    } catch {
      // Entry doesn't exist, create new
      execSync(
        `security add-generic-password -s "${service}" -a "${account}" -w '${secret.replace(/'/g, "'\"'\"'")}'`,
        { encoding: "utf8", timeout: 5000, stdio: "pipe" },
      );
      return true;
    }
  } catch (err) {
    log.error("Failed to store in keychain", { service, error: String(err) });
    return false;
  }
}

/**
 * Retrieves a secret from macOS Keychain.
 */
function readFromKeychain(service: string, account: string): string | null {
  try {
    const result = execSync(`security find-generic-password -s "${service}" -a "${account}" -w`, {
      encoding: "utf8",
      timeout: 5000,
      stdio: "pipe",
    });
    return result.trim();
  } catch {
    return null;
  }
}

/**
 * Deletes a secret from macOS Keychain.
 */
function deleteFromKeychain(service: string, account: string): boolean {
  try {
    execSync(`security delete-generic-password -s "${service}" -a "${account}"`, {
      encoding: "utf8",
      timeout: 5000,
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LINUX SECRET SERVICE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Stores a secret using Linux Secret Service (libsecret).
 */
function storeInSecretService(service: string, account: string, secret: string): boolean {
  try {
    execSync(
      `echo -n '${secret.replace(/'/g, "'\\''")}' | secret-tool store --label="${service}" service "${service}" account "${account}"`,
      { encoding: "utf8", timeout: 5000, stdio: "pipe", shell: "/bin/bash" },
    );
    return true;
  } catch (err) {
    log.error("Failed to store in Secret Service", { service, error: String(err) });
    return false;
  }
}

/**
 * Retrieves a secret from Linux Secret Service.
 */
function readFromSecretService(service: string, account: string): string | null {
  try {
    const result = execSync(`secret-tool lookup service "${service}" account "${account}"`, {
      encoding: "utf8",
      timeout: 5000,
      stdio: "pipe",
    });
    return result.trim() || null;
  } catch {
    return null;
  }
}

/**
 * Deletes a secret from Linux Secret Service.
 */
function deleteFromSecretService(service: string, account: string): boolean {
  try {
    execSync(`secret-tool clear service "${service}" account "${account}"`, {
      encoding: "utf8",
      timeout: 5000,
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENCRYPTED FILE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Gets the default path for encrypted secrets file.
 */
export function getDefaultEncryptedSecretsPath(): string {
  return path.join(os.homedir(), ".clawdbot", "secrets.enc");
}

/**
 * Reads all secrets from encrypted file.
 */
function readEncryptedSecretsFile(filePath: string): Record<string, string> {
  if (!fs.existsSync(filePath)) {
    return {};
  }

  try {
    const encrypted = fs.readFileSync(filePath);
    const decrypted = decryptData(encrypted);
    return JSON.parse(decrypted);
  } catch (err) {
    log.error("Failed to read encrypted secrets file", { error: String(err) });
    return {};
  }
}

/**
 * Writes all secrets to encrypted file.
 */
function writeEncryptedSecretsFile(filePath: string, secrets: Record<string, string>): boolean {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    const encrypted = encryptData(JSON.stringify(secrets));
    fs.writeFileSync(filePath, encrypted, { mode: 0o600 });
    return true;
  } catch (err) {
    log.error("Failed to write encrypted secrets file", { error: String(err) });
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Stores a secret securely using the best available backend.
 */
export function storeSecret(
  key: string,
  value: string,
  config: Partial<SecretsConfig> = {},
): SecretsResult<void> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const platform = process.platform;
  const service = `${KEYCHAIN_SERVICE_PREFIX}-${key}`;
  const account = "default";

  if (cfg.preferKeychain) {
    // Try platform-specific keychain first
    if (platform === "darwin") {
      if (storeInKeychain(service, account, value)) {
        log.info("Stored secret in macOS Keychain", { key });
        return { success: true, storage: "keychain" };
      }
    } else if (platform === "linux") {
      const backends = detectAvailableBackends();
      if (backends.secretService && storeInSecretService(service, account, value)) {
        log.info("Stored secret in Secret Service", { key });
        return { success: true, storage: "keychain" };
      }
    }
  }

  // Fall back to encrypted file
  if (cfg.enableEncryptedFallback) {
    const filePath = cfg.encryptedFilePath ?? getDefaultEncryptedSecretsPath();
    const secrets = readEncryptedSecretsFile(filePath);
    secrets[key] = value;
    if (writeEncryptedSecretsFile(filePath, secrets)) {
      log.info("Stored secret in encrypted file", { key });
      return { success: true, storage: "encrypted-file" };
    }
  }

  return { success: false, error: "No storage backend available", storage: "none" };
}

/**
 * Retrieves a secret from secure storage.
 */
export function getSecret(key: string, config: Partial<SecretsConfig> = {}): SecretsResult<string> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const platform = process.platform;
  const service = `${KEYCHAIN_SERVICE_PREFIX}-${key}`;
  const account = "default";

  if (cfg.preferKeychain) {
    // Try platform-specific keychain first
    if (platform === "darwin") {
      const value = readFromKeychain(service, account);
      if (value !== null) {
        return { success: true, value, storage: "keychain" };
      }
    } else if (platform === "linux") {
      const backends = detectAvailableBackends();
      if (backends.secretService) {
        const value = readFromSecretService(service, account);
        if (value !== null) {
          return { success: true, value, storage: "keychain" };
        }
      }
    }
  }

  // Fall back to encrypted file
  if (cfg.enableEncryptedFallback) {
    const filePath = cfg.encryptedFilePath ?? getDefaultEncryptedSecretsPath();
    const secrets = readEncryptedSecretsFile(filePath);
    if (key in secrets) {
      return { success: true, value: secrets[key], storage: "encrypted-file" };
    }
  }

  return { success: false, error: "Secret not found", storage: "none" };
}

/**
 * Deletes a secret from secure storage.
 */
export function deleteSecret(
  key: string,
  config: Partial<SecretsConfig> = {},
): SecretsResult<void> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const platform = process.platform;
  const service = `${KEYCHAIN_SERVICE_PREFIX}-${key}`;
  const account = "default";

  let deleted = false;

  // Try to delete from keychain
  if (platform === "darwin") {
    deleted = deleteFromKeychain(service, account) || deleted;
  } else if (platform === "linux") {
    const backends = detectAvailableBackends();
    if (backends.secretService) {
      deleted = deleteFromSecretService(service, account) || deleted;
    }
  }

  // Also delete from encrypted file
  if (cfg.enableEncryptedFallback) {
    const filePath = cfg.encryptedFilePath ?? getDefaultEncryptedSecretsPath();
    const secrets = readEncryptedSecretsFile(filePath);
    if (key in secrets) {
      delete secrets[key];
      if (writeEncryptedSecretsFile(filePath, secrets)) {
        deleted = true;
      }
    }
  }

  if (deleted) {
    log.info("Deleted secret", { key });
    return { success: true, storage: "keychain" };
  }

  return { success: false, error: "Secret not found or could not be deleted", storage: "none" };
}

/**
 * Lists all stored secret keys (not values).
 */
export function listSecretKeys(config: Partial<SecretsConfig> = {}): string[] {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const keys: Set<string> = new Set();

  // Note: Listing keychain entries programmatically is complex and varies by platform.
  // For now, we only list keys from the encrypted file.

  if (cfg.enableEncryptedFallback) {
    const filePath = cfg.encryptedFilePath ?? getDefaultEncryptedSecretsPath();
    const secrets = readEncryptedSecretsFile(filePath);
    for (const key of Object.keys(secrets)) {
      keys.add(key);
    }
  }

  return Array.from(keys);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MIGRATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Migrates a plain-text config value to secure storage.
 */
export function migrateToSecureStorage(
  key: string,
  plainValue: string,
  config: Partial<SecretsConfig> = {},
): SecretsResult<void> {
  const result = storeSecret(key, plainValue, config);
  if (result.success) {
    log.info("Migrated secret to secure storage", { key, storage: result.storage });
  }
  return result;
}

/**
 * Checks if a secret exists in any storage backend.
 */
export function hasSecret(key: string, config: Partial<SecretsConfig> = {}): boolean {
  const result = getSecret(key, config);
  return result.success;
}

/**
 * Generates a cryptographically secure random token.
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString("base64url");
}

/**
 * Hashes a secret for comparison without storing the original.
 */
export function hashSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

/**
 * Verifies a secret against a stored hash.
 */
export function verifySecretHash(secret: string, hash: string): boolean {
  const computed = hashSecret(secret);
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(hash));
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE ENCRYPTION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encrypts a file in place, creating a .enc version.
 * The original file can be optionally removed for security.
 *
 * @returns Path to the encrypted file, or null on failure
 */
export function encryptFile(
  filePath: string,
  opts: { removeOriginal?: boolean; password?: string } = {},
): string | null {
  try {
    if (!fs.existsSync(filePath)) {
      log.warn("Cannot encrypt non-existent file", { filePath });
      return null;
    }

    const content = fs.readFileSync(filePath, "utf8");
    const encrypted = encryptData(content, opts.password);
    const encryptedPath = `${filePath}.enc`;

    fs.writeFileSync(encryptedPath, encrypted, { mode: 0o600 });

    if (opts.removeOriginal) {
      fs.unlinkSync(filePath);
    }

    log.info("Encrypted file", { filePath, encryptedPath });
    return encryptedPath;
  } catch (err) {
    log.error("Failed to encrypt file", { filePath, error: String(err) });
    return null;
  }
}

/**
 * Decrypts a .enc file back to its original form.
 * The encrypted file can be optionally removed after decryption.
 *
 * @returns The decrypted content, or null on failure
 */
export function decryptFile(
  encryptedPath: string,
  opts: { removeEncrypted?: boolean; password?: string } = {},
): string | null {
  try {
    if (!fs.existsSync(encryptedPath)) {
      log.warn("Cannot decrypt non-existent file", { encryptedPath });
      return null;
    }

    const encrypted = fs.readFileSync(encryptedPath);
    const content = decryptData(encrypted, opts.password);

    if (opts.removeEncrypted) {
      fs.unlinkSync(encryptedPath);
    }

    return content;
  } catch (err) {
    log.error("Failed to decrypt file", { encryptedPath, error: String(err) });
    return null;
  }
}

/**
 * Reads a file that may be encrypted or plaintext.
 * If the .enc version exists, decrypts it. Otherwise reads the plaintext version.
 *
 * @returns Object with content and whether it was encrypted
 */
export function readPossiblyEncryptedFile(
  basePath: string,
  opts: { password?: string } = {},
): { content: string | null; encrypted: boolean } {
  const encryptedPath = `${basePath}.enc`;

  // Prefer encrypted version if it exists
  if (fs.existsSync(encryptedPath)) {
    const content = decryptFile(encryptedPath, opts);
    return { content, encrypted: true };
  }

  // Fall back to plaintext
  if (fs.existsSync(basePath)) {
    try {
      const content = fs.readFileSync(basePath, "utf8");
      return { content, encrypted: false };
    } catch (err) {
      log.error("Failed to read plaintext file", { basePath, error: String(err) });
      return { content: null, encrypted: false };
    }
  }

  return { content: null, encrypted: false };
}

/**
 * Writes a file encrypted. If a plaintext version exists, can migrate it.
 *
 * @returns Path to the encrypted file, or null on failure
 */
export function writePossiblyEncryptedFile(
  basePath: string,
  content: string,
  opts: { encrypt?: boolean; password?: string; removePlaintext?: boolean } = {},
): string | null {
  try {
    if (opts.encrypt !== false) {
      // Write encrypted version
      const encryptedPath = `${basePath}.enc`;
      const encrypted = encryptData(content, opts.password);
      const dir = path.dirname(encryptedPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
      fs.writeFileSync(encryptedPath, encrypted, { mode: 0o600 });

      // Optionally remove plaintext version
      if (opts.removePlaintext && fs.existsSync(basePath)) {
        fs.unlinkSync(basePath);
      }

      return encryptedPath;
    } else {
      // Write plaintext (for compatibility)
      const dir = path.dirname(basePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
      fs.writeFileSync(basePath, content, { mode: 0o600 });
      return basePath;
    }
  } catch (err) {
    log.error("Failed to write file", { basePath, error: String(err) });
    return null;
  }
}

/**
 * Migrates an existing plaintext file to encrypted storage.
 *
 * @returns Path to the encrypted file, or null if migration failed or wasn't needed
 */
export function migrateFileToEncrypted(
  filePath: string,
  opts: { removeOriginal?: boolean; password?: string } = {},
): string | null {
  const encryptedPath = `${filePath}.enc`;

  // Already encrypted
  if (fs.existsSync(encryptedPath)) {
    log.info("File already encrypted", { filePath });
    return encryptedPath;
  }

  // No plaintext to migrate
  if (!fs.existsSync(filePath)) {
    return null;
  }

  return encryptFile(filePath, opts);
}
