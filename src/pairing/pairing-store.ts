import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import lockfile from "proper-lockfile";
import { getPairingAdapter } from "../channels/plugins/pairing.js";
import type { ChannelId, ChannelPairingAdapter } from "../channels/plugins/types.js";
import { resolveOAuthDir, resolveStateDir } from "../config/paths.js";

// SECURITY: 16 chars × 5 bits/char = 80 bits entropy (increased from 40 bits)
const PAIRING_CODE_LENGTH = 16;
const PAIRING_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PAIRING_PENDING_TTL_MS = 60 * 60 * 1000;
const PAIRING_PENDING_MAX = 3;
// Rate limiting: max attempts per minute per channel
const PAIRING_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const PAIRING_RATE_LIMIT_MAX_ATTEMPTS = 10;
const PAIRING_STORE_LOCK_OPTIONS = {
  retries: {
    retries: 10,
    factor: 2,
    minTimeout: 100,
    maxTimeout: 10_000,
    randomize: true,
  },
  stale: 30_000,
} as const;

export type PairingChannel = ChannelId;

export type PairingRequest = {
  id: string;
  code: string;
  createdAt: string;
  lastSeenAt: string;
  meta?: Record<string, string>;
};

type PairingStore = {
  version: 1;
  requests: PairingRequest[];
  /** HMAC signature for integrity verification (computed over requests) */
  signature?: string;
};

/** Rate limit tracking for pairing attempts */
type PairingRateLimitEntry = {
  attempts: number;
  windowStartMs: number;
};

/** In-memory rate limit tracker (per channel) */
const rateLimitTracker = new Map<string, PairingRateLimitEntry>();

/**
 * Compute HMAC-SHA256 signature for pairing store integrity.
 * Uses a machine-derived key for signing.
 */
function computePairingStoreSignature(requests: PairingRequest[]): string {
  // Derive a machine-specific key from hostname + platform
  const machineKey = crypto
    .createHash("sha256")
    .update(`clawdbot-pairing-${os.hostname()}-${os.platform()}`)
    .digest();

  const content = JSON.stringify(
    requests.map((r) => ({ id: r.id, code: r.code, createdAt: r.createdAt })),
  );

  return crypto.createHmac("sha256", machineKey).update(content).digest("hex");
}

/**
 * Verify HMAC signature of pairing store.
 * Returns true if signature is valid or missing (for backwards compatibility).
 */
function verifyPairingStoreSignature(store: PairingStore): boolean {
  if (!store.signature) return true; // Backwards compatibility: unsigned stores are accepted
  const expected = computePairingStoreSignature(store.requests);
  return crypto.timingSafeEqual(Buffer.from(store.signature, "hex"), Buffer.from(expected, "hex"));
}

/**
 * Check if a pairing attempt is rate limited.
 * Returns true if the attempt should be blocked.
 */
function isPairingRateLimited(channelKey: string): boolean {
  const now = Date.now();
  const entry = rateLimitTracker.get(channelKey);

  if (!entry) {
    return false;
  }

  // Check if window has expired
  if (now - entry.windowStartMs > PAIRING_RATE_LIMIT_WINDOW_MS) {
    rateLimitTracker.delete(channelKey);
    return false;
  }

  return entry.attempts >= PAIRING_RATE_LIMIT_MAX_ATTEMPTS;
}

/**
 * Record a pairing attempt for rate limiting.
 */
function recordPairingAttempt(channelKey: string): void {
  const now = Date.now();
  const entry = rateLimitTracker.get(channelKey);

  if (!entry || now - entry.windowStartMs > PAIRING_RATE_LIMIT_WINDOW_MS) {
    rateLimitTracker.set(channelKey, { attempts: 1, windowStartMs: now });
    return;
  }

  entry.attempts += 1;
}

/**
 * Write pairing store with HMAC signature for integrity.
 */
async function writeSignedPairingStore(
  filePath: string,
  requests: PairingRequest[],
): Promise<void> {
  const signature = computePairingStoreSignature(requests);
  await writeJsonFile(filePath, {
    version: 1,
    requests,
    signature,
  } satisfies PairingStore);
}

type AllowFromStore = {
  version: 1;
  allowFrom: string[];
};

function resolveCredentialsDir(env: NodeJS.ProcessEnv = process.env): string {
  const stateDir = resolveStateDir(env, os.homedir);
  return resolveOAuthDir(env, stateDir);
}

/** Sanitize channel ID for use in filenames (prevent path traversal). */
function safeChannelKey(channel: PairingChannel): string {
  const raw = String(channel).trim().toLowerCase();
  if (!raw) throw new Error("invalid pairing channel");
  const safe = raw.replace(/[\\/:*?"<>|]/g, "_").replace(/\.\./g, "_");
  if (!safe || safe === "_") throw new Error("invalid pairing channel");
  return safe;
}

function resolvePairingPath(channel: PairingChannel, env: NodeJS.ProcessEnv = process.env): string {
  return path.join(resolveCredentialsDir(env), `${safeChannelKey(channel)}-pairing.json`);
}

function resolveAllowFromPath(
  channel: PairingChannel,
  env: NodeJS.ProcessEnv = process.env,
): string {
  return path.join(resolveCredentialsDir(env), `${safeChannelKey(channel)}-allowFrom.json`);
}

function safeParseJson<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

async function readJsonFile<T>(
  filePath: string,
  fallback: T,
): Promise<{ value: T; exists: boolean }> {
  try {
    const raw = await fs.promises.readFile(filePath, "utf-8");
    const parsed = safeParseJson<T>(raw);
    if (parsed == null) return { value: fallback, exists: true };
    return { value: parsed, exists: true };
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ENOENT") return { value: fallback, exists: false };
    return { value: fallback, exists: false };
  }
}

async function writeJsonFile(filePath: string, value: unknown): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `${path.basename(filePath)}.${crypto.randomUUID()}.tmp`);
  await fs.promises.writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf-8",
  });
  await fs.promises.chmod(tmp, 0o600);
  await fs.promises.rename(tmp, filePath);
}

async function ensureJsonFile(filePath: string, fallback: unknown) {
  try {
    await fs.promises.access(filePath);
  } catch {
    await writeJsonFile(filePath, fallback);
  }
}

async function withFileLock<T>(
  filePath: string,
  fallback: unknown,
  fn: () => Promise<T>,
): Promise<T> {
  await ensureJsonFile(filePath, fallback);
  let release: (() => Promise<void>) | undefined;
  try {
    release = await lockfile.lock(filePath, PAIRING_STORE_LOCK_OPTIONS);
    return await fn();
  } finally {
    if (release) {
      try {
        await release();
      } catch {
        // ignore unlock errors
      }
    }
  }
}

function parseTimestamp(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  return parsed;
}

function isExpired(entry: PairingRequest, nowMs: number): boolean {
  const createdAt = parseTimestamp(entry.createdAt);
  if (!createdAt) return true;
  return nowMs - createdAt > PAIRING_PENDING_TTL_MS;
}

function pruneExpiredRequests(reqs: PairingRequest[], nowMs: number) {
  const kept: PairingRequest[] = [];
  let removed = false;
  for (const req of reqs) {
    if (isExpired(req, nowMs)) {
      removed = true;
      continue;
    }
    kept.push(req);
  }
  return { requests: kept, removed };
}

function resolveLastSeenAt(entry: PairingRequest): number {
  return parseTimestamp(entry.lastSeenAt) ?? parseTimestamp(entry.createdAt) ?? 0;
}

function pruneExcessRequests(reqs: PairingRequest[], maxPending: number) {
  if (maxPending <= 0 || reqs.length <= maxPending) {
    return { requests: reqs, removed: false };
  }
  const sorted = reqs.slice().sort((a, b) => resolveLastSeenAt(a) - resolveLastSeenAt(b));
  return { requests: sorted.slice(-maxPending), removed: true };
}

function randomCode(): string {
  // Human-friendly: 8 chars, upper, no ambiguous chars (0O1I).
  let out = "";
  for (let i = 0; i < PAIRING_CODE_LENGTH; i++) {
    const idx = crypto.randomInt(0, PAIRING_CODE_ALPHABET.length);
    out += PAIRING_CODE_ALPHABET[idx];
  }
  return out;
}

function generateUniqueCode(existing: Set<string>): string {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const code = randomCode();
    if (!existing.has(code)) return code;
  }
  throw new Error("failed to generate unique pairing code");
}

function normalizeId(value: string | number): string {
  return String(value).trim();
}

function normalizeAllowEntry(channel: PairingChannel, entry: string): string {
  const trimmed = entry.trim();
  if (!trimmed) return "";
  if (trimmed === "*") return "";
  const adapter = getPairingAdapter(channel);
  const normalized = adapter?.normalizeAllowEntry ? adapter.normalizeAllowEntry(trimmed) : trimmed;
  return String(normalized).trim();
}

export async function readChannelAllowFromStore(
  channel: PairingChannel,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string[]> {
  const filePath = resolveAllowFromPath(channel, env);
  const { value } = await readJsonFile<AllowFromStore>(filePath, {
    version: 1,
    allowFrom: [],
  });
  const list = Array.isArray(value.allowFrom) ? value.allowFrom : [];
  return list.map((v) => normalizeAllowEntry(channel, String(v))).filter(Boolean);
}

export async function addChannelAllowFromStoreEntry(params: {
  channel: PairingChannel;
  entry: string | number;
  env?: NodeJS.ProcessEnv;
}): Promise<{ changed: boolean; allowFrom: string[] }> {
  const env = params.env ?? process.env;
  const filePath = resolveAllowFromPath(params.channel, env);
  return await withFileLock(
    filePath,
    { version: 1, allowFrom: [] } satisfies AllowFromStore,
    async () => {
      const { value } = await readJsonFile<AllowFromStore>(filePath, {
        version: 1,
        allowFrom: [],
      });
      const current = (Array.isArray(value.allowFrom) ? value.allowFrom : [])
        .map((v) => normalizeAllowEntry(params.channel, String(v)))
        .filter(Boolean);
      const normalized = normalizeAllowEntry(params.channel, normalizeId(params.entry));
      if (!normalized) return { changed: false, allowFrom: current };
      if (current.includes(normalized)) return { changed: false, allowFrom: current };
      const next = [...current, normalized];
      await writeJsonFile(filePath, {
        version: 1,
        allowFrom: next,
      } satisfies AllowFromStore);
      return { changed: true, allowFrom: next };
    },
  );
}

export async function removeChannelAllowFromStoreEntry(params: {
  channel: PairingChannel;
  entry: string | number;
  env?: NodeJS.ProcessEnv;
}): Promise<{ changed: boolean; allowFrom: string[] }> {
  const env = params.env ?? process.env;
  const filePath = resolveAllowFromPath(params.channel, env);
  return await withFileLock(
    filePath,
    { version: 1, allowFrom: [] } satisfies AllowFromStore,
    async () => {
      const { value } = await readJsonFile<AllowFromStore>(filePath, {
        version: 1,
        allowFrom: [],
      });
      const current = (Array.isArray(value.allowFrom) ? value.allowFrom : [])
        .map((v) => normalizeAllowEntry(params.channel, String(v)))
        .filter(Boolean);
      const normalized = normalizeAllowEntry(params.channel, normalizeId(params.entry));
      if (!normalized) return { changed: false, allowFrom: current };
      const next = current.filter((entry) => entry !== normalized);
      if (next.length === current.length) return { changed: false, allowFrom: current };
      await writeJsonFile(filePath, {
        version: 1,
        allowFrom: next,
      } satisfies AllowFromStore);
      return { changed: true, allowFrom: next };
    },
  );
}

export async function listChannelPairingRequests(
  channel: PairingChannel,
  env: NodeJS.ProcessEnv = process.env,
): Promise<PairingRequest[]> {
  const filePath = resolvePairingPath(channel, env);
  return await withFileLock(
    filePath,
    { version: 1, requests: [] } satisfies PairingStore,
    async () => {
      const { value } = await readJsonFile<PairingStore>(filePath, {
        version: 1,
        requests: [],
      });

      // SECURITY: Verify store signature to detect tampering
      if (!verifyPairingStoreSignature(value)) {
        // Signature mismatch - clear the store
        await writeSignedPairingStore(filePath, []);
        return [];
      }

      const reqs = Array.isArray(value.requests) ? value.requests : [];
      const nowMs = Date.now();
      const { requests: prunedExpired, removed: expiredRemoved } = pruneExpiredRequests(
        reqs,
        nowMs,
      );
      const { requests: pruned, removed: cappedRemoved } = pruneExcessRequests(
        prunedExpired,
        PAIRING_PENDING_MAX,
      );
      if (expiredRemoved || cappedRemoved) {
        await writeSignedPairingStore(filePath, pruned);
      }
      return pruned
        .filter(
          (r) =>
            r &&
            typeof r.id === "string" &&
            typeof r.code === "string" &&
            typeof r.createdAt === "string",
        )
        .slice()
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    },
  );
}

export async function upsertChannelPairingRequest(params: {
  channel: PairingChannel;
  id: string | number;
  meta?: Record<string, string | undefined | null>;
  env?: NodeJS.ProcessEnv;
  /** Extension channels can pass their adapter directly to bypass registry lookup. */
  pairingAdapter?: ChannelPairingAdapter;
}): Promise<{ code: string; created: boolean }> {
  const env = params.env ?? process.env;
  const filePath = resolvePairingPath(params.channel, env);
  return await withFileLock(
    filePath,
    { version: 1, requests: [] } satisfies PairingStore,
    async () => {
      let { value } = await readJsonFile<PairingStore>(filePath, {
        version: 1,
        requests: [],
      });

      // SECURITY: Verify store signature to detect tampering
      if (!verifyPairingStoreSignature(value)) {
        // Signature mismatch - reset to empty store
        await writeSignedPairingStore(filePath, []);
        value = { version: 1, requests: [] };
      }

      const now = new Date().toISOString();
      const nowMs = Date.now();
      const id = normalizeId(params.id);
      const meta =
        params.meta && typeof params.meta === "object"
          ? Object.fromEntries(
              Object.entries(params.meta)
                .map(([k, v]) => [k, String(v ?? "").trim()] as const)
                .filter(([_, v]) => Boolean(v)),
            )
          : undefined;

      let reqs = Array.isArray(value.requests) ? value.requests : [];
      const { requests: prunedExpired, removed: expiredRemoved } = pruneExpiredRequests(
        reqs,
        nowMs,
      );
      reqs = prunedExpired;
      const existingIdx = reqs.findIndex((r) => r.id === id);
      const existingCodes = new Set(
        reqs.map((req) =>
          String(req.code ?? "")
            .trim()
            .toUpperCase(),
        ),
      );

      if (existingIdx >= 0) {
        const existing = reqs[existingIdx];
        const existingCode =
          existing && typeof existing.code === "string" ? existing.code.trim() : "";
        const code = existingCode || generateUniqueCode(existingCodes);
        const next: PairingRequest = {
          id,
          code,
          createdAt: existing?.createdAt ?? now,
          lastSeenAt: now,
          meta: meta ?? existing?.meta,
        };
        reqs[existingIdx] = next;
        const { requests: capped } = pruneExcessRequests(reqs, PAIRING_PENDING_MAX);
        await writeSignedPairingStore(filePath, capped);
        return { code, created: false };
      }

      const { requests: capped, removed: cappedRemoved } = pruneExcessRequests(
        reqs,
        PAIRING_PENDING_MAX,
      );
      reqs = capped;
      if (PAIRING_PENDING_MAX > 0 && reqs.length >= PAIRING_PENDING_MAX) {
        if (expiredRemoved || cappedRemoved) {
          await writeSignedPairingStore(filePath, reqs);
        }
        return { code: "", created: false };
      }
      const code = generateUniqueCode(existingCodes);
      const next: PairingRequest = {
        id,
        code,
        createdAt: now,
        lastSeenAt: now,
        ...(meta ? { meta } : {}),
      };
      await writeSignedPairingStore(filePath, [...reqs, next]);
      return { code, created: true };
    },
  );
}

export type ApproveChannelPairingCodeResult =
  | { id: string; entry?: PairingRequest }
  | { rateLimited: true }
  | null;

export async function approveChannelPairingCode(params: {
  channel: PairingChannel;
  code: string;
  env?: NodeJS.ProcessEnv;
}): Promise<ApproveChannelPairingCodeResult> {
  const env = params.env ?? process.env;
  const code = params.code.trim().toUpperCase();
  if (!code) return null;

  // SECURITY: Rate limit pairing attempts to prevent brute-force attacks
  const channelKey = safeChannelKey(params.channel);
  if (isPairingRateLimited(channelKey)) {
    return { rateLimited: true };
  }
  recordPairingAttempt(channelKey);

  const filePath = resolvePairingPath(params.channel, env);
  return await withFileLock(
    filePath,
    { version: 1, requests: [] } satisfies PairingStore,
    async () => {
      const { value } = await readJsonFile<PairingStore>(filePath, {
        version: 1,
        requests: [],
      });

      // SECURITY: Verify store signature to detect tampering
      if (!verifyPairingStoreSignature(value)) {
        // Signature mismatch - store may have been tampered with
        // Clear the store and return null (force re-pairing)
        await writeSignedPairingStore(filePath, []);
        return null;
      }

      const reqs = Array.isArray(value.requests) ? value.requests : [];
      const nowMs = Date.now();
      const { requests: pruned, removed } = pruneExpiredRequests(reqs, nowMs);
      const idx = pruned.findIndex((r) => String(r.code ?? "").toUpperCase() === code);
      if (idx < 0) {
        if (removed) {
          await writeSignedPairingStore(filePath, pruned);
        }
        return null;
      }
      const entry = pruned[idx];
      if (!entry) return null;
      pruned.splice(idx, 1);
      await writeSignedPairingStore(filePath, pruned);
      await addChannelAllowFromStoreEntry({
        channel: params.channel,
        entry: entry.id,
        env,
      });
      return { id: entry.id, entry };
    },
  );
}
