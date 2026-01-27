import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { resolveOAuthDir } from "../config/paths.js";
import {
  approveChannelPairingCode,
  listChannelPairingRequests,
  upsertChannelPairingRequest,
} from "./pairing-store.js";

async function withTempStateDir<T>(fn: (stateDir: string) => Promise<T>) {
  const previous = process.env.CLAWDBOT_STATE_DIR;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdbot-pairing-"));
  process.env.CLAWDBOT_STATE_DIR = dir;
  try {
    return await fn(dir);
  } finally {
    if (previous === undefined) delete process.env.CLAWDBOT_STATE_DIR;
    else process.env.CLAWDBOT_STATE_DIR = previous;
    await fs.rm(dir, { recursive: true, force: true });
  }
}

describe("pairing store", () => {
  it("reuses pending code and reports created=false", async () => {
    await withTempStateDir(async () => {
      const first = await upsertChannelPairingRequest({
        channel: "discord",
        id: "u1",
      });
      const second = await upsertChannelPairingRequest({
        channel: "discord",
        id: "u1",
      });
      expect(first.created).toBe(true);
      expect(second.created).toBe(false);
      expect(second.code).toBe(first.code);

      const list = await listChannelPairingRequests("discord");
      expect(list).toHaveLength(1);
      expect(list[0]?.code).toBe(first.code);
    });
  });

  it("expires pending requests after TTL", async () => {
    await withTempStateDir(async (stateDir) => {
      const created = await upsertChannelPairingRequest({
        channel: "signal",
        id: "+15550001111",
      });
      expect(created.created).toBe(true);

      const oauthDir = resolveOAuthDir(process.env, stateDir);
      const filePath = path.join(oauthDir, "signal-pairing.json");
      const raw = await fs.readFile(filePath, "utf8");
      const parsed = JSON.parse(raw) as {
        requests?: Array<Record<string, unknown>>;
      };
      const expiredAt = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
      const requests = (parsed.requests ?? []).map((entry) => ({
        ...entry,
        createdAt: expiredAt,
        lastSeenAt: expiredAt,
      }));
      await fs.writeFile(
        filePath,
        `${JSON.stringify({ version: 1, requests }, null, 2)}\n`,
        "utf8",
      );

      const list = await listChannelPairingRequests("signal");
      expect(list).toHaveLength(0);

      const next = await upsertChannelPairingRequest({
        channel: "signal",
        id: "+15550001111",
      });
      expect(next.created).toBe(true);
    });
  });

  it("regenerates when a generated code collides", async () => {
    await withTempStateDir(async () => {
      const spy = vi.spyOn(crypto, "randomInt");
      try {
        spy.mockReturnValue(0);
        const first = await upsertChannelPairingRequest({
          channel: "telegram",
          id: "123",
        });
        // SECURITY: Codes are now 16 chars for 80-bit entropy (up from 8 chars / 40 bits)
        expect(first.code).toBe("AAAAAAAAAAAAAAAA");

        // Generate 16 A's (collides), then 16 B's (unique)
        const sequence = Array(16).fill(0).concat(Array(16).fill(1));
        let idx = 0;
        spy.mockImplementation(() => sequence[idx++] ?? 1);
        const second = await upsertChannelPairingRequest({
          channel: "telegram",
          id: "456",
        });
        expect(second.code).toBe("BBBBBBBBBBBBBBBB");
      } finally {
        spy.mockRestore();
      }
    });
  });

  it("caps pending requests at the default limit", async () => {
    await withTempStateDir(async () => {
      const ids = ["+15550000001", "+15550000002", "+15550000003"];
      for (const id of ids) {
        const created = await upsertChannelPairingRequest({
          channel: "whatsapp",
          id,
        });
        expect(created.created).toBe(true);
      }

      const blocked = await upsertChannelPairingRequest({
        channel: "whatsapp",
        id: "+15550000004",
      });
      expect(blocked.created).toBe(false);

      const list = await listChannelPairingRequests("whatsapp");
      const listIds = list.map((entry) => entry.id);
      expect(listIds).toHaveLength(3);
      expect(listIds).toContain("+15550000001");
      expect(listIds).toContain("+15550000002");
      expect(listIds).toContain("+15550000003");
      expect(listIds).not.toContain("+15550000004");
    });
  });

  it("generates 16-character codes for 80-bit entropy", async () => {
    await withTempStateDir(async () => {
      const result = await upsertChannelPairingRequest({
        channel: "discord",
        id: "security-test-user",
      });
      expect(result.code).toHaveLength(16);
      // Verify all characters are from the allowed alphabet
      const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      for (const char of result.code) {
        expect(alphabet).toContain(char);
      }
    });
  });
});

describe("pairing store security", () => {
  it("approves valid pairing code", async () => {
    await withTempStateDir(async () => {
      const created = await upsertChannelPairingRequest({
        channel: "discord",
        id: "test-user-1",
      });
      expect(created.created).toBe(true);

      const result = await approveChannelPairingCode({
        channel: "discord",
        code: created.code,
      });
      expect(result).not.toBeNull();
      expect(result).not.toHaveProperty("rateLimited");
      expect((result as { id: string }).id).toBe("test-user-1");

      // Code should be consumed - list should be empty
      const list = await listChannelPairingRequests("discord");
      expect(list).toHaveLength(0);
    });
  });

  it("returns null for invalid pairing code", async () => {
    await withTempStateDir(async () => {
      await upsertChannelPairingRequest({
        channel: "discord",
        id: "test-user-1",
      });

      const result = await approveChannelPairingCode({
        channel: "discord",
        code: "INVALIDCODEINVALID",
      });
      expect(result).toBeNull();
    });
  });

  it("detects tampering via signature verification", async () => {
    await withTempStateDir(async (stateDir) => {
      // Create a pairing request
      const created = await upsertChannelPairingRequest({
        channel: "signal",
        id: "+15551234567",
      });
      expect(created.created).toBe(true);

      // Tamper with the store directly
      const oauthDir = resolveOAuthDir(process.env, stateDir);
      const filePath = path.join(oauthDir, "signal-pairing.json");
      const raw = await fs.readFile(filePath, "utf8");
      const parsed = JSON.parse(raw) as {
        version: number;
        requests: Array<{ id: string; code: string }>;
        signature?: string;
      };

      // Modify a request without updating the signature
      if (parsed.requests[0]) {
        parsed.requests[0].code = "TAMPEREDCODETAMP";
      }
      await fs.writeFile(filePath, JSON.stringify(parsed, null, 2), "utf8");

      // Reading should detect tampering and reset the store
      const list = await listChannelPairingRequests("signal");
      expect(list).toHaveLength(0);
    });
  });

  it("rate limits excessive pairing approval attempts", async () => {
    await withTempStateDir(async () => {
      await upsertChannelPairingRequest({
        channel: "telegram",
        id: "rate-limit-test",
      });

      // Make many failed attempts (rate limit is 10 per minute)
      const results: Awaited<ReturnType<typeof approveChannelPairingCode>>[] = [];
      for (let i = 0; i < 12; i++) {
        const result = await approveChannelPairingCode({
          channel: "telegram",
          code: `INVALID${i}CODEXXXX`,
        });
        results.push(result);
      }

      // First 10 should return null (invalid code)
      for (let i = 0; i < 10; i++) {
        expect(results[i]).toBeNull();
      }

      // After 10 attempts, should be rate limited
      expect(results[10]).toEqual({ rateLimited: true });
      expect(results[11]).toEqual({ rateLimited: true });
    });
  });

  it("handles case-insensitive code matching", async () => {
    await withTempStateDir(async () => {
      const created = await upsertChannelPairingRequest({
        channel: "discord",
        id: "case-test-user",
      });

      // Try with lowercase
      const result = await approveChannelPairingCode({
        channel: "discord",
        code: created.code.toLowerCase(),
      });
      expect(result).not.toBeNull();
      expect(result).not.toHaveProperty("rateLimited");
    });
  });

  it("stores are signed on write", async () => {
    await withTempStateDir(async (stateDir) => {
      await upsertChannelPairingRequest({
        channel: "slack",
        id: "signature-test",
      });

      const oauthDir = resolveOAuthDir(process.env, stateDir);
      const filePath = path.join(oauthDir, "slack-pairing.json");
      const raw = await fs.readFile(filePath, "utf8");
      const parsed = JSON.parse(raw) as {
        version: number;
        requests: unknown[];
        signature?: string;
      };

      // Should have a signature
      expect(parsed.signature).toBeDefined();
      expect(typeof parsed.signature).toBe("string");
      expect(parsed.signature).toHaveLength(64); // SHA-256 hex = 64 chars
    });
  });
});
