import { afterEach, describe, expect, it, vi } from "vitest";

import type { ClawdbotConfig } from "../config/config.js";
import { resolveDiscordToken } from "./token.js";

describe("resolveDiscordToken", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("prefers config token over env", () => {
    vi.stubEnv("DISCORD_BOT_TOKEN", "env-token");
    const cfg = {
      channels: { discord: { token: "cfg-token" } },
    } as ClawdbotConfig;
    // Skip secrets to test config/env precedence in isolation
    const res = resolveDiscordToken(cfg, { skipSecrets: true });
    expect(res.token).toBe("cfg-token");
    expect(res.source).toBe("config");
  });

  it("uses env token when config is missing", () => {
    vi.stubEnv("DISCORD_BOT_TOKEN", "env-token");
    const cfg = {
      channels: { discord: {} },
    } as ClawdbotConfig;
    // Skip secrets to test config/env precedence in isolation
    const res = resolveDiscordToken(cfg, { skipSecrets: true });
    expect(res.token).toBe("env-token");
    expect(res.source).toBe("env");
  });

  it("prefers account token for non-default accounts", () => {
    vi.stubEnv("DISCORD_BOT_TOKEN", "env-token");
    const cfg = {
      channels: {
        discord: {
          token: "base-token",
          accounts: {
            work: { token: "acct-token" },
          },
        },
      },
    } as ClawdbotConfig;
    // Skip secrets to test config/env precedence in isolation
    const res = resolveDiscordToken(cfg, { accountId: "work", skipSecrets: true });
    expect(res.token).toBe("acct-token");
    expect(res.source).toBe("config");
  });

  it("returns source=none when no token is available", () => {
    const cfg = {
      channels: { discord: {} },
    } as ClawdbotConfig;
    const res = resolveDiscordToken(cfg, { skipSecrets: true });
    expect(res.token).toBe("");
    expect(res.source).toBe("none");
  });
});
