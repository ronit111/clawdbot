import type { ClawdbotConfig } from "../config/config.js";
import { getSecret } from "../infra/secrets-manager.js";
import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from "../routing/session-key.js";

export type DiscordTokenSource = "env" | "config" | "secrets" | "none";

export type DiscordTokenResolution = {
  token: string;
  source: DiscordTokenSource;
};

export function normalizeDiscordToken(raw?: string | null): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  return trimmed.replace(/^Bot\s+/i, "");
}

/**
 * Resolves the secret key name for a Discord token.
 */
function getDiscordSecretKey(accountId: string): string {
  return `discord-token-${accountId}`;
}

/**
 * Resolves Discord bot token from multiple sources in priority order:
 * 1. Secure secrets storage (keychain/encrypted file)
 * 2. Config file (channels.discord.accounts[accountId].token)
 * 3. Environment variable (DISCORD_BOT_TOKEN) for default account only
 */
export function resolveDiscordToken(
  cfg?: ClawdbotConfig,
  opts: { accountId?: string | null; envToken?: string | null; skipSecrets?: boolean } = {},
): DiscordTokenResolution {
  const accountId = normalizeAccountId(opts.accountId);

  // Priority 1: Check secure secrets storage first (unless explicitly skipped)
  if (!opts.skipSecrets) {
    const secretKey = getDiscordSecretKey(accountId);
    const secretResult = getSecret(secretKey);
    if (secretResult.success && secretResult.value) {
      const secretToken = normalizeDiscordToken(secretResult.value);
      if (secretToken) return { token: secretToken, source: "secrets" };
    }
  }

  // Priority 2: Check config file
  const discordCfg = cfg?.channels?.discord;
  const accountCfg =
    accountId !== DEFAULT_ACCOUNT_ID
      ? discordCfg?.accounts?.[accountId]
      : discordCfg?.accounts?.[DEFAULT_ACCOUNT_ID];
  const accountToken = normalizeDiscordToken(accountCfg?.token ?? undefined);
  if (accountToken) return { token: accountToken, source: "config" };

  const allowEnv = accountId === DEFAULT_ACCOUNT_ID;
  const configToken = allowEnv ? normalizeDiscordToken(discordCfg?.token ?? undefined) : undefined;
  if (configToken) return { token: configToken, source: "config" };

  // Priority 3: Check environment variable (default account only)
  const envToken = allowEnv
    ? normalizeDiscordToken(opts.envToken ?? process.env.DISCORD_BOT_TOKEN)
    : undefined;
  if (envToken) return { token: envToken, source: "env" };

  return { token: "", source: "none" };
}
