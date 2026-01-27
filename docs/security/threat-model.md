---
title: Threat Model
summary: Security threat analysis for Clawdbot's attack surfaces and mitigations.
permalink: /security/threat-model/
---

# Threat Model

This document describes Clawdbot's security threat model, attack surfaces, and implemented mitigations.

## System Overview

Clawdbot is a personal AI assistant that:
- Connects to messaging platforms (WhatsApp, Telegram, Discord, Slack, Signal, iMessage)
- Executes shell commands on the host machine
- Can control browsers via automation tools
- Stores configuration, credentials, and session data locally

## Threat Actors

### External Attackers
- **Network-based:** Attackers who can reach the gateway over the network
- **Message-based:** Malicious users who can send messages through connected channels
- **Supply chain:** Compromised dependencies or plugins

### Malicious Message Senders
- Authorized users who attempt to abuse the system
- Attackers who gain access to an authorized user's account
- Prompt injection attempts through message content

### Local Attackers
- Users with local access to the machine
- Malware running on the same machine

## Attack Surfaces

### 1. Messaging Channels

**Risk:** Unauthorized command execution via messaging platforms.

**Attack vectors:**
- Sending messages to the bot without authorization
- Impersonating authorized users
- Prompt injection attacks embedded in messages
- Exploiting channel-specific authentication weaknesses

**Mitigations:**
- Pairing codes with 80-bit entropy (16 chars, 32-char alphabet)
- Per-channel allowlists for authorized senders
- Rate limiting on pairing attempts (10/min)
- HMAC-signed pairing stores to detect tampering
- Prompt injection detection with tiered severity (critical/high/medium/low)
- Prompt boundary markers (`[USER_INPUT_START]`/`[USER_INPUT_END]`)

### 2. Shell Command Execution

**Risk:** Arbitrary code execution, system compromise, data exfiltration.

**Attack vectors:**
- Direct malicious commands from authorized users
- Prompt injection leading to command execution
- Shell metacharacter injection
- Path traversal in command arguments

**Mitigations:**
- Command execution blocklist (critical/high/medium severity)
- Critical patterns always blocked: `rm -rf /`, `dd if=/dev/zero of=/dev/sda`, `mkfs`, fork bombs
- High severity blocked by default: `sudo`, `passwd`, `iptables`, user management
- Allowlist-based execution for untrusted contexts
- Shell command parsing and analysis before execution
- Safe bins list for common utilities with restricted arguments
- One-time-use nonces for exec approval tokens (replay protection)

### 3. Gateway API

**Risk:** Unauthorized access to bot functionality, denial of service.

**Attack vectors:**
- Unauthenticated access to exposed gateway
- Brute-force attacks on authentication
- Rate-based denial of service
- Session hijacking

**Mitigations:**
- Security warning at startup for non-loopback binding without auth
- Token or password authentication for remote access
- Rate limiting with token bucket algorithm:
  - Unauthenticated: 60 requests/min
  - Channel messages: 200/min per channel
  - Burst support (2x multiplier)
- Exponential backoff after authentication failures (1s base, 60s max)
- Per-client tracking (separate buckets per IP/session)

### 4. Local File Storage

**Risk:** Credential theft, session hijacking, configuration tampering.

**Attack vectors:**
- Reading unencrypted credentials from disk
- Modifying configuration files
- Tampering with pairing stores
- Session file manipulation

**Mitigations:**
- Secrets stored in system keychain (macOS Keychain, Linux Secret Service)
- Fallback to AES-256-GCM encrypted files with PBKDF2 key derivation
- Machine-derived encryption keys for file fallback
- HMAC signatures on pairing stores
- File permissions set to 0o600 (owner read/write only)

### 5. Browser Automation

**Risk:** Session theft, credential capture, unintended actions.

**Attack vectors:**
- Accessing sensitive pages without consent
- Capturing authentication cookies
- Executing JavaScript with elevated privileges
- Taking screenshots of sensitive content

**Mitigations:**
- Browser actions require explicit user session
- No automatic credential capture
- User-initiated browser automation only

### 6. Plugin/Extension System

**Risk:** Malicious or vulnerable plugins executing arbitrary code.

**Attack vectors:**
- Malicious plugins with broad permissions
- Vulnerable plugins with security flaws
- Dependency confusion attacks

**Mitigations:**
- Plugins run in the same trust context as the main process
- Plugin installation requires explicit user action
- Plugins installed from npm with standard security practices

## Residual Risks

### Accepted Risks
1. **Local administrator access:** System assumes local admin is trusted
2. **Authorized user abuse:** Rate limits but cannot prevent all abuse
3. **LLM prompt injection:** Detection is heuristic-based, not foolproof
4. **Supply chain:** Depends on npm ecosystem security

### Known Limitations
1. **No sandboxing:** Commands execute in the main process context
2. **Single-user model:** Not designed for multi-tenant use
3. **Trust on first use:** Initial setup requires manual verification

## Security Properties

### Confidentiality
- Credentials protected by system keychain or encryption
- Message content not logged by default
- Session data isolated per agent

### Integrity
- Pairing stores signed with HMAC
- Configuration files protected by file permissions
- One-time nonces prevent replay attacks

### Availability
- Rate limiting prevents resource exhaustion
- Exponential backoff limits brute-force impact
- Graceful degradation on provider failures

## Security Controls Summary

| Control | Implementation | Status |
|---------|---------------|--------|
| Prompt injection detection | `src/gateway/chat-sanitize.ts` | Active |
| Command blocklist | `src/infra/exec-blocklist.ts` | Active |
| Secrets encryption | `src/infra/secrets-manager.ts` | Active |
| Gateway rate limiting | `src/gateway/rate-limit.ts` | Active |
| Pairing hardening | `src/pairing/pairing-store.ts` | Active |
| Approval nonces | `src/infra/exec-approvals.ts` | Active |

## Incident Response

If you discover a security vulnerability:
1. Do not disclose publicly until patched
2. Report via GitHub security advisories
3. Provide reproduction steps and impact assessment

## Version History

- **2026-01-27:** Initial threat model for Phase 1 security hardening
