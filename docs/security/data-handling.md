---
title: Data Handling Policy
summary: How Clawdbot handles user data, retention, logging, and privacy.
permalink: /security/data-handling/
---

# Data Handling Policy

This document describes how Clawdbot handles user data, including storage, retention, logging, and user rights.

## Data Categories

### 1. Configuration Data

**Location:** `~/.clawdbot/clawdbot.json` or `config.yaml`

**Contents:**
- LLM provider settings (model, temperature, etc.)
- Channel configuration (enabled platforms)
- Gateway settings (host, port, auth mode)
- Tool and skill preferences

**Retention:** Persists until user deletes or modifies

**Protection:** File permissions (0o600)

### 2. Credentials and Secrets

**Location:** System keychain (preferred) or `~/.clawdbot/credentials/`

**Contents:**
- API keys for LLM providers
- Bot tokens for messaging platforms (Discord, Telegram, Slack)
- OAuth tokens and session data

**Retention:** Persists until explicitly revoked or rotated

**Protection:**
- System keychain (macOS Keychain, Linux Secret Service) when available
- AES-256-GCM encryption with PBKDF2 key derivation for file fallback
- Machine-derived encryption keys

**Deletion:** Use `clawdbot config unset` or delete from system keychain

### 3. Session Data

**Location:** `~/.clawdbot/sessions/`

**Contents:**
- Conversation history with LLM
- Tool execution results
- Agent state and context

**Retention:** Configurable via `session.maxMessages` and `session.ttl`

**Protection:** File permissions (0o600), isolated per agent ID

**Deletion:** `clawdbot session clear` or delete session files directly

### 4. Pairing and Authorization Data

**Location:** `~/.clawdbot/credentials/<channel>-pairing.json` and `<channel>-allowFrom.json`

**Contents:**
- Pending pairing requests with codes
- Authorized sender IDs per channel

**Retention:**
- Pending requests: 1 hour TTL
- Authorized senders: Persists until removed

**Protection:**
- HMAC-SHA256 signatures for integrity verification
- File permissions (0o600)
- Rate limiting on approval attempts

**Deletion:** `clawdbot pairing revoke` or edit allowFrom files

### 5. Message Content

**What is stored:**
- Messages are passed to the LLM provider for processing
- Session history may include message excerpts for context

**What is NOT stored by default:**
- Full message history is not logged to disk
- Attachments are not persistently stored

**LLM Provider Data:**
- Message content is sent to configured LLM providers
- Subject to provider's data retention policies
- See provider documentation for details

### 6. Logs

**Location:** Configured via `logging` settings

**Default behavior:**
- Errors and warnings logged to console
- No persistent disk logging by default

**When enabled:**
- Log files may contain error messages and stack traces
- Debug logging may include request/response data
- Sensitive data (tokens, credentials) should be redacted

**Retention:** Configurable, no automatic rotation by default

## User Rights

### Access Your Data

Users can access their data through:
- Reading configuration files directly
- Using `clawdbot config show` for settings
- Using `clawdbot session list` for conversations
- Checking system keychain for stored secrets

### Export Your Data

To export all Clawdbot data:

```bash
# Configuration
cp ~/.clawdbot/clawdbot.json ~/clawdbot-backup/

# Sessions
cp -r ~/.clawdbot/sessions/ ~/clawdbot-backup/sessions/

# Pairing and authorization
cp ~/.clawdbot/credentials/*.json ~/clawdbot-backup/credentials/

# Note: Keychain credentials must be exported via system tools
```

### Delete Your Data

To remove all Clawdbot data:

```bash
# Stop the gateway
clawdbot gateway stop

# Remove all local data
rm -rf ~/.clawdbot/

# Remove keychain entries (macOS)
security delete-generic-password -s "clawdbot" -a "*"

# Remove keychain entries (Linux)
secret-tool clear service clawdbot
```

### Data Portability

Configuration and session data are stored in JSON format and can be:
- Backed up and restored
- Migrated to another machine
- Inspected with standard tools

## Data Flow

### Inbound Messages

```
Channel (WhatsApp/Telegram/etc.)
    ↓
Gateway (auth check, rate limit)
    ↓
Prompt Injection Check
    ↓
LLM Provider (OpenAI/Anthropic/etc.)
    ↓
Response Processing
    ↓
Tool Execution (if requested)
    ↓
Channel Response
```

### Outbound Data

Data leaves the system in these cases:
1. **LLM API calls:** Message content sent to configured provider
2. **Channel responses:** Bot replies sent to messaging platforms
3. **Tool execution:** Commands may access network resources
4. **Browser automation:** Web requests as directed by user

## Third-Party Services

### LLM Providers

Clawdbot integrates with:
- OpenAI (ChatGPT, GPT-4)
- Anthropic (Claude)
- Google (Gemini)
- Local models (Ollama)

Each provider has their own data handling policies. Review:
- [OpenAI Privacy Policy](https://openai.com/policies/privacy-policy)
- [Anthropic Privacy Policy](https://www.anthropic.com/privacy)
- [Google AI Privacy](https://ai.google/privacy/)

### Messaging Platforms

Each connected channel has its own privacy implications:
- **WhatsApp:** End-to-end encrypted, but bot can read messages it receives
- **Telegram:** Bot API messages are not end-to-end encrypted
- **Discord:** Subject to Discord's terms and privacy policy
- **Slack:** Workspace-level data access policies apply

## Consent Model

### Explicit Consent Required For:
- Initial bot setup and configuration
- Connecting to messaging platforms
- Executing shell commands (approval mode)
- Pairing new authorized senders

### Implicit Consent (by using the bot):
- Messages being processed by LLM
- Session data being stored locally
- Rate limiting and security logging

### No Consent Possible (always active):
- Security controls (blocklists, rate limits)
- Prompt injection detection
- Credential encryption

## Compliance Considerations

### GDPR (if applicable)
- **Right to access:** Users can read their data directly
- **Right to erasure:** Delete data as documented above
- **Data portability:** JSON format enables export
- **Processing records:** Not maintained by default

### Security Best Practices
- Credentials stored in system keychain when possible
- File permissions restrict access to owner
- Sensitive data encrypted at rest
- No telemetry or analytics by default

## Changes to This Policy

This policy may be updated as features change. Significant changes will be noted in the changelog.

---

*Last updated: 2026-01-27*
