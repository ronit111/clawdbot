/**
 * Centralized error utilities and base types.
 *
 * This module provides:
 * - ClawdbotError: Base error class with code and metadata support
 * - Common error utilities for formatting and type checking
 * - Re-exports of domain-specific errors for discoverability
 *
 * Domain errors remain co-located with their modules for cohesion.
 * This index provides a single discovery point for error types.
 */

// Base error class with standardized structure
export type ErrorCode = string;

export interface ErrorMetadata {
  [key: string]: unknown;
}

/**
 * Base error class for Clawdbot errors.
 * Provides consistent structure with error codes and metadata.
 */
export class ClawdbotError extends Error {
  readonly code: ErrorCode;
  readonly metadata?: ErrorMetadata;

  constructor(
    code: ErrorCode,
    message: string,
    options?: { cause?: unknown; metadata?: ErrorMetadata },
  ) {
    super(message, { cause: options?.cause });
    this.name = "ClawdbotError";
    this.code = code;
    this.metadata = options?.metadata;
  }

  /**
   * Create a JSON-serializable representation.
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      metadata: this.metadata,
      stack: this.stack,
    };
  }
}

/**
 * Type guard for ClawdbotError instances.
 */
export function isClawdbotError(err: unknown): err is ClawdbotError {
  return err instanceof ClawdbotError;
}

/**
 * Type guard for Error instances.
 */
export function isError(err: unknown): err is Error {
  return err instanceof Error;
}

/**
 * Extract the error message from any value.
 */
export function getErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  if (typeof err === "number" || typeof err === "boolean" || typeof err === "bigint") {
    return String(err);
  }
  if (err && typeof err === "object" && "message" in err) {
    const message = (err as { message: unknown }).message;
    if (typeof message === "string") return message;
  }
  return String(err);
}

/**
 * Extract the error code from any value.
 */
export function getErrorCode(err: unknown): string | undefined {
  if (isClawdbotError(err)) return err.code;
  if (!err || typeof err !== "object") return undefined;
  const code = (err as { code?: unknown }).code;
  if (typeof code === "string") return code;
  if (typeof code === "number") return String(code);
  return undefined;
}

/**
 * Extract HTTP status code from an error if present.
 */
export function getErrorStatus(err: unknown): number | undefined {
  if (!err || typeof err !== "object") return undefined;
  const candidate =
    (err as { status?: unknown }).status ?? (err as { statusCode?: unknown }).statusCode;
  if (typeof candidate === "number" && Number.isFinite(candidate)) return candidate;
  if (typeof candidate === "string" && /^\d+$/.test(candidate)) return Number(candidate);
  return undefined;
}

/**
 * Format an error for logging (includes stack trace for Error instances).
 */
export function formatErrorForLog(err: unknown): string {
  if (err instanceof Error) {
    return err.stack ?? err.message ?? err.name;
  }
  return getErrorMessage(err);
}

/**
 * Format an error for user display (no stack trace).
 */
export function formatErrorForUser(err: unknown): string {
  if (isClawdbotError(err)) {
    return `[${err.code}] ${err.message}`;
  }
  return getErrorMessage(err);
}

/**
 * Wrap an unknown error in a ClawdbotError if it isn't already one.
 */
export function wrapError(err: unknown, code: ErrorCode, defaultMessage?: string): ClawdbotError {
  if (isClawdbotError(err)) return err;
  const message = getErrorMessage(err) || defaultMessage || "Unknown error";
  return new ClawdbotError(code, message, { cause: err });
}

// Re-export common error utilities from infra
export { extractErrorCode, formatErrorMessage, formatUncaughtError } from "../infra/errors.js";

// Re-export domain-specific errors for discoverability
export { FailoverError, isFailoverError } from "../agents/failover-error.js";
export { MediaFetchError, type MediaFetchErrorCode } from "../media/fetch.js";
export { GatewayLockError } from "../infra/gateway-lock.js";
export { SsrFBlockedError } from "../infra/net/ssrf.js";
export { MissingEnvVarError } from "../config/env-substitution.js";
export { SafeOpenError } from "../infra/fs-safe.js";
export { ConfigIncludeError } from "../config/includes.js";
export { DuplicateAgentDirError } from "../config/agent-dirs.js";
export { MediaUnderstandingSkipError } from "../media-understanding/errors.js";

// Re-export error classification utilities
export {
  isContextOverflowError,
  isLikelyContextOverflowError,
  isRateLimitErrorMessage,
  isTimeoutErrorMessage,
  isBillingErrorMessage,
  isAuthErrorMessage,
  isOverloadedErrorMessage,
  classifyFailoverReason,
} from "../agents/pi-embedded-helpers/errors.js";
