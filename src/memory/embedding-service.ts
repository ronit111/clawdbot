/**
 * Embedding service for memory search.
 *
 * Handles embedding generation, batching, caching, and retry logic.
 * Extracted from MemoryIndexManager for focused responsibility.
 */

import type { DatabaseSync } from "node:sqlite";

import { createSubsystemLogger } from "../logging/subsystem.js";
import {
  OPENAI_BATCH_ENDPOINT,
  type OpenAiBatchRequest,
  runOpenAiEmbeddingBatches,
} from "./batch-openai.js";
import { runGeminiEmbeddingBatches, type GeminiBatchRequest } from "./batch-gemini.js";
import type {
  EmbeddingProvider,
  GeminiEmbeddingClient,
  OpenAiEmbeddingClient,
} from "./embeddings.js";
import { hashText, parseEmbedding, type MemoryChunk } from "./internal.js";

const log = createSubsystemLogger("memory");

const EMBEDDING_CACHE_TABLE = "embedding_cache";
const EMBEDDING_BATCH_MAX_TOKENS = 8000;
const EMBEDDING_APPROX_CHARS_PER_TOKEN = 1;
const EMBEDDING_RETRY_MAX_ATTEMPTS = 3;
const EMBEDDING_RETRY_BASE_DELAY_MS = 500;
const EMBEDDING_RETRY_MAX_DELAY_MS = 8000;
const BATCH_FAILURE_LIMIT = 2;
const EMBEDDING_QUERY_TIMEOUT_REMOTE_MS = 60_000;
const EMBEDDING_QUERY_TIMEOUT_LOCAL_MS = 5 * 60_000;
const EMBEDDING_BATCH_TIMEOUT_REMOTE_MS = 2 * 60_000;
const EMBEDDING_BATCH_TIMEOUT_LOCAL_MS = 10 * 60_000;

export type EmbeddingServiceConfig = {
  provider: EmbeddingProvider;
  providerKey: string;
  openAi?: OpenAiEmbeddingClient;
  gemini?: GeminiEmbeddingClient;
  cache: { enabled: boolean; maxEntries?: number };
  batch: {
    enabled: boolean;
    wait: boolean;
    concurrency: number;
    pollIntervalMs: number;
    timeoutMs: number;
  };
  agentId: string;
};

export type EmbeddingBatchStatus = {
  enabled: boolean;
  failures: number;
  limit: number;
  wait: boolean;
  concurrency: number;
  pollIntervalMs: number;
  timeoutMs: number;
  lastError?: string;
  lastProvider?: string;
};

type MemorySource = "memory" | "sessions";

type FileEntry = {
  path: string;
  absPath: string;
  mtimeMs: number;
  size: number;
  hash: string;
};

export class EmbeddingService {
  private readonly db: DatabaseSync;
  private readonly provider: EmbeddingProvider;
  private readonly providerKey: string;
  private readonly openAi?: OpenAiEmbeddingClient;
  private readonly gemini?: GeminiEmbeddingClient;
  private readonly cache: { enabled: boolean; maxEntries?: number };
  private batch: {
    enabled: boolean;
    wait: boolean;
    concurrency: number;
    pollIntervalMs: number;
    timeoutMs: number;
  };
  private readonly agentId: string;

  private batchFailureCount = 0;
  private batchFailureLastError?: string;
  private batchFailureLastProvider?: string;
  private batchFailureLock: Promise<void> = Promise.resolve();

  constructor(db: DatabaseSync, config: EmbeddingServiceConfig) {
    this.db = db;
    this.provider = config.provider;
    this.providerKey = config.providerKey;
    this.openAi = config.openAi;
    this.gemini = config.gemini;
    this.cache = config.cache;
    this.batch = { ...config.batch };
    this.agentId = config.agentId;
  }

  /**
   * Get current batch status for reporting.
   */
  getBatchStatus(): EmbeddingBatchStatus {
    return {
      enabled: this.batch.enabled,
      failures: this.batchFailureCount,
      limit: BATCH_FAILURE_LIMIT,
      wait: this.batch.wait,
      concurrency: this.batch.concurrency,
      pollIntervalMs: this.batch.pollIntervalMs,
      timeoutMs: this.batch.timeoutMs,
      lastError: this.batchFailureLastError,
      lastProvider: this.batchFailureLastProvider,
    };
  }

  /**
   * Get cache entry count.
   */
  getCacheEntryCount(): number {
    if (!this.cache.enabled) return 0;
    const row = this.db.prepare(`SELECT COUNT(*) as c FROM ${EMBEDDING_CACHE_TABLE}`).get() as
      | { c: number }
      | undefined;
    return row?.c ?? 0;
  }

  /**
   * Check if batch mode is enabled.
   */
  isBatchEnabled(): boolean {
    return this.batch.enabled;
  }

  /**
   * Get the index concurrency based on batch mode.
   */
  getIndexConcurrency(defaultConcurrency: number): number {
    return this.batch.enabled ? this.batch.concurrency : defaultConcurrency;
  }

  /**
   * Embed a query string with timeout.
   */
  async embedQuery(text: string): Promise<number[]> {
    const timeoutMs = this.resolveEmbeddingTimeout("query");
    log.debug("memory embeddings: query start", { provider: this.provider.id, timeoutMs });
    return await this.withTimeout(
      this.provider.embedQuery(text),
      timeoutMs,
      `memory embeddings query timed out after ${Math.round(timeoutMs / 1000)}s`,
    );
  }

  /**
   * Embed chunks for a file, using batch API if available.
   */
  async embedChunksForFile(
    chunks: MemoryChunk[],
    entry: FileEntry,
    source: MemorySource,
  ): Promise<number[][]> {
    if (this.batch.enabled) {
      return this.embedChunksWithBatch(chunks, entry, source);
    }
    return this.embedChunksInBatches(chunks);
  }

  /**
   * Embed chunks in batches (non-batch API).
   */
  async embedChunksInBatches(chunks: MemoryChunk[]): Promise<number[][]> {
    if (chunks.length === 0) return [];
    const cached = this.loadEmbeddingCache(chunks.map((chunk) => chunk.hash));
    const embeddings: number[][] = Array.from({ length: chunks.length }, () => []);
    const missing: Array<{ index: number; chunk: MemoryChunk }> = [];

    for (let i = 0; i < chunks.length; i += 1) {
      const chunk = chunks[i];
      const hit = chunk?.hash ? cached.get(chunk.hash) : undefined;
      if (hit && hit.length > 0) {
        embeddings[i] = hit;
      } else if (chunk) {
        missing.push({ index: i, chunk });
      }
    }

    if (missing.length === 0) return embeddings;

    const missingChunks = missing.map((m) => m.chunk);
    const batches = this.buildEmbeddingBatches(missingChunks);
    const toCache: Array<{ hash: string; embedding: number[] }> = [];
    let cursor = 0;
    for (const batch of batches) {
      const batchEmbeddings = await this.embedBatchWithRetry(batch.map((chunk) => chunk.text));
      for (let i = 0; i < batch.length; i += 1) {
        const item = missing[cursor + i];
        const embedding = batchEmbeddings[i] ?? [];
        if (item) {
          embeddings[item.index] = embedding;
          toCache.push({ hash: item.chunk.hash, embedding });
        }
      }
      cursor += batch.length;
    }
    this.upsertEmbeddingCache(toCache);
    return embeddings;
  }

  /**
   * Prune embedding cache if over limit.
   */
  pruneEmbeddingCacheIfNeeded(): void {
    if (!this.cache.enabled) return;
    const max = this.cache.maxEntries;
    if (!max || max <= 0) return;
    const row = this.db.prepare(`SELECT COUNT(*) as c FROM ${EMBEDDING_CACHE_TABLE}`).get() as
      | { c: number }
      | undefined;
    const count = row?.c ?? 0;
    if (count <= max) return;
    const excess = count - max;
    this.db
      .prepare(
        `DELETE FROM ${EMBEDDING_CACHE_TABLE}\n` +
          ` WHERE rowid IN (\n` +
          `   SELECT rowid FROM ${EMBEDDING_CACHE_TABLE}\n` +
          `   ORDER BY updated_at ASC\n` +
          `   LIMIT ?\n` +
          ` )`,
      )
      .run(excess);
  }

  /**
   * Seed embedding cache from another database.
   */
  seedEmbeddingCache(sourceDb: DatabaseSync): void {
    if (!this.cache.enabled) return;
    try {
      const rows = sourceDb
        .prepare(
          `SELECT provider, model, provider_key, hash, embedding, dims, updated_at FROM ${EMBEDDING_CACHE_TABLE}`,
        )
        .all() as Array<{
        provider: string;
        model: string;
        provider_key: string;
        hash: string;
        embedding: string;
        dims: number | null;
        updated_at: number;
      }>;
      if (!rows.length) return;
      const insert = this.db.prepare(
        `INSERT INTO ${EMBEDDING_CACHE_TABLE} (provider, model, provider_key, hash, embedding, dims, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(provider, model, provider_key, hash) DO UPDATE SET
           embedding=excluded.embedding,
           dims=excluded.dims,
           updated_at=excluded.updated_at`,
      );
      this.db.exec("BEGIN");
      for (const row of rows) {
        insert.run(
          row.provider,
          row.model,
          row.provider_key,
          row.hash,
          row.embedding,
          row.dims,
          row.updated_at,
        );
      }
      this.db.exec("COMMIT");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {}
      throw err;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Private: Batching
  // ─────────────────────────────────────────────────────────────────────────────

  private estimateEmbeddingTokens(text: string): number {
    if (!text) return 0;
    return Math.ceil(text.length / EMBEDDING_APPROX_CHARS_PER_TOKEN);
  }

  private buildEmbeddingBatches(chunks: MemoryChunk[]): MemoryChunk[][] {
    const batches: MemoryChunk[][] = [];
    let current: MemoryChunk[] = [];
    let currentTokens = 0;

    for (const chunk of chunks) {
      const estimate = this.estimateEmbeddingTokens(chunk.text);
      const wouldExceed =
        current.length > 0 && currentTokens + estimate > EMBEDDING_BATCH_MAX_TOKENS;
      if (wouldExceed) {
        batches.push(current);
        current = [];
        currentTokens = 0;
      }
      if (current.length === 0 && estimate > EMBEDDING_BATCH_MAX_TOKENS) {
        batches.push([chunk]);
        continue;
      }
      current.push(chunk);
      currentTokens += estimate;
    }

    if (current.length > 0) {
      batches.push(current);
    }
    return batches;
  }

  private async embedBatchWithRetry(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return [];
    let attempt = 0;
    let delayMs = EMBEDDING_RETRY_BASE_DELAY_MS;
    while (true) {
      try {
        const timeoutMs = this.resolveEmbeddingTimeout("batch");
        log.debug("memory embeddings: batch start", {
          provider: this.provider.id,
          items: texts.length,
          timeoutMs,
        });
        return await this.withTimeout(
          this.provider.embedBatch(texts),
          timeoutMs,
          `memory embeddings batch timed out after ${Math.round(timeoutMs / 1000)}s`,
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (!this.isRetryableEmbeddingError(message) || attempt >= EMBEDDING_RETRY_MAX_ATTEMPTS) {
          throw err;
        }
        const waitMs = Math.min(
          EMBEDDING_RETRY_MAX_DELAY_MS,
          Math.round(delayMs * (1 + Math.random() * 0.2)),
        );
        log.warn(`memory embeddings rate limited; retrying in ${waitMs}ms`);
        await new Promise((resolve) => setTimeout(resolve, waitMs));
        delayMs *= 2;
        attempt += 1;
      }
    }
  }

  private isRetryableEmbeddingError(message: string): boolean {
    return /(rate[_ ]limit|too many requests|429|resource has been exhausted|5\d\d|cloudflare)/i.test(
      message,
    );
  }

  private resolveEmbeddingTimeout(kind: "query" | "batch"): number {
    const isLocal = this.provider.id === "local";
    if (kind === "query") {
      return isLocal ? EMBEDDING_QUERY_TIMEOUT_LOCAL_MS : EMBEDDING_QUERY_TIMEOUT_REMOTE_MS;
    }
    return isLocal ? EMBEDDING_BATCH_TIMEOUT_LOCAL_MS : EMBEDDING_BATCH_TIMEOUT_REMOTE_MS;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Private: Cache
  // ─────────────────────────────────────────────────────────────────────────────

  private loadEmbeddingCache(hashes: string[]): Map<string, number[]> {
    if (!this.cache.enabled) return new Map();
    if (hashes.length === 0) return new Map();
    const unique: string[] = [];
    const seen = new Set<string>();
    for (const hash of hashes) {
      if (!hash) continue;
      if (seen.has(hash)) continue;
      seen.add(hash);
      unique.push(hash);
    }
    if (unique.length === 0) return new Map();

    const out = new Map<string, number[]>();
    const baseParams = [this.provider.id, this.provider.model, this.providerKey];
    const batchSize = 400;
    for (let start = 0; start < unique.length; start += batchSize) {
      const batch = unique.slice(start, start + batchSize);
      const placeholders = batch.map(() => "?").join(", ");
      const rows = this.db
        .prepare(
          `SELECT hash, embedding FROM ${EMBEDDING_CACHE_TABLE}\n` +
            ` WHERE provider = ? AND model = ? AND provider_key = ? AND hash IN (${placeholders})`,
        )
        .all(...baseParams, ...batch) as Array<{ hash: string; embedding: string }>;
      for (const row of rows) {
        out.set(row.hash, parseEmbedding(row.embedding));
      }
    }
    return out;
  }

  private upsertEmbeddingCache(entries: Array<{ hash: string; embedding: number[] }>): void {
    if (!this.cache.enabled) return;
    if (entries.length === 0) return;
    const now = Date.now();
    const stmt = this.db.prepare(
      `INSERT INTO ${EMBEDDING_CACHE_TABLE} (provider, model, provider_key, hash, embedding, dims, updated_at)\n` +
        ` VALUES (?, ?, ?, ?, ?, ?, ?)\n` +
        ` ON CONFLICT(provider, model, provider_key, hash) DO UPDATE SET\n` +
        `   embedding=excluded.embedding,\n` +
        `   dims=excluded.dims,\n` +
        `   updated_at=excluded.updated_at`,
    );
    for (const entry of entries) {
      const embedding = entry.embedding ?? [];
      stmt.run(
        this.provider.id,
        this.provider.model,
        this.providerKey,
        entry.hash,
        JSON.stringify(embedding),
        embedding.length,
        now,
      );
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Private: Batch API (OpenAI, Gemini)
  // ─────────────────────────────────────────────────────────────────────────────

  private async embedChunksWithBatch(
    chunks: MemoryChunk[],
    entry: FileEntry,
    source: MemorySource,
  ): Promise<number[][]> {
    if (this.provider.id === "openai" && this.openAi) {
      return this.embedChunksWithOpenAiBatch(chunks, entry, source);
    }
    if (this.provider.id === "gemini" && this.gemini) {
      return this.embedChunksWithGeminiBatch(chunks, entry, source);
    }
    return this.embedChunksInBatches(chunks);
  }

  private async embedChunksWithOpenAiBatch(
    chunks: MemoryChunk[],
    entry: FileEntry,
    source: MemorySource,
  ): Promise<number[][]> {
    const openAi = this.openAi;
    if (!openAi) {
      return this.embedChunksInBatches(chunks);
    }
    if (chunks.length === 0) return [];
    const cached = this.loadEmbeddingCache(chunks.map((chunk) => chunk.hash));
    const embeddings: number[][] = Array.from({ length: chunks.length }, () => []);
    const missing: Array<{ index: number; chunk: MemoryChunk }> = [];

    for (let i = 0; i < chunks.length; i += 1) {
      const chunk = chunks[i];
      const hit = chunk?.hash ? cached.get(chunk.hash) : undefined;
      if (hit && hit.length > 0) {
        embeddings[i] = hit;
      } else if (chunk) {
        missing.push({ index: i, chunk });
      }
    }

    if (missing.length === 0) return embeddings;

    const requests: OpenAiBatchRequest[] = [];
    const mapping = new Map<string, { index: number; hash: string }>();
    for (const item of missing) {
      const chunk = item.chunk;
      const customId = hashText(
        `${source}:${entry.path}:${chunk.startLine}:${chunk.endLine}:${chunk.hash}:${item.index}`,
      );
      mapping.set(customId, { index: item.index, hash: chunk.hash });
      requests.push({
        custom_id: customId,
        method: "POST",
        url: OPENAI_BATCH_ENDPOINT,
        body: {
          model: this.openAi?.model ?? this.provider.model,
          input: chunk.text,
        },
      });
    }
    const batchResult = await this.runBatchWithFallback({
      provider: "openai",
      run: async () =>
        await runOpenAiEmbeddingBatches({
          openAi,
          agentId: this.agentId,
          requests,
          wait: this.batch.wait,
          concurrency: this.batch.concurrency,
          pollIntervalMs: this.batch.pollIntervalMs,
          timeoutMs: this.batch.timeoutMs,
          debug: (message, data) => log.debug(message, { ...data, source, chunks: chunks.length }),
        }),
      fallback: async () => await this.embedChunksInBatches(chunks),
    });
    if (Array.isArray(batchResult)) return batchResult;
    const byCustomId = batchResult;

    const toCache: Array<{ hash: string; embedding: number[] }> = [];
    for (const [customId, embedding] of byCustomId.entries()) {
      const mapped = mapping.get(customId);
      if (!mapped) continue;
      embeddings[mapped.index] = embedding;
      toCache.push({ hash: mapped.hash, embedding });
    }
    this.upsertEmbeddingCache(toCache);
    return embeddings;
  }

  private async embedChunksWithGeminiBatch(
    chunks: MemoryChunk[],
    entry: FileEntry,
    source: MemorySource,
  ): Promise<number[][]> {
    const gemini = this.gemini;
    if (!gemini) {
      return this.embedChunksInBatches(chunks);
    }
    if (chunks.length === 0) return [];
    const cached = this.loadEmbeddingCache(chunks.map((chunk) => chunk.hash));
    const embeddings: number[][] = Array.from({ length: chunks.length }, () => []);
    const missing: Array<{ index: number; chunk: MemoryChunk }> = [];

    for (let i = 0; i < chunks.length; i += 1) {
      const chunk = chunks[i];
      const hit = chunk?.hash ? cached.get(chunk.hash) : undefined;
      if (hit && hit.length > 0) {
        embeddings[i] = hit;
      } else if (chunk) {
        missing.push({ index: i, chunk });
      }
    }

    if (missing.length === 0) return embeddings;

    const requests: GeminiBatchRequest[] = [];
    const mapping = new Map<string, { index: number; hash: string }>();
    for (const item of missing) {
      const chunk = item.chunk;
      const customId = hashText(
        `${source}:${entry.path}:${chunk.startLine}:${chunk.endLine}:${chunk.hash}:${item.index}`,
      );
      mapping.set(customId, { index: item.index, hash: chunk.hash });
      requests.push({
        custom_id: customId,
        content: { parts: [{ text: chunk.text }] },
        taskType: "RETRIEVAL_DOCUMENT",
      });
    }

    const batchResult = await this.runBatchWithFallback({
      provider: "gemini",
      run: async () =>
        await runGeminiEmbeddingBatches({
          gemini,
          agentId: this.agentId,
          requests,
          wait: this.batch.wait,
          concurrency: this.batch.concurrency,
          pollIntervalMs: this.batch.pollIntervalMs,
          timeoutMs: this.batch.timeoutMs,
          debug: (message, data) => log.debug(message, { ...data, source, chunks: chunks.length }),
        }),
      fallback: async () => await this.embedChunksInBatches(chunks),
    });
    if (Array.isArray(batchResult)) return batchResult;
    const byCustomId = batchResult;

    const toCache: Array<{ hash: string; embedding: number[] }> = [];
    for (const [customId, embedding] of byCustomId.entries()) {
      const mapped = mapping.get(customId);
      if (!mapped) continue;
      embeddings[mapped.index] = embedding;
      toCache.push({ hash: mapped.hash, embedding });
    }
    this.upsertEmbeddingCache(toCache);
    return embeddings;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Private: Batch failure handling
  // ─────────────────────────────────────────────────────────────────────────────

  private async withBatchFailureLock<T>(fn: () => Promise<T>): Promise<T> {
    let release: () => void;
    const wait = this.batchFailureLock;
    this.batchFailureLock = new Promise<void>((resolve) => {
      release = resolve;
    });
    await wait;
    try {
      return await fn();
    } finally {
      release!();
    }
  }

  private async resetBatchFailureCount(): Promise<void> {
    await this.withBatchFailureLock(async () => {
      if (this.batchFailureCount > 0) {
        log.debug("memory embeddings: batch recovered; resetting failure count");
      }
      this.batchFailureCount = 0;
      this.batchFailureLastError = undefined;
      this.batchFailureLastProvider = undefined;
    });
  }

  private async recordBatchFailure(params: {
    provider: string;
    message: string;
    attempts?: number;
    forceDisable?: boolean;
  }): Promise<{ disabled: boolean; count: number }> {
    return await this.withBatchFailureLock(async () => {
      if (!this.batch.enabled) {
        return { disabled: true, count: this.batchFailureCount };
      }
      const increment = params.forceDisable
        ? BATCH_FAILURE_LIMIT
        : Math.max(1, params.attempts ?? 1);
      this.batchFailureCount += increment;
      this.batchFailureLastError = params.message;
      this.batchFailureLastProvider = params.provider;
      const disabled = params.forceDisable || this.batchFailureCount >= BATCH_FAILURE_LIMIT;
      if (disabled) {
        this.batch.enabled = false;
      }
      return { disabled, count: this.batchFailureCount };
    });
  }

  private isBatchTimeoutError(message: string): boolean {
    return /timed out|timeout/i.test(message);
  }

  private async runBatchWithTimeoutRetry<T>(params: {
    provider: string;
    run: () => Promise<T>;
  }): Promise<T> {
    try {
      return await params.run();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (this.isBatchTimeoutError(message)) {
        log.warn(`memory embeddings: ${params.provider} batch timed out; retrying once`);
        try {
          return await params.run();
        } catch (retryErr) {
          (retryErr as { batchAttempts?: number }).batchAttempts = 2;
          throw retryErr;
        }
      }
      throw err;
    }
  }

  private async runBatchWithFallback<T>(params: {
    provider: string;
    run: () => Promise<T>;
    fallback: () => Promise<number[][]>;
  }): Promise<T | number[][]> {
    if (!this.batch.enabled) {
      return await params.fallback();
    }
    try {
      const result = await this.runBatchWithTimeoutRetry({
        provider: params.provider,
        run: params.run,
      });
      await this.resetBatchFailureCount();
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const attempts = (err as { batchAttempts?: number }).batchAttempts ?? 1;
      const forceDisable = /asyncBatchEmbedContent not available/i.test(message);
      const failure = await this.recordBatchFailure({
        provider: params.provider,
        message,
        attempts,
        forceDisable,
      });
      const suffix = failure.disabled ? "disabling batch" : "keeping batch enabled";
      log.warn(
        `memory embeddings: ${params.provider} batch failed (${failure.count}/${BATCH_FAILURE_LIMIT}); ${suffix}; falling back to non-batch embeddings: ${message}`,
      );
      return await params.fallback();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Private: Utilities
  // ─────────────────────────────────────────────────────────────────────────────

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    message: string,
  ): Promise<T> {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return await promise;
    let timer: NodeJS.Timeout | null = null;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    });
    try {
      return (await Promise.race([promise, timeoutPromise])) as T;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
