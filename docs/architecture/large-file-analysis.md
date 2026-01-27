# Large File Analysis for Refactoring

This document analyzes TypeScript files over 700 LOC for potential refactoring opportunities.

## Summary

| File | LOC | Priority | Recommendation |
|------|-----|----------|----------------|
| memory/manager.ts | 2178 | High | Split by responsibility |
| line/flex-templates.ts | 1507 | Low | Template data, leave as-is |
| agents/bash-tools.exec.ts | 1495 | Medium | Extract validation/sanitization |
| tts/tts.ts | 1473 | Medium | Split by provider |
| infra/exec-approvals.ts | 1267 | Medium | Extract approval strategies |
| cli/update-cli.ts | 1204 | Low | Sequential workflow, ok as-is |
| node-host/runner.ts | 1199 | Medium | Extract message handlers |
| media-understanding/runner.ts | 1118 | Medium | Extract provider adapters |
| config/schema.ts | 987 | Low | Zod schema, ok as-is |

## Detailed Analysis

### memory/manager.ts (2178 LOC) - HIGH PRIORITY

**Current Structure:**
- Single `MemoryIndexManager` class handling everything
- Responsibilities: embedding generation, vector storage, FTS indexing, file watching, search

**Refactoring Opportunities:**
1. Extract `MemoryEmbeddingService` - embedding generation, batching, caching
2. Extract `MemoryFileWatcher` - chokidar setup, debouncing, dirty tracking
3. Extract `MemoryIndexer` - chunking, indexing, schema management
4. Keep `MemorySearchManager` for search orchestration

**Benefits:**
- Each module testable in isolation
- Clearer separation of async/sync concerns
- Easier to add new embedding providers

### agents/bash-tools.exec.ts (1495 LOC) - MEDIUM PRIORITY

**Current Structure:**
- One large `createExecTool` factory function
- Handles: command parsing, sandboxing, approval, execution, output formatting

**Refactoring Opportunities:**
1. Extract `CommandSanitizer` - input validation, escaping
2. Extract `SandboxResolver` - sandbox mode detection, policy application
3. Keep execution logic as core

**Considerations:**
- Highly cohesive as a tool definition
- Breaking apart may reduce readability of the tool's behavior

### tts/tts.ts (1473 LOC) - MEDIUM PRIORITY

**Current Structure:**
- Many exported utility functions
- Provider-specific logic mixed together (OpenAI, ElevenLabs, Edge)

**Refactoring Opportunities:**
1. Extract `tts-openai.ts` - OpenAI-specific synthesis
2. Extract `tts-elevenlabs.ts` - ElevenLabs-specific synthesis
3. Extract `tts-edge.ts` - Edge TTS synthesis
4. Keep `tts.ts` as coordinator with prefs management

**Benefits:**
- Provider implementations isolated
- Easier to add new TTS providers
- Core prefs/config logic cleaner

### infra/exec-approvals.ts (1267 LOC) - MEDIUM PRIORITY

**Current Structure:**
- Approval system for dangerous commands
- Multiple approval strategies and state management

**Refactoring Opportunities:**
1. Extract approval strategy implementations
2. Extract approval state persistence
3. Keep approval orchestration in main file

### node-host/runner.ts (1199 LOC) - MEDIUM PRIORITY

**Current Structure:**
- Node process runner for agent execution
- Message handling, state management, IPC

**Refactoring Opportunities:**
1. Extract message type handlers
2. Extract state machine logic
3. Keep runner lifecycle in main file

### media-understanding/runner.ts (1118 LOC) - MEDIUM PRIORITY

**Current Structure:**
- Media analysis orchestration
- Multiple provider adapters

**Refactoring Opportunities:**
1. Extract provider-specific adapters
2. Extract result normalization
3. Keep orchestration in main file

## Files to Leave As-Is

### line/flex-templates.ts (1507 LOC)
Large but contains static template definitions for LINE Flex messages. No logic to split.

### cli/update-cli.ts (1204 LOC)
Sequential update workflow. Splitting would reduce readability without improving maintainability.

### config/schema.ts (987 LOC)
Zod schema definitions. Schemas are declarative and benefit from co-location.

## Recommended Refactoring Order

1. **memory/manager.ts** - Highest ROI, complex responsibilities
2. **tts/tts.ts** - Clear provider boundaries
3. **exec-approvals.ts** - Growing complexity with approval strategies
4. **bash-tools.exec.ts** - If validation complexity increases
5. **node-host/runner.ts** - If message handling expands

## Completed Refactoring

- **session-utils.ts** (644 LOC) - Split into avatar, agents, store modules ✓
