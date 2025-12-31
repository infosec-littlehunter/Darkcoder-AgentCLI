# Parallel Tool Execution Design Document

## Overview

This document outlines the design and implementation plan for adding parallel tool execution to DarkCoder. This feature will significantly improve performance during security engagements by allowing multiple independent tools to run concurrently.

## Problem Statement

Currently, DarkCoder executes tools **sequentially**. In security engagements, this creates unnecessary delays when running independent operations:

**Example Scenario:**

```typescript
// User request: "Scan target.com with multiple tools"
// Current behavior (Sequential - ~40 seconds total):
1. Shodan scan (10s)        ← waits
2. Censys search (15s)       ← waits
3. URLScan analysis (8s)     ← waits
4. Nuclei scan (7s)          ← waits

// Desired behavior (Parallel - ~15 seconds total):
1. Shodan scan (10s)   ┐
2. Censys search (15s) ├─→ All run concurrently
3. URLScan analysis (8s)┤
4. Nuclei scan (7s)    ┘
```

## Design Goals

1. **Automatic Parallelization** - Detect and run independent tools concurrently
2. **Dependency Management** - Respect tool dependencies (e.g., Tool B needs Tool A's output)
3. **Resource Control** - Limit concurrent executions to prevent system overload
4. **User Control** - Allow users to configure parallelism levels
5. **Backward Compatibility** - Maintain existing tool behavior and APIs
6. **Error Handling** - One tool failure shouldn't block others
7. **Live Output** - Support streaming output from multiple concurrent tools

## Architecture Changes

### 1. Tool Dependency Analysis

Add dependency detection to determine which tools can run in parallel:

```typescript
// packages/core/src/core/toolDependencyAnalyzer.ts

export interface ToolDependency {
  toolCallId: string;
  dependsOn: string[]; // Array of callIds this tool depends on
}

export class ToolDependencyAnalyzer {
  /**
   * Analyzes tool calls to determine execution order and parallelism opportunities
   * @param toolCalls - Array of scheduled tool calls
   * @returns Execution plan with dependency information
   */
  analyzeDependencies(toolCalls: ScheduledToolCall[]): ExecutionPlan {
    // 1. Build dependency graph by analyzing:
    //    - Tool input parameters (references to previous tool outputs)
    //    - File system conflicts (e.g., two tools writing to same file)
    //    - Explicit dependencies (from tool metadata)

    // 2. Group into execution waves:
    //    - Wave 1: Tools with no dependencies
    //    - Wave 2: Tools depending only on Wave 1
    //    - etc.

    return executionPlan;
  }
}

export interface ExecutionPlan {
  waves: ToolWave[];
}

export interface ToolWave {
  toolCalls: ScheduledToolCall[];
  maxConcurrency: number;
}
```

### 2. Parallel Execution Scheduler

Modify `CoreToolScheduler.attemptExecutionOfScheduledCalls()` to support parallel execution:

```typescript
// packages/core/src/core/coreToolScheduler.ts (modifications)

export class CoreToolScheduler {
  private maxConcurrentTools: number = 5; // Configurable via Config

  private async attemptExecutionOfScheduledCalls(
    signal: AbortSignal,
  ): Promise<void> {
    const allCallsFinalOrScheduled = this.toolCalls.every(
      (call) =>
        call.status === 'scheduled' ||
        call.status === 'cancelled' ||
        call.status === 'success' ||
        call.status === 'error',
    );

    if (allCallsFinalOrScheduled) {
      const callsToExecute = this.toolCalls.filter(
        (call) => call.status === 'scheduled',
      );

      // NEW: Analyze dependencies and create execution plan
      const analyzer = new ToolDependencyAnalyzer();
      const executionPlan = analyzer.analyzeDependencies(callsToExecute);

      // Execute tools in waves
      for (const wave of executionPlan.waves) {
        await this.executeToolWave(wave, signal);
      }
    }
  }

  /**
   * Executes a wave of tools with controlled concurrency
   */
  private async executeToolWave(
    wave: ToolWave,
    signal: AbortSignal,
  ): Promise<void> {
    const concurrencyLimit = Math.min(
      wave.maxConcurrency,
      this.maxConcurrentTools,
    );

    // Use promise-based concurrency limiter
    const queue = new PQueue({ concurrency: concurrencyLimit });

    const executions = wave.toolCalls.map((toolCall) =>
      queue.add(() => this.executeSingleTool(toolCall, signal)),
    );

    // Wait for all tools in this wave to complete
    await Promise.allSettled(executions);
  }

  /**
   * Executes a single tool (extracted from current implementation)
   */
  private async executeSingleTool(
    toolCall: ScheduledToolCall,
    signal: AbortSignal,
  ): Promise<void> {
    // Move existing tool execution logic here
    // (Lines 1053-1203 from current implementation)
  }
}
```

### 3. Configuration Options

Add configuration for parallel execution:

```typescript
// packages/core/src/config/config.ts (additions)

export interface ParallelExecutionConfig {
  /** Enable parallel tool execution */
  enabled: boolean;

  /** Maximum number of tools to run concurrently (default: 5) */
  maxConcurrentTools: number;

  /** Maximum concurrent tools per category */
  maxPerCategory?: {
    network?: number; // Shodan, Censys, URLScan (default: 3)
    malware?: number; // VirusTotal, YARAify, Hybrid Analysis (default: 3)
    filesystem?: number; // Read, Write, Edit (default: 1)
    shell?: number; // Shell commands (default: 1)
  };
}

export interface Config {
  // ... existing config

  getParallelExecutionConfig(): ParallelExecutionConfig;
}
```

**Settings file example:**

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 5,
    "maxPerCategory": {
      "network": 3,
      "malware": 2,
      "filesystem": 1,
      "shell": 1
    }
  }
}
```

### 4. Tool Categorization

Add categories to tools for better resource management:

```typescript
// packages/core/src/tools/tools.ts (additions)

export enum ToolCategory {
  NETWORK = 'network', // Shodan, Censys, URLScan, etc.
  MALWARE_ANALYSIS = 'malware', // VirusTotal, YARAify, Hybrid Analysis
  FILESYSTEM = 'filesystem', // Read, Write, Edit, Glob, Grep
  SHELL = 'shell', // Shell command execution
  BUG_BOUNTY = 'bug_bounty', // Bug bounty platform tools
  INTEL = 'intel', // CVE, Exploit search
  WEB_RECON = 'web_recon', // Nuclei, ffuf, wayback
}

export abstract class BaseDeclarativeTool {
  // ... existing properties

  /** Tool category for resource management */
  readonly category: ToolCategory;

  /** Whether this tool can run in parallel with others */
  readonly canRunInParallel: boolean = true;

  /** List of tool categories this tool conflicts with */
  readonly conflictsWith: ToolCategory[] = [];
}
```

**Example tool categorization:**

```typescript
// packages/core/src/tools/shodan.ts
export class ShodanTool extends BaseDeclarativeTool {
  readonly category = ToolCategory.NETWORK;
  readonly canRunInParallel = true;
}

// packages/core/src/tools/shell.ts
export class ShellTool extends BaseDeclarativeTool {
  readonly category = ToolCategory.SHELL;
  readonly canRunInParallel = true;
  // Multiple shell commands can run in parallel,
  // but we limit concurrency via config
}

// packages/core/src/tools/edit.ts
export class EditTool extends BaseDeclarativeTool {
  readonly category = ToolCategory.FILESYSTEM;
  readonly canRunInParallel = true;
  // Parallel is allowed, but we check for file conflicts
}
```

### 5. Dependency Detection Strategies

#### Strategy 1: Parameter Analysis

Detect if a tool's input references another tool's output:

```typescript
function detectParameterDependencies(
  toolCall: ScheduledToolCall,
  previousCalls: ScheduledToolCall[],
): string[] {
  const dependencies: string[] = [];

  // Check if parameters reference other tool outputs
  // Example: If Tool B uses "{{tool_a_output}}" in its params
  const paramStr = JSON.stringify(toolCall.request.args);

  for (const prevCall of previousCalls) {
    // Check for various reference patterns
    const patterns = [
      new RegExp(`{{${prevCall.request.callId}}}`, 'i'),
      new RegExp(`\\$\\{${prevCall.request.name}\\}`, 'i'),
      new RegExp(`result_of_${prevCall.request.name}`, 'i'),
    ];

    if (patterns.some((pattern) => pattern.test(paramStr))) {
      dependencies.push(prevCall.request.callId);
    }
  }

  return dependencies;
}
```

#### Strategy 2: File System Conflict Detection

Prevent parallel writes to the same file:

```typescript
function detectFileSystemConflicts(
  toolCall: ScheduledToolCall,
  concurrentCalls: ScheduledToolCall[],
): boolean {
  const locations = toolCall.invocation.toolLocations();

  for (const concurrent of concurrentCalls) {
    const concurrentLocations = concurrent.invocation.toolLocations();

    // Check for write-write or write-read conflicts
    for (const loc of locations) {
      for (const concLoc of concurrentLocations) {
        if (filesConflict(loc, concLoc)) {
          return true; // Conflict detected
        }
      }
    }
  }

  return false;
}

function filesConflict(loc1: ToolLocation, loc2: ToolLocation): boolean {
  // Same file path
  if (loc1.path === loc2.path) {
    // Write-Write conflict
    if (loc1.operation === 'write' && loc2.operation === 'write') {
      return true;
    }
    // Write-Read conflict (if tool requires consistent state)
    if (
      (loc1.operation === 'write' && loc2.operation === 'read') ||
      (loc1.operation === 'read' && loc2.operation === 'write')
    ) {
      return true;
    }
  }

  return false;
}
```

#### Strategy 3: Explicit Dependencies

Allow tools to declare explicit dependencies:

```typescript
export class ToolInvocation {
  /**
   * Optional: Explicitly declare tools this invocation depends on
   */
  getDependencies?(): string[] {
    return [];
  }
}

// Example: Custom tool that needs results from Shodan
export class CustomReconInvocation extends BaseToolInvocation {
  getDependencies(): string[] {
    // This tool must run after Shodan completes
    return ['shodan'];
  }
}
```

### 6. Progress Tracking for Parallel Tools

Update UI to show parallel execution progress:

```typescript
// packages/cli/src/ui/components/ToolExecutionProgress.tsx

export const ToolExecutionProgress = ({ toolCalls }: Props) => {
  const executingTools = toolCalls.filter(t => t.status === 'executing');

  return (
    <Box flexDirection="column">
      <Text bold>Executing {executingTools.length} tools in parallel:</Text>
      {executingTools.map(tool => (
        <Box key={tool.request.callId} marginLeft={2}>
          <Text>
            <Spinner type="dots" />
            {' '}
            {tool.tool.displayName}
            {tool.liveOutput && ` - ${formatProgress(tool.liveOutput)}`}
          </Text>
        </Box>
      ))}
    </Box>
  );
};
```

## Implementation Plan

### Phase 1: Foundation (Week 1)

1. ✅ Add `ToolCategory` enum and categorize existing tools
2. ✅ Add `canRunInParallel` property to tools
3. ✅ Create `ParallelExecutionConfig` in settings
4. ✅ Add config getters to `Config` interface

### Phase 2: Dependency Analysis (Week 2)

1. ✅ Create `ToolDependencyAnalyzer` class
2. ✅ Implement parameter-based dependency detection
3. ✅ Implement file system conflict detection
4. ✅ Add `getDependencies()` to `ToolInvocation` interface
5. ✅ Write comprehensive tests for dependency detection

### Phase 3: Parallel Execution (Week 3)

1. ✅ Extract `executeSingleTool()` from `attemptExecutionOfScheduledCalls()`
2. ✅ Implement `executeToolWave()` with concurrency control
3. ✅ Integrate dependency analyzer into scheduler
4. ✅ Add per-category concurrency limits
5. ✅ Ensure AbortSignal works correctly with parallel execution

### Phase 4: UI & Monitoring (Week 4)

1. ✅ Update UI to show parallel tool execution
2. ✅ Add progress indicators for concurrent tools
3. ✅ Implement live output aggregation for parallel tools
4. ✅ Add telemetry for parallel execution metrics

### Phase 5: Testing & Optimization (Week 5)

1. ✅ Integration tests for parallel execution
2. ✅ Performance benchmarks (sequential vs parallel)
3. ✅ Memory usage profiling
4. ✅ Error handling edge cases
5. ✅ Documentation and examples

## Usage Examples

### Example 1: Reconnaissance Suite

```typescript
// User: "Run full recon on target.com"
// DarkCoder automatically parallelizes:

// Wave 1 (all run concurrently):
await Promise.all([
  shodan.scan('target.com'),
  censys.search('target.com'),
  urlscan.analyze('target.com'),
  wayback.enumerate('target.com'),
]);

// Wave 2 (depends on Wave 1 results):
await Promise.all([
  nuclei.scan(discoveredHosts),
  ffuf.fuzz(discoveredEndpoints),
]);
```

### Example 2: Malware Analysis

```typescript
// User: "Analyze suspicious file with all tools"

// Wave 1 (independent hash lookups):
await Promise.all([
  virustotal.lookupHash(fileHash),
  yaraify.lookupHash(fileHash),
]);

// Wave 2 (file upload and analysis):
await Promise.all([
  virustotal.scanFile(filePath),
  yaraify.scanFile(filePath),
  cuckoo.submitFile(filePath), // Long-running, doesn't block others
]);
```

### Example 3: User-Controlled Parallelism

```bash
# Default: Auto-parallel (max 5 concurrent)
darkcoder "Scan target.com with all tools"

# High parallelism for fast scans
darkcoder --parallel-tools 10 "Quick recon on target.com"

# Sequential execution (disable parallelism)
darkcoder --no-parallel "Carefully analyze target.com"

# Custom per-category limits
darkcoder --network-parallel 5 --shell-parallel 1 "Full scan"
```

## Configuration Examples

### Conservative (Default)

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 5,
    "maxPerCategory": {
      "network": 3,
      "malware": 2,
      "filesystem": 1,
      "shell": 1
    }
  }
}
```

### Aggressive (Fast Recon)

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 10,
    "maxPerCategory": {
      "network": 6,
      "malware": 4,
      "filesystem": 2,
      "shell": 2
    }
  }
}
```

### Sequential (Legacy Behavior)

```json
{
  "parallelExecution": {
    "enabled": false,
    "maxConcurrentTools": 1
  }
}
```

## Performance Expectations

### Benchmark Scenarios

| Scenario                        | Sequential Time | Parallel Time | Speedup |
| ------------------------------- | --------------- | ------------- | ------- |
| Basic Recon (4 tools)           | 40s             | 15s           | 2.67x   |
| Full Recon (8 tools)            | 90s             | 30s           | 3.0x    |
| Malware Analysis (6 tools)      | 120s            | 45s           | 2.67x   |
| Bug Bounty Search (5 platforms) | 25s             | 8s            | 3.12x   |

**Expected Average Speedup:** 2.5-3.5x for typical security workflows

## Risk Mitigation

### 1. Resource Exhaustion

**Risk:** Too many concurrent tools overwhelming system
**Mitigation:**

- Default conservative limits (5 concurrent max)
- Per-category limits
- Automatic throttling based on system resources
- User can disable parallelism

### 2. Rate Limiting

**Risk:** Parallel API calls hitting rate limits
**Mitigation:**

- Network tools limited to 3 concurrent by default
- Tools implement exponential backoff
- Config allows per-tool rate limiting

### 3. Dependency Bugs

**Risk:** Missing dependencies causing incorrect results
**Mitigation:**

- Conservative dependency detection (assume dependency if uncertain)
- Comprehensive test suite
- Fallback to sequential on dependency detection failure
- User can force sequential mode

### 4. Error Propagation

**Risk:** One tool failure breaking entire workflow
**Mitigation:**

- `Promise.allSettled()` instead of `Promise.all()`
- Each tool failure recorded independently
- Partial results returned to user
- Clear error attribution to specific tools

## Success Metrics

1. **Performance:**
   - Average workflow completion time reduced by 50%+
   - 90th percentile latency improvement of 60%+

2. **Reliability:**
   - No increase in tool failure rates
   - 99.9% correct dependency ordering

3. **Adoption:**
   - Parallel execution enabled by default
   - <5% of users disabling feature
   - Positive user feedback on speed improvements

4. **Resource Usage:**
   - Memory usage increase <30%
   - CPU usage stays within acceptable limits
   - No system stability issues

## Future Enhancements

1. **Smart Scheduling:**
   - Machine learning to predict optimal concurrency
   - Adaptive limits based on system resources

2. **Distributed Execution:**
   - Run tools across multiple machines
   - Cloud-based tool execution

3. **Streaming Results:**
   - Show results as they complete (don't wait for all)
   - Progressive enhancement of findings

4. **Tool Pipelines:**
   - Define custom tool chains
   - Automatic parallelization of pipelines

## References

- [CoreToolScheduler source](../../packages/core/src/core/coreToolScheduler.ts)
- [Tool architecture](../../packages/core/src/tools/tools.ts)
- [Config system](../../packages/core/src/config/config.ts)
- [p-queue for concurrency control](https://github.com/sindresorhus/p-queue)

## Approval & Sign-off

**Proposed by:** DarkCoder Team
**Status:** 📋 Draft - Awaiting Review
**Target Release:** v0.7.0
