# AI-Driven Parallel Tool Execution

## Overview

This document describes how DarkCoder's AI model automatically determines which tools to run in parallel, making intelligent decisions based on task context, dependencies, and execution strategy.

## Key Concept

**The LLM decides parallelism, not the user or system.**

Instead of:

- ❌ User manually specifying "run these in parallel"
- ❌ System automatically detecting independence
- ❌ Configuration files controlling behavior

We have:

- ✅ **AI model analyzes the task and chooses optimal execution strategy**
- ✅ **LLM can call multiple tools in a single response when beneficial**
- ✅ **AI learns from context which tools can/should run together**

## How It Works

### Current Behavior (Sequential)

```
User: "Scan target.com with Shodan, Censys, and URLScan"

AI Response:
{
  "toolCalls": [
    { "name": "shodan", "args": { "target": "target.com" } }
  ]
}
// Wait for result...

AI Response:
{
  "toolCalls": [
    { "name": "censys", "args": { "query": "target.com" } }
  ]
}
// Wait for result...

AI Response:
{
  "toolCalls": [
    { "name": "urlscan", "args": { "url": "https://target.com" } }
  ]
}
```

**Total time:** ~40 seconds (sequential)

### New Behavior (AI-Driven Parallel)

```
User: "Scan target.com with Shodan, Censys, and URLScan"

AI Response (single turn with multiple tool calls):
{
  "toolCalls": [
    { "id": "call_1", "name": "shodan", "args": { "target": "target.com" } },
    { "id": "call_2", "name": "censys", "args": { "query": "target.com" } },
    { "id": "call_3", "name": "urlscan", "args": { "url": "https://target.com" } }
  ]
}
// All three execute in parallel!
```

**Total time:** ~15 seconds (parallel)

### AI Makes Smart Decisions

The AI model can intelligently decide based on task requirements:

**Example 1: Parallel execution (independent tasks)**

```
User: "Check if this hash is malicious"

AI thinks: "I can query multiple databases simultaneously"

AI Response:
{
  "toolCalls": [
    { "id": "call_1", "name": "virustotal", "args": { "hash": "abc123..." } },
    { "id": "call_2", "name": "yaraify", "args": { "hash": "abc123..." } },
    { "id": "call_3", "name": "check_malware_bazaar", "args": { "hash": "abc123..." } }
  ]
}
```

**Example 2: Sequential execution (dependent tasks)**

```
User: "Scan target.com with Shodan, then run Nuclei on discovered IPs"

AI thinks: "Nuclei needs Shodan results first, so I must run sequentially"

AI Response (Turn 1):
{
  "toolCalls": [
    { "id": "call_1", "name": "shodan", "args": { "target": "target.com" } }
  ]
}

// After Shodan completes...

AI Response (Turn 2):
{
  "toolCalls": [
    { "id": "call_2", "name": "nuclei", "args": { "targets": ["1.2.3.4", "5.6.7.8"] } }
  ]
}
```

**Example 3: Mixed strategy (partial parallel)**

```
User: "Full reconnaissance on target.com"

AI thinks: "Some tasks are independent, others depend on results"

AI Response (Wave 1 - parallel):
{
  "toolCalls": [
    { "id": "call_1", "name": "shodan", "args": { "target": "target.com" } },
    { "id": "call_2", "name": "censys", "args": { "query": "target.com" } },
    { "id": "call_3", "name": "wayback", "args": { "domain": "target.com" } }
  ]
}

// After Wave 1 completes...

AI Response (Wave 2 - parallel, using Wave 1 results):
{
  "toolCalls": [
    { "id": "call_4", "name": "nuclei", "args": { "targets": [...discovered_ips] } },
    { "id": "call_5", "name": "ffuf", "args": { "urls": [...discovered_endpoints] } }
  ]
}
```

## Implementation Architecture

### 1. Enable Multi-Tool Calls in Single Turn

The AI model already supports calling multiple tools in one response. We just need to handle it properly:

```typescript
// packages/core/src/core/coreToolScheduler.ts

/**
 * Current implementation already supports this!
 * The schedule() method accepts ToolCallRequestInfo[]
 */
schedule(
  request: ToolCallRequestInfo | ToolCallRequestInfo[], // ← Already supports arrays!
  signal: AbortSignal,
): Promise<void>
```

**Key insight:** The infrastructure is already there! We just need to:

1. Execute the array of tool calls in parallel (instead of sequential loop)
2. Update the AI's system prompt to encourage multi-tool calls when appropriate

### 2. Modify Tool Execution to Run in Parallel

Current code executes tools sequentially in a `for` loop. Change to parallel execution:

```typescript
// packages/core/src/core/coreToolScheduler.ts (line 1037-1206)

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

    // OLD: Sequential execution
    // for (const toolCall of callsToExecute) {
    //   await this.executeSingleTool(toolCall, signal);
    // }

    // NEW: Parallel execution with Promise.allSettled
    const executions = callsToExecute.map((toolCall) =>
      this.executeSingleTool(toolCall, signal)
    );

    // Wait for all tools to complete (doesn't fail if one tool fails)
    await Promise.allSettled(executions);
  }
}

private async executeSingleTool(
  toolCall: ScheduledToolCall,
  signal: AbortSignal,
): Promise<void> {
  // Extract existing tool execution logic here (lines 1053-1203)
  // Each tool runs independently in its own promise
}
```

**That's it!** The scheduler already:

- ✅ Handles multiple tool calls
- ✅ Tracks each tool's status independently
- ✅ Supports AbortSignal for cancellation
- ✅ Has live output callbacks for streaming

We just need to change from sequential `for` loop to parallel `Promise.allSettled()`.

### 3. Update AI System Prompt

Add guidance to the AI's system instructions to encourage intelligent parallel execution:

```typescript
// packages/core/src/core/prompts.ts

export const PARALLEL_EXECUTION_GUIDANCE = `
# Multi-Tool Parallel Execution

You can call multiple tools in a single response when they are independent and can run concurrently. This significantly improves performance for security operations.

## When to Use Parallel Execution

**DO use multiple tool calls in one response when:**
1. Tools are querying different data sources (Shodan, Censys, VirusTotal, etc.)
2. Tools operate on the same input but independently (hash lookups across multiple databases)
3. Tools scan different aspects of the same target (port scan + cert check + historical data)
4. Tasks are time-consuming and independent (multiple network reconnaissance tools)

**Example - Parallel Hash Lookup:**
\`\`\`json
{
  "toolCalls": [
    { "id": "call_1", "name": "virustotal", "args": { "operation": "lookup_hash", "hash": "abc123..." } },
    { "id": "call_2", "name": "yaraify", "args": { "operation": "lookup_hash", "hash": "abc123..." } },
    { "id": "call_3", "name": "malware_bazaar", "args": { "hash": "abc123..." } }
  ]
}
\`\`\`

**Example - Parallel Reconnaissance:**
\`\`\`json
{
  "toolCalls": [
    { "id": "call_1", "name": "shodan", "args": { "searchType": "host", "ip": "8.8.8.8" } },
    { "id": "call_2", "name": "censys", "args": { "searchType": "hosts", "query": "ip:8.8.8.8" } },
    { "id": "call_3", "name": "urlscan", "args": { "searchType": "ip", "ip": "8.8.8.8" } }
  ]
}
\`\`\`

**DO NOT use parallel execution when:**
1. One tool needs the output of another tool (dependencies)
2. Tools might conflict (writing to the same file)
3. Sequential execution is logically necessary (download → analyze → report)
4. User explicitly requests step-by-step analysis

**Example - Sequential (Dependencies):**
\`\`\`json
// Turn 1: Get target info
{
  "toolCalls": [
    { "id": "call_1", "name": "shodan", "args": { "searchType": "host", "ip": "target.com" } }
  ]
}

// Turn 2: Use Shodan results for targeted scanning
{
  "toolCalls": [
    { "id": "call_2", "name": "nuclei", "args": { "targets": ["discovered_ip_1", "discovered_ip_2"] } }
  ]
}
\`\`\`

## Performance Considerations

Parallel execution can provide **2-4x speedup** for typical security workflows:
- Hash lookups: 3x faster (multiple databases queried simultaneously)
- Reconnaissance: 2.5x faster (Shodan + Censys + URLScan in parallel)
- Multi-platform searches: 4x faster (bug bounty platforms queried concurrently)

Always prefer parallel execution when tasks are independent - it significantly improves user experience during security engagements.
`;
```

Add this to the system prompt:

```typescript
// packages/core/src/core/contentGenerator.ts

const systemInstruction = `
${BASE_SYSTEM_PROMPT}

${PARALLEL_EXECUTION_GUIDANCE}

${TOOL_USAGE_INSTRUCTIONS}
...
`;
```

### 4. Handle Concurrent Tool Output in UI

Update the UI to show multiple tools executing simultaneously:

```typescript
// packages/cli/src/ui/components/messages/ToolExecutionMessage.tsx

export const ToolExecutionMessage = ({ toolCalls }: Props) => {
  const executingTools = toolCalls.filter(t => t.status === 'executing');

  if (executingTools.length > 1) {
    // Multiple tools running in parallel
    return (
      <Box flexDirection="column">
        <Text bold color="cyan">
          ⚡ Executing {executingTools.length} tools in parallel:
        </Text>
        {executingTools.map(tool => (
          <Box key={tool.request.callId} marginLeft={2}>
            <Text>
              <Spinner type="dots" /> {tool.tool.displayName}
              {tool.liveOutput && ` - ${truncate(tool.liveOutput.text, 50)}`}
            </Text>
          </Box>
        ))}
      </Box>
    );
  } else {
    // Single tool execution (existing UI)
    return <SingleToolExecution tool={executingTools[0]} />;
  }
};
```

## Benefits of AI-Driven Approach

### 1. **Zero Configuration**

- Users don't need to configure anything
- No settings files to manage
- No understanding of parallel vs sequential

### 2. **Context-Aware Decisions**

- AI considers the specific task
- AI knows which tools can run together
- AI adapts to different scenarios automatically

### 3. **Optimal Performance**

- AI maximizes parallelism when safe
- AI respects dependencies automatically
- AI learns from tool descriptions and behaviors

### 4. **Natural User Experience**

- User asks for what they want
- AI figures out the best execution strategy
- Results appear faster without user intervention

### 5. **Flexibility**

- AI can mix parallel and sequential in same workflow
- AI can adjust strategy based on intermediate results
- AI can optimize for different objectives (speed vs accuracy)

## Real-World Examples

### Example 1: Malware Hash Analysis

**User Query:**

```
"Check if this file hash is malicious: d41d8cd98f00b204e9800998ecf8427e"
```

**AI Decision:**

```typescript
// AI thinks: "All these databases can be queried independently"
{
  "toolCalls": [
    { "id": "vt", "name": "virustotal", "args": { "operation": "lookup_hash", "hash": "d41d8cd..." } },
    { "id": "yara", "name": "yaraify", "args": { "operation": "lookup_hash", "hash": "d41d8cd..." } },
    { "id": "mwdb", "name": "malware_bazaar", "args": { "hash": "d41d8cd..." } }
  ]
}
```

**Result:** 3x faster than sequential

### Example 2: Target Reconnaissance

**User Query:**

```
"Do full reconnaissance on acme.com"
```

**AI Decision (Multi-Wave):**

**Wave 1 (Parallel):**

```typescript
{
  "toolCalls": [
    { "id": "shodan", "name": "shodan", "args": { "searchType": "dns", "hostname": "acme.com" } },
    { "id": "censys", "name": "censys", "args": { "searchType": "certificates", "query": "parsed.names: acme.com" } },
    { "id": "wayback", "name": "wayback_machine", "args": { "target": "acme.com", "searchType": "urls" } },
    { "id": "urlscan", "name": "urlscan", "args": { "searchType": "domain", "domain": "acme.com" } }
  ]
}
```

**Wave 2 (After analyzing Wave 1 results - Parallel):**

```typescript
{
  "toolCalls": [
    { "id": "nuclei1", "name": "nuclei", "args": { "target": "discovered_subdomain1.acme.com" } },
    { "id": "nuclei2", "name": "nuclei", "args": { "target": "discovered_subdomain2.acme.com" } },
    { "id": "ffuf", "name": "ffuf", "args": { "url": "https://acme.com", "wordlist": "common.txt" } }
  ]
}
```

**Result:** 2.5-3x faster overall

### Example 3: Bug Bounty Program Search

**User Query:**

```
"Find high-paying Web3 bug bounty programs"
```

**AI Decision:**

```typescript
// AI thinks: "All platforms can be searched independently"
{
  "toolCalls": [
    { "id": "h1", "name": "bug_bounty", "args": { "operation": "search", "platform": "hackerone", "query": "web3" } },
    { "id": "bc", "name": "bug_bounty", "args": { "operation": "search", "platform": "bugcrowd", "query": "web3" } },
    { "id": "imm", "name": "bug_bounty", "args": { "operation": "search", "platform": "immunefi", "query": "web3" } },
    { "id": "int", "name": "bug_bounty", "args": { "operation": "search", "platform": "intigriti", "query": "web3" } },
    { "id": "ywh", "name": "bug_bounty", "args": { "operation": "search", "platform": "yeswehack", "query": "web3" } }
  ]
}
```

**Result:** 5x faster than sequential

### Example 4: Smart Sequential (Dependency)

**User Query:**

```
"Scan target.com with Shodan and then run Nuclei on any discovered web servers"
```

**AI Decision:**

**Turn 1:**

```typescript
// AI thinks: "I need Shodan results first to find targets for Nuclei"
{
  "toolCalls": [
    { "id": "shodan", "name": "shodan", "args": { "searchType": "host", "ip": "target.com" } }
  ]
}
```

**Turn 2 (After Shodan completes):**

```typescript
// AI thinks: "Now I have discovered IPs, run Nuclei on each"
{
  "toolCalls": [
    { "id": "nuclei1", "name": "nuclei", "args": { "target": "192.0.2.1:443" } },
    { "id": "nuclei2", "name": "nuclei", "args": { "target": "192.0.2.2:8080" } },
    { "id": "nuclei3", "name": "nuclei", "args": { "target": "192.0.2.3:80" } }
  ]
}
```

**Result:** Optimal strategy (sequential when needed, parallel when possible)

## Implementation Checklist

### Phase 1: Core Changes (1-2 days)

- [ ] Change `attemptExecutionOfScheduledCalls()` from sequential `for` loop to `Promise.allSettled()`
- [ ] Extract `executeSingleTool()` method from existing tool execution logic
- [ ] Test parallel execution with 2-3 simple tools
- [ ] Ensure AbortSignal works correctly with parallel execution

### Phase 2: UI Updates (1 day)

- [ ] Update `ToolExecutionMessage` to show multiple executing tools
- [ ] Add parallel execution indicator (⚡ icon)
- [ ] Handle live output from multiple tools simultaneously
- [ ] Test UI with various tool combinations

### Phase 3: AI Prompt Engineering (2-3 days)

- [ ] Add `PARALLEL_EXECUTION_GUIDANCE` to system prompt
- [ ] Provide clear examples of when to parallelize
- [ ] Add tool descriptions indicating independence
- [ ] Test AI's decision-making with various queries

### Phase 4: Testing & Refinement (3-4 days)

- [ ] Integration tests for parallel execution
- [ ] Test error handling (one tool fails, others continue)
- [ ] Test cancellation (abort all parallel tools)
- [ ] Performance benchmarks (sequential vs parallel)
- [ ] Edge case testing (file conflicts, rate limits, etc.)

### Phase 5: Documentation (1 day)

- [ ] Update README with parallel execution examples
- [ ] Add user-facing documentation
- [ ] Create troubleshooting guide
- [ ] Document AI decision-making patterns

**Total estimated time:** 8-11 days

## Code Changes Required

### Minimal Changes Needed

The beauty of this approach is that **most infrastructure already exists**! Here's what needs to change:

**File 1: `packages/core/src/core/coreToolScheduler.ts`**

```typescript
// CHANGE: Line 1053-1206 (attemptExecutionOfScheduledCalls method)

// BEFORE (Sequential):
for (const toolCall of callsToExecute) {
  await this.executeSingleTool(toolCall, signal);
}

// AFTER (Parallel):
const executions = callsToExecute.map((toolCall) =>
  this.executeSingleTool(toolCall, signal),
);
await Promise.allSettled(executions);
```

**File 2: `packages/core/src/core/prompts.ts`**

```typescript
// ADD: Parallel execution guidance to system prompt
export const PARALLEL_EXECUTION_GUIDANCE = `...`;

// UPDATE: Include in main system prompt
export function getSystemPrompt(config: Config): string {
  return `
    ${BASE_INSTRUCTIONS}
    ${PARALLEL_EXECUTION_GUIDANCE}
    ${TOOL_INSTRUCTIONS}
  `;
}
```

**File 3: `packages/cli/src/ui/components/messages/ToolExecutionMessage.tsx`**

```typescript
// UPDATE: Show multiple tools executing
if (executingTools.length > 1) {
  return <ParallelToolExecutionView tools={executingTools} />;
} else {
  return <SingleToolExecutionView tool={executingTools[0]} />;
}
```

That's it! **~100 lines of code changes total.**

## Success Metrics

### Performance Improvements

- **Target:** 2-3x average speedup for multi-tool queries
- **Measurement:** Track execution time before/after for common patterns

### AI Decision Quality

- **Target:** 95%+ correct parallelization decisions
- **Measurement:** Manual review of AI's tool call patterns

### User Satisfaction

- **Target:** Faster engagement workflows
- **Measurement:** User feedback, time-to-results metrics

### System Stability

- **Target:** No increase in error rates
- **Measurement:** Monitor tool failure rates, error logs

## Risks & Mitigation

### Risk 1: AI Makes Wrong Decisions

**Mitigation:**

- Clear prompt guidance with examples
- Conservative approach (when in doubt, sequential)
- User can force sequential via prompt ("carefully", "step by step")

### Risk 2: Resource Exhaustion

**Mitigation:**

- Optional max concurrency limit in config (default: 10)
- System monitoring for resource usage
- Graceful degradation if system overloaded

### Risk 3: Rate Limiting

**Mitigation:**

- Tools implement exponential backoff
- AI learns from failures
- User can specify "slowly" in prompt

### Risk 4: Dependency Bugs

**Mitigation:**

- Comprehensive testing
- Clear tool descriptions
- Fallback to sequential on ambiguous cases

## Future Enhancements

1. **Learning from History:**
   - AI learns which tool combinations work well together
   - Adaptive optimization based on past performance

2. **Dynamic Concurrency:**
   - Adjust parallelism based on system resources
   - Throttle automatically on rate limit errors

3. **User Preferences:**
   - Learn user preferences (fast vs careful)
   - Personalize execution strategy

4. **Advanced Scheduling:**
   - Priority-based execution
   - Resource-aware scheduling

## Conclusion

AI-driven parallel execution is **simple, powerful, and requires minimal code changes**. The AI model already has the capability to call multiple tools - we just need to:

1. Execute them in parallel instead of sequentially
2. Guide the AI to make smart parallelization decisions
3. Update the UI to show concurrent execution

**Result:** 2-3x performance improvement with zero user configuration and intelligent, context-aware execution strategy.
