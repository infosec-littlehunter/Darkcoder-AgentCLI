# Memory Management Guide

This guide explains how to prevent and resolve heap out of memory errors in DarkCoder using the built-in memory management features.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Memory Monitoring](#memory-monitoring)
- [Worker Thread Pool](#worker-thread-pool)
- [Build Scripts with Memory Management](#build-scripts-with-memory-management)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

DarkCoder is a large TypeScript monorepo that can encounter memory issues during build operations. This guide covers the memory management utilities designed to prevent heap out of memory errors.

### Common Symptoms

```
FATAL ERROR: Ineffective mark-compacts near heap limit
Allocation failed - JavaScript heap out of memory
```

## Quick Start

### 1. Set Global Node Memory Limit

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"
```

Then reload your shell:

```bash
source ~/.bashrc  # or source ~/.zshrc
```

### 2. Use Memory-Managed Build Scripts

Instead of `npm run build`, use:

```bash
# Standard build with memory management (8GB limit + auto-GC)
npm run build:managed

# Safe build for limited memory systems (16GB limit + auto-GC)
npm run build:safe
```

### 3. Monitor Memory Usage

The memory monitor is automatically integrated into the managed build scripts. You can also use it programmatically:

```typescript
import { startMemoryMonitor } from '@darkcoder/darkcoder-cli/utils/memoryMonitor.js';

startMemoryMonitor({
  intervalMs: 30000, // Check every 30 seconds
  autoGC: true, // Enable automatic garbage collection
  verbose: true, // Enable detailed logging
  onWarning: (msg) => console.warn(msg),
  onCritical: (msg) => console.error(msg),
});
```

## Memory Monitoring

### Features

The memory monitoring utility provides:

- **Real-time memory tracking**: Monitors heap usage at configurable intervals
- **Automatic garbage collection**: Triggers GC when memory usage exceeds 90%
- **Cooldown period**: Prevents excessive GC calls (30-second cooldown)
- **Warning thresholds**:
  - Warning at 75% usage
  - Critical at 90% usage

### API Reference

#### `getMemoryStats()`

Returns current memory statistics:

```typescript
const stats = getMemoryStats();
// {
//   heapUsedMB: 1024.50,
//   heapLimitMB: 8192.00,
//   heapUsagePercent: 13,
//   isWarning: false,
//   isCritical: false
// }
```

#### `checkMemoryUsage()`

Returns a warning message if memory usage is high:

```typescript
const warning = checkMemoryUsage();
if (warning) {
  console.warn(warning);
}
```

#### `formatMemoryUsage()`

Returns formatted memory usage string:

```typescript
console.log(formatMemoryUsage());
// Output: "1024.50MB / 8192.00MB (13%)"
```

#### `triggerGarbageCollection()`

Manually triggers garbage collection (requires `--expose-gc` flag):

```typescript
const triggered = triggerGarbageCollection();
if (triggered) {
  console.log('GC completed');
}
```

#### `autoGarbageCollection()`

Automatically triggers GC if memory is critical:

```typescript
const triggered = autoGarbageCollection();
// Returns true if GC was triggered, false otherwise
```

#### `startMemoryMonitor(config)`

Starts periodic memory monitoring:

```typescript
interface MemoryMonitorConfig {
  intervalMs?: number; // Default: 60000 (1 minute)
  onWarning?: (msg: string) => void;
  onCritical?: (msg: string) => void;
  autoGC?: boolean; // Default: false
  verbose?: boolean; // Default: false
}

startMemoryMonitor({
  intervalMs: 30000,
  autoGC: true,
  verbose: true,
});
```

#### `stopMemoryMonitor()`

Stops the memory monitor:

```typescript
stopMemoryMonitor();
```

## Worker Thread Pool

For offloading heavy operations to separate threads, preventing main thread memory overflow.

### Features

- **Automatic worker management**: Creates/destroys workers based on load
- **Task queuing**: Handles concurrent tasks efficiently
- **Idle timeout**: Terminates unused workers after timeout
- **Memory isolation**: Each worker has its own memory space

### Usage Example

```typescript
import { createWorkerPool } from '@darkcoder/darkcoder-cli/utils/workerPool.js';

// Create a worker pool
const pool = createWorkerPool('./buildWorker.js', {
  maxWorkers: 4, // Max concurrent workers
  minWorkers: 0, // Keep 0 workers alive when idle
  idleTimeout: 60000, // Terminate idle workers after 60s
  verbose: true,
});

// Execute tasks
try {
  const result = await pool.exec({
    type: 'buildPackage',
    data: { workspace: 'packages/core' },
  });

  console.log('Build result:', result);
} catch (error) {
  console.error('Build failed:', error);
}

// Get statistics
const stats = pool.getStats();
console.log('Pool stats:', stats);
// {
//   totalWorkers: 2,
//   busyWorkers: 1,
//   idleWorkers: 1,
//   queuedTasks: 3,
//   totalTasksCompleted: 42
// }

// Shutdown when done
await pool.shutdown();
```

### Built-in Build Worker

DarkCoder includes a pre-built worker for common build tasks:

```typescript
import { createWorkerPool } from '@darkcoder/darkcoder-cli/utils/workerPool.js';

const pool = createWorkerPool('./scripts/buildWorker.js');

// Build a package
await pool.exec({
  type: 'buildPackage',
  data: { workspace: 'packages/core' },
});

// Run type checking
await pool.exec({
  type: 'typecheck',
  data: { workspace: 'packages/cli' },
});

// Run tests
await pool.exec({
  type: 'test',
  data: { workspace: 'core', testPath: 'src/tools' },
});

// Lint code
await pool.exec({
  type: 'lint',
  data: { fix: true },
});

// Clean artifacts
await pool.exec({
  type: 'clean',
  data: { workspace: 'packages/cli' },
});
```

## Build Scripts with Memory Management

### Available Scripts

#### `npm run build:managed`

Standard build with memory management:

- 8GB heap limit
- Auto-GC enabled
- Memory monitoring every 30 seconds
- Sequential package builds to reduce memory pressure

#### `npm run build:safe`

Safe build for memory-constrained systems:

- 16GB heap limit
- Auto-GC enabled
- All memory monitoring features
- Recommended for CI/CD environments

#### `npm run bundle`

Bundle creation with GC support:

- Includes `--expose-gc` flag
- Automatic garbage collection during bundle creation

### Script Features

The enhanced build script (`build-with-memory-management.js`) provides:

1. **Pre-build memory checks**: Verifies available memory before starting
2. **Per-step monitoring**: Logs memory usage before/after each build step
3. **Automatic GC**: Triggers garbage collection when memory is high
4. **Sequential builds**: Builds packages one at a time to reduce peak memory
5. **Error recovery**: Logs memory state on failures for debugging

### Example Output

```
🚀 Starting build with memory management...

💾 Memory: 512.34MB / 8192.00MB (6%)
📦 Building package: core...
💾 Memory: 512.34MB / 8192.00MB (6%)
✅ Building package: core completed in 12.34s
💾 Memory: 1024.50MB / 8192.00MB (13%)

📦 Building package: cli...
💾 Memory: 1024.50MB / 8192.00MB (13%)
⚠️  High memory usage: 78% (6400.00MB / 8192.00MB)
♻️  Triggering garbage collection...
✅ GC complete. Freed 512.25MB
💾 Memory: 6144.00MB / 8192.00MB (75%)
✅ Building package: cli completed in 18.52s

✅ Build completed successfully!
💾 Memory: 2048.75MB / 8192.00MB (25%)
```

## Best Practices

### 1. Set Global Memory Limits

Always set `NODE_OPTIONS` in your environment:

```bash
# Add to ~/.bashrc or ~/.zshrc
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"
```

### 2. Use Managed Build Scripts

Prefer memory-managed scripts for all builds:

```bash
# Good
npm run build:managed

# Better (for CI/CD)
npm run build:safe

# Avoid for large builds
npm run build  # No memory management
```

### 3. Monitor Memory During Development

Start the memory monitor at application startup:

```typescript
if (process.env.NODE_ENV === 'development') {
  startMemoryMonitor({
    intervalMs: 30000,
    autoGC: true,
    verbose: true,
  });
}
```

### 4. Use Worker Threads for Heavy Operations

Offload CPU/memory-intensive tasks to workers:

```typescript
// Instead of this (blocks main thread)
const result = heavyComputation(data);

// Do this (isolated in worker thread)
const result = await workerPool.exec({
  type: 'heavyComputation',
  data,
});
```

### 5. Clean Build Artifacts Regularly

Remove old build files to free up memory:

```bash
npm run clean
```

### 6. Build Incrementally

Build specific packages instead of everything:

```bash
# Build only what changed
npm run build --workspace=packages/core
npm run build --workspace=packages/cli

# Instead of
npm run build  # Builds everything
```

## Troubleshooting

### Problem: Still Getting Heap Out of Memory Errors

**Solution 1**: Increase memory limit

```bash
# Try 16GB
export NODE_OPTIONS="--max-old-space-size=16384 --expose-gc"
```

**Solution 2**: Use the safe build script

```bash
npm run build:safe
```

**Solution 3**: Build packages individually

```bash
npm run clean
npm run build --workspace=packages/core
npm run build --workspace=packages/cli
```

### Problem: GC Not Triggering

**Check**: Is `--expose-gc` flag enabled?

```bash
# Check current NODE_OPTIONS
echo $NODE_OPTIONS

# Should include --expose-gc
# If not, set it:
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"
```

**Verify**: Test GC manually

```javascript
node --expose-gc -e "console.log(typeof global.gc); global.gc()"
// Should print: function
```

### Problem: Workers Not Starting

**Check**: Worker script path is correct

```typescript
// Use absolute path
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const workerPath = join(__dirname, 'scripts/buildWorker.js');

const pool = createWorkerPool(workerPath);
```

### Problem: Memory Monitor Not Showing Logs

**Check**: Verbose mode is enabled

```typescript
startMemoryMonitor({
  verbose: true, // Enable logging
  autoGC: true,
});
```

### Problem: Build Slow with Memory Management

This is expected! Memory-managed builds are slower because they:

- Check memory frequently
- Trigger GC when needed
- Build packages sequentially

**Trade-off**: Slower builds vs. preventing crashes

If you need speed and have enough memory:

```bash
npm run build  # Faster but may crash on low memory
```

If you need stability:

```bash
npm run build:safe  # Slower but more reliable
```

## Advanced Configuration

### Custom Worker Script

Create your own worker for custom tasks:

```javascript
// myWorker.js
import { parentPort } from 'node:worker_threads';

parentPort.on('message', async (task) => {
  try {
    const result = await processTask(task);
    parentPort.postMessage({ success: true, result });
  } catch (error) {
    parentPort.postMessage({
      success: false,
      error: error.message,
    });
  }
});
```

```typescript
// Use your worker
const pool = createWorkerPool('./myWorker.js', {
  maxWorkers: 8,
  verbose: true,
});

await pool.exec({ type: 'myTask', data: { ... } });
```

### Integration with Build Tools

```typescript
// esbuild plugin
import { Plugin } from 'esbuild';
import { startMemoryMonitor } from './utils/memoryMonitor.js';

export const memoryMonitorPlugin: Plugin = {
  name: 'memory-monitor',
  setup(build) {
    build.onStart(() => {
      startMemoryMonitor({ autoGC: true, verbose: true });
    });

    build.onEnd(() => {
      stopMemoryMonitor();
    });
  },
};
```

## CI/CD Recommendations

### GitHub Actions

```yaml
name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Build with memory management
        run: npm run build:safe
        env:
          NODE_OPTIONS: --max-old-space-size=16384 --expose-gc
```

### Docker

```dockerfile
FROM node:20-alpine

# Set memory limits
ENV NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"

# Build with memory management
RUN npm run build:managed
```

## Performance Impact

### Memory Monitoring

- **CPU overhead**: ~0.1% (checks every 30-60s)
- **Memory overhead**: Negligible (~1MB)
- **Build time impact**: 0-2% slower

### Auto-GC

- **CPU overhead**: 1-5% (when triggered)
- **Memory reclaimed**: 20-50% (varies by usage)
- **Cooldown period**: 30 seconds between GC calls

### Worker Threads

- **Memory overhead**: ~50MB per worker
- **CPU overhead**: Thread creation/destruction cost
- **Build time**: Can be 20-30% slower for sequential builds, but prevents crashes

## Related Documentation

- [Node.js Memory Management](https://nodejs.org/en/docs/guides/simple-profiling/)
- [V8 Heap Statistics](https://nodejs.org/api/v8.html#v8getheapstatistics)
- [Worker Threads](https://nodejs.org/api/worker_threads.html)
- [TypeScript Project References](https://www.typescriptlang.org/docs/handbook/project-references.html)
