# Memory Management Quick Reference

Quick commands and snippets to prevent heap out of memory errors in DarkCoder.

## Immediate Fix

If you're experiencing heap out of memory errors right now:

```bash
# Set environment variable (temporary - current session only)
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"

# Use safe build script
npm run build:safe
```

## Permanent Fix

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# Add this line to the end of the file
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"
```

Then reload:

```bash
source ~/.bashrc  # or source ~/.zshrc
```

## Build Commands

| Command                 | Memory Limit | Auto-GC | Use Case                  |
| ----------------------- | ------------ | ------- | ------------------------- |
| `npm run build`         | 8GB          | ❌      | Normal builds (may crash) |
| `npm run build:managed` | 8GB          | ✅      | Recommended for local dev |
| `npm run build:safe`    | 16GB         | ✅      | CI/CD, low memory systems |
| `npm run bundle`        | 8GB          | ✅      | Bundle creation           |

## Programmatic Usage

### Start Memory Monitoring

```typescript
import { startMemoryMonitor } from '@darkcoder/darkcoder-cli/utils/memoryMonitor.js';

startMemoryMonitor({
  intervalMs: 30000, // Check every 30s
  autoGC: true, // Auto garbage collection
  verbose: true, // Enable logging
});
```

### Trigger Garbage Collection

```typescript
import { triggerGarbageCollection } from '@darkcoder/darkcoder-cli/utils/memoryMonitor.js';

// Manually trigger GC
if (triggerGarbageCollection()) {
  console.log('GC completed');
}
```

### Check Memory Stats

```typescript
import { getMemoryStats } from '@darkcoder/darkcoder-cli/utils/memoryMonitor.js';

const stats = getMemoryStats();
console.log(`Memory: ${stats.heapUsagePercent}%`);

if (stats.isCritical) {
  console.error('Memory critical!');
}
```

### Use Worker Pool

```typescript
import { createWorkerPool } from '@darkcoder/darkcoder-cli/utils/workerPool.js';

const pool = createWorkerPool('./scripts/buildWorker.js', {
  maxWorkers: 4,
  verbose: true,
});

// Execute task
const result = await pool.exec({
  type: 'buildPackage',
  data: { workspace: 'packages/core' },
});

// Cleanup
await pool.shutdown();
```

## Memory Thresholds

| Level    | Percentage | Action                            |
| -------- | ---------- | --------------------------------- |
| Normal   | 0-74%      | ✅ No action needed               |
| Warning  | 75-89%     | ⚠️ Warning logged                 |
| Critical | 90-100%    | 🚨 Auto-GC triggered (if enabled) |

## Common Issues

### Issue: "Heap out of memory" during build

**Fix:**

```bash
npm run build:safe
```

### Issue: GC not triggering

**Check:**

```bash
echo $NODE_OPTIONS
# Should show: --expose-gc
```

**Fix:**

```bash
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"
```

### Issue: Build too slow

**Fix:** Build specific packages only

```bash
npm run build --workspace=packages/core
```

### Issue: CI/CD running out of memory

**Fix:** Use safe build in CI config

```yaml
# .github/workflows/build.yml
- run: npm run build:safe
  env:
    NODE_OPTIONS: --max-old-space-size=16384 --expose-gc
```

## Environment Variables

```bash
# Recommended default
NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"

# For low memory systems (4GB RAM)
NODE_OPTIONS="--max-old-space-size=4096 --expose-gc"

# For high memory systems (32GB+ RAM)
NODE_OPTIONS="--max-old-space-size=16384 --expose-gc"

# Maximum (64GB systems)
NODE_OPTIONS="--max-old-space-size=32768 --expose-gc"
```

## Monitoring Commands

```bash
# Check Node.js memory settings
node -e "console.log(require('v8').getHeapStatistics())"

# Test GC availability
node --expose-gc -e "console.log(typeof global.gc)"

# Monitor memory during build
npm run build:managed 2>&1 | grep "Memory:"
```

## Best Practices Checklist

- [ ] Set `NODE_OPTIONS` in shell profile
- [ ] Use `npm run build:managed` or `build:safe`
- [ ] Run `npm run clean` before major builds
- [ ] Build packages incrementally when possible
- [ ] Enable auto-GC for long-running processes
- [ ] Monitor memory in development
- [ ] Use worker threads for heavy operations

## API Quick Reference

### Memory Monitor

```typescript
import {
  getMemoryStats, // Get current stats
  checkMemoryUsage, // Check if warning needed
  formatMemoryUsage, // Format as string
  triggerGarbageCollection, // Manual GC
  autoGarbageCollection, // Auto GC if critical
  startMemoryMonitor, // Start monitoring
  stopMemoryMonitor, // Stop monitoring
} from '@darkcoder/darkcoder-cli/utils/memoryMonitor.js';
```

### Worker Pool

```typescript
import {
  WorkerPool,
  createWorkerPool,
} from '@darkcoder/darkcoder-cli/utils/workerPool.js';

const pool = createWorkerPool(scriptPath, config);
await pool.exec(task);
pool.getStats();
await pool.shutdown();
```

## For More Information

See [MEMORY_MANAGEMENT.md](./MEMORY_MANAGEMENT.md) for complete documentation.
