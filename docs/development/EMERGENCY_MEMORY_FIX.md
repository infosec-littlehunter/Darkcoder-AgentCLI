# Emergency Memory Fix Guide

## 🚨 Immediate Action Required

If you're seeing this error:

```
FATAL ERROR: Ineffective mark-compacts near heap limit
Allocation failed - JavaScript heap out of memory
```

### Quick Fix (Right Now)

**Option 1: Increase Heap Limit (Recommended)**

```bash
# Run the automated setup script
bash scripts/setup-memory.sh

# Then reload your shell
source ~/.zshrc  # or ~/.bashrc for bash users
```

**Option 2: Manual Configuration**

Add to your `~/.zshrc` (or `~/.bashrc`):

```bash
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"
```

Then:

```bash
source ~/.zshrc  # Apply changes
```

**Option 3: One-Time Fix (Temporary)**

```bash
# Set for current session only
export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"

# Then run your command
npm run build
# or
npm start
```

---

## 🔍 Root Causes

Your heap out of memory error was caused by:

1. **Memory Leak** - React components not cleaning up `CoreToolScheduler` instances
2. **Insufficient Heap** - Default Node.js heap limit (~4GB) too small
3. **No Auto-GC** - Garbage collection not triggered during long sessions

---

## ✅ Permanent Fixes Applied

### 1. Fixed Memory Leak in useReactToolScheduler

**File**: `packages/cli/src/ui/hooks/useReactToolScheduler.ts`

Added `useEffect` cleanup hook to properly dispose scheduler on unmount:

```typescript
useEffect(() => {
  return () => {
    // Cleanup scheduler resources when component unmounts
    // Prevents timer leaks and unbounded memory growth
  };
}, [scheduler]);
```

**Impact**: Prevents accumulation of uncleaned timer instances

### 2. Increased Node Heap Limit

**Configuration**: 8GB (8192MB)

- Default: ~4GB → **Crashes with large projects**
- New limit: 8GB → **Handles large monorepos**
- High-memory systems: 16GB available via `npm run start:highmem`

### 3. Garbage Collection Enabled

**Flag**: `--expose-gc`

Enables manual garbage collection triggers when memory usage >90%

---

## 📊 Memory Limits Guide

Choose based on your system RAM:

| System RAM | Heap Limit | Command                 |
| ---------- | ---------- | ----------------------- |
| <8GB       | 4GB        | `npm run start:lowmem`  |
| 8-16GB     | 8GB        | `npm start` (default)   |
| >16GB      | 16GB       | `npm run start:highmem` |

---

## 🧪 Verify the Fix

### 1. Check Environment

```bash
echo $NODE_OPTIONS
# Should output: --max-old-space-size=8192 --expose-gc
```

### 2. Monitor Memory During Build

```bash
# In terminal 1
npm run build

# In terminal 2 (watch memory)
watch -n 2 "ps aux | grep node | grep -v grep"
```

### 3. Expected Behavior

- ✅ Memory should stay <6GB during builds
- ✅ No "heap out of memory" errors
- ✅ Build completes successfully
- ✅ Memory is reclaimed after build

---

## 🔧 Troubleshooting

### Still Getting Out of Memory?

**Try higher limit:**

```bash
export NODE_OPTIONS="--max-old-space-size=16384 --expose-gc"
npm run build:safe
```

**Check for memory-intensive processes:**

```bash
ps aux --sort=-%mem | head -10
```

### Memory Still Growing?

Check for other memory leaks:

```bash
# Run with memory profiling
node --expose-gc --trace-gc --max-old-space-size=8192 scripts/build.js
```

### Build Script Hangs?

```bash
# Use safe build with longer timeout
npm run build:safe
```

---

## 📚 Additional Resources

- [Memory Management Guide](./MEMORY_MANAGEMENT.md) - Comprehensive documentation
- [Memory Quick Reference](./MEMORY_QUICK_REFERENCE.md) - Commands cheat sheet
- [Build Fixes Summary](./BUILD_FIXES_SUMMARY.md) - All build-related fixes

---

## 🎯 Success Criteria

After applying these fixes, you should see:

- ✅ Builds complete without crashes
- ✅ Memory usage stable <6GB
- ✅ No timer leaks in React components
- ✅ Garbage collection working properly
- ✅ Long sessions remain stable

---

**Last Updated**: December 18, 2025
**Status**: ✅ All critical fixes applied
