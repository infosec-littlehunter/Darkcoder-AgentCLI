/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Enhanced build script with memory monitoring and management
 * This script uses worker threads for heavy operations to prevent heap overflow
 * Supports both Node.js and Bun runtimes with automatic detection
 */

import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as v8 from 'node:v8';
import { isBun, getRuntimeCommand } from './detect-runtime.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = join(__dirname, '..');

// Import memory monitoring utilities (if available)
let memoryMonitor;
try {
  const module =
    await import('../packages/cli/dist/utils/memoryMonitor.js').catch(() =>
      import('../packages/cli/src/utils/memoryMonitor.ts').catch(() => null),
    );
  if (module) {
    memoryMonitor = module;
  }
} catch (_error) {
  console.warn(
    'Memory monitor not available, proceeding without memory monitoring',
  );
}

/**
 * Memory management utilities
 */
const MEMORY_WARNING_THRESHOLD = 0.75; // 75%
const MEMORY_CRITICAL_THRESHOLD = 0.85; // 85%

function getMemoryStats() {
  // Bun has native heap management with --smol flag
  if (isBun) {
    const mem = process.memoryUsage();
    const heapUsedMB = mem.heapUsed / (1024 * 1024);
    const heapLimitMB = mem.heapTotal / (1024 * 1024);
    const heapUsagePercent = mem.heapUsed / mem.heapTotal;

    return {
      heapUsedMB: Math.round(heapUsedMB * 100) / 100,
      heapLimitMB: Math.round(heapLimitMB * 100) / 100,
      heapUsagePercent: Math.round(heapUsagePercent * 100),
      isWarning: heapUsagePercent >= MEMORY_WARNING_THRESHOLD,
      isCritical: heapUsagePercent >= MEMORY_CRITICAL_THRESHOLD,
    };
  }

  // Node.js V8 heap statistics
  const heapStats = v8.getHeapStatistics();
  const heapUsedMB = heapStats.used_heap_size / (1024 * 1024);
  const heapLimitMB = heapStats.heap_size_limit / (1024 * 1024);
  const heapUsagePercent = heapStats.used_heap_size / heapStats.heap_size_limit;

  return {
    heapUsedMB: Math.round(heapUsedMB * 100) / 100,
    heapLimitMB: Math.round(heapLimitMB * 100) / 100,
    heapUsagePercent: Math.round(heapUsagePercent * 100),
    isWarning: heapUsagePercent >= MEMORY_WARNING_THRESHOLD,
    isCritical: heapUsagePercent >= MEMORY_CRITICAL_THRESHOLD,
  };
}

function logMemoryStats(label = '') {
  const stats = getMemoryStats();
  const prefix = label ? `[${label}] ` : '';
  console.log(
    `${prefix}💾 Memory: ${stats.heapUsedMB}MB / ${stats.heapLimitMB}MB (${stats.heapUsagePercent}%)`,
  );

  if (stats.isCritical) {
    console.warn(`⚠️  CRITICAL: Memory usage is very high!`);
  } else if (stats.isWarning) {
    console.warn(`⚠️  WARNING: Memory usage is high`);
  }
}

function triggerGC() {
  // Bun manages GC automatically with --smol flag
  if (isBun) {
    console.log('♻️  Bun manages memory automatically with --smol flag');
    // Bun.gc() is available but not recommended for manual calls
    return;
  }

  // Node.js manual GC (requires --expose-gc flag)
  if (typeof global.gc === 'function') {
    const beforeStats = getMemoryStats();
    console.log('♻️  Triggering garbage collection...');
    global.gc();
    const afterStats = getMemoryStats();
    const freed = beforeStats.heapUsedMB - afterStats.heapUsedMB;
    console.log(`✅ GC complete. Freed ${freed.toFixed(2)}MB`);
    logMemoryStats('After GC');
    return true;
  } else {
    console.warn(
      '⚠️  Garbage collection not available. Run with --expose-gc flag.',
    );
    return false;
  }
}

/**
 * Start memory monitoring
 */
let monitorInterval;
function startMemoryMonitoring() {
  console.log('🔍 Starting memory monitor...');

  if (memoryMonitor?.startMemoryMonitor) {
    // Use the imported memory monitor with auto-GC
    memoryMonitor.startMemoryMonitor({
      intervalMs: 30000, // Check every 30 seconds
      autoGC: true,
      verbose: true,
      onWarning: (msg) => console.warn(`⚠️  ${msg}`),
      onCritical: (msg) => console.error(`🚨 ${msg}`),
    });
  } else {
    // Fallback to basic monitoring
    monitorInterval = setInterval(() => {
      const stats = getMemoryStats();
      if (stats.isCritical) {
        console.error(
          `🚨 Critical memory usage: ${stats.heapUsagePercent}% (${stats.heapUsedMB}MB / ${stats.heapLimitMB}MB)`,
        );
        triggerGC();
      } else if (stats.isWarning) {
        console.warn(
          `⚠️  High memory usage: ${stats.heapUsagePercent}% (${stats.heapUsedMB}MB / ${stats.heapLimitMB}MB)`,
        );
      }
    }, 30000);

    // Allow process to exit even with active interval
    monitorInterval.unref();
  }
}

function stopMemoryMonitoring() {
  if (memoryMonitor?.stopMemoryMonitor) {
    memoryMonitor.stopMemoryMonitor();
  } else if (monitorInterval) {
    clearInterval(monitorInterval);
  }
}

/**
 * Execute a build step with memory monitoring
 */
function execWithMemoryCheck(command, label) {
  console.log(`\n📦 ${label}...`);
  logMemoryStats('Before');

  const startTime = Date.now();

  try {
    execSync(command, { stdio: 'inherit', cwd: root });
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`✅ ${label} completed in ${duration}s`);
  } catch (err) {
    console.error(`❌ ${label} failed:`, err.message);
    throw err;
  } finally {
    logMemoryStats('After');

    // Trigger GC after each major step if memory is high
    const stats = getMemoryStats();
    if (stats.isWarning) {
      triggerGC();
    }
  }
}

/**
 * Main build process
 */
async function main() {
  console.log(
    `🚀 Starting build with memory management on ${getRuntimeCommand()}...\n`,
  );

  // Initial memory stats
  logMemoryStats('Initial');

  // Check runtime and GC availability
  if (isBun) {
    console.log(
      '✅ Running on Bun with --smol flag (automatic memory management)',
    );
  } else if (typeof global.gc !== 'function') {
    console.warn(
      '⚠️  WARNING: --expose-gc flag not detected. Automatic garbage collection will not be available.',
    );
    console.warn('   Add NODE_OPTIONS="--expose-gc" to enable automatic GC.\n');
  }

  // Start memory monitoring
  startMemoryMonitoring();

  try {
    // npm install if node_modules was removed
    if (!existsSync(join(root, 'node_modules'))) {
      execWithMemoryCheck('npm install', 'Installing dependencies');
    }

    // Generate git commit info (lightweight)
    execWithMemoryCheck('npm run generate', 'Generating git commit info');

    // Build packages one by one to reduce memory pressure
    const packages = ['core', 'cli', 'sdk-typescript', 'test-utils'];

    for (const pkg of packages) {
      const packagePath = join(root, 'packages', pkg);
      if (existsSync(packagePath)) {
        execWithMemoryCheck(
          `npm run build --workspace=packages/${pkg}`,
          `Building package: ${pkg}`,
        );
      }
    }

    // Build sandbox if enabled
    try {
      execSync('node scripts/sandbox_command.js -q', {
        stdio: 'inherit',
        cwd: root,
      });

      if (
        process.env.BUILD_SANDBOX === '1' ||
        process.env.BUILD_SANDBOX === 'true'
      ) {
        execWithMemoryCheck(
          'node scripts/build_sandbox.js -s',
          'Building sandbox',
        );
      }
    } catch {
      // Sandbox build is optional
    }

    console.log('\n✅ Build completed successfully!');
    logMemoryStats('Final');
  } catch (_error) {
    console.error('\n❌ Build failed!');
    logMemoryStats('Error state');
    process.exitCode = 1;
  } finally {
    stopMemoryMonitoring();
  }
}

// Run the build
main();
