/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as v8 from 'node:v8';

/**
 * Memory usage thresholds for warnings
 */
const MEMORY_WARNING_THRESHOLD = 0.75; // 75% of heap limit
const MEMORY_CRITICAL_THRESHOLD = 0.9; // 90% of heap limit

/**
 * Gets current memory usage statistics
 */
export function getMemoryStats() {
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

/**
 * Checks memory usage and returns a warning message if necessary
 */
export function checkMemoryUsage(): string | null {
  const stats = getMemoryStats();

  if (stats.isCritical) {
    return `⚠️  Critical memory usage: ${stats.heapUsagePercent}% (${stats.heapUsedMB}MB / ${stats.heapLimitMB}MB). Consider restarting the session.`;
  }

  if (stats.isWarning) {
    return `⚠️  High memory usage: ${stats.heapUsagePercent}% (${stats.heapUsedMB}MB / ${stats.heapLimitMB}MB)`;
  }

  return null;
}

/**
 * Formats memory usage for display
 */
export function formatMemoryUsage(): string {
  const stats = getMemoryStats();
  return `${stats.heapUsedMB}MB / ${stats.heapLimitMB}MB (${stats.heapUsagePercent}%)`;
}

/**
 * Triggers garbage collection if available (requires --expose-gc flag)
 * Returns true if GC was triggered, false otherwise
 */
export function triggerGarbageCollection(): boolean {
  if (typeof global.gc === 'function') {
    global.gc();
    return true;
  }
  return false;
}

/**
 * Attempts automatic garbage collection when memory is critical
 * Returns true if GC was performed, false otherwise
 */
export function autoGarbageCollection(): boolean {
  const stats = getMemoryStats();

  // Trigger GC if we're above critical threshold
  if (stats.isCritical && typeof global.gc === 'function') {
    try {
      global.gc();
      return true;
    } catch (error) {
      console.warn('Failed to trigger garbage collection:', error);
      return false;
    }
  }

  return false;
}

/**
 * Configuration for memory monitor
 */
export interface MemoryMonitorConfig {
  /** Interval in milliseconds to check memory (default: 60000) */
  intervalMs?: number;
  /** Callback when memory warning is detected */
  onWarning?: (message: string) => void;
  /** Callback when memory is critical */
  onCritical?: (message: string) => void;
  /** Enable automatic GC when memory is critical (requires --expose-gc) */
  autoGC?: boolean;
  /** Enable verbose logging */
  verbose?: boolean;
}

/**
 * Periodic memory monitor that logs warnings when memory is high
 */
let memoryMonitorInterval: NodeJS.Timeout | null = null;
let lastGcTime = 0;
const GC_COOLDOWN_MS = 30000; // Don't trigger GC more than once every 30 seconds

export function startMemoryMonitor(config?: MemoryMonitorConfig): void {
  const {
    intervalMs = 60000,
    onWarning,
    onCritical,
    autoGC = false,
    verbose = false,
  } = config || {};

  if (memoryMonitorInterval) {
    return; // Already running
  }

  if (verbose) {
    console.log(
      `🔍 Memory monitor started (interval: ${intervalMs}ms, autoGC: ${autoGC})`,
    );
  }

  memoryMonitorInterval = setInterval(() => {
    const stats = getMemoryStats();
    const warning = checkMemoryUsage();

    if (stats.isCritical) {
      if (onCritical) {
        onCritical(
          warning ||
            `Critical memory usage: ${stats.heapUsagePercent}% (${stats.heapUsedMB}MB / ${stats.heapLimitMB}MB)`,
        );
      }

      // Trigger automatic GC if enabled and not in cooldown
      if (autoGC && Date.now() - lastGcTime > GC_COOLDOWN_MS) {
        const gcTriggered = autoGarbageCollection();
        if (gcTriggered) {
          lastGcTime = Date.now();
          if (verbose) {
            const newStats = getMemoryStats();
            console.log(
              `♻️  Automatic GC triggered. Memory: ${newStats.heapUsagePercent}% (freed ${stats.heapUsedMB - newStats.heapUsedMB}MB)`,
            );
          }
        }
      }
    } else if (warning && onWarning) {
      onWarning(warning);
    }
  }, intervalMs);

  // Don't prevent process exit
  memoryMonitorInterval.unref();
}

export function stopMemoryMonitor(): void {
  if (memoryMonitorInterval) {
    clearInterval(memoryMonitorInterval);
    memoryMonitorInterval = null;
  }
}
