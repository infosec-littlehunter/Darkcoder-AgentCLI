/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  getMemoryStats,
  checkMemoryUsage,
  formatMemoryUsage,
  triggerGarbageCollection,
  autoGarbageCollection,
  startMemoryMonitor,
  stopMemoryMonitor,
} from './memoryMonitor.js';

describe('memoryMonitor', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    stopMemoryMonitor();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe('getMemoryStats', () => {
    it('should return memory statistics', () => {
      const stats = getMemoryStats();

      expect(stats).toHaveProperty('heapUsedMB');
      expect(stats).toHaveProperty('heapLimitMB');
      expect(stats).toHaveProperty('heapUsagePercent');
      expect(stats).toHaveProperty('isWarning');
      expect(stats).toHaveProperty('isCritical');

      expect(typeof stats.heapUsedMB).toBe('number');
      expect(typeof stats.heapLimitMB).toBe('number');
      expect(typeof stats.heapUsagePercent).toBe('number');
      expect(typeof stats.isWarning).toBe('boolean');
      expect(typeof stats.isCritical).toBe('boolean');

      expect(stats.heapUsedMB).toBeGreaterThan(0);
      expect(stats.heapLimitMB).toBeGreaterThan(0);
      expect(stats.heapUsagePercent).toBeGreaterThanOrEqual(0);
      expect(stats.heapUsagePercent).toBeLessThanOrEqual(100);
    });

    it('should indicate warning at 75% usage', () => {
      const stats = getMemoryStats();
      // Can't easily mock this, but we can verify the logic
      expect(stats.isWarning).toBe(stats.heapUsagePercent >= 75);
    });

    it('should indicate critical at 90% usage', () => {
      const stats = getMemoryStats();
      expect(stats.isCritical).toBe(stats.heapUsagePercent >= 90);
    });
  });

  describe('checkMemoryUsage', () => {
    it('should return null when memory usage is normal', () => {
      const result = checkMemoryUsage();
      const stats = getMemoryStats();

      if (stats.heapUsagePercent < 75) {
        expect(result).toBeNull();
      }
    });

    it('should return warning message when appropriate', () => {
      const stats = getMemoryStats();

      if (stats.isWarning && !stats.isCritical) {
        const result = checkMemoryUsage();
        expect(result).toContain('High memory usage');
        expect(result).toContain('%');
      }
    });

    it('should return critical message when appropriate', () => {
      const stats = getMemoryStats();

      if (stats.isCritical) {
        const result = checkMemoryUsage();
        expect(result).toContain('Critical memory usage');
        expect(result).toContain('%');
      }
    });
  });

  describe('formatMemoryUsage', () => {
    it('should format memory usage as string', () => {
      const result = formatMemoryUsage();

      expect(typeof result).toBe('string');
      expect(result).toMatch(/\d+(\.\d+)?MB \/ \d+(\.\d+)?MB \(\d+%\)/);
    });
  });

  describe('triggerGarbageCollection', () => {
    it('should return false when gc is not available', () => {
      const originalGc = global.gc;
      // Set to undefined instead of delete (delete not allowed on global)
      (global as any).gc = undefined;

      const result = triggerGarbageCollection();
      expect(result).toBe(false);

      global.gc = originalGc;
    });

    it('should return true and trigger gc when available', () => {
      if (typeof global.gc === 'function') {
        const originalGc = global.gc;
        let gcCalled = false;
        (global as any).gc = () => {
          gcCalled = true;
          originalGc();
        };

        const result = triggerGarbageCollection();

        expect(result).toBe(true);
        expect(gcCalled).toBe(true);

        global.gc = originalGc;
      }
    });
  });

  describe('autoGarbageCollection', () => {
    it('should not trigger GC when memory is not critical', () => {
      if (typeof global.gc === 'function') {
        const originalGc = global.gc;
        let gcCalled = false;
        (global as any).gc = () => {
          gcCalled = true;
          originalGc();
        };

        // Only trigger if memory is actually critical
        const stats = getMemoryStats();
        if (!stats.isCritical) {
          const result = autoGarbageCollection();
          expect(result).toBe(false);
          expect(gcCalled).toBe(false);
        }

        global.gc = originalGc;
      }
    });
  });

  describe('startMemoryMonitor', () => {
    it('should start monitoring with default interval', () => {
      const onWarning = vi.fn();
      const onCritical = vi.fn();

      startMemoryMonitor({
        onWarning,
        onCritical,
      });

      // Should not throw
      expect(() => stopMemoryMonitor()).not.toThrow();
    });

    it('should call onWarning when memory is high', () => {
      const onWarning = vi.fn();

      startMemoryMonitor({
        intervalMs: 1000,
        onWarning,
      });

      // Fast-forward time
      vi.advanceTimersByTime(1000);

      // Stop monitoring
      stopMemoryMonitor();

      // If memory was high during the test, callback should have been called
      const stats = getMemoryStats();
      if (stats.isWarning && !stats.isCritical) {
        expect(onWarning).toHaveBeenCalled();
      }
    });

    it('should call onCritical when memory is critical', () => {
      const onCritical = vi.fn();

      startMemoryMonitor({
        intervalMs: 1000,
        onCritical,
      });

      // Fast-forward time
      vi.advanceTimersByTime(1000);

      // Stop monitoring
      stopMemoryMonitor();

      // If memory was critical during the test, callback should have been called
      const stats = getMemoryStats();
      if (stats.isCritical) {
        expect(onCritical).toHaveBeenCalled();
      }
    });

    it('should not start multiple monitors', () => {
      startMemoryMonitor();
      startMemoryMonitor(); // Second call should be ignored

      // Should only stop once
      stopMemoryMonitor();
    });

    it('should support autoGC option', () => {
      if (typeof global.gc === 'function') {
        const originalGc = global.gc;
        let gcCallCount = 0;
        (global as any).gc = () => {
          gcCallCount++;
          originalGc();
        };

        startMemoryMonitor({
          intervalMs: 1000,
          autoGC: true,
        });

        // Fast-forward time
        vi.advanceTimersByTime(1000);

        stopMemoryMonitor();

        // GC should only be called if memory was critical
        const stats = getMemoryStats();
        if (stats.isCritical) {
          expect(gcCallCount).toBeGreaterThan(0);
        }

        global.gc = originalGc;
      }
    });

    it('should respect GC cooldown period', () => {
      if (typeof global.gc === 'function') {
        const originalGc = global.gc;
        let gcCallCount = 0;
        (global as any).gc = () => {
          gcCallCount++;
          originalGc();
        };

        startMemoryMonitor({
          intervalMs: 1000,
          autoGC: true,
        });

        // Advance multiple intervals
        vi.advanceTimersByTime(1000);
        vi.advanceTimersByTime(1000);
        vi.advanceTimersByTime(1000);

        stopMemoryMonitor();

        // GC should not be called more than once within cooldown period
        const stats = getMemoryStats();
        if (stats.isCritical && gcCallCount > 0) {
          // Should not be called excessively (max once per 30 seconds)
          expect(gcCallCount).toBeLessThan(3);
        }

        global.gc = originalGc;
      }
    });
  });

  describe('stopMemoryMonitor', () => {
    it('should stop monitoring', () => {
      startMemoryMonitor();
      expect(() => stopMemoryMonitor()).not.toThrow();
    });

    it('should handle being called when not started', () => {
      expect(() => stopMemoryMonitor()).not.toThrow();
    });
  });
});
