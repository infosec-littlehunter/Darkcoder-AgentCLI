/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Status } from './coreToolScheduler.js';

/**
 * Thread-safe manager for tool call status updates
 * Prevents race conditions when multiple tools update status concurrently
 */
export class ThreadSafeStatusManager {
  private updateQueue: StatusUpdate[] = [];
  private isProcessing = false;
  private processingPromise: Promise<void> | null = null;

  /**
   * Queues a status update to be applied atomically
   */
  async queueStatusUpdate(update: StatusUpdate): Promise<void> {
    return new Promise((resolve, reject) => {
      this.updateQueue.push({
        ...update,
        resolve,
        reject,
      });

      // Start processing if not already running
      if (!this.isProcessing) {
        this.processingPromise = this.processQueue();
      }
    });
  }

  /**
   * Processes all queued status updates sequentially
   */
  private async processQueue(): Promise<void> {
    this.isProcessing = true;

    try {
      while (this.updateQueue.length > 0) {
        const update = this.updateQueue.shift()!;

        try {
          // Apply the update
          await update.applyUpdate();

          // Resolve the promise
          update.resolve?.();
        } catch (error) {
          // Reject with error
          update.reject?.(
            error instanceof Error ? error : new Error(String(error)),
          );
        }
      }
    } finally {
      this.isProcessing = false;
      this.processingPromise = null;
    }
  }

  /**
   * Waits for all pending updates to complete
   */
  async flush(): Promise<void> {
    if (this.processingPromise) {
      await this.processingPromise;
    }
  }

  /**
   * Gets the number of pending updates
   */
  getPendingCount(): number {
    return this.updateQueue.length;
  }

  /**
   * Checks if updates are being processed
   */
  isProcessingUpdates(): boolean {
    return this.isProcessing;
  }

  /**
   * Clears all pending updates (use with caution!)
   */
  clear(): void {
    // Reject all pending updates
    for (const update of this.updateQueue) {
      update.reject?.(new Error('Status update queue cleared'));
    }

    this.updateQueue = [];
  }
}

/**
 * Represents a status update operation
 */
interface StatusUpdate {
  /** Applies the status update */
  applyUpdate: () => void | Promise<void>;

  /** Called when update succeeds */
  resolve?: () => void;

  /** Called when update fails */
  reject?: (error: Error) => void;
}

/**
 * Optimized status updater that batches multiple updates
 */
export class BatchedStatusUpdater {
  private pendingUpdates = new Map<
    string,
    {
      status: Status;
      data?: any;
    }
  >();

  private flushTimer: NodeJS.Timeout | null = null;
  private readonly BATCH_DELAY_MS = 5; // Very short delay for status updates

  constructor(
    private readonly onFlush: (
      updates: Map<
        string,
        {
          status: Status;
          data?: any;
        }
      >,
    ) => void,
  ) {}

  /**
   * Schedules a status update to be batched
   */
  scheduleUpdate(callId: string, status: Status, data?: any): void {
    // Store the update (overwrites previous update for same callId)
    this.pendingUpdates.set(callId, { status, data });

    // Schedule flush if not already scheduled
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => {
        this.flush();
      }, this.BATCH_DELAY_MS);
    }
  }

  /**
   * Immediately flushes all pending updates
   */
  flush(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    if (this.pendingUpdates.size === 0) {
      return;
    }

    // Create snapshot and clear
    const updates = new Map(this.pendingUpdates);
    this.pendingUpdates.clear();

    // Apply batched updates
    this.onFlush(updates);
  }

  /**
   * Cancels all pending updates
   */
  cancel(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    this.pendingUpdates.clear();
  }

  /**
   * Gets the number of pending updates
   */
  getPendingCount(): number {
    return this.pendingUpdates.size;
  }
}

/**
 * Coordinator for managing multiple concurrent status updates safely
 */
export class ConcurrentStatusCoordinator {
  private locks = new Map<string, Promise<void>>();

  /**
   * Executes an update with exclusive access to a specific call ID
   */
  async withLock<T>(
    callId: string,
    operation: () => T | Promise<T>,
  ): Promise<T> {
    // Wait for any existing lock on this callId
    while (this.locks.has(callId)) {
      await this.locks.get(callId);
    }

    // Create new lock
    let releaseLock: () => void = () => {};
    const lockPromise = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });

    this.locks.set(callId, lockPromise);

    try {
      // Execute the operation
      return await operation();
    } finally {
      // Release the lock
      this.locks.delete(callId);
      releaseLock();
    }
  }

  /**
   * Checks if a call ID is currently locked
   */
  isLocked(callId: string): boolean {
    return this.locks.has(callId);
  }

  /**
   * Gets the number of active locks
   */
  getActiveLockCount(): number {
    return this.locks.size;
  }

  /**
   * Waits for all locks to be released
   */
  async waitForAll(): Promise<void> {
    await Promise.all(Array.from(this.locks.values()));
  }

  /**
   * Clears all locks (use with caution!)
   */
  clearAll(): void {
    this.locks.clear();
  }
}

/**
 * Helper for tracking status update statistics
 */
export class StatusUpdateStats {
  private totalUpdates = 0;
  private updatesByStatus = new Map<Status, number>();
  private updatesByCallId = new Map<string, number>();
  private startTime = Date.now();

  /**
   * Records a status update
   */
  recordUpdate(callId: string, status: Status): void {
    this.totalUpdates++;

    // Count by status
    this.updatesByStatus.set(
      status,
      (this.updatesByStatus.get(status) || 0) + 1,
    );

    // Count by call ID
    this.updatesByCallId.set(
      callId,
      (this.updatesByCallId.get(callId) || 0) + 1,
    );
  }

  /**
   * Gets total number of updates
   */
  getTotalUpdates(): number {
    return this.totalUpdates;
  }

  /**
   * Gets update count for a specific status
   */
  getUpdatesForStatus(status: Status): number {
    return this.updatesByStatus.get(status) || 0;
  }

  /**
   * Gets update count for a specific call ID
   */
  getUpdatesForCallId(callId: string): number {
    return this.updatesByCallId.get(callId) || 0;
  }

  /**
   * Gets updates per second
   */
  getUpdatesPerSecond(): number {
    const elapsed = (Date.now() - this.startTime) / 1000;
    return elapsed > 0 ? this.totalUpdates / elapsed : 0;
  }

  /**
   * Gets a summary of update statistics
   */
  getSummary(): string {
    const lines = [
      `Total updates: ${this.totalUpdates}`,
      `Updates/second: ${this.getUpdatesPerSecond().toFixed(1)}`,
      `By status:`,
    ];

    for (const [status, count] of this.updatesByStatus.entries()) {
      lines.push(`  ${status}: ${count}`);
    }

    return lines.join('\n');
  }

  /**
   * Resets all statistics
   */
  reset(): void {
    this.totalUpdates = 0;
    this.updatesByStatus.clear();
    this.updatesByCallId.clear();
    this.startTime = Date.now();
  }
}
