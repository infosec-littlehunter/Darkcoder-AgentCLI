/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { ToolCall } from './coreToolScheduler.js';

/**
 * Manages atomic state updates for tool calls to prevent race conditions
 * during parallel execution
 */
export class AtomicStateManager {
  private updateQueue: Array<StateUpdateOperation> = [];
  private isProcessing = false;

  /**
   * Queues a state update operation to be applied atomically
   */
  async queueUpdate(operation: StateUpdateOperation): Promise<void> {
    return new Promise((resolve, reject) => {
      this.updateQueue.push({
        ...operation,
        resolve,
        reject,
      });

      // Start processing if not already running
      void this.processQueue();
    });
  }

  /**
   * Processes queued state updates sequentially to ensure atomicity
   */
  private async processQueue(): Promise<void> {
    // Prevent concurrent processing
    if (this.isProcessing) {
      return;
    }

    this.isProcessing = true;

    try {
      while (this.updateQueue.length > 0) {
        const operation = this.updateQueue.shift()!;

        try {
          await operation.execute();
          operation.resolve?.();
        } catch (error) {
          operation.reject?.(
            error instanceof Error ? error : new Error(String(error)),
          );
        }
      }
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Gets the current queue size (for monitoring/debugging)
   */
  getQueueSize(): number {
    return this.updateQueue.length;
  }

  /**
   * Checks if updates are currently being processed
   */
  isProcessingUpdates(): boolean {
    return this.isProcessing;
  }

  /**
   * Clears all pending updates (use with caution)
   */
  clearQueue(): void {
    // Reject all pending operations
    for (const operation of this.updateQueue) {
      operation.reject?.(new Error('Queue cleared'));
    }

    this.updateQueue = [];
  }

  /**
   * Cleans up all resources
   */
  dispose(): void {
    this.clearQueue(); // Reject all pending operations
    this.isProcessing = false;
  }
}

/**
 * Represents a state update operation
 */
interface StateUpdateOperation {
  /** Function that performs the state update */
  execute: () => void | Promise<void>;

  /** Called when update succeeds */
  resolve?: () => void;

  /** Called when update fails */
  reject?: (error: Error) => void;
}

/**
 * Helper for batching multiple tool call updates
 */
export class ToolCallBatcher {
  private pendingUpdates = new Map<string, Partial<ToolCall>>();
  private flushTimer: NodeJS.Timeout | null = null;
  private readonly BATCH_DELAY_MS = 10;

  constructor(
    private onFlush: (updates: Map<string, Partial<ToolCall>>) => void,
  ) {}

  /**
   * Schedules a tool call update to be batched
   */
  scheduleUpdate(callId: string, update: Partial<ToolCall>): void {
    // Merge with existing pending update for this call
    const existing = this.pendingUpdates.get(callId);
    this.pendingUpdates.set(callId, {
      ...existing,
      ...update,
    });

    // Reset flush timer
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
    }

    this.flushTimer = setTimeout(() => {
      this.flush();
    }, this.BATCH_DELAY_MS);
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

  /**
   * Cleans up all resources
   */
  dispose(): void {
    this.cancel(); // Clear timer and pending updates
  }
}

/**
 * Error aggregator for collecting errors from parallel tool executions
 */
export class ErrorAggregator {
  private errors = new Map<string, Error>();

  /**
   * Records an error for a specific tool call
   */
  recordError(callId: string, error: Error): void {
    this.errors.set(callId, error);
  }

  /**
   * Gets all recorded errors
   */
  getErrors(): Map<string, Error> {
    return new Map(this.errors);
  }

  /**
   * Gets error for a specific tool call
   */
  getError(callId: string): Error | undefined {
    return this.errors.get(callId);
  }

  /**
   * Checks if any errors were recorded
   */
  hasErrors(): boolean {
    return this.errors.size > 0;
  }

  /**
   * Gets the number of errors
   */
  getErrorCount(): number {
    return this.errors.size;
  }

  /**
   * Clears all recorded errors
   */
  clear(): void {
    this.errors.clear();
  }

  /**
   * Creates a summary message of all errors
   */
  getSummary(): string {
    if (this.errors.size === 0) {
      return 'No errors';
    }

    const messages = Array.from(this.errors.entries()).map(
      ([callId, error]) => `${callId}: ${error.message}`,
    );

    return `${this.errors.size} tool(s) failed:\n${messages.join('\n')}`;
  }
}
