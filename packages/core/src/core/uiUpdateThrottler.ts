/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Throttles UI update notifications to prevent excessive re-renders
 * during parallel tool execution with streaming output
 */
export class UIUpdateThrottler {
  private lastNotifyTime = 0;
  private pendingNotifyTimer: NodeJS.Timeout | null = null;
  private hasPendingUpdates = false;

  constructor(
    private readonly notifyCallback: () => void,
    private readonly throttleMs: number = 50, // Max 20 updates/second
  ) {}

  /**
   * Requests a UI notification, which will be throttled
   */
  requestNotification(): void {
    const now = Date.now();
    const timeSinceLastNotify = now - this.lastNotifyTime;

    // If enough time has passed, notify immediately
    if (timeSinceLastNotify >= this.throttleMs) {
      this.doNotify();
      return;
    }

    // Otherwise, schedule a delayed notification
    this.hasPendingUpdates = true;

    if (!this.pendingNotifyTimer) {
      const remainingTime = this.throttleMs - timeSinceLastNotify;

      this.pendingNotifyTimer = setTimeout(() => {
        this.pendingNotifyTimer = null;

        if (this.hasPendingUpdates) {
          this.doNotify();
        }
      }, remainingTime);
    }
  }

  /**
   * Forces an immediate notification, bypassing throttling
   */
  forceNotification(): void {
    // Cancel any pending timer
    if (this.pendingNotifyTimer) {
      clearTimeout(this.pendingNotifyTimer);
      this.pendingNotifyTimer = null;
    }

    this.doNotify();
  }

  /**
   * Performs the actual notification
   */
  private doNotify(): void {
    this.lastNotifyTime = Date.now();
    this.hasPendingUpdates = false;
    this.notifyCallback();
  }

  /**
   * Cancels any pending notifications
   */
  cancel(): void {
    if (this.pendingNotifyTimer) {
      clearTimeout(this.pendingNotifyTimer);
      this.pendingNotifyTimer = null;
    }

    this.hasPendingUpdates = false;
  }

  /**
   * Checks if there are pending notifications
   */
  hasPending(): boolean {
    return this.hasPendingUpdates;
  }

  /**
   * Gets the throttle interval in milliseconds
   */
  getThrottleMs(): number {
    return this.throttleMs;
  }

  /**
   * Gets time since last notification
   */
  getTimeSinceLastNotify(): number {
    return Date.now() - this.lastNotifyTime;
  }

  /**
   * Cleans up all resources (call when destroying)
   */
  dispose(): void {
    this.cancel(); // Clear pending timer
  }
}

/**
 * Adaptive throttler that adjusts throttle rate based on update frequency
 */
export class AdaptiveUIThrottler extends UIUpdateThrottler {
  private updateCount = 0;
  private windowStart = Date.now();
  private readonly windowMs = 1000; // 1 second window

  private readonly minThrottleMs = 16; // ~60fps
  private readonly maxThrottleMs = 200; // ~5fps
  private readonly targetUpdatesPerSecond = 20;

  constructor(notifyCallback: () => void) {
    super(notifyCallback, 50);
  }

  override requestNotification(): void {
    this.updateCount++;

    // Check if we should adjust throttle rate
    const now = Date.now();
    const windowElapsed = now - this.windowStart;

    if (windowElapsed >= this.windowMs) {
      const updatesPerSecond = (this.updateCount / windowElapsed) * 1000;

      // Adjust throttle based on update frequency
      let newThrottle: number;

      if (updatesPerSecond > this.targetUpdatesPerSecond * 2) {
        // Too many updates - increase throttle
        newThrottle = Math.min(
          this.maxThrottleMs,
          (this as any).throttleMs * 1.5,
        );
      } else if (updatesPerSecond < this.targetUpdatesPerSecond * 0.5) {
        // Too few updates - decrease throttle
        newThrottle = Math.max(
          this.minThrottleMs,
          (this as any).throttleMs * 0.75,
        );
      } else {
        newThrottle = (this as any).throttleMs;
      }

      // Update throttle
      (this as any).throttleMs = Math.round(newThrottle);

      // Reset window
      this.updateCount = 0;
      this.windowStart = now;
    }

    super.requestNotification();
  }

  /**
   * Gets current adaptive throttle value
   */
  getCurrentThrottle(): number {
    return this.getThrottleMs();
  }

  /**
   * Gets current update frequency
   */
  getCurrentUpdateRate(): number {
    const elapsed = Date.now() - this.windowStart;
    if (elapsed === 0) return 0;

    return (this.updateCount / elapsed) * 1000;
  }

  /**
   * Cleans up all resources and resets adaptive state
   */
  override dispose(): void {
    // Reset adaptive state
    this.updateCount = 0;
    this.windowStart = Date.now();

    // Call parent cleanup
    super.dispose();
  }
}

/**
 * Batched update coordinator for multiple concurrent tool outputs
 */
export class BatchedUpdateCoordinator {
  private pendingUpdates = new Set<string>();
  private flushTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly onFlush: (toolIds: Set<string>) => void,
    private readonly batchDelayMs: number = 10,
  ) {}

  /**
   * Records that a tool has pending updates
   */
  recordUpdate(toolId: string): void {
    this.pendingUpdates.add(toolId);

    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => {
        this.flush();
      }, this.batchDelayMs);
    }
  }

  /**
   * Flushes all pending updates immediately
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
    const updates = new Set(this.pendingUpdates);
    this.pendingUpdates.clear();

    // Notify with batched updates
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
   * Gets count of pending updates
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
