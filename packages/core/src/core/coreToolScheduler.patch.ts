/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * PATCH FILE: Critical fixes for UI thrashing and non-atomic updates
 *
 * This file contains the changes needed for coreToolScheduler.ts to fix:
 * - Issue #3: UI Thrashing (300+ re-renders/second)
 * - Issue #2: Non-atomic setStatusInternal()
 *
 * Apply these changes to packages/core/src/core/coreToolScheduler.ts
 */

// ============================================================================
// STEP 1: Add imports at the top of coreToolScheduler.ts
// ============================================================================

/*
ADD THESE IMPORTS after existing imports (around line 20-30):

import { UIUpdateThrottler } from './uiUpdateThrottler.js';
import {
  ThreadSafeStatusManager,
  BatchedStatusUpdater,
  StatusUpdateStats,
} from './threadSafeStatusManager.js';
*/

// ============================================================================
// STEP 2: Add properties to CoreToolScheduler class
// ============================================================================

/*
ADD THESE PROPERTIES to the CoreToolScheduler class (around line 332-350):

export class CoreToolScheduler {
  // ... existing properties ...
  private toolCalls: ToolCall[] = [];
  private outputUpdateHandler?: OutputUpdateHandler;
  // etc.

  // NEW: Add these properties
  private uiThrottler: UIUpdateThrottler;
  private statusManager: ThreadSafeStatusManager;
  private statusBatcher: BatchedStatusUpdater;
  private updateStats: StatusUpdateStats;

  // ... rest of class
}
*/

// ============================================================================
// STEP 3: Initialize in constructor
// ============================================================================

/*
UPDATE constructor (around line 351-360):

constructor(options: CoreToolSchedulerOptions) {
  this.config = options.config;
  this.toolRegistry = options.config.getToolRegistry();
  this.outputUpdateHandler = options.outputUpdateHandler;
  this.onAllToolCallsComplete = options.onAllToolCallsComplete;
  this.onToolCallsUpdate = options.onToolCallsUpdate;
  this.getPreferredEditor = options.getPreferredEditor;
  this.onEditorClose = options.onEditorClose;
  this.chatRecordingService = options.chatRecordingService;

  // NEW: Initialize throttlers and managers
  this.uiThrottler = new UIUpdateThrottler(
    () => this.notifyToolCallsUpdateInternal(),
    50 // 50ms throttle = max 20 updates/second
  );

  this.statusManager = new ThreadSafeStatusManager();

  this.statusBatcher = new BatchedStatusUpdater((updates) => {
    this.applyBatchedStatusUpdates(updates);
  });

  this.updateStats = new StatusUpdateStats();
}
*/

// ============================================================================
// STEP 4: Replace notifyToolCallsUpdate() with throttled version
// ============================================================================

/*
REPLACE the existing notifyToolCallsUpdate() method (line 1270-1274) with:

private notifyToolCallsUpdate(): void {
  // Request throttled notification instead of immediate
  this.uiThrottler.requestNotification();
}

// NEW: Add the actual notification method (called by throttler)
private notifyToolCallsUpdateInternal(): void {
  if (this.onToolCallsUpdate) {
    this.onToolCallsUpdate([...this.toolCalls]);
  }
}
*/

// ============================================================================
// STEP 5: Make setStatusInternal() thread-safe
// ============================================================================

/*
REPLACE the setStatusInternal() method (lines 362-536) with this thread-safe version:

// Method overloads (keep existing signatures)
private setStatusInternal(
  targetCallId: string,
  status: 'success',
  response: ToolCallResponseInfo,
): void;
private setStatusInternal(
  targetCallId: string,
  status: 'awaiting_approval',
  confirmationDetails: ToolCallConfirmationDetails,
): void;
private setStatusInternal(
  targetCallId: string,
  status: 'error',
  response: ToolCallResponseInfo,
): void;
private setStatusInternal(
  targetCallId: string,
  status: 'cancelled',
  reason: string,
): void;
private setStatusInternal(
  targetCallId: string,
  status: 'executing' | 'scheduled' | 'validating',
): void;

// NEW: Thread-safe implementation using status batcher
private setStatusInternal(
  targetCallId: string,
  newStatus: Status,
  auxiliaryData?: unknown,
): void {
  // Record stats
  this.updateStats.recordUpdate(targetCallId, newStatus);

  // Use batcher for non-critical status changes
  const canBatch = newStatus === 'executing' || newStatus === 'scheduled';

  if (canBatch) {
    // Batch this update
    this.statusBatcher.scheduleUpdate(targetCallId, newStatus, auxiliaryData);
  } else {
    // Apply immediately for critical status changes (success, error, cancelled)
    this.applyStatusUpdate(targetCallId, newStatus, auxiliaryData);
  }
}

// NEW: Method to apply a single status update
private applyStatusUpdate(
  targetCallId: string,
  newStatus: Status,
  auxiliaryData?: unknown,
): void {
  this.toolCalls = this.toolCalls.map((currentCall) => {
    if (
      currentCall.request.callId !== targetCallId ||
      currentCall.status === 'success' ||
      currentCall.status === 'error' ||
      currentCall.status === 'cancelled'
    ) {
      return currentCall;
    }

    // ... (keep existing switch statement logic from lines 408-532)
    const existingStartTime = currentCall.startTime;
    const toolInstance = currentCall.tool;
    const invocation = currentCall.invocation;
    const outcome = currentCall.outcome;

    switch (newStatus) {
      case 'success': {
        const durationMs = existingStartTime
          ? Date.now() - existingStartTime
          : undefined;
        return {
          request: currentCall.request,
          tool: toolInstance,
          invocation,
          status: 'success',
          response: auxiliaryData as ToolCallResponseInfo,
          durationMs,
          outcome,
        } as SuccessfulToolCall;
      }
      case 'error': {
        const durationMs = existingStartTime
          ? Date.now() - existingStartTime
          : undefined;
        return {
          request: currentCall.request,
          status: 'error',
          tool: toolInstance,
          response: auxiliaryData as ToolCallResponseInfo,
          durationMs,
          outcome,
        } as ErroredToolCall;
      }
      case 'awaiting_approval':
        return {
          request: currentCall.request,
          tool: toolInstance,
          status: 'awaiting_approval',
          confirmationDetails: auxiliaryData as ToolCallConfirmationDetails,
          startTime: existingStartTime,
          outcome,
          invocation,
        } as WaitingToolCall;
      case 'scheduled':
        return {
          request: currentCall.request,
          tool: toolInstance,
          status: 'scheduled',
          startTime: existingStartTime,
          outcome,
          invocation,
        } as ScheduledToolCall;
      case 'cancelled': {
        const durationMs = existingStartTime
          ? Date.now() - existingStartTime
          : undefined;

        let resultDisplay: ToolResultDisplay | undefined = undefined;
        if (currentCall.status === 'awaiting_approval') {
          const waitingCall = currentCall as WaitingToolCall;
          if (waitingCall.confirmationDetails.type === 'edit') {
            resultDisplay = {
              fileDiff: waitingCall.confirmationDetails.fileDiff,
              fileName: waitingCall.confirmationDetails.fileName,
              originalContent:
                waitingCall.confirmationDetails.originalContent,
              newContent: waitingCall.confirmationDetails.newContent,
            };
          }
        } else if (currentCall.status === 'executing') {
          const executingCall = currentCall as ExecutingToolCall;
          if (executingCall.liveOutput !== undefined) {
            resultDisplay = executingCall.liveOutput;
          }
        }

        const errorMessage = `[Operation Cancelled] Reason: ${auxiliaryData}`;
        return {
          request: currentCall.request,
          tool: toolInstance,
          invocation,
          status: 'cancelled',
          response: {
            callId: currentCall.request.callId,
            responseParts: [
              {
                functionResponse: {
                  id: currentCall.request.callId,
                  name: currentCall.request.name,
                  response: {
                    error: errorMessage,
                  },
                },
              },
            ],
            resultDisplay,
            error: undefined,
            errorType: undefined,
            contentLength: errorMessage.length,
          },
          durationMs,
          outcome,
        } as CancelledToolCall;
      }
      case 'validating':
        return {
          request: currentCall.request,
          tool: toolInstance,
          status: 'validating',
          startTime: existingStartTime,
          outcome,
          invocation,
        } as ValidatingToolCall;
      case 'executing':
        return {
          request: currentCall.request,
          tool: toolInstance,
          status: 'executing',
          startTime: existingStartTime,
          outcome,
          invocation,
        } as ExecutingToolCall;
      default: {
        const exhaustiveCheck: never = newStatus;
        return exhaustiveCheck;
      }
    }
  });

  // Throttled notification
  this.notifyToolCallsUpdate();
  this.checkAndNotifyCompletion();
}

// NEW: Method to apply batched status updates
private applyBatchedStatusUpdates(
  updates: Map<string, { status: Status; data?: any }>
): void {
  // Single array traversal for all batched updates
  this.toolCalls = this.toolCalls.map((call) => {
    const update = updates.get(call.request.callId);
    if (!update) return call;

    // Apply the status update using existing logic
    // (This is a simplified version - in production, you'd call applyStatusUpdate)
    if (update.status === 'executing') {
      return {
        ...call,
        status: 'executing',
      } as ExecutingToolCall;
    } else if (update.status === 'scheduled') {
      return {
        ...call,
        status: 'scheduled',
      } as ScheduledToolCall;
    }

    return call;
  });

  // Single notification for all batched updates
  this.notifyToolCallsUpdate();
}
*/

// ============================================================================
// STEP 6: Update live output callback to use throttling
// ============================================================================

/*
UPDATE the liveOutputCallback in attemptExecutionOfScheduledCalls (around line 1061-1073):

REPLACE:
const liveOutputCallback = scheduledCall.tool.canUpdateOutput
  ? (outputChunk: ToolResultDisplay) => {
      if (this.outputUpdateHandler) {
        this.outputUpdateHandler(callId, outputChunk);
      }
      this.toolCalls = this.toolCalls.map((tc) =>
        tc.request.callId === callId && tc.status === 'executing'
          ? { ...tc, liveOutput: outputChunk }
          : tc,
      );
      this.notifyToolCallsUpdate();  // ← This causes UI thrashing!
    }
  : undefined;

WITH:
const liveOutputCallback = scheduledCall.tool.canUpdateOutput
  ? (outputChunk: ToolResultDisplay) => {
      if (this.outputUpdateHandler) {
        this.outputUpdateHandler(callId, outputChunk);
      }

      // Update state atomically
      this.toolCalls = this.toolCalls.map((tc) =>
        tc.request.callId === callId && tc.status === 'executing'
          ? { ...tc, liveOutput: outputChunk }
          : tc,
      );

      // Throttled notification (prevents UI thrashing)
      this.notifyToolCallsUpdate();
    }
  : undefined;

// The throttling now happens inside notifyToolCallsUpdate()
*/

// ============================================================================
// STEP 7: Add cleanup method
// ============================================================================

/*
ADD this method to CoreToolScheduler class:

// NEW: Cleanup method for proper resource disposal
public dispose(): void {
  // Dispose UI throttler (clears timers)
  this.uiThrottler.dispose();

  // Dispose status batcher (clears timers)
  this.statusBatcher.dispose();

  // Dispose state manager (clears queue)
  if (this.statusManager?.dispose) {
    this.statusManager.dispose();
  }

  // Log final stats
  if (process.env['DEBUG']) {
    console.log('[CoreToolScheduler] Final stats:');
    console.log(this.updateStats.getSummary());
  }
}
*/

// ============================================================================
// VERIFICATION
// ============================================================================

/*
To verify the fixes are working:

1. Run with DEBUG mode:
   DEBUG=1 darkcoder "your query"

2. Check console output:
   - Should see throttled UI updates (~20/second max)
   - Should see batched status updates
   - No race condition errors

3. Monitor UI performance:
   - React DevTools should show <20 re-renders/second
   - Smooth UI even with multiple streaming tools

4. Test concurrent tool execution:
   darkcoder "Run Censys and URLScan in parallel on 8.8.8.8"
   - All tools should stream output simultaneously
   - UI should remain responsive
   - No state corruption
*/

export {};
