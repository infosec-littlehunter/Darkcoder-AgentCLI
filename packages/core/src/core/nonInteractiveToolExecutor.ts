/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type {
  ToolCallRequestInfo,
  ToolCallResponseInfo,
  Config,
} from '../index.js';
import {
  CoreToolScheduler,
  type AllToolCallsCompleteHandler,
  type OutputUpdateHandler,
  type ToolCallsUpdateHandler,
} from './coreToolScheduler.js';

export interface ExecuteToolCallOptions {
  outputUpdateHandler?: OutputUpdateHandler;
  onAllToolCallsComplete?: AllToolCallsCompleteHandler;
  onToolCallsUpdate?: ToolCallsUpdateHandler;
}

/**
 * Executes a single tool call non-interactively by leveraging the CoreToolScheduler.
 */
export async function executeToolCall(
  config: Config,
  toolCallRequest: ToolCallRequestInfo,
  abortSignal: AbortSignal,
  options: ExecuteToolCallOptions = {},
): Promise<ToolCallResponseInfo> {
  return new Promise<ToolCallResponseInfo>((resolve, reject) => {
    // Store scheduler reference for proper cleanup
    const scheduler = new CoreToolScheduler({
      config,
      chatRecordingService: config.getChatRecordingService(),
      outputUpdateHandler: options.outputUpdateHandler,
      onAllToolCallsComplete: async (completedToolCalls) => {
        try {
          if (options.onAllToolCallsComplete) {
            await options.onAllToolCallsComplete(completedToolCalls);
          }
          resolve(completedToolCalls[0].response);
        } finally {
          // Clean up scheduler resources
          scheduler.dispose();
        }
      },
      onToolCallsUpdate: options.onToolCallsUpdate,
      getPreferredEditor: () => undefined,
      onEditorClose: () => {},
    });

    scheduler.schedule(toolCallRequest, abortSignal).catch((error) => {
      // Clean up scheduler resources on error
      scheduler.dispose();
      reject(error);
    });
  });
}
