/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type { GenerateContentParameters } from '@google/genai';
import type { RequestContext } from './telemetryService.js';

export interface ErrorHandler {
  handle(
    error: unknown,
    context: RequestContext,
    request: GenerateContentParameters,
  ): never;
  shouldSuppressErrorLogging(
    error: unknown,
    request: GenerateContentParameters,
  ): boolean;
}

export class EnhancedErrorHandler implements ErrorHandler {
  constructor(
    private shouldSuppressLogging: (
      error: unknown,
      request: GenerateContentParameters,
    ) => boolean = () => false,
  ) {}

  handle(
    error: unknown,
    context: RequestContext,
    request: GenerateContentParameters,
  ): never {
    const isTimeoutError = this.isTimeoutError(error);
    const errorMessage = this.buildErrorMessage(error, context, isTimeoutError);

    // Allow subclasses to suppress error logging for specific scenarios
    if (!this.shouldSuppressErrorLogging(error, request)) {
      const logPrefix = context.isStreaming
        ? 'OpenAI API Streaming Error:'
        : 'OpenAI API Error:';
      console.error(logPrefix, errorMessage);
    }

    // Provide helpful timeout-specific error message
    if (isTimeoutError) {
      throw new Error(
        `${errorMessage}\n\n${this.getTimeoutTroubleshootingTips(context)}`,
      );
    }

    throw error;
  }

  shouldSuppressErrorLogging(
    error: unknown,
    request: GenerateContentParameters,
  ): boolean {
    return this.shouldSuppressLogging(error, request);
  }

  private isTimeoutError(error: unknown): boolean {
    if (!error) return false;

    const errorMessage =
      error instanceof Error
        ? error.message.toLowerCase()
        : String(error).toLowerCase();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const errorCode = (error as any)?.code;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const errorType = (error as any)?.type;

    // Check for common timeout indicators
    return (
      errorMessage.includes('timeout') ||
      errorMessage.includes('timed out') ||
      errorMessage.includes('connection timeout') ||
      errorMessage.includes('request timeout') ||
      errorMessage.includes('read timeout') ||
      errorMessage.includes('etimedout') ||
      errorMessage.includes('esockettimedout') ||
      errorCode === 'ETIMEDOUT' ||
      errorCode === 'ESOCKETTIMEDOUT' ||
      errorType === 'timeout' ||
      errorMessage.includes('request timed out') ||
      errorMessage.includes('deadline exceeded')
    );
  }

  private buildErrorMessage(
    error: unknown,
    context: RequestContext,
    isTimeoutError: boolean,
  ): string {
    const durationSeconds = Math.round(context.duration / 1000);

    if (isTimeoutError) {
      const prefix = context.isStreaming
        ? 'Streaming request timeout'
        : 'Request timeout';
      return `${prefix} after ${durationSeconds}s. Try reducing input length or increasing timeout in config.`;
    }

    // Check for Anthropic direct API 404 error (they don't support OpenAI format)
    const errorMessage = error instanceof Error ? error.message : String(error);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const status = (error as any)?.status;

    if (status === 404 && context.model?.toLowerCase().includes('claude')) {
      return (
        `${errorMessage}\n\n` +
        `Note: Anthropic's direct API does not support OpenAI-compatible format.\n` +
        `To use Claude models, please use OpenRouter instead:\n` +
        `  - Get an API key from https://openrouter.ai\n` +
        `  - Set OPENROUTER_API_KEY environment variable\n` +
        `  - Use model name like: anthropic/claude-sonnet-4-20250514\n` +
        `  - Set base URL to: https://openrouter.ai/api/v1`
      );
    }

    // Check for tool/function calling not supported error (common on free models)
    if (
      status === 404 &&
      (errorMessage.toLowerCase().includes('tool') ||
        errorMessage.toLowerCase().includes('function'))
    ) {
      return (
        `${errorMessage}\n\n` +
        `This model does not support tool/function calling.\n` +
        `Options:\n` +
        `  1. Use --disable-tools flag to run in basic chat mode (no file editing, no code execution)\n` +
        `  2. Switch to a model that supports tools, e.g.:\n` +
        `     - google/gemini-2.0-flash-exp:free (free, 1M context, tool support)\n` +
        `     - meta-llama/llama-3.3-70b-instruct:free (free, 128K context, tool support)\n` +
        `     - qwen/qwen-2.5-72b-instruct:free (free, 32K context, tool support)`
      );
    }

    return errorMessage;
  }

  private getTimeoutTroubleshootingTips(context: RequestContext): string {
    const baseTitle = context.isStreaming
      ? 'Streaming timeout troubleshooting:'
      : 'Troubleshooting tips:';

    const baseTips = [
      '- Reduce input length or complexity',
      '- Increase timeout in config: contentGenerator.timeout',
      '- Check network connectivity',
    ];

    const streamingSpecificTips = context.isStreaming
      ? [
          '- Check network stability for streaming connections',
          '- Consider using non-streaming mode for very long inputs',
        ]
      : ['- Consider using streaming mode for long responses'];

    return `${baseTitle}\n${[...baseTips, ...streamingSpecificTips].join('\n')}`;
  }
}
