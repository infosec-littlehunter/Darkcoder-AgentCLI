/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type OpenAI from 'openai';
import type { Config } from '../../../config/config.js';
import type { ContentGeneratorConfig } from '../../contentGenerator.js';
import { DefaultOpenAICompatibleProvider } from './default.js';

/**
 * Provider for Google Gemini API (via OpenAI-compatible endpoint)
 *
 * Google Gemini models can be accessed via:
 * 1. OpenAI-compatible endpoint - https://generativelanguage.googleapis.com/v1beta/openai/
 * 2. OpenRouter - https://openrouter.ai/api/v1
 *
 * Popular Gemini models:
 * - gemini-2.5-pro-preview-06-05 (Latest, most capable)
 * - gemini-2.5-flash-preview-05-20 (Fast and efficient)
 * - gemini-2.0-flash (Production ready)
 * - gemini-1.5-pro (Stable, large context)
 * - gemini-1.5-flash (Fast, cost-effective)
 *
 * Environment variables:
 * - GEMINI_API_KEY: Your Google AI Studio API key
 *
 * Usage:
 * ```bash
 * export GEMINI_API_KEY="your-api-key"
 * export OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
 * export OPENAI_API_KEY="$GEMINI_API_KEY"
 * qwen-code --model gemini-2.5-flash
 * ```
 */
export class GeminiOpenAICompatibleProvider extends DefaultOpenAICompatibleProvider {
  constructor(
    contentGeneratorConfig: ContentGeneratorConfig,
    cliConfig: Config,
  ) {
    super(contentGeneratorConfig, cliConfig);
  }

  /**
   * Checks if the configuration is for Google Gemini.
   * Detects based on:
   * - Base URL containing 'generativelanguage.googleapis.com'
   * - Model name starting with 'gemini' or 'google/'
   */
  static isGeminiProvider(
    contentGeneratorConfig: ContentGeneratorConfig,
  ): boolean {
    const baseUrl = contentGeneratorConfig.baseUrl ?? '';
    const model = contentGeneratorConfig.model ?? '';

    // Check base URL for Google's generative language API
    if (
      baseUrl.toLowerCase().includes('generativelanguage.googleapis.com') ||
      baseUrl.toLowerCase().includes('aiplatform.googleapis.com')
    ) {
      return true;
    }

    // Check model name (for OpenRouter or direct usage)
    if (
      model.toLowerCase().startsWith('gemini') ||
      model.toLowerCase().startsWith('google/')
    ) {
      return true;
    }

    return false;
  }

  override buildHeaders(): Record<string, string | undefined> {
    const baseHeaders = super.buildHeaders();
    const baseUrl = this.contentGeneratorConfig.baseUrl ?? '';

    // For Google's generative language API
    if (
      baseUrl.includes('generativelanguage.googleapis.com') ||
      baseUrl.includes('aiplatform.googleapis.com')
    ) {
      return {
        ...baseHeaders,
        'x-goog-api-client': 'qwen-code',
      };
    }

    // For OpenRouter with Gemini models
    return {
      ...baseHeaders,
      'HTTP-Referer': 'https://github.com/QwenLM/qwen-code.git',
      'X-Title': 'Qwen Code - Gemini Integration',
    };
  }

  override buildRequest(
    request: OpenAI.Chat.ChatCompletionCreateParams,
    userPromptId: string,
  ): OpenAI.Chat.ChatCompletionCreateParams {
    const baseRequest = super.buildRequest(request, userPromptId);

    // Gemini-specific handling
    // Extract native system instruction if available (passed via _systemInstruction)
    const systemInstruction = (request as any)._systemInstruction;

    if (systemInstruction) {
      // For Gemini, preserve system instruction for native handling
      // This is a workaround for OpenAI-compatible endpoint
      (baseRequest as any)._nativeSystemInstruction = systemInstruction;
      // Remove from messages to prevent duplication
      baseRequest.messages = baseRequest.messages.filter(
        (msg) => msg.role !== 'system',
      );
    }

    // Remove unsupported parameters for Gemini
    const geminiRequest = { ...baseRequest };

    // Gemini doesn't support 'logprobs' in OpenAI-compatible mode
    if ('logprobs' in geminiRequest) {
      delete (geminiRequest as Record<string, unknown>)['logprobs'];
    }

    // Gemini doesn't support 'top_logprobs' in OpenAI-compatible mode
    if ('top_logprobs' in geminiRequest) {
      delete (geminiRequest as Record<string, unknown>)['top_logprobs'];
    }

    return geminiRequest;
  }
}
