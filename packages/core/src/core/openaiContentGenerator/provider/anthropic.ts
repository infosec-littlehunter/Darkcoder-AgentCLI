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
 * Provider for Anthropic Claude API (via OpenRouter or direct)
 *
 * Anthropic Claude models can be accessed via:
 * 1. OpenRouter (recommended) - https://openrouter.ai/api/v1
 * 2. Direct Anthropic API - https://api.anthropic.com/v1
 *
 * Popular Claude models:
 * - claude-sonnet-4.5-20250514 (Latest Sonnet 4.5, superior coding)
 * - claude-sonnet-4-20250514 (Latest Sonnet 4, best for coding)
 * - claude-3-5-sonnet-20241022 (Fast and capable)
 * - claude-3-5-haiku-20241022 (Latest fast model)
 * - claude-3-opus-20240229 (Most capable)
 * - claude-3-haiku-20240307 (Fastest)
 */
export class AnthropicOpenAICompatibleProvider extends DefaultOpenAICompatibleProvider {
  constructor(
    contentGeneratorConfig: ContentGeneratorConfig,
    cliConfig: Config,
  ) {
    super(contentGeneratorConfig, cliConfig);
  }

  /**
   * Checks if the configuration is for Anthropic Claude.
   * Detects based on:
   * - Base URL containing 'anthropic.com'
   * - API key starting with 'sk-ant-'
   * - Model name starting with 'claude' or 'anthropic/'
   */
  static isAnthropicProvider(
    contentGeneratorConfig: ContentGeneratorConfig,
  ): boolean {
    const baseUrl = contentGeneratorConfig.baseUrl ?? '';
    const apiKey = contentGeneratorConfig.apiKey ?? '';
    const model = contentGeneratorConfig.model ?? '';

    // Check base URL
    if (baseUrl.toLowerCase().includes('anthropic.com')) {
      return true;
    }

    // Check API key format (Anthropic keys start with sk-ant-)
    if (apiKey.startsWith('sk-ant-')) {
      return true;
    }

    // Check model name (for OpenRouter format)
    if (
      model.toLowerCase().startsWith('claude') ||
      model.toLowerCase().startsWith('anthropic/')
    ) {
      return true;
    }

    return false;
  }

  override buildHeaders(): Record<string, string | undefined> {
    const baseHeaders = super.buildHeaders();
    const baseUrl = this.contentGeneratorConfig.baseUrl ?? '';

    // For direct Anthropic API
    if (baseUrl.includes('anthropic.com')) {
      return {
        ...baseHeaders,
        'anthropic-version': '2023-06-01',
        'x-api-key': this.contentGeneratorConfig.apiKey,
      };
    }

    // For OpenRouter with Claude models
    return {
      ...baseHeaders,
      'HTTP-Referer': 'https://github.com/QwenLM/qwen-code.git',
      'X-Title': 'Qwen Code - Claude Integration',
    };
  }

  override buildRequest(
    request: OpenAI.Chat.ChatCompletionCreateParams,
    userPromptId: string,
  ): OpenAI.Chat.ChatCompletionCreateParams {
    const baseRequest = super.buildRequest(request, userPromptId);

    // Claude-specific optimizations
    // Claude prefers explicit system messages and handles them well
    // No special transformations needed for OpenAI-compatible format

    return baseRequest;
  }
}
