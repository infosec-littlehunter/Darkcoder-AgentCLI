/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type OpenAI from 'openai';
import { GeminiOpenAICompatibleProvider } from './gemini.js';
import { DefaultOpenAICompatibleProvider } from './default.js';
import type { Config } from '../../../config/config.js';
import type { ContentGeneratorConfig } from '../../contentGenerator.js';

// Mock OpenAI
vi.mock('openai', () => ({
  default: vi.fn().mockImplementation(() => ({
    chat: {
      completions: {
        create: vi.fn(),
      },
    },
  })),
}));

describe('GeminiOpenAICompatibleProvider', () => {
  let provider: GeminiOpenAICompatibleProvider;
  let mockContentGeneratorConfig: ContentGeneratorConfig;
  let mockCliConfig: Config;

  beforeEach(() => {
    vi.clearAllMocks();

    // Mock ContentGeneratorConfig
    mockContentGeneratorConfig = {
      apiKey: 'test-api-key',
      baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai/',
      timeout: 60000,
      maxRetries: 2,
      model: 'gemini-2.5-flash',
    } as ContentGeneratorConfig;

    // Mock Config
    mockCliConfig = {
      getCliVersion: vi.fn().mockReturnValue('1.0.0'),
    } as unknown as Config;

    provider = new GeminiOpenAICompatibleProvider(
      mockContentGeneratorConfig,
      mockCliConfig,
    );
  });

  describe('constructor', () => {
    it('should extend DefaultOpenAICompatibleProvider', () => {
      expect(provider).toBeInstanceOf(DefaultOpenAICompatibleProvider);
      expect(provider).toBeInstanceOf(GeminiOpenAICompatibleProvider);
    });
  });

  describe('isGeminiProvider', () => {
    it('should return true for generativelanguage.googleapis.com URLs', () => {
      const configs = [
        { baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai/' },
        { baseUrl: 'https://generativelanguage.googleapis.com/v1/models' },
      ];

      configs.forEach((config) => {
        const result = GeminiOpenAICompatibleProvider.isGeminiProvider(
          config as ContentGeneratorConfig,
        );
        expect(result).toBe(true);
      });
    });

    it('should return true for aiplatform.googleapis.com URLs', () => {
      const config = {
        baseUrl: 'https://aiplatform.googleapis.com/v1/projects/test',
      };
      const result = GeminiOpenAICompatibleProvider.isGeminiProvider(
        config as ContentGeneratorConfig,
      );
      expect(result).toBe(true);
    });

    it('should return true for gemini model names', () => {
      const configs = [
        { model: 'gemini-2.5-pro' },
        { model: 'gemini-2.5-flash' },
        { model: 'gemini-2.0-flash' },
        { model: 'gemini-1.5-pro' },
        { model: 'gemini-1.5-flash' },
      ];

      configs.forEach((config) => {
        const result = GeminiOpenAICompatibleProvider.isGeminiProvider(
          config as ContentGeneratorConfig,
        );
        expect(result).toBe(true);
      });
    });

    it('should return true for google/ prefixed models (OpenRouter format)', () => {
      const config = { model: 'google/gemini-2.5-pro' };
      const result = GeminiOpenAICompatibleProvider.isGeminiProvider(
        config as ContentGeneratorConfig,
      );
      expect(result).toBe(true);
    });

    it('should return false for non-Gemini URLs and models', () => {
      const configs = [
        { baseUrl: 'https://api.openai.com/v1', model: 'gpt-4' },
        { baseUrl: 'https://api.anthropic.com/v1', model: 'claude-3-sonnet' },
        { baseUrl: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
      ];

      configs.forEach((config) => {
        const result = GeminiOpenAICompatibleProvider.isGeminiProvider(
          config as ContentGeneratorConfig,
        );
        expect(result).toBe(false);
      });
    });
  });

  describe('buildHeaders', () => {
    it('should add x-goog-api-client header for Google API URLs', () => {
      const headers = provider.buildHeaders();

      expect(headers).toHaveProperty('x-goog-api-client', 'qwen-code');
      expect(headers).toHaveProperty('User-Agent');
    });

    it('should add OpenRouter headers for non-Google URLs', () => {
      const openRouterConfig = {
        ...mockContentGeneratorConfig,
        baseUrl: 'https://openrouter.ai/api/v1',
      };

      const openRouterProvider = new GeminiOpenAICompatibleProvider(
        openRouterConfig as ContentGeneratorConfig,
        mockCliConfig,
      );

      const headers = openRouterProvider.buildHeaders();

      expect(headers).toHaveProperty(
        'HTTP-Referer',
        'https://github.com/QwenLM/qwen-code.git',
      );
      expect(headers).toHaveProperty(
        'X-Title',
        'Qwen Code - Gemini Integration',
      );
    });
  });

  describe('buildRequest', () => {
    it('should remove logprobs from request', () => {
      const request = {
        model: 'gemini-2.5-flash',
        messages: [{ role: 'user', content: 'Hello' }],
        logprobs: true,
      } as OpenAI.Chat.ChatCompletionCreateParams;

      const result = provider.buildRequest(request, 'test-prompt-id');

      expect(result).not.toHaveProperty('logprobs');
    });

    it('should remove top_logprobs from request', () => {
      const request = {
        model: 'gemini-2.5-flash',
        messages: [{ role: 'user', content: 'Hello' }],
        top_logprobs: 5,
      } as OpenAI.Chat.ChatCompletionCreateParams;

      const result = provider.buildRequest(request, 'test-prompt-id');

      expect(result).not.toHaveProperty('top_logprobs');
    });

    it('should preserve other parameters', () => {
      const request = {
        model: 'gemini-2.5-flash',
        messages: [{ role: 'user', content: 'Hello' }],
        temperature: 0.7,
        max_tokens: 1000,
      } as OpenAI.Chat.ChatCompletionCreateParams;

      const result = provider.buildRequest(request, 'test-prompt-id');

      expect(result.model).toBe('gemini-2.5-flash');
      expect(result.temperature).toBe(0.7);
      expect(result.max_tokens).toBe(1000);
    });
  });
});
