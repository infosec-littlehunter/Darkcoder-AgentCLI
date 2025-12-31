/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { t } from '../../i18n/index.js';

/**
 * AI Provider definition with branding and model information
 */
export interface AIProvider {
  /** Unique identifier for the provider */
  id: string;
  /** Display name */
  name: string;
  /** Provider description */
  description: string;
  /** Provider icon/emoji for UI display */
  icon: string;
  /** Provider color for UI theming */
  color: string;
  /** Base URL for API calls */
  baseUrl: string;
  /** Environment variable for API key */
  envKeyName: string;
  /** List of available models */
  models: AIProviderModel[];
  /** Whether this provider is currently configured (has API key) */
  isConfigured?: boolean;
}

/**
 * Model definition within a provider
 */
export interface AIProviderModel {
  /** Model identifier (used in API calls) */
  id: string;
  /** Display name */
  name: string;
  /** Short description */
  description: string;
  /** Model capabilities tags */
  tags: string[];
  /** Is this a vision-capable model */
  isVision?: boolean;
  /** Context window size */
  contextWindow?: number;
  /** Relative cost indicator (1-5, 5 being most expensive) */
  costTier?: number;
  /** Price per 1 million input tokens in USD */
  inputPricePer1M?: number;
  /** Price per 1 million output tokens in USD */
  outputPricePer1M?: number;
}

/**
 * Available AI Providers with their models
 */
export const AI_PROVIDERS: AIProvider[] = [
  {
    id: 'qwen',
    name: 'Qwen',
    get description() {
      return t('Alibaba Cloud Qwen models - optimized for coding');
    },
    icon: '🔮',
    color: '#7C3AED',
    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    envKeyName: 'DASHSCOPE_API_KEY',
    models: [
      {
        id: 'coder-model',
        name: 'Qwen Coder Plus',
        get description() {
          return t('Latest Qwen coding model with excellent performance');
        },
        tags: ['coding', 'fast', 'recommended'],
        contextWindow: 131072,
        costTier: 2,
        inputPricePer1M: 0.5,
        outputPricePer1M: 1.5,
      },
      {
        id: 'vision-model',
        name: 'Qwen VL Plus',
        get description() {
          return t('Vision-language model for image understanding');
        },
        tags: ['vision', 'multimodal'],
        isVision: true,
        contextWindow: 32768,
        costTier: 3,
        inputPricePer1M: 0.8,
        outputPricePer1M: 2.0,
      },
      {
        id: 'qwen-max',
        name: 'Qwen Max',
        get description() {
          return t('Most capable Qwen model for complex reasoning');
        },
        tags: ['reasoning', 'complex'],
        contextWindow: 32768,
        costTier: 4,
        inputPricePer1M: 2.0,
        outputPricePer1M: 6.0,
      },
    ],
  },
  {
    id: 'anthropic',
    name: 'Anthropic Claude',
    get description() {
      return t('Claude models - use OpenRouter for API access');
    },
    icon: '🤖',
    color: '#D97706',
    // Note: Anthropic's direct API uses a different format than OpenAI
    // Users should use OpenRouter (https://openrouter.ai) for Claude via OpenAI-compatible API
    baseUrl: 'https://api.anthropic.com/v1',
    envKeyName: 'ANTHROPIC_API_KEY',
    models: [
      {
        id: 'claude-sonnet-4.5-20250514',
        name: 'Claude Sonnet 4.5',
        get description() {
          return t('Latest Claude Sonnet 4.5 - superior coding and analysis');
        },
        tags: ['coding', 'analysis', 'latest', 'recommended'],
        contextWindow: 200000,
        costTier: 3,
        inputPricePer1M: 3.0,
        outputPricePer1M: 15.0,
      },
      {
        id: 'claude-sonnet-4-20250514',
        name: 'Claude Sonnet 4',
        get description() {
          return t('Latest Claude - best balance of speed and capability');
        },
        tags: ['coding', 'analysis', 'recommended'],
        contextWindow: 200000,
        costTier: 3,
        inputPricePer1M: 3.0,
        outputPricePer1M: 15.0,
      },
      {
        id: 'claude-3-5-sonnet-20241022',
        name: 'Claude 3.5 Sonnet',
        get description() {
          return t('Fast and highly capable for most tasks');
        },
        tags: ['fast', 'coding'],
        contextWindow: 200000,
        costTier: 3,
        inputPricePer1M: 3.0,
        outputPricePer1M: 15.0,
      },
      {
        id: 'claude-3-5-haiku-20241022',
        name: 'Claude 3.5 Haiku',
        get description() {
          return t('Latest fast model with improved capabilities');
        },
        tags: ['fast', 'efficient', 'new'],
        contextWindow: 200000,
        costTier: 1,
        inputPricePer1M: 0.8,
        outputPricePer1M: 4.0,
      },
      {
        id: 'claude-3-opus-20240229',
        name: 'Claude 3 Opus',
        get description() {
          return t('Most capable Claude for complex reasoning');
        },
        tags: ['reasoning', 'complex', 'premium'],
        contextWindow: 200000,
        costTier: 5,
        inputPricePer1M: 15.0,
        outputPricePer1M: 75.0,
      },
      {
        id: 'claude-3-haiku-20240307',
        name: 'Claude 3 Haiku',
        get description() {
          return t('Fastest Claude model for quick tasks');
        },
        tags: ['fast', 'efficient'],
        contextWindow: 200000,
        costTier: 1,
        inputPricePer1M: 0.25,
        outputPricePer1M: 1.25,
      },
    ],
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    get description() {
      return t('Access many AI models through one API');
    },
    icon: '🔀',
    color: '#6366F1',
    baseUrl: 'https://openrouter.ai/api/v1',
    envKeyName: 'OPENROUTER_API_KEY',
    models: [
      {
        id: 'anthropic/claude-sonnet-4.5-20250514',
        name: 'Claude Sonnet 4.5',
        get description() {
          return t('Latest Claude Sonnet 4.5 via OpenRouter');
        },
        tags: ['coding', 'analysis', 'latest', 'recommended'],
        contextWindow: 200000,
        costTier: 3,
        inputPricePer1M: 3.0,
        outputPricePer1M: 15.0,
      },
      {
        id: 'anthropic/claude-sonnet-4-20250514',
        name: 'Claude Sonnet 4',
        get description() {
          return t('Latest Claude via OpenRouter');
        },
        tags: ['coding', 'analysis'],
        contextWindow: 200000,
        costTier: 3,
        inputPricePer1M: 3.0,
        outputPricePer1M: 15.0,
      },
      {
        id: 'anthropic/claude-3-5-sonnet-20241022',
        name: 'Claude 3.5 Sonnet',
        get description() {
          return t('Fast Claude via OpenRouter');
        },
        tags: ['fast', 'coding'],
        contextWindow: 200000,
        costTier: 3,
        inputPricePer1M: 3.0,
        outputPricePer1M: 15.0,
      },
      {
        id: 'anthropic/claude-3-5-haiku-20241022',
        name: 'Claude 3.5 Haiku',
        get description() {
          return t('Fast and efficient via OpenRouter');
        },
        tags: ['fast', 'efficient'],
        contextWindow: 200000,
        costTier: 1,
        inputPricePer1M: 0.8,
        outputPricePer1M: 4.0,
      },
      {
        id: 'openai/gpt-4o',
        name: 'GPT-4o',
        get description() {
          return t('OpenAI GPT-4o via OpenRouter');
        },
        tags: ['coding', 'vision'],
        contextWindow: 128000,
        costTier: 3,
        inputPricePer1M: 2.5,
        outputPricePer1M: 10.0,
      },
      {
        id: 'google/gemini-2.5-flash',
        name: 'Gemini 2.5 Flash',
        get description() {
          return t('Google Gemini via OpenRouter');
        },
        tags: ['fast', 'multimodal'],
        contextWindow: 1048576,
        costTier: 2,
        inputPricePer1M: 0.3,
        outputPricePer1M: 2.5,
      },
      {
        id: 'meta-llama/llama-3.3-70b-instruct',
        name: 'Llama 3.3 70B',
        get description() {
          return t('Open source model with strong performance');
        },
        tags: ['open-source', 'coding'],
        contextWindow: 131072,
        costTier: 1,
        inputPricePer1M: 0.4,
        outputPricePer1M: 0.4,
      },
      {
        id: 'mistralai/mistral-large-2411',
        name: 'Mistral Large',
        get description() {
          return t('Powerful model from Mistral AI');
        },
        tags: ['coding', 'reasoning'],
        contextWindow: 128000,
        costTier: 2,
        inputPricePer1M: 2.0,
        outputPricePer1M: 6.0,
      },
    ],
  },
  {
    id: 'openai',
    name: 'OpenAI',
    get description() {
      return t('GPT models - versatile and widely used');
    },
    icon: '🧠',
    color: '#10A37F',
    baseUrl: 'https://api.openai.com/v1',
    envKeyName: 'OPENAI_API_KEY',
    models: [
      {
        id: 'chatgpt-4o-latest',
        name: 'ChatGPT-4o',
        get description() {
          return t('Latest ChatGPT with dynamic model updates');
        },
        tags: ['coding', 'vision', 'latest', 'recommended'],
        isVision: true,
        contextWindow: 128000,
        costTier: 4,
        inputPricePer1M: 2.5,
        outputPricePer1M: 10.0,
      },
      {
        id: 'gpt-4o',
        name: 'GPT-4o',
        get description() {
          return t('Latest GPT-4 with vision and excellent coding');
        },
        tags: ['coding', 'vision', 'recommended'],
        isVision: true,
        contextWindow: 128000,
        costTier: 4,
        inputPricePer1M: 2.5,
        outputPricePer1M: 10.0,
      },
      {
        id: 'gpt-4o-mini',
        name: 'GPT-4o Mini',
        get description() {
          return t('Fast and efficient for most coding tasks');
        },
        tags: ['fast', 'efficient'],
        contextWindow: 128000,
        costTier: 1,
        inputPricePer1M: 0.15,
        outputPricePer1M: 0.6,
      },
      {
        id: 'o1',
        name: 'o1',
        get description() {
          return t('Advanced reasoning model for complex problems');
        },
        tags: ['reasoning', 'complex', 'premium'],
        contextWindow: 200000,
        costTier: 5,
        inputPricePer1M: 15.0,
        outputPricePer1M: 60.0,
      },
      {
        id: 'o1-mini',
        name: 'o1 Mini',
        get description() {
          return t('Fast reasoning model for STEM tasks');
        },
        tags: ['reasoning', 'efficient'],
        contextWindow: 128000,
        costTier: 3,
        inputPricePer1M: 3.0,
        outputPricePer1M: 12.0,
      },
      {
        id: 'o1-preview',
        name: 'o1 Preview',
        get description() {
          return t('Preview reasoning model (deprecated)');
        },
        tags: ['reasoning', 'deprecated'],
        contextWindow: 128000,
        costTier: 5,
        inputPricePer1M: 15.0,
        outputPricePer1M: 60.0,
      },
    ],
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    get description() {
      return t('DeepSeek models - cost-effective coding specialists');
    },
    icon: '🌊',
    color: '#0EA5E9',
    baseUrl: 'https://api.deepseek.com/v1',
    envKeyName: 'DEEPSEEK_API_KEY',
    models: [
      {
        id: 'deepseek-chat',
        name: 'DeepSeek Chat',
        get description() {
          return t('General purpose with strong coding abilities');
        },
        tags: ['coding', 'efficient'],
        contextWindow: 200000,
        costTier: 1,
        inputPricePer1M: 0.28,
        outputPricePer1M: 0.42,
      },
      {
        id: 'deepseek-reasoner',
        name: 'DeepSeek Reasoner',
        get description() {
          return t('Advanced reasoning model with chain-of-thought');
        },
        tags: ['reasoning', 'advanced'],
        contextWindow: 131072,
        costTier: 2,
        inputPricePer1M: 0.28,
        outputPricePer1M: 0.42,
      },
    ],
  },
  {
    id: 'google',
    name: 'Google Gemini',
    get description() {
      return t('Gemini models - multimodal and versatile');
    },
    icon: '✨',
    color: '#4285F4',
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai/',
    envKeyName: 'GEMINI_API_KEY',
    models: [
      {
        id: 'gemini-2.5-flash',
        name: 'Gemini 2.5 Flash',
        get description() {
          return t('Latest fast multimodal model - excellent for coding');
        },
        tags: ['fast', 'coding', 'recommended'],
        isVision: true,
        contextWindow: 1048576,
        costTier: 1,
        inputPricePer1M: 0.3,
        outputPricePer1M: 2.5,
      },
      {
        id: 'gemini-2.5-pro',
        name: 'Gemini 2.5 Pro',
        get description() {
          return t('Most capable Gemini for complex reasoning');
        },
        tags: ['reasoning', 'complex', 'premium'],
        isVision: true,
        contextWindow: 1048576,
        costTier: 3,
        inputPricePer1M: 1.25,
        outputPricePer1M: 10.0,
      },
      {
        id: 'gemini-2.0-flash',
        name: 'Gemini 2.0 Flash',
        get description() {
          return t('Fast multimodal model with great reasoning');
        },
        tags: ['fast', 'multimodal'],
        isVision: true,
        contextWindow: 1048576,
        costTier: 2,
        inputPricePer1M: 0.1,
        outputPricePer1M: 0.4,
      },
      {
        id: 'gemini-1.5-pro',
        name: 'Gemini 1.5 Pro',
        get description() {
          return t('Balanced performance with massive context');
        },
        tags: ['coding', 'long-context'],
        contextWindow: 2097152,
        costTier: 3,
        inputPricePer1M: 1.25,
        outputPricePer1M: 5.0,
      },
    ],
  },
];

/**
 * Get a provider by ID
 */
export function getProviderById(id: string): AIProvider | undefined {
  return AI_PROVIDERS.find((p) => p.id === id);
}

/**
 * Get a model by provider and model ID
 */
export function getModelById(
  providerId: string,
  modelId: string,
): AIProviderModel | undefined {
  const provider = getProviderById(providerId);
  return provider?.models.find((m) => m.id === modelId);
}

/**
 * Find provider by model ID (searches all providers)
 */
export function findProviderByModelId(modelId: string): AIProvider | undefined {
  return AI_PROVIDERS.find((p) => p.models.some((m) => m.id === modelId));
}

/**
 * Get all models across all providers, flattened
 */
export function getAllModels(): Array<{
  provider: AIProvider;
  model: AIProviderModel;
}> {
  return AI_PROVIDERS.flatMap((provider) =>
    provider.models.map((model) => ({ provider, model })),
  );
}

/**
 * Check if a provider is configured (has API key in environment)
 */
export function isProviderConfigured(provider: AIProvider): boolean {
  // Check provider-specific env var first
  if (process.env[provider.envKeyName]) {
    return true;
  }

  // For providers that can use OPENAI_API_KEY, check that too
  if (
    provider.id === 'google' ||
    provider.id === 'openai' ||
    provider.id === 'deepseek'
  ) {
    return !!process.env['OPENAI_API_KEY'];
  }

  return false;
}

/**
 * Get configured providers
 */
export function getConfiguredProviders(): AIProvider[] {
  return AI_PROVIDERS.filter(isProviderConfigured);
}
