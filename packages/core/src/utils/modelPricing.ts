/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Model pricing database with real-time cost calculation
 * Updated: December 2025
 */

export interface ModelPricing {
  inputPricePer1M: number;
  outputPricePer1M: number;
  cachedInputPricePer1M?: number; // For models supporting prompt caching
  contextWindow?: number;
}

/**
 * Comprehensive model pricing database
 */
export const MODEL_PRICING: Record<string, ModelPricing> = {
  // Anthropic Claude Models
  'claude-sonnet-4.5-20250514': {
    inputPricePer1M: 3.0,
    outputPricePer1M: 15.0,
    cachedInputPricePer1M: 0.3,
    contextWindow: 200000,
  },
  'claude-sonnet-4-20250514': {
    inputPricePer1M: 3.0,
    outputPricePer1M: 15.0,
    cachedInputPricePer1M: 0.3,
    contextWindow: 200000,
  },
  'claude-3-5-sonnet-20241022': {
    inputPricePer1M: 3.0,
    outputPricePer1M: 15.0,
    cachedInputPricePer1M: 0.3,
    contextWindow: 200000,
  },
  'claude-3-5-haiku-20241022': {
    inputPricePer1M: 0.8,
    outputPricePer1M: 4.0,
    cachedInputPricePer1M: 0.08,
    contextWindow: 200000,
  },
  'claude-3-opus-20240229': {
    inputPricePer1M: 15.0,
    outputPricePer1M: 75.0,
    cachedInputPricePer1M: 1.5,
    contextWindow: 200000,
  },
  'claude-3-haiku-20240307': {
    inputPricePer1M: 0.25,
    outputPricePer1M: 1.25,
    cachedInputPricePer1M: 0.03,
    contextWindow: 200000,
  },

  // OpenAI Models (Official pricing as of Dec 2025)
  'chatgpt-4o-latest': {
    inputPricePer1M: 2.5,
    outputPricePer1M: 10.0,
    cachedInputPricePer1M: 1.25,
    contextWindow: 128000,
  },
  'gpt-4o': {
    inputPricePer1M: 2.5,
    outputPricePer1M: 10.0,
    cachedInputPricePer1M: 1.25,
    contextWindow: 128000,
  },
  'gpt-4o-2024-11-20': {
    inputPricePer1M: 2.5,
    outputPricePer1M: 10.0,
    cachedInputPricePer1M: 1.25,
    contextWindow: 128000,
  },
  'gpt-4o-mini': {
    inputPricePer1M: 0.15,
    outputPricePer1M: 0.6,
    cachedInputPricePer1M: 0.075,
    contextWindow: 128000,
  },
  'gpt-4o-mini-2024-07-18': {
    inputPricePer1M: 0.15,
    outputPricePer1M: 0.6,
    cachedInputPricePer1M: 0.075,
    contextWindow: 128000,
  },
  o1: {
    inputPricePer1M: 15.0,
    outputPricePer1M: 60.0,
    contextWindow: 200000,
  },
  'o1-2024-12-17': {
    inputPricePer1M: 15.0,
    outputPricePer1M: 60.0,
    contextWindow: 200000,
  },
  'o1-preview': {
    inputPricePer1M: 15.0,
    outputPricePer1M: 60.0,
    contextWindow: 128000,
  },
  'o1-preview-2024-09-12': {
    inputPricePer1M: 15.0,
    outputPricePer1M: 60.0,
    contextWindow: 128000,
  },
  'o1-mini': {
    inputPricePer1M: 3.0,
    outputPricePer1M: 12.0,
    contextWindow: 128000,
  },
  'o1-mini-2024-09-12': {
    inputPricePer1M: 3.0,
    outputPricePer1M: 12.0,
    contextWindow: 128000,
  },
  'gpt-4-turbo': {
    inputPricePer1M: 10.0,
    outputPricePer1M: 30.0,
    contextWindow: 128000,
  },
  'gpt-4-turbo-2024-04-09': {
    inputPricePer1M: 10.0,
    outputPricePer1M: 30.0,
    contextWindow: 128000,
  },

  // Google Gemini Models
  'gemini-2.5-flash': {
    inputPricePer1M: 0.075,
    outputPricePer1M: 0.3,
    cachedInputPricePer1M: 0.01875,
    contextWindow: 1048576,
  },
  'gemini-2.5-flash-latest': {
    inputPricePer1M: 0.075,
    outputPricePer1M: 0.3,
    cachedInputPricePer1M: 0.01875,
    contextWindow: 1048576,
  },
  'gemini-2.5-pro': {
    inputPricePer1M: 1.25,
    outputPricePer1M: 10.0,
    cachedInputPricePer1M: 0.31,
    contextWindow: 1048576,
  },
  'gemini-2.0-flash': {
    inputPricePer1M: 0.1,
    outputPricePer1M: 0.4,
    contextWindow: 1048576,
  },
  'gemini-1.5-pro': {
    inputPricePer1M: 1.25,
    outputPricePer1M: 5.0,
    cachedInputPricePer1M: 0.31,
    contextWindow: 2097152,
  },

  // DeepSeek Models
  'deepseek-chat': {
    inputPricePer1M: 0.28,
    outputPricePer1M: 0.42,
    cachedInputPricePer1M: 0.028,
    contextWindow: 128000,
  },
  'deepseek-reasoner': {
    inputPricePer1M: 0.28,
    outputPricePer1M: 0.42,
    contextWindow: 128000,
  },

  // Qwen Models
  'qwen3-coder-plus': {
    inputPricePer1M: 0.5,
    outputPricePer1M: 1.5,
    contextWindow: 1048576,
  },
  'qwen-plus-latest': {
    inputPricePer1M: 0.28,
    outputPricePer1M: 0.84,
    contextWindow: 1048576,
  },
  'qwen-max': {
    inputPricePer1M: 2.0,
    outputPricePer1M: 6.0,
    contextWindow: 32768,
  },
  'coder-model': {
    inputPricePer1M: 0.5,
    outputPricePer1M: 1.5,
    contextWindow: 131072,
  },

  // Mistral Models
  'mistral-large-2411': {
    inputPricePer1M: 2.0,
    outputPricePer1M: 6.0,
    contextWindow: 128000,
  },
  codestral: {
    inputPricePer1M: 0.2,
    outputPricePer1M: 0.6,
    contextWindow: 32000,
  },

  // Meta Llama Models
  'llama-3.3-70b-instruct': {
    inputPricePer1M: 0.4,
    outputPricePer1M: 0.4,
    contextWindow: 131072,
  },
};

/**
 * Default pricing for unknown models
 */
const DEFAULT_PRICING: ModelPricing = {
  inputPricePer1M: 1.0,
  outputPricePer1M: 3.0,
  contextWindow: 128000,
};

/**
 * Get pricing for a specific model
 * Supports partial matching (e.g., "gpt-4o" matches "gpt-4o-2024-05-13")
 */
export function getModelPricing(modelId: string): ModelPricing {
  // Direct match
  if (MODEL_PRICING[modelId]) {
    return MODEL_PRICING[modelId];
  }

  // Try to match by removing provider prefix (e.g., "anthropic/claude-sonnet-4")
  const modelWithoutPrefix = modelId.split('/').pop() || modelId;
  if (MODEL_PRICING[modelWithoutPrefix]) {
    return MODEL_PRICING[modelWithoutPrefix];
  }

  // Try partial match (find model ID that starts with the given string)
  for (const [key, pricing] of Object.entries(MODEL_PRICING)) {
    if (
      key.startsWith(modelWithoutPrefix) ||
      modelWithoutPrefix.startsWith(key)
    ) {
      return pricing;
    }
  }

  // Return default pricing
  return DEFAULT_PRICING;
}

/**
 * Calculate cost for token usage
 */
export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cachedInputTokens?: number;
}

export interface CostBreakdown {
  inputCost: number;
  outputCost: number;
  cachedInputCost: number;
  totalCost: number;
  estimatedSavingsFromCache: number;
}

/**
 * Calculate real-time cost for token usage
 */
export function calculateCost(
  modelId: string,
  usage: TokenUsage,
): CostBreakdown {
  const pricing = getModelPricing(modelId);

  const inputCost = (usage.inputTokens / 1_000_000) * pricing.inputPricePer1M;
  const outputCost =
    (usage.outputTokens / 1_000_000) * pricing.outputPricePer1M;

  let cachedInputCost = 0;
  let estimatedSavingsFromCache = 0;

  if (usage.cachedInputTokens && pricing.cachedInputPricePer1M) {
    cachedInputCost =
      (usage.cachedInputTokens / 1_000_000) * pricing.cachedInputPricePer1M;
    estimatedSavingsFromCache =
      (usage.cachedInputTokens / 1_000_000) *
      (pricing.inputPricePer1M - pricing.cachedInputPricePer1M);
  }

  const totalCost = inputCost + outputCost + cachedInputCost;

  return {
    inputCost,
    outputCost,
    cachedInputCost,
    totalCost,
    estimatedSavingsFromCache,
  };
}

/**
 * Format cost as a readable string
 */
export function formatCost(cost: number, includeSymbol = true): string {
  const symbol = includeSymbol ? '$' : '';

  if (cost < 0.0001) {
    return `<${symbol}0.0001`;
  }
  if (cost < 0.001) {
    return `${symbol}${cost.toFixed(5)}`;
  }
  if (cost < 0.01) {
    return `${symbol}${cost.toFixed(4)}`;
  }
  if (cost < 1) {
    return `${symbol}${cost.toFixed(3)}`;
  }
  return `${symbol}${cost.toFixed(2)}`;
}

/**
 * Format token count with K/M suffixes
 */
export function formatTokenCount(count: number): string {
  if (count < 1000) {
    return count.toString();
  }
  if (count < 1_000_000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return `${(count / 1_000_000).toFixed(2)}M`;
}

/**
 * Get cost per 1000 tokens (for display purposes)
 */
export function getCostPer1000Tokens(modelId: string): {
  input: number;
  output: number;
} {
  const pricing = getModelPricing(modelId);
  return {
    input: pricing.inputPricePer1M / 1000,
    output: pricing.outputPricePer1M / 1000,
  };
}

/**
 * Estimate cost for a given number of tokens
 */
export function estimateCost(
  modelId: string,
  inputTokens: number,
  outputTokens: number,
): number {
  const breakdown = calculateCost(modelId, { inputTokens, outputTokens });
  return breakdown.totalCost;
}

/**
 * Compare costs between different models
 */
export function compareModelCosts(
  models: string[],
  inputTokens: number,
  outputTokens: number,
): Array<{ modelId: string; cost: number; formattedCost: string }> {
  return models
    .map((modelId) => {
      const cost = estimateCost(modelId, inputTokens, outputTokens);
      return {
        modelId,
        cost,
        formattedCost: formatCost(cost),
      };
    })
    .sort((a, b) => a.cost - b.cost);
}
