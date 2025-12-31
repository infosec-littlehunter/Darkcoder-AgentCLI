/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type { SessionMetrics, ModelMetrics } from '@darkcoder/darkcoder-core';
import { AI_PROVIDERS } from '../models/aiProviders.js';

/**
 * Default pricing for unknown models (per 1M tokens)
 */
const DEFAULT_PRICING = {
  inputPricePer1M: 1.0,
  outputPricePer1M: 3.0,
};

/**
 * Find model pricing by model ID (searches all providers)
 */
export function findModelPricing(modelId: string): {
  inputPricePer1M: number;
  outputPricePer1M: number;
} {
  // Handle free models (e.g., "meta-llama/llama-3.3-70b-instruct:free")
  if (modelId.endsWith(':free')) {
    return {
      inputPricePer1M: 0,
      outputPricePer1M: 0,
    };
  }

  for (const provider of AI_PROVIDERS) {
    const model = provider.models.find((m) => m.id === modelId);
    if (model) {
      return {
        inputPricePer1M:
          model.inputPricePer1M ?? DEFAULT_PRICING.inputPricePer1M,
        outputPricePer1M:
          model.outputPricePer1M ?? DEFAULT_PRICING.outputPricePer1M,
      };
    }
  }

  // Try to find partial match (e.g., "gpt-4o" in "openai/gpt-4o")
  // Also strip :free suffix for matching base model
  const baseModelId = modelId.replace(/:free$/, '');
  for (const provider of AI_PROVIDERS) {
    const model = provider.models.find(
      (m) =>
        modelId.includes(m.id) ||
        m.id.includes(modelId) ||
        baseModelId.includes(m.id) ||
        m.id.includes(baseModelId),
    );
    if (model) {
      return {
        inputPricePer1M:
          model.inputPricePer1M ?? DEFAULT_PRICING.inputPricePer1M,
        outputPricePer1M:
          model.outputPricePer1M ?? DEFAULT_PRICING.outputPricePer1M,
      };
    }
  }

  return DEFAULT_PRICING;
}

/**
 * Calculate cost for a single model's usage
 */
export function calculateModelCost(
  modelId: string,
  metrics: ModelMetrics,
): number {
  const pricing = findModelPricing(modelId);
  const inputCost =
    (metrics.tokens.prompt / 1_000_000) * pricing.inputPricePer1M;
  const outputCost =
    (metrics.tokens.candidates / 1_000_000) * pricing.outputPricePer1M;
  return inputCost + outputCost;
}

/**
 * Calculate total session cost across all models
 */
export function calculateSessionCost(metrics: SessionMetrics): number {
  let totalCost = 0;
  for (const [modelId, modelMetrics] of Object.entries(metrics.models)) {
    totalCost += calculateModelCost(modelId, modelMetrics);
  }
  return totalCost;
}

/**
 * Get detailed cost breakdown by model
 */
export interface ModelCostBreakdown {
  modelId: string;
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  inputCost: number;
  outputCost: number;
  totalCost: number;
}

export function getSessionCostBreakdown(
  metrics: SessionMetrics,
): ModelCostBreakdown[] {
  const breakdown: ModelCostBreakdown[] = [];

  for (const [modelId, modelMetrics] of Object.entries(metrics.models)) {
    const pricing = findModelPricing(modelId);
    const inputCost =
      (modelMetrics.tokens.prompt / 1_000_000) * pricing.inputPricePer1M;
    const outputCost =
      (modelMetrics.tokens.candidates / 1_000_000) * pricing.outputPricePer1M;

    breakdown.push({
      modelId,
      inputTokens: modelMetrics.tokens.prompt,
      outputTokens: modelMetrics.tokens.candidates,
      cachedTokens: modelMetrics.tokens.cached,
      inputCost,
      outputCost,
      totalCost: inputCost + outputCost,
    });
  }

  return breakdown.sort((a, b) => b.totalCost - a.totalCost);
}

/**
 * Format cost as currency string
 */
export function formatCost(cost: number): string {
  if (cost < 0.001) {
    return '<$0.001';
  }
  if (cost < 0.01) {
    return `$${cost.toFixed(4)}`;
  }
  if (cost < 1) {
    return `$${cost.toFixed(3)}`;
  }
  return `$${cost.toFixed(2)}`;
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
 * Get total tokens from session metrics
 */
export function getSessionTokens(metrics: SessionMetrics): {
  input: number;
  output: number;
  cached: number;
  total: number;
} {
  let input = 0;
  let output = 0;
  let cached = 0;

  for (const modelMetrics of Object.values(metrics.models)) {
    input += modelMetrics.tokens.prompt;
    output += modelMetrics.tokens.candidates;
    cached += modelMetrics.tokens.cached;
  }

  return {
    input,
    output,
    cached,
    total: input + output,
  };
}
