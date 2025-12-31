/**
 * Model Pricing and Configuration Validation Tests
 * Verifies pricing accuracy, token limits, and cost calculations for all supported models
 */

import { describe, it, expect } from 'vitest';
import {
  getModelPricing,
  calculateCost,
  compareModelCosts,
} from '../packages/core/src/utils/modelPricing.js';

describe('Model Pricing Validation', () => {
  describe('Anthropic Claude Models', () => {
    it('should have correct pricing for Claude Sonnet 4.5', () => {
      const pricing = getModelPricing('claude-sonnet-4.5-20250514');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(3.0);
      expect(pricing?.outputPricePer1M).toBe(15.0);
      expect(pricing?.cachedInputPricePer1M).toBe(0.3);
      expect(pricing?.contextWindow).toBe(200000);
    });

    it('should have correct pricing for Claude Sonnet 4', () => {
      const pricing = getModelPricing('claude-sonnet-4-20250514');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(3.0);
      expect(pricing?.outputPricePer1M).toBe(15.0);
      expect(pricing?.cachedInputPricePer1M).toBe(0.3);
    });

    it('should have correct pricing for Claude 3.5 Sonnet', () => {
      const pricing = getModelPricing('claude-3-5-sonnet-20241022');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(3.0);
      expect(pricing?.outputPricePer1M).toBe(15.0);
      expect(pricing?.cachedInputPricePer1M).toBe(0.3);
    });

    it('should have correct pricing for Claude 3.5 Haiku', () => {
      const pricing = getModelPricing('claude-3-5-haiku-20241022');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(0.8);
      expect(pricing?.outputPricePer1M).toBe(4.0);
      expect(pricing?.cachedInputPricePer1M).toBe(0.08);
    });

    it('should have correct pricing for Claude 3 Opus', () => {
      const pricing = getModelPricing('claude-3-opus-20240229');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(15.0);
      expect(pricing?.outputPricePer1M).toBe(75.0);
    });

    it('should have correct pricing for Claude 3 Haiku', () => {
      const pricing = getModelPricing('claude-3-haiku-20240307');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(0.25);
      expect(pricing?.outputPricePer1M).toBe(1.25);
    });
  });

  describe('OpenAI Models', () => {
    it('should have correct pricing for ChatGPT-4o', () => {
      const pricing = getModelPricing('chatgpt-4o-latest');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(2.5);
      expect(pricing?.outputPricePer1M).toBe(10.0);
      expect(pricing?.cachedInputPricePer1M).toBe(1.25);
    });

    it('should have correct pricing for GPT-4o', () => {
      const pricing = getModelPricing('gpt-4o');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(2.5);
      expect(pricing?.outputPricePer1M).toBe(10.0);
      expect(pricing?.cachedInputPricePer1M).toBe(1.25);
    });

    it('should have correct pricing for GPT-4o Mini', () => {
      const pricing = getModelPricing('gpt-4o-mini');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(0.15);
      expect(pricing?.outputPricePer1M).toBe(0.6);
      expect(pricing?.cachedInputPricePer1M).toBe(0.075);
    });

    it('should have correct pricing for o1', () => {
      const pricing = getModelPricing('o1');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(15.0);
      expect(pricing?.outputPricePer1M).toBe(60.0);
      expect(pricing?.contextWindow).toBe(200000);
    });

    it('should have correct pricing for o1-mini', () => {
      const pricing = getModelPricing('o1-mini');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(3.0);
      expect(pricing?.outputPricePer1M).toBe(12.0);
    });

    it('should have correct pricing for o1-preview', () => {
      const pricing = getModelPricing('o1-preview');
      expect(pricing).toBeDefined();
      expect(pricing?.inputPricePer1M).toBe(15.0);
      expect(pricing?.outputPricePer1M).toBe(60.0);
    });
  });

  describe('Cost Calculation', () => {
    it('should calculate cost correctly for Claude Sonnet 4.5', () => {
      const cost = calculateCost('claude-sonnet-4.5-20250514', {
        inputTokens: 100000,
        outputTokens: 50000,
      });
      expect(cost.totalCost).toBeCloseTo(1.05, 2); // (100k/1M)*3 + (50k/1M)*15 = 0.3 + 0.75 = 1.05
      expect(cost.inputCost).toBeCloseTo(0.3, 2);
      expect(cost.outputCost).toBeCloseTo(0.75, 2);
    });

    it('should calculate cost with caching for Claude 3.5 Sonnet', () => {
      const cost = calculateCost('claude-3-5-sonnet-20241022', {
        inputTokens: 20000,
        outputTokens: 50000,
        cachedInputTokens: 80000,
      });
      expect(cost.totalCost).toBeCloseTo(0.834, 2);
      // (20k/1M)*3 + (80k/1M)*0.3 + (50k/1M)*15 = 0.06 + 0.024 + 0.75 = 0.834
      expect(cost.inputCost).toBeCloseTo(0.06, 2);
      expect(cost.cachedInputCost).toBeCloseTo(0.024, 2);
      expect(cost.outputCost).toBeCloseTo(0.75, 2);
    });

    it('should calculate cost correctly for GPT-4o', () => {
      const cost = calculateCost('gpt-4o', {
        inputTokens: 100000,
        outputTokens: 50000,
      });
      expect(cost.totalCost).toBeCloseTo(0.75, 2); // (100k/1M)*2.5 + (50k/1M)*10 = 0.25 + 0.5 = 0.75
      expect(cost.inputCost).toBeCloseTo(0.25, 2);
      expect(cost.outputCost).toBeCloseTo(0.5, 2);
    });

    it('should calculate cost correctly for o1', () => {
      const cost = calculateCost('o1', {
        inputTokens: 100000,
        outputTokens: 50000,
      });
      expect(cost.totalCost).toBeCloseTo(4.5, 2); // (100k/1M)*15 + (50k/1M)*60 = 1.5 + 3.0 = 4.5
      expect(cost.inputCost).toBeCloseTo(1.5, 2);
      expect(cost.outputCost).toBeCloseTo(3.0, 2);
    });

    it('should calculate cost correctly for o1-mini', () => {
      const cost = calculateCost('o1-mini', {
        inputTokens: 100000,
        outputTokens: 50000,
      });
      expect(cost.totalCost).toBeCloseTo(0.9, 2); // (100k/1M)*3 + (50k/1M)*12 = 0.3 + 0.6 = 0.9
      expect(cost.inputCost).toBeCloseTo(0.3, 2);
      expect(cost.outputCost).toBeCloseTo(0.6, 2);
    });

    it('should return cost for unknown model using defaults', () => {
      const cost = calculateCost('unknown-model', {
        inputTokens: 100000,
        outputTokens: 50000,
      });
      // Default pricing: input=$1/1M, output=$3/1M
      expect(cost.totalCost).toBeCloseTo(0.25, 2); // (100k/1M)*1 + (50k/1M)*3 = 0.1 + 0.15 = 0.25
    });
  });

  describe('Model Comparison', () => {
    it('should compare costs correctly', () => {
      const comparison = compareModelCosts(
        ['claude-sonnet-4.5-20250514', 'gpt-4o', 'claude-3-5-haiku-20241022'],
        100000,
        50000,
      );

      expect(comparison).toHaveLength(3);
      // Claude 3.5 Haiku should be cheapest
      expect(comparison[0].modelId).toBe('claude-3-5-haiku-20241022');
      expect(comparison[0].cost).toBeCloseTo(0.28, 2); // (100k/1M)*0.8 + (50k/1M)*4 = 0.08 + 0.2 = 0.28

      // GPT-4o should be middle
      expect(comparison[1].modelId).toBe('gpt-4o');
      expect(comparison[1].cost).toBeCloseTo(0.75, 2);

      // Claude Sonnet 4.5 should be most expensive
      expect(comparison[2].modelId).toBe('claude-sonnet-4.5-20250514');
      expect(comparison[2].cost).toBeCloseTo(1.05, 2);
    });
  });

  describe('Regression Tests', () => {
    it('should maintain backward compatibility with existing models', () => {
      // Test that old models still work
      const geminiPricing = getModelPricing('gemini-2.5-flash-latest');
      expect(geminiPricing).toBeDefined();
      expect(geminiPricing?.inputPricePer1M).toBe(0.075);

      const deepseekPricing = getModelPricing('deepseek-chat');
      expect(deepseekPricing).toBeDefined();
      expect(deepseekPricing?.inputPricePer1M).toBeCloseTo(0.27, 1);

      const qwenPricing = getModelPricing('qwen-plus-latest');
      expect(qwenPricing).toBeDefined();
      expect(qwenPricing?.inputPricePer1M).toBe(0.28);
    });

    it('should handle fuzzy model name matching', () => {
      // Test fuzzy matching with different date formats
      const pricing1 = getModelPricing('claude-sonnet-4.5-20250514');
      const pricing2 = getModelPricing('claude-sonnet-4.5');
      // Should match to same base model (both return claude-sonnet-4.5-20250514)
      expect(pricing1.inputPricePer1M).toBe(pricing2.inputPricePer1M);
      expect(pricing1.outputPricePer1M).toBe(pricing2.outputPricePer1M);
    });
  });
});
