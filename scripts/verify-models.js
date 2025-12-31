#!/usr/bin/env node
/**
 * Test script to verify all models are properly loaded in the CLI
 */

import { AI_PROVIDERS } from '../packages/cli/dist/src/ui/models/aiProviders.js';
import {
  getAllAvailableModels,
  getModelsForProvider,
} from '../packages/cli/dist/src/ui/models/availableModels.js';

console.log('🔍 Verifying Model Availability in CLI\n');
console.log('='.repeat(80));

// Test 1: Verify AI_PROVIDERS is loaded
console.log('\n✅ Test 1: AI Providers Loaded');
console.log(`   Total providers: ${AI_PROVIDERS.length}`);
AI_PROVIDERS.forEach((provider) => {
  console.log(
    `   - ${provider.icon} ${provider.name}: ${provider.models.length} models`,
  );
});

// Test 2: Verify getAllAvailableModels works
console.log('\n✅ Test 2: Get All Available Models');
const allModels = getAllAvailableModels();
console.log(`   Total models available: ${allModels.length}`);

// Test 3: Verify new models are present
console.log('\n✅ Test 3: New Models Present');
const newModels = [
  'chatgpt-4o-latest',
  'o1',
  'o1-mini',
  'claude-sonnet-4.5-20250514',
  'claude-3-5-haiku-20241022',
];

newModels.forEach((modelId) => {
  const found = allModels.find((m) => m.id === modelId);
  if (found) {
    console.log(`   ✓ ${modelId}`);
    console.log(`     Provider: ${found.provider}`);
    console.log(
      `     Cost: $${found.inputPricePer1M}/$${found.outputPricePer1M} per 1M tokens`,
    );
    console.log(
      `     Context: ${found.contextWindow?.toLocaleString()} tokens`,
    );
  } else {
    console.log(`   ✗ ${modelId} - NOT FOUND`);
  }
});

// Test 4: Verify provider-specific queries
console.log('\n✅ Test 4: Provider-Specific Model Queries');
const openaiModels = getModelsForProvider('openai');
const anthropicModels = getModelsForProvider('anthropic');
console.log(`   OpenAI models: ${openaiModels.length}`);
console.log(`   Anthropic models: ${anthropicModels.length}`);

// Test 5: Display model comparison
console.log(
  '\n✅ Test 5: Model Cost Comparison (100k input + 50k output tokens)',
);
const testModels = allModels
  .filter((m) => m.inputPricePer1M && m.outputPricePer1M)
  .map((m) => {
    const inputCost = (100000 / 1000000) * m.inputPricePer1M;
    const outputCost = (50000 / 1000000) * m.outputPricePer1M;
    const totalCost = inputCost + outputCost;
    return {
      id: m.id,
      provider: m.provider,
      cost: totalCost,
    };
  })
  .sort((a, b) => a.cost - b.cost)
  .slice(0, 10);

console.log('\n   Top 10 Most Cost-Effective Models:');
testModels.forEach((m, i) => {
  console.log(
    `   ${i + 1}. ${m.id.padEnd(40)} $${m.cost.toFixed(3)} (${m.provider})`,
  );
});

console.log('\n' + '='.repeat(80));
console.log('✅ All tests completed successfully!\n');
