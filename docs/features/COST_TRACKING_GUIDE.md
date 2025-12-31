# 💰 Real-Time Cost Tracking & Token Usage

**Complete guide to monitoring API costs and token consumption in DarkCoder**

---

## 📋 Overview

DarkCoder now includes **real-time cost tracking** for all supported AI models, helping you:

- 💵 **Monitor spending** across different providers
- 📊 **Track token usage** (input, output, cached)
- 🎯 **Optimize model selection** based on cost-effectiveness
- 📈 **Analyze cost trends** over sessions
- 💾 **Leverage prompt caching** for cost savings

---

## ✨ Features

### 1. **Real-Time Cost Calculation**

- Accurate per-model pricing based on December 2025 rates
- Separate tracking for input/output/cached tokens
- Cost breakdown by operation

### 2. **Supported Models**

#### Anthropic Claude (Updated December 2025)

| Model                 | Input     | Output    | Cached   | Context |
| --------------------- | --------- | --------- | -------- | ------- |
| **Claude Sonnet 4.5** | $3.00/1M  | $15.00/1M | $0.30/1M | 200K    |
| **Claude Sonnet 4**   | $3.00/1M  | $15.00/1M | $0.30/1M | 200K    |
| Claude 3.5 Sonnet     | $3.00/1M  | $15.00/1M | $0.30/1M | 200K    |
| Claude 3.5 Haiku      | $0.80/1M  | $4.00/1M  | $0.08/1M | 200K    |
| Claude 3 Opus         | $15.00/1M | $75.00/1M | $1.50/1M | 200K    |
| Claude 3 Haiku        | $0.25/1M  | $1.25/1M  | $0.03/1M | 200K    |

#### OpenAI Models

| Model       | Input     | Output    | Cached    | Context |
| ----------- | --------- | --------- | --------- | ------- |
| GPT-4o      | $2.50/1M  | $10.00/1M | $1.25/1M  | 128K    |
| GPT-4o Mini | $0.15/1M  | $0.60/1M  | $0.075/1M | 128K    |
| o1 Preview  | $15.00/1M | $60.00/1M | -         | 128K    |
| o1 Mini     | $3.00/1M  | $12.00/1M | -         | 128K    |

#### Google Gemini Models

| Model            | Input    | Output    | Cached     | Context |
| ---------------- | -------- | --------- | ---------- | ------- |
| Gemini 2.5 Flash | $0.30/1M | $2.50/1M  | $0.0375/1M | 1M      |
| Gemini 2.5 Pro   | $1.25/1M | $10.00/1M | $0.31/1M   | 1M      |
| Gemini 2.0 Flash | $0.10/1M | $0.40/1M  | -          | 1M      |
| Gemini 1.5 Pro   | $1.25/1M | $5.00/1M  | $0.31/1M   | 2M      |

#### DeepSeek Models

| Model             | Input    | Output   | Cached    | Context |
| ----------------- | -------- | -------- | --------- | ------- |
| DeepSeek Chat     | $0.28/1M | $0.42/1M | $0.028/1M | 128K    |
| DeepSeek Reasoner | $0.28/1M | $0.42/1M | -         | 128K    |

#### Qwen Models

| Model            | Input    | Output   | Context |
| ---------------- | -------- | -------- | ------- |
| Qwen3 Coder Plus | $0.50/1M | $1.50/1M | 1M      |
| Qwen Max         | $2.00/1M | $6.00/1M | 32K     |
| Coder Model      | $0.50/1M | $1.50/1M | 131K    |

---

## 🚀 Usage

### Programmatic Access

```typescript
import {
  calculateCost,
  getModelPricing,
  formatCost,
  compareModelCosts,
} from '@darkcoder/darkcoder-core';

// Calculate cost for a specific model
const usage = {
  inputTokens: 10000,
  outputTokens: 2000,
  cachedInputTokens: 5000,
};

const breakdown = calculateCost('claude-sonnet-4.5-20250514', usage);
console.log(`Total cost: ${formatCost(breakdown.totalCost)}`);
console.log(
  `Savings from cache: ${formatCost(breakdown.estimatedSavingsFromCache)}`,
);

// Get pricing for any model
const pricing = getModelPricing('gpt-4o');
console.log(`Input: $${pricing.inputPricePer1M}/1M tokens`);
console.log(`Output: $${pricing.outputPricePer1M}/1M tokens`);

// Compare costs across models
const models = [
  'claude-sonnet-4.5-20250514',
  'gpt-4o',
  'gemini-2.5-flash',
  'deepseek-chat',
];

const comparison = compareModelCosts(models, 50000, 10000);
comparison.forEach(({ modelId, formattedCost }) => {
  console.log(`${modelId}: ${formattedCost}`);
});
```

### Subagent Statistics

Subagents automatically track costs:

```typescript
const stats = subagentStatistics.getSummary();
console.log(`Input tokens: ${stats.inputTokens.toLocaleString()}`);
console.log(`Output tokens: ${stats.outputTokens.toLocaleString()}`);
console.log(`Estimated cost: $${stats.estimatedCost.toFixed(4)}`);
```

---

## 💡 Cost Optimization Tips

### 1. **Use Prompt Caching**

Models with caching support can save up to 90% on repeated inputs:

```typescript
// Claude Sonnet 4.5 with caching
Input: 100K tokens @ $3.00/1M = $0.30
Cached: 100K tokens @ $0.30/1M = $0.03
Savings: $0.27 (90%)
```

**Models with caching:**

- ✅ All Claude models
- ✅ GPT-4o/4o-mini
- ✅ Gemini 2.5/1.5 models
- ✅ DeepSeek Chat

### 2. **Choose the Right Model**

For **code generation** (low cost):

1. DeepSeek Chat - $0.28/$0.42 per 1M
2. Gemini 2.0 Flash - $0.10/$0.40 per 1M
3. GPT-4o Mini - $0.15/$0.60 per 1M
4. Qwen3 Coder Plus - $0.50/$1.50 per 1M

For **complex reasoning** (quality):

1. Claude 3 Opus - Most capable, $15/$75 per 1M
2. o1 Preview - Advanced reasoning, $15/$60 per 1M
3. Claude Sonnet 4.5 - Best balance, $3/$15 per 1M

For **balanced performance**:

1. Claude Sonnet 4.5 - $3/$15 per 1M ⭐ **Recommended**
2. GPT-4o - $2.50/$10 per 1M
3. Gemini 2.5 Pro - $1.25/$10 per 1M

### 3. **Monitor Token Usage**

```bash
# In DarkCoder CLI
> /stats

# Shows:
# - Total tokens used
# - Cost breakdown
# - Model distribution
# - Cache hit rate
```

### 4. **Set Budget Limits**

Add to `~/.qwen/settings.json`:

```json
{
  "advanced": {
    "maxCostPerSession": 1.0,
    "warnCostThreshold": 0.5
  }
}
```

---

## 📊 Cost Tracking API

### Core Functions

#### `calculateCost(modelId, usage)`

Calculate cost for token usage with caching support.

**Returns:**

```typescript
{
  inputCost: number;
  outputCost: number;
  cachedInputCost: number;
  totalCost: number;
  estimatedSavingsFromCache: number;
}
```

#### `getModelPricing(modelId)`

Get pricing information for any model.

**Returns:**

```typescript
{
  inputPricePer1M: number;
  outputPricePer1M: number;
  cachedInputPricePer1M?: number;
  contextWindow?: number;
}
```

#### `formatCost(cost, includeSymbol?)`

Format cost as readable string.

**Examples:**

- `formatCost(0.0001234)` → `"$0.00012"`
- `formatCost(1.5678)` → `"$1.57"`
- `formatCost(0.0000001)` → `"<$0.0001"`

#### `formatTokenCount(count)`

Format token count with K/M suffixes.

**Examples:**

- `formatTokenCount(1500)` → `"1.5K"`
- `formatTokenCount(1500000)` → `"1.50M"`

#### `estimateCost(modelId, inputTokens, outputTokens)`

Quick cost estimation.

**Returns:** `number` (total cost in USD)

#### `compareModelCosts(models, inputTokens, outputTokens)`

Compare costs across multiple models, sorted by price.

**Returns:**

```typescript
Array<{
  modelId: string;
  cost: number;
  formattedCost: string;
}>;
```

---

## 📈 Real-Time Cost Display

### Session Statistics

DarkCoder automatically tracks costs during sessions:

```
📋 Task Completed: Implement user authentication
🔧 Tool Usage: 15 calls, 93.3% success
⏱️ Duration: 45.2s | 🔁 Rounds: 3
🔢 Tokens: 45,234 (in 32,100, out 13,134)
💰 Cost: $0.6785
  Input: $0.0963 (32.1K tokens)
  Output: $0.1970 (13.1K tokens)
  Cached: $0.0012 (4.2K tokens)
  Savings: $0.0114 (from caching)
```

### Cost Breakdown by Model

```bash
# View detailed cost breakdown
> /cost

Model: claude-sonnet-4.5-20250514
─────────────────────────────────
Input tokens:    32,100  ($0.0963)
Output tokens:   13,134  ($0.1970)
Cached tokens:    4,200  ($0.0012)
─────────────────────────────────
Total cost:              $0.2945
Cache savings:           $0.0114
Effective cost:          $0.2831
```

---

## 🎯 Best Practices

### 1. **Track Costs Per Feature**

```typescript
const beforeStats = session.getStats();

// Implement feature...

const afterStats = session.getStats();
const featureCost = afterStats.totalCost - beforeStats.totalCost;
console.log(`Feature cost: ${formatCost(featureCost)}`);
```

### 2. **Use Cost-Aware Model Selection**

```typescript
// For quick tasks, use cheaper models
if (taskComplexity === 'simple') {
  model = 'deepseek-chat'; // $0.28/$0.42
} else if (taskComplexity === 'medium') {
  model = 'claude-3-5-haiku-20241022'; // $0.80/$4.00
} else {
  model = 'claude-sonnet-4.5-20250514'; // $3.00/$15.00
}
```

### 3. **Leverage Caching**

```typescript
// Reuse system prompts and context
const systemPrompt = '...'; // Cached automatically
const userPrompt = 'New request'; // Only this changes

// Claude will cache the system prompt
// 90% cost reduction on repeated sessions
```

### 4. **Monitor Long Sessions**

```typescript
setInterval(() => {
  const stats = session.getStats();
  if (stats.totalCost > maxBudget) {
    console.warn(`Budget exceeded: ${formatCost(stats.totalCost)}`);
    // Take action: switch model, warn user, etc.
  }
}, 60000); // Check every minute
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Enable detailed cost logging
export DARKCODER_LOG_COSTS=true

# Set cost warning threshold
export DARKCODER_COST_WARN=0.50

# Set maximum session cost
export DARKCODER_COST_MAX=2.00
```

### Settings File

`~/.qwen/settings.json`:

```json
{
  "advanced": {
    "costTracking": {
      "enabled": true,
      "showRealTime": true,
      "warnThreshold": 0.5,
      "maxPerSession": 2.0,
      "logToFile": true,
      "logPath": "~/.qwen/cost-log.json"
    }
  }
}
```

---

## 📝 Example: Cost-Optimized Workflow

```typescript
import {
  calculateCost,
  compareModelCosts,
  formatCost,
} from '@darkcoder/darkcoder-core';

// 1. Estimate costs before starting
const models = ['claude-sonnet-4.5-20250514', 'gpt-4o', 'deepseek-chat'];

const estimatedTokens = {
  input: 50000,
  output: 15000,
};

const comparison = compareModelCosts(
  models,
  estimatedTokens.input,
  estimatedTokens.output,
);

console.log('Cost comparison:');
comparison.forEach(({ modelId, formattedCost }) => {
  console.log(`  ${modelId}: ${formattedCost}`);
});

// 2. Select most cost-effective model for requirements
const selectedModel = comparison[0].modelId;

// 3. Track actual usage
const session = startSession(selectedModel);
// ... perform operations ...

// 4. Review actual costs
const finalStats = session.getStats();
console.log(`\nActual cost: ${formatCost(finalStats.totalCost)}`);
console.log(`Tokens used: ${finalStats.totalTokens.toLocaleString()}`);
console.log(`Cache savings: ${formatCost(finalStats.cacheSavings)}`);
```

---

## 🆕 What's New (December 2025)

### Latest Model Support

- ✅ **Claude Sonnet 4.5** - Latest flagship model
- ✅ **Claude 3.5 Haiku** - Improved fast model
- ✅ Updated pricing for all models
- ✅ Enhanced prompt caching support

### Enhanced Features

- 🎯 Real-time cost calculation
- 📊 Detailed cost breakdown
- 💾 Prompt caching savings tracking
- 🔄 Multi-model cost comparison
- 📈 Session-level cost analytics

---

## 📚 See Also

- [Multi-Provider System](MULTI_PROVIDER_SYSTEM.md)
- [Model Selection Guide](MODEL_SELECTION_GUIDE.md)
- [Performance Optimization](PERFORMANCE_OPTIMIZATION.md)

---

**Last Updated:** December 11, 2025  
**DarkCoder Version:** 0.6.0+
