# OpenRouter Setup Guide

OpenRouter is a unified API gateway that provides access to 100+ AI models from multiple providers (OpenAI, Anthropic, Google, Meta, Mistral, and more) with a single API key.

## Why OpenRouter?

- **🆓 Free Models**: Access free tiers of Gemini, Llama, Qwen, and more
- **🔄 Single API Key**: One key for 100+ models
- **💰 Pay-as-you-go**: No subscriptions, pay only for what you use
- **🌐 Unified Interface**: Same API format for all models

## Quick Start

### 1. Get API Key

1. Go to [OpenRouter](https://openrouter.ai)
2. Sign up or log in
3. Go to [API Keys](https://openrouter.ai/keys)
4. Create a new API key

### 2. Set Environment Variable

```bash
export OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxx"
```

### 3. Run DarkCoder

```bash
# With Docker
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
  darkcoder --model google/gemini-2.0-flash-exp:free

# From source
darkcoder --model google/gemini-2.0-flash-exp:free
```

## Free Models

These models are completely free on OpenRouter:

| Model                                    | Context     | Tool Support | Best For                  |
| ---------------------------------------- | ----------- | ------------ | ------------------------- |
| `google/gemini-2.0-flash-exp:free`       | 1M tokens   | ✅ Yes       | General use, long context |
| `qwen/qwen-2.5-72b-instruct:free`        | 32K tokens  | ✅ Yes       | Coding, Chinese language  |
| `meta-llama/llama-3.3-70b-instruct:free` | 128K tokens | ✅ Yes       | Open source tasks         |
| `allenai/olmo-3.1-32b-think:free`        | 32K tokens  | ❌ No        | Reasoning (chat-only)     |

### Using Free Models

```bash
# Best free model with full tool support
darkcoder --model google/gemini-2.0-flash-exp:free

# Llama for open-source preference
darkcoder --model meta-llama/llama-3.3-70b-instruct:free

# Models without tool support need --disable-tools
darkcoder --model allenai/olmo-3.1-32b-think:free --disable-tools
```

## Paid Models (via OpenRouter)

Access premium models at competitive prices:

```bash
# Claude Sonnet 4.5 (latest)
darkcoder --model anthropic/claude-sonnet-4.5-20250514

# Claude Sonnet 4
darkcoder --model anthropic/claude-sonnet-4-20250514

# GPT-4o
darkcoder --model openai/gpt-4o

# Gemini 2.5 Pro
darkcoder --model google/gemini-2.5-pro-preview-06-05
```

## Rate Limits

Free models have rate limits:

- Requests per minute vary by model
- Wait a few minutes if you hit 429 errors
- Consider paid models for heavy usage

## Troubleshooting

### Error: 400 Provider returned error

This usually means the model doesn't support tool calling:

```bash
# Solution: Use --disable-tools flag
darkcoder --model your-model:free --disable-tools
```

### Error: 429 Rate limit exceeded

You've hit the rate limit for free models:

- Wait 1-2 minutes and try again
- Switch to a different free model
- Use a paid model for no rate limits

### Error: 404 No endpoints found

The model name might be wrong. Check [OpenRouter Models](https://openrouter.ai/models) for correct model IDs.

## Settings File Configuration

Add to `~/.qwen/settings.json`:

```json
{
  "model": {
    "name": "google/gemini-2.0-flash-exp:free",
    "disableTools": false
  }
}
```

For models without tool support:

```json
{
  "model": {
    "name": "allenai/olmo-3.1-32b-think:free",
    "disableTools": true
  }
}
```

## Docker Examples

```bash
# Free Gemini model
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
  darkcoder --model google/gemini-2.0-flash-exp:free

# Claude via OpenRouter
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
  darkcoder --model anthropic/claude-sonnet-4-20250514

# Model without tool support
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
  darkcoder --model allenai/olmo-3.1-32b-think:free --disable-tools
```

## Model Comparison

| Use Case          | Recommended Model                        | Cost              |
| ----------------- | ---------------------------------------- | ----------------- |
| General coding    | `google/gemini-2.0-flash-exp:free`       | Free              |
| Security analysis | `anthropic/claude-sonnet-4-20250514`     | $3/$15 per 1M     |
| Long documents    | `google/gemini-2.0-flash-exp:free`       | Free (1M context) |
| Reasoning         | `anthropic/claude-sonnet-4.5-20250514`   | $3/$15 per 1M     |
| Budget option     | `meta-llama/llama-3.3-70b-instruct:free` | Free              |
