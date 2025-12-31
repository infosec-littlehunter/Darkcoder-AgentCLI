# Multi-Provider AI System Documentation

> **Version:** 0.4.1  
> **Date:** December 8, 2025  
> **Author:** Development Team

## Overview

Qwen Code CLI now supports multiple AI providers through a unified OpenAI-compatible interface. This document describes the architecture, supported providers, and how to configure and switch between them.

## Supported Providers

| Provider          | Base URL                                                   | API Key Format      | Models                                                                  |
| ----------------- | ---------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------- |
| **Qwen**          | DashScope API                                              | `DASHSCOPE_API_KEY` | qwen3-coder, qwen-coder-plus, qwen-max                                  |
| **OpenAI**        | `https://api.openai.com/v1`                                | `sk-...`            | gpt-4o, gpt-4-turbo, gpt-3.5-turbo                                      |
| **Anthropic**     | `https://api.anthropic.com/v1`                             | `sk-ant-...`        | claude-sonnet-4.5, claude-sonnet-4, claude-3.5-sonnet, claude-3.5-haiku |
| **Google Gemini** | `https://generativelanguage.googleapis.com/v1beta/openai/` | `AIza...`           | gemini-2.5-flash, gemini-2.5-pro, gemini-2.0-flash                      |
| **DeepSeek**      | `https://api.deepseek.com/v1`                              | `sk-...`            | deepseek-chat, deepseek-reasoner                                        |
| **OpenRouter**    | `https://openrouter.ai/api/v1`                             | `sk-or-...`         | anthropic/claude-_, openai/gpt-_, google/gemini-\*                      |
| **xAI Grok**      | `https://api.x.ai/v1`                                      | `xai-...`           | grok-beta                                                               |
| **Mistral**       | `https://api.mistral.ai/v1`                                | `...`               | mistral-large, codestral, mistral-small                                 |
| **Ollama**        | `http://localhost:11434/v1`                                | N/A (local)         | llama3, codellama, mistral                                              |

## Quick Start

### Using `/keys` Command (Recommended)

1. Start the CLI: `qwen`
2. Type `/keys` and press Enter
3. Select your provider (e.g., DeepSeek, Google Gemini, Anthropic)
4. Enter your API key
5. Select a default model
6. Press Enter to save

### Using `/provider` Command (Switch Models)

1. Type `/provider` in the CLI
2. Select a provider from the list
3. Choose a model
4. The API key, base URL, and model are automatically configured

## Provider Configuration

### Anthropic Claude (Direct API)

```json
{
  "security": {
    "auth": {
      "apiKey": "sk-ant-api03-...",
      "baseUrl": "https://api.anthropic.com/v1",
      "providers": {
        "anthropic": {
          "apiKey": "sk-ant-api03-...",
          "baseUrl": "https://api.anthropic.com/v1",
          "model": "claude-sonnet-4.5-20250514"
        }
      }
    }
  },
  "model": {
    "name": "claude-sonnet-4.5-20250514"
  }
}
```

**Important:**

- API key starts with `sk-ant-...`
- Model names do NOT have `anthropic/` prefix
- Available models:
  - `claude-sonnet-4.5-20250514` (Latest, superior coding)
  - `claude-sonnet-4-20250514` (Latest Sonnet 4)
  - `claude-3-5-sonnet-20241022` (Fast and capable)
  - `claude-3-5-haiku-20241022` (Latest fast model)
  - `claude-3-opus-20240229` (Most capable)
  - `claude-3-haiku-20240307` (Fastest)

**Pricing (per 1M tokens):**
| Model | Input | Output | Cached Input |
|-------|-------|--------|--------------|
| Sonnet 4.5 | $3.00 | $15.00 | $0.30 |
| Sonnet 4 | $3.00 | $15.00 | $0.30 |
| 3.5 Sonnet | $3.00 | $15.00 | $0.30 |
| 3.5 Haiku | $0.80 | $4.00 | $0.08 |
| 3 Opus | $15.00 | $75.00 | $1.50 |
| 3 Haiku | $0.25 | $1.25 | $0.03 |

### Google Gemini

```json
{
  "security": {
    "auth": {
      "apiKey": "AIzaSy...",
      "baseUrl": "https://generativelanguage.googleapis.com/v1beta/openai/",
      "providers": {
        "google": {
          "apiKey": "AIzaSy...",
          "baseUrl": "https://generativelanguage.googleapis.com/v1beta/openai/",
          "model": "gemini-2.5-flash"
        }
      }
    }
  },
  "model": {
    "name": "gemini-2.5-flash"
  }
}
```

**Free Tier Limits:**
| Model | Requests/Minute | Requests/Day |
|-------|-----------------|--------------|
| gemini-2.5-flash | 500 | 1,500 |
| gemini-2.5-pro | 25 | 50 |
| gemini-2.0-flash | 15 | 1,500 |

**Recommendation:** Use `gemini-2.5-flash` for development - it has the best free tier limits.

### DeepSeek

```json
{
  "security": {
    "auth": {
      "apiKey": "sk-...",
      "baseUrl": "https://api.deepseek.com/v1",
      "providers": {
        "deepseek": {
          "apiKey": "sk-...",
          "baseUrl": "https://api.deepseek.com/v1",
          "model": "deepseek-chat"
        }
      }
    }
  },
  "model": {
    "name": "deepseek-chat"
  }
}
```

**Available Models:**

- `deepseek-chat` - Fast, cost-effective for most tasks
- `deepseek-reasoner` - Enhanced reasoning capabilities

### OpenRouter (Multi-Provider Access)

OpenRouter provides access to multiple AI providers through a single API key.

```json
{
  "security": {
    "auth": {
      "apiKey": "sk-or-v1-...",
      "baseUrl": "https://openrouter.ai/api/v1",
      "providers": {
        "openrouter": {
          "apiKey": "sk-or-v1-...",
          "baseUrl": "https://openrouter.ai/api/v1",
          "model": "anthropic/claude-sonnet-4-20250514"
        }
      }
    }
  },
  "model": {
    "name": "anthropic/claude-sonnet-4-20250514"
  }
}
```

**Important:**

- API key starts with `sk-or-...`
- Model names INCLUDE provider prefix (e.g., `anthropic/claude-*`, `openai/gpt-*`)

## Architecture

### Provider Detection Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     OpenAI Content Generator                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Check     │───▶│   Check     │───▶│   Check     │          │
│  │   Gemini    │    │  Anthropic  │    │   DashScope │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Gemini    │    │  Anthropic  │    │  DashScope  │          │
│  │  Provider   │    │  Provider   │    │  Provider   │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│                                                                   │
│                    ┌─────────────────┐                           │
│                    │     Default     │                           │
│                    │    Provider     │                           │
│                    │  (OpenAI Compat)│                           │
│                    └─────────────────┘                           │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

1. **`packages/core/src/core/openaiContentGenerator/`**
   - `index.ts` - Main content generator with provider detection
   - `provider/default.ts` - Default OpenAI-compatible provider
   - `provider/gemini.ts` - Google Gemini specific provider
   - `provider/anthropic.ts` - Anthropic Claude specific provider
   - `provider/dashscope.ts` - Qwen/DashScope specific provider

2. **`packages/cli/src/ui/models/aiProviders.ts`**
   - AI provider definitions with models and configurations
   - Used by ProviderDialog and ProviderKeysDialog

3. **`packages/cli/src/ui/components/`**
   - `ProviderDialog.tsx` - Select provider and model (persists all settings)
   - `ProviderKeysDialog.tsx` - Manage API keys for providers
   - `AuthDialog.tsx` - Initial authentication with link to provider keys

## CLI Commands

| Command     | Description                                                             |
| ----------- | ----------------------------------------------------------------------- |
| `/auth`     | Open authentication dialog (includes "Manage Provider API Keys" option) |
| `/provider` | Switch AI provider and model                                            |
| `/keys`     | Manage API keys for all configured providers                            |
| `/model`    | Quick model switch within current provider                              |

## Troubleshooting

### Error: "Model Not Exist" (400)

**Cause:** Model name format doesn't match the API.

**Solutions:**

- Anthropic direct API: Use `claude-sonnet-4-20250514` (no prefix)
- OpenRouter: Use `anthropic/claude-sonnet-4-20250514` (with prefix)
- Gemini: Use `gemini-2.5-flash` (no prefix)

### Error: "No cookie auth credentials found" (401)

**Cause:** API key doesn't match the base URL.

**Solutions:**

- `sk-ant-...` keys only work with `https://api.anthropic.com/v1`
- `sk-or-...` keys only work with `https://openrouter.ai/api/v1`
- Ensure apiKey, baseUrl, and model are all from the same provider

### Error: "Rate limit exceeded" (429)

**Cause:** Exceeded free tier limits.

**Solutions:**

- Switch to a model with higher limits (e.g., gemini-2.5-flash)
- Wait for rate limit to reset
- Upgrade to paid tier

### Provider not switching properly

**Cause:** Settings not persisted correctly.

**Solution:** Use `/provider` command which now saves:

- `security.auth.apiKey`
- `security.auth.baseUrl`
- `model.name`

## Example Settings File

Complete `~/.qwen/settings.json` with multiple providers:

```json
{
  "security": {
    "auth": {
      "selectedType": "openai",
      "apiKey": "current-active-api-key",
      "baseUrl": "https://api.deepseek.com/v1",
      "providers": {
        "google": {
          "apiKey": "AIzaSy...",
          "baseUrl": "https://generativelanguage.googleapis.com/v1beta/openai/",
          "model": "gemini-2.5-flash"
        },
        "deepseek": {
          "apiKey": "sk-...",
          "baseUrl": "https://api.deepseek.com/v1",
          "model": "deepseek-chat"
        },
        "anthropic": {
          "apiKey": "sk-ant-...",
          "baseUrl": "https://api.anthropic.com/v1",
          "model": "claude-sonnet-4-20250514"
        },
        "openrouter": {
          "apiKey": "sk-or-...",
          "baseUrl": "https://openrouter.ai/api/v1",
          "model": "anthropic/claude-3-5-sonnet-20241022"
        }
      }
    }
  },
  "$version": 2,
  "model": {
    "name": "deepseek-chat"
  }
}
```

## Version History

- **v0.4.1** (2025-12-08)
  - Fixed provider switching to persist apiKey, baseUrl, and model.name
  - Added OpenRouter as separate provider
  - Fixed Anthropic direct API model names (removed `anthropic/` prefix)
  - Added "Manage Provider API Keys" option to /auth dialog
  - Improved error messages for API mismatches

- **v0.4.0** (2025-12-08)
  - Added multi-provider support with `/keys` command
  - Added Google Gemini provider
  - Added Anthropic Claude provider
  - Simplified AuthDialog to 2 options
  - Updated DeepSeek to only show supported models

## License

Copyright 2025 Qwen. Licensed under Apache-2.0.
