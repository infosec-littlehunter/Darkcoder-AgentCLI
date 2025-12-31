# AI Provider Setup Guides

DarkCoder supports multiple AI providers. Choose the one that best fits your needs.

## Quick Comparison

| Provider                      | Free Tier | Best For                        | Setup Difficulty |
| ----------------------------- | --------- | ------------------------------- | ---------------- |
| [OpenRouter](./openrouter.md) | ✅ Yes    | Multi-model access, free models | ⭐ Easy          |
| [OpenAI](./openai.md)         | ❌ No     | GPT-4o, enterprise support      | ⭐ Easy          |
| [Qwen/DashScope](./qwen.md)   | ✅ Yes    | Coding, Chinese language        | ⭐ Easy          |
| [Google Gemini](./google.md)  | ✅ Yes    | Long context (1M tokens)        | ⭐ Easy          |
| [DeepSeek](./deepseek.md)     | ✅ Yes    | Budget-friendly, reasoning      | ⭐ Easy          |
| [Local (Ollama)](./local.md)  | ✅ Yes    | Privacy, offline use            | ⭐⭐ Medium      |

## Recommended Setup

### For Most Users: OpenRouter

OpenRouter provides access to 100+ models with a single API key, including free options:

```bash
export OPENROUTER_API_KEY="your_key"
darkcoder --model google/gemini-2.0-flash-exp:free
```

See [OpenRouter Guide](./openrouter.md) for details.

### For Enterprise: OpenAI or Anthropic

Direct API access with enterprise support:

```bash
export OPENAI_API_KEY="your_key"
darkcoder --model gpt-4o
```

### For Privacy: Local Models

Run models locally with Ollama:

```bash
export OPENAI_BASE_URL="http://localhost:11434/v1"
export OPENAI_API_KEY="ollama"
darkcoder --model llama3.1
```

See [Local Models Guide](./local.md) for details.

## Environment Variables Reference

| Variable             | Provider     | Description         |
| -------------------- | ------------ | ------------------- |
| `OPENROUTER_API_KEY` | OpenRouter   | Access 100+ models  |
| `OPENAI_API_KEY`     | OpenAI       | GPT models          |
| `DASHSCOPE_API_KEY`  | Qwen/Alibaba | Qwen models         |
| `GOOGLE_API_KEY`     | Google       | Gemini models       |
| `OPENAI_BASE_URL`    | Custom/Local | Custom API endpoint |
