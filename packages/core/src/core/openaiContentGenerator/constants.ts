export const DEFAULT_TIMEOUT = 120000;
export const DEFAULT_MAX_RETRIES = 3;

export const DEFAULT_OPENAI_BASE_URL = 'https://api.openai.com/v1';
export const DEFAULT_DASHSCOPE_BASE_URL =
  'https://dashscope.aliyuncs.com/compatible-mode/v1';
export const DEFAULT_DEEPSEEK_BASE_URL = 'https://api.deepseek.com/v1';
export const DEFAULT_OPEN_ROUTER_BASE_URL = 'https://openrouter.ai/api/v1';
export const DEFAULT_GEMINI_BASE_URL =
  'https://generativelanguage.googleapis.com/v1beta/openai/';
export const DEFAULT_ANTHROPIC_BASE_URL = 'https://api.anthropic.com/v1';

/**
 * Provider presets for easy configuration
 * Users can set OPENAI_PROVIDER=gemini to use Gemini without extra configuration
 */
export const PROVIDER_PRESETS: Record<
  string,
  { baseUrl: string; defaultModel: string }
> = {
  openai: {
    baseUrl: DEFAULT_OPENAI_BASE_URL,
    defaultModel: 'gpt-4o',
  },
  gemini: {
    baseUrl: DEFAULT_GEMINI_BASE_URL,
    defaultModel: 'gemini-2.5-flash',
  },
  dashscope: {
    baseUrl: DEFAULT_DASHSCOPE_BASE_URL,
    defaultModel: 'qwen3-coder-plus',
  },
  deepseek: {
    baseUrl: DEFAULT_DEEPSEEK_BASE_URL,
    defaultModel: 'deepseek-chat',
  },
  openrouter: {
    baseUrl: DEFAULT_OPEN_ROUTER_BASE_URL,
    defaultModel: 'google/gemini-2.5-pro',
  },
  anthropic: {
    baseUrl: DEFAULT_ANTHROPIC_BASE_URL,
    defaultModel: 'claude-sonnet-4.5-20250514',
  },
};
