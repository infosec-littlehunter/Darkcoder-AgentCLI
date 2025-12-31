import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getCoreSystemPrompt } from './prompts.js';
import fs from 'node:fs';
import path from 'node:path';

vi.mock('node:fs');
vi.mock('../utils/gitUtils', () => ({
  isGitRepository: vi.fn().mockReturnValue(false),
}));

describe('Expert System Prompt Integration', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.stubEnv('QWEN_SYSTEM_MD', undefined);
  });

  it('should read the expert system prompt file by default', () => {
    const expertPromptContent = '# Expert AI System Prompt';

    vi.mocked(fs.readFileSync).mockImplementation((filePath) => {
      if (
        typeof filePath === 'string' &&
        filePath.endsWith('expert-ai-system-prompt.md')
      ) {
        return expertPromptContent;
      }
      return '';
    });

    const prompt = getCoreSystemPrompt();

    expect(fs.readFileSync).toHaveBeenCalledTimes(1);
    const callArgs = vi.mocked(fs.readFileSync).mock.calls[0];
    expect(callArgs[0]).toContain('expert-ai-system-prompt.md');
    expect(prompt).toContain(expertPromptContent);
  });

  it('should still allow overriding with QWEN_SYSTEM_MD', () => {
    const customPromptContent = '# Custom System Prompt';
    const customPath = '/custom/system.md';

    vi.stubEnv('QWEN_SYSTEM_MD', customPath);
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockImplementation((filePath) => {
      if (filePath === path.resolve(customPath)) {
        return customPromptContent;
      }
      return '';
    });

    const prompt = getCoreSystemPrompt();

    expect(fs.readFileSync).toHaveBeenCalledTimes(1);
    expect(fs.readFileSync).toHaveBeenCalledWith(
      path.resolve(customPath),
      'utf8',
    );
    expect(prompt).toContain(customPromptContent);
  });
});
