/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AuthType,
  IdeClient,
  IdeConnectionEvent,
  IdeConnectionType,
  logIdeConnection,
  type Config,
} from '@darkcoder/darkcoder-core';
import { type LoadedSettings, SettingScope } from '../config/settings.js';
import { performInitialAuth } from './auth.js';
import { validateTheme } from './theme.js';
import { initializeI18n } from '../i18n/index.js';

export interface InitializationResult {
  authError: string | null;
  themeError: string | null;
  shouldOpenAuthDialog: boolean;
  geminiMdFileCount: number;
}

/**
 * Get auth type from environment variables.
 * Returns USE_OPENAI if any OpenAI-compatible API key is set.
 */
function getAuthTypeFromEnv(): AuthType | undefined {
  if (
    process.env['OPENAI_API_KEY'] ||
    process.env['ANTHROPIC_API_KEY'] ||
    process.env['DEEPSEEK_API_KEY'] ||
    process.env['OPENROUTER_API_KEY'] ||
    process.env['DASHSCOPE_API_KEY']
  ) {
    return AuthType.USE_OPENAI;
  }
  if (process.env['QWEN_OAUTH']) {
    return AuthType.QWEN_OAUTH;
  }
  return undefined;
}

/**
 * Orchestrates the application's startup initialization.
 * This runs BEFORE the React UI is rendered.
 * @param config The application config.
 * @param settings The loaded application settings.
 * @returns The results of the initialization.
 */
export async function initializeApp(
  config: Config,
  settings: LoadedSettings,
): Promise<InitializationResult> {
  // Initialize i18n system
  const languageSetting =
    process.env['QWEN_CODE_LANG'] ||
    settings.merged.general?.language ||
    'auto';
  await initializeI18n(languageSetting);

  // Get auth type from settings, or fall back to env vars
  const settingsAuthType = settings.merged.security?.auth?.selectedType;
  const envAuthType = getAuthTypeFromEnv();
  const authType = settingsAuthType || envAuthType;

  const authError = await performInitialAuth(config, authType);

  // Fallback to user select when initial authentication fails
  if (authError) {
    settings.setValue(
      SettingScope.User,
      'security.auth.selectedType',
      undefined,
    );
  }
  const themeError = validateTheme(settings);

  // Only open auth dialog if no auth type is configured (in settings or env vars) or auth failed
  const hasAuthType =
    settingsAuthType !== undefined || envAuthType !== undefined;
  const shouldOpenAuthDialog = !hasAuthType || !!authError;

  if (config.getIdeMode()) {
    const ideClient = await IdeClient.getInstance();
    await ideClient.connect();
    logIdeConnection(config, new IdeConnectionEvent(IdeConnectionType.START));
  }

  return {
    authError,
    themeError,
    shouldOpenAuthDialog,
    geminiMdFileCount: config.getGeminiMdFileCount(),
  };
}
