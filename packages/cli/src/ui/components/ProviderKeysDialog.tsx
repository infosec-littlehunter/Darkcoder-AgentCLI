/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type React from 'react';
import { useState, useMemo, useCallback, useContext } from 'react';
import { Box, Text } from 'ink';
import { Colors } from '../colors.js';
import { useKeypress } from '../hooks/useKeypress.js';
import { useSettings } from '../contexts/SettingsContext.js';
import { ConfigContext } from '../contexts/ConfigContext.js';
import { SettingScope } from '../../config/settings.js';
import { AI_PROVIDERS, type AIProvider } from '../models/aiProviders.js';
import { AuthType } from '@darkcoder/darkcoder-core';
import { t } from '../../i18n/index.js';

interface ProviderKeysDialogProps {
  onClose: () => void;
}

type DialogState = 'list' | 'edit';

interface ProviderKeyConfig {
  apiKey: string;
  baseUrl: string;
  model: string;
}

/**
 * ProviderKeysDialog - Manage API keys for multiple AI providers
 *
 * Allows users to:
 * - View all providers and their API key status
 * - Add/edit API keys for each provider
 * - Set default models per provider
 */
export function ProviderKeysDialog({
  onClose,
}: ProviderKeysDialogProps): React.JSX.Element {
  const config = useContext(ConfigContext);
  const settings = useSettings();
  const [dialogState, setDialogState] = useState<DialogState>('list');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [editingProvider, setEditingProvider] = useState<AIProvider | null>(
    null,
  );
  const [editField, setEditField] = useState<'apiKey' | 'model'>('apiKey');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [modelInput, setModelInput] = useState('');
  const [message, setMessage] = useState<{
    text: string;
    type: 'success' | 'error';
  } | null>(null);

  // Get stored provider configs from settings
  const storedProviders = useMemo(
    () =>
      (settings.merged.security?.auth?.providers || {}) as Record<
        string,
        ProviderKeyConfig
      >,
    [settings.merged.security?.auth?.providers],
  );

  // Filter to show only providers that use API keys (exclude qwen which uses OAuth)
  const apiKeyProviders = useMemo(
    () => AI_PROVIDERS.filter((p) => p.id !== 'qwen'),
    [],
  );

  // Check if provider has API key configured
  const hasApiKey = useCallback(
    (provider: AIProvider): boolean => {
      // Check stored settings first
      if (storedProviders[provider.id]?.apiKey) {
        return true;
      }
      // Check environment variable
      return (
        !!process.env[provider.envKeyName] || !!process.env['OPENAI_API_KEY']
      );
    },
    [storedProviders],
  );

  // Get masked API key for display
  const getMaskedKey = useCallback(
    (provider: AIProvider): string => {
      const storedKey = storedProviders[provider.id]?.apiKey;
      const envKey =
        process.env[provider.envKeyName] || process.env['OPENAI_API_KEY'];
      const key = storedKey || envKey;

      if (!key) return t('Not configured');
      if (key.length <= 8) return '••••••••';
      return `${key.slice(0, 4)}••••${key.slice(-4)}`;
    },
    [storedProviders],
  );

  // Get default model for provider
  const getDefaultModel = useCallback(
    (provider: AIProvider): string => {
      const storedModel = storedProviders[provider.id]?.model;
      if (storedModel) return storedModel;
      return provider.models[0]?.id || '';
    },
    [storedProviders],
  );

  // Save provider config
  const saveProviderConfig = useCallback(
    async (providerId: string, providerConfig: Partial<ProviderKeyConfig>) => {
      const currentProviders = { ...storedProviders };
      currentProviders[providerId] = {
        ...currentProviders[providerId],
        ...providerConfig,
      } as ProviderKeyConfig;

      settings.setValue(
        SettingScope.User,
        'security.auth.providers',
        currentProviders,
      );

      // Set the selected model name
      const selectedModel =
        providerConfig.model || currentProviders[providerId]?.model;
      if (selectedModel) {
        settings.setValue(SettingScope.User, 'model.name', selectedModel);
      }

      // Set selectedType to USE_OPENAI so the auth dialog doesn't prompt again
      settings.setValue(
        SettingScope.User,
        'security.auth.selectedType',
        AuthType.USE_OPENAI,
      );

      // Update runtime credentials if config is available
      if (config) {
        config.updateCredentials({
          baseUrl: providerConfig.baseUrl || '',
          model: selectedModel || '',
          ...(providerConfig.apiKey && { apiKey: providerConfig.apiKey }),
        });

        // Refresh auth to recreate the content generator with new provider settings
        await config.refreshAuth(AuthType.USE_OPENAI);
      }
    },
    [settings, storedProviders, config],
  );

  // Handle list navigation
  useKeypress(
    (key) => {
      if (dialogState !== 'list') return;

      if (key.name === 'escape') {
        onClose();
        return;
      }

      if (key.name === 'up') {
        setSelectedIndex((prev) => Math.max(0, prev - 1));
        return;
      }

      if (key.name === 'down') {
        setSelectedIndex((prev) =>
          Math.min(apiKeyProviders.length - 1, prev + 1),
        );
        return;
      }

      if (key.name === 'return') {
        const provider = apiKeyProviders[selectedIndex];
        if (provider) {
          setEditingProvider(provider);
          setApiKeyInput(storedProviders[provider.id]?.apiKey || '');
          setModelInput(getDefaultModel(provider));
          setEditField('apiKey');
          setDialogState('edit');
        }
        return;
      }

      // Quick key shortcuts (1-9) to select provider
      if (key.sequence && /^[1-9]$/.test(key.sequence)) {
        const idx = parseInt(key.sequence, 10) - 1;
        if (idx < apiKeyProviders.length) {
          setSelectedIndex(idx);
        }
      }
    },
    { isActive: dialogState === 'list' },
  );

  // Handle edit mode
  useKeypress(
    (key) => {
      if (dialogState !== 'edit' || !editingProvider) return;

      if (key.name === 'escape') {
        setDialogState('list');
        setEditingProvider(null);
        setMessage(null);
        return;
      }

      if (key.name === 'tab' || key.name === 'down') {
        setEditField((prev) => (prev === 'apiKey' ? 'model' : 'apiKey'));
        return;
      }

      if (key.name === 'up') {
        setEditField((prev) => (prev === 'model' ? 'apiKey' : 'model'));
        return;
      }

      if (key.name === 'return') {
        if (editField === 'apiKey') {
          setEditField('model');
        } else {
          // Save and exit
          if (apiKeyInput.trim()) {
            // Call async save function
            saveProviderConfig(editingProvider.id, {
              apiKey: apiKeyInput.trim(),
              baseUrl: editingProvider.baseUrl,
              model: modelInput.trim() || editingProvider.models[0]?.id,
            }).then(() => {
              setMessage({ text: t('API key saved!'), type: 'success' });
              setTimeout(() => {
                setDialogState('list');
                setEditingProvider(null);
                setMessage(null);
              }, 500);
            }).catch((err) => {
              console.error('Error saving provider config:', err);
              setMessage({ text: t('Failed to save API key'), type: 'error' });
            });
          } else {
            setMessage({ text: t('API key is required'), type: 'error' });
          }
        }
        return;
      }

      if (key.name === 'backspace' || key.name === 'delete') {
        if (editField === 'apiKey') {
          setApiKeyInput((prev) => prev.slice(0, -1));
        } else {
          setModelInput((prev) => prev.slice(0, -1));
        }
        return;
      }

      // Handle paste
      if (key.paste && key.sequence) {
        // Filter escape sequences and control characters
        const cleanInput = key.sequence
          .replace(/\[200~/g, '')
          .replace(/\[201~/g, '')
          .replace(/^\[|~$/g, '')
          .split('')
          .filter((ch) => ch.charCodeAt(0) >= 32)
          .join('');

        if (cleanInput.length > 0) {
          if (editField === 'apiKey') {
            setApiKeyInput((prev) => prev + cleanInput);
          } else {
            setModelInput((prev) => prev + cleanInput);
          }
        }
        return;
      }

      // Handle regular input
      if (key.sequence && !key.ctrl && !key.meta) {
        const cleanInput = key.sequence
          .split('')
          .filter((ch) => ch.charCodeAt(0) >= 32)
          .join('');

        if (cleanInput.length > 0) {
          if (editField === 'apiKey') {
            setApiKeyInput((prev) => prev + cleanInput);
          } else {
            setModelInput((prev) => prev + cleanInput);
          }
        }
      }
    },
    { isActive: dialogState === 'edit' },
  );

  // Render provider list
  if (dialogState === 'list') {
    return (
      <Box
        borderStyle="round"
        borderColor={Colors.AccentBlue}
        flexDirection="column"
        padding={1}
        width="100%"
      >
        <Text bold color={Colors.AccentBlue}>
          🔑 {t('Manage API Keys')}
        </Text>

        <Box marginTop={1} marginBottom={1}>
          <Text color={Colors.Gray}>
            {t('Configure API keys for different AI providers.')}
          </Text>
        </Box>

        {apiKeyProviders.map((provider, index) => {
          const isSelected = index === selectedIndex;
          const configured = hasApiKey(provider);

          return (
            <Box key={provider.id} flexDirection="row">
              <Box width={3}>
                <Text color={isSelected ? Colors.AccentBlue : Colors.Gray}>
                  {isSelected ? '❯ ' : '  '}
                </Text>
              </Box>
              <Box width={3}>
                <Text>{provider.icon}</Text>
              </Box>
              <Box width={20}>
                <Text
                  color={isSelected ? Colors.AccentBlue : Colors.Foreground}
                  bold={isSelected}
                >
                  {provider.name}
                </Text>
              </Box>
              <Box width={5}>
                <Text color={configured ? Colors.AccentGreen : Colors.Gray}>
                  {configured ? '✓' : '○'}
                </Text>
              </Box>
              <Box>
                <Text color={Colors.Gray}>{getMaskedKey(provider)}</Text>
              </Box>
            </Box>
          );
        })}

        <Box marginTop={1}>
          <Text color={Colors.Gray}>
            {t('↑↓ Navigate • Enter Edit • Esc Close')}
          </Text>
        </Box>
      </Box>
    );
  }

  // Render edit mode
  return (
    <Box
      borderStyle="round"
      borderColor={Colors.AccentBlue}
      flexDirection="column"
      padding={1}
      width="100%"
    >
      <Text bold color={Colors.AccentBlue}>
        {editingProvider?.icon}{' '}
        {t('Configure {{name}}', { name: editingProvider?.name || '' })}
      </Text>

      {message && (
        <Box marginTop={1}>
          <Text
            color={
              message.type === 'success' ? Colors.AccentGreen : Colors.AccentRed
            }
          >
            {message.text}
          </Text>
        </Box>
      )}

      <Box marginTop={1} flexDirection="column">
        <Box flexDirection="row">
          <Box width={12}>
            <Text
              color={editField === 'apiKey' ? Colors.AccentBlue : Colors.Gray}
            >
              {t('API Key:')}
            </Text>
          </Box>
          <Box flexGrow={1}>
            <Text>
              {editField === 'apiKey' ? '> ' : '  '}
              {apiKeyInput
                ? `${apiKeyInput.slice(0, 4)}${'•'.repeat(Math.max(0, apiKeyInput.length - 4))}`
                : ' '}
            </Text>
          </Box>
        </Box>

        <Box marginTop={1} flexDirection="row">
          <Box width={12}>
            <Text
              color={editField === 'model' ? Colors.AccentBlue : Colors.Gray}
            >
              {t('Model:')}
            </Text>
          </Box>
          <Box flexGrow={1}>
            <Text>
              {editField === 'model' ? '> ' : '  '}
              {modelInput || editingProvider?.models[0]?.id || ''}
            </Text>
          </Box>
        </Box>
      </Box>

      <Box marginTop={1}>
        <Text color={Colors.Gray}>
          {t('Available models: {{models}}', {
            models: editingProvider?.models.map((m) => m.id).join(', ') || '',
          })}
        </Text>
      </Box>

      <Box marginTop={1}>
        <Text color={Colors.Gray}>
          {t('Enter/Tab to continue • Esc to cancel')}
        </Text>
      </Box>
    </Box>
  );
}
