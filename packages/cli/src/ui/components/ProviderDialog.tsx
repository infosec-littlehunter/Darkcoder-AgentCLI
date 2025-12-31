/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useContext, useMemo, useState } from 'react';
import { Box, Text } from 'ink';
import { useKeypress } from '../hooks/useKeypress.js';
import { theme } from '../semantic-colors.js';
import { DescriptiveRadioButtonSelect } from './shared/DescriptiveRadioButtonSelect.js';
import { ConfigContext } from '../contexts/ConfigContext.js';
import {
  AI_PROVIDERS,
  type AIProvider,
  isProviderConfigured,
} from '../models/aiProviders.js';
import { useSettings } from '../contexts/SettingsContext.js';
import { SettingScope } from '../../config/settings.js';
import { t } from '../../i18n/index.js';

interface ProviderDialogProps {
  onClose: () => void;
}

type DialogState = 'provider' | 'model';

/**
 * ProviderDialog - A two-step dialog for selecting AI provider and model
 *
 * Step 1: Select AI Provider (Claude, GPT-4, Qwen, etc.)
 * Step 2: Select specific model from that provider
 */
export function ProviderDialog({
  onClose,
}: ProviderDialogProps): React.JSX.Element {
  const config = useContext(ConfigContext);
  const settings = useSettings();
  const [dialogState, setDialogState] = useState<DialogState>('provider');
  const [selectedProvider, setSelectedProvider] = useState<AIProvider | null>(
    null,
  );

  // Get stored provider configs from settings
  const storedProviders = useMemo(() => {
    const providers = settings.merged.security?.auth?.providers || {};
    return providers as Record<string, { apiKey?: string; model?: string }>;
  }, [settings.merged.security?.auth?.providers]);

  // Get current model to show as selected
  const currentModel = config?.getModel() || '';

  // Check if a provider is configured (in settings or env)
  const checkProviderConfigured = useCallback(
    (provider: AIProvider): boolean => {
      // Check stored settings first
      if (storedProviders[provider.id]?.apiKey) {
        return true;
      }
      // Fall back to environment check
      return isProviderConfigured(provider);
    },
    [storedProviders],
  );

  // Provider selection options with status indicators
  const providerOptions = useMemo(
    () =>
      AI_PROVIDERS.map((provider) => {
        const configured = checkProviderConfigured(provider);
        const statusIcon = configured ? '✓' : '○';
        const statusColor = configured
          ? theme.status.success
          : theme.text.secondary;

        return {
          value: provider.id,
          title: `${provider.icon} ${provider.name}`,
          description: `${provider.description} ${configured ? '(configured)' : '(needs API key)'}`,
          key: provider.id,
          provider,
          configured,
          statusIcon,
          statusColor,
        };
      }),
    [checkProviderConfigured],
  );

  // Model selection options for selected provider
  const modelOptions = useMemo(() => {
    if (!selectedProvider) return [];

    return selectedProvider.models.map((model) => {
      const isCurrentModel = currentModel === model.id;
      const tags = model.tags.map((tag) => `[${tag}]`).join(' ');

      return {
        value: model.id,
        title: `${model.name}${isCurrentModel ? ' ●' : ''}`,
        description: `${model.description} ${tags}`,
        key: model.id,
        model,
      };
    });
  }, [selectedProvider, currentModel]);

  // Handle escape to go back or close
  useKeypress(
    (key) => {
      if (key.name === 'escape') {
        if (dialogState === 'model') {
          setDialogState('provider');
          setSelectedProvider(null);
        } else {
          onClose();
        }
      }
    },
    { isActive: true },
  );

  // Handle provider selection
  const handleProviderSelect = useCallback((providerId: string) => {
    const provider = AI_PROVIDERS.find((p) => p.id === providerId);
    if (provider) {
      if (!isProviderConfigured(provider)) {
        // Show setup instructions for unconfigured providers
        // For now, just show a message (could expand to setup wizard)
      }
      setSelectedProvider(provider);
      setDialogState('model');
    }
  }, []);

  // Handle model selection
  const handleModelSelect = useCallback(
    async (modelId: string) => {
      if (config && selectedProvider) {
        // Get API key from stored providers or environment
        const storedApiKey = storedProviders[selectedProvider.id]?.apiKey;
        const envApiKey = process.env[selectedProvider.envKeyName];
        const apiKey = storedApiKey || envApiKey;

        // Update runtime credentials
        config.updateCredentials({
          baseUrl: selectedProvider.baseUrl,
          model: modelId,
          ...(apiKey && { apiKey }),
        });

        // Refresh auth to recreate the content generator with new provider settings
        // This ensures the new baseUrl and model are used for API calls
        const { AuthType } = await import('@darkcoder/darkcoder-core');
        await config.refreshAuth(AuthType.USE_OPENAI);

        // Persist to settings file so the changes survive restart
        if (apiKey) {
          settings.setValue(SettingScope.User, 'security.auth.apiKey', apiKey);
        }
        settings.setValue(
          SettingScope.User,
          'security.auth.baseUrl',
          selectedProvider.baseUrl,
        );
        // Also save the model name
        settings.setValue(SettingScope.User, 'model.name', modelId);
        // Also save the auth type
        settings.setValue(
          SettingScope.User,
          'security.auth.selectedType',
          AuthType.USE_OPENAI,
        );
      }
      onClose();
    },
    [config, selectedProvider, storedProviders, settings, onClose],
  );

  // Find initial index for provider list
  const providerInitialIndex = useMemo(() => {
    const currentProviderIndex = providerOptions.findIndex((opt) =>
      opt.provider.models.some((m) => m.id === currentModel),
    );
    return currentProviderIndex >= 0 ? currentProviderIndex : 0;
  }, [providerOptions, currentModel]);

  // Find initial index for model list
  const modelInitialIndex = useMemo(() => {
    const idx = modelOptions.findIndex((opt) => opt.value === currentModel);
    return idx >= 0 ? idx : 0;
  }, [modelOptions, currentModel]);

  return (
    <Box
      borderStyle="round"
      borderColor={theme.border.default}
      flexDirection="column"
      padding={1}
      width="100%"
    >
      {/* Header */}
      <Box marginBottom={1}>
        <Text bold color={theme.text.accent}>
          {dialogState === 'provider'
            ? t('🚀 Select AI Provider')
            : `${selectedProvider?.icon} ${selectedProvider?.name} - ${t('Select Model')}`}
        </Text>
      </Box>

      {/* Provider Banner for Multi-AI */}
      {dialogState === 'provider' && (
        <Box
          marginBottom={1}
          paddingX={1}
          borderStyle="single"
          borderColor={theme.border.default}
        >
          <Text color={theme.text.secondary}>
            {t(
              'Switch between AI providers for different tasks. Use Claude for analysis, GPT-4 for coding, Qwen for fast responses.',
            )}
          </Text>
        </Box>
      )}

      {/* Selection List */}
      <Box marginTop={1}>
        {dialogState === 'provider' ? (
          <DescriptiveRadioButtonSelect
            items={providerOptions}
            onSelect={handleProviderSelect}
            initialIndex={providerInitialIndex}
            showNumbers={true}
            maxItemsToShow={6}
          />
        ) : (
          <DescriptiveRadioButtonSelect
            items={modelOptions}
            onSelect={handleModelSelect}
            initialIndex={modelInitialIndex}
            showNumbers={true}
            maxItemsToShow={5}
          />
        )}
      </Box>

      {/* Footer with instructions */}
      <Box marginTop={1} flexDirection="column">
        <Text color={theme.text.secondary}>
          {dialogState === 'provider'
            ? t('↑↓ Navigate • Enter Select • Esc Close')
            : t('↑↓ Navigate • Enter Select • Esc Back')}
        </Text>
        {dialogState === 'model' && selectedProvider && (
          <Box marginTop={1}>
            <Text color={theme.text.secondary} dimColor>
              {t('API: {{baseUrl}}', { baseUrl: selectedProvider.baseUrl })}
            </Text>
          </Box>
        )}
      </Box>

      {/* Setup hint for unconfigured providers */}
      {dialogState === 'model' &&
        selectedProvider &&
        !isProviderConfigured(selectedProvider) && (
          <Box
            marginTop={1}
            paddingX={1}
            borderStyle="single"
            borderColor={theme.status.warning}
          >
            <Text color={theme.status.warning}>
              ⚠️{' '}
              {t('Set {{envKey}} environment variable to use this provider', {
                envKey: selectedProvider.envKeyName,
              })}
            </Text>
          </Box>
        )}
    </Box>
  );
}
