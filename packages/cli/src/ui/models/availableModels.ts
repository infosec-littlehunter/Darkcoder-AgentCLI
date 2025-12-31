/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AuthType,
  DEFAULT_QWEN_MODEL,
  PROVIDER_PRESETS,
} from '@darkcoder/darkcoder-core';
import { t } from '../../i18n/index.js';
import { AI_PROVIDERS } from './aiProviders.js';

export type AvailableModel = {
  id: string;
  label: string;
  description?: string;
  isVision?: boolean;
  provider?: string;
  contextWindow?: number;
  costTier?: number;
  inputPricePer1M?: number;
  outputPricePer1M?: number;
};

export const MAINLINE_VLM = 'vision-model';
export const MAINLINE_CODER = DEFAULT_QWEN_MODEL;

export const AVAILABLE_MODELS_QWEN: AvailableModel[] = [
  {
    id: MAINLINE_CODER,
    label: MAINLINE_CODER,
    get description() {
      return t(
        'The latest Qwen Coder model from Alibaba Cloud ModelStudio (version: qwen3-coder-plus-2025-09-23)',
      );
    },
  },
  {
    id: MAINLINE_VLM,
    label: MAINLINE_VLM,
    get description() {
      return t(
        'The latest Qwen Vision model from Alibaba Cloud ModelStudio (version: qwen3-vl-plus-2025-09-23)',
      );
    },
    isVision: true,
  },
];

/**
 * Get available Qwen models filtered by vision model preview setting
 */
export function getFilteredQwenModels(
  visionModelPreviewEnabled: boolean,
): AvailableModel[] {
  if (visionModelPreviewEnabled) {
    return AVAILABLE_MODELS_QWEN;
  }
  return AVAILABLE_MODELS_QWEN.filter((model) => !model.isVision);
}

/**
 * Get the model from environment variables or provider preset.
 * Priority: OPENAI_MODEL > OPENAI_PROVIDER preset > null
 */
export function getOpenAIAvailableModelFromEnv(): AvailableModel | null {
  const id = process.env['OPENAI_MODEL']?.trim();
  if (id) {
    return { id, label: id };
  }

  // Check for provider preset
  const providerPreset = process.env['OPENAI_PROVIDER']?.toLowerCase();
  if (providerPreset && PROVIDER_PRESETS[providerPreset]) {
    const presetModel = PROVIDER_PRESETS[providerPreset].defaultModel;
    return { id: presetModel, label: presetModel };
  }

  return null;
}

/**
 * Get all available models from all providers
 */
export function getAllAvailableModels(): AvailableModel[] {
  const models: AvailableModel[] = [];

  for (const provider of AI_PROVIDERS) {
    for (const model of provider.models) {
      models.push({
        id: model.id,
        label: model.name,
        description: model.description,
        isVision: model.isVision,
        provider: provider.name,
        contextWindow: model.contextWindow,
        costTier: model.costTier,
        inputPricePer1M: model.inputPricePer1M,
        outputPricePer1M: model.outputPricePer1M,
      });
    }
  }

  return models;
}

/**
 * Get models for a specific provider
 */
export function getModelsForProvider(providerId: string): AvailableModel[] {
  const provider = AI_PROVIDERS.find((p) => p.id === providerId);
  if (!provider) return [];

  return provider.models.map((model) => ({
    id: model.id,
    label: model.name,
    description: model.description,
    isVision: model.isVision,
    provider: provider.name,
    contextWindow: model.contextWindow,
    costTier: model.costTier,
    inputPricePer1M: model.inputPricePer1M,
    outputPricePer1M: model.outputPricePer1M,
  }));
}

export function getAvailableModelsForAuthType(
  authType: AuthType,
): AvailableModel[] {
  switch (authType) {
    case AuthType.QWEN_OAUTH:
      return AVAILABLE_MODELS_QWEN;
    case AuthType.USE_OPENAI: {
      const openAIModel = getOpenAIAvailableModelFromEnv();
      if (openAIModel) {
        return [openAIModel];
      }
      // If no environment variable, return all OpenAI models from providers
      return getModelsForProvider('openai');
    }
    default:
      // For other auth types, return all available models
      return getAllAvailableModels();
  }
}

/**
/**
 * Hard code the default vision model as a string literal,
 * until our coding model supports multimodal.
 */
export function getDefaultVisionModel(): string {
  return MAINLINE_VLM;
}

export function isVisionModel(modelId: string): boolean {
  return AVAILABLE_MODELS_QWEN.some(
    (model) => model.id === modelId && model.isVision,
  );
}
