/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { GenerateContentParameters } from '@google/genai';
import type OpenAI from 'openai';

/**
 * Handler for system instructions that are provider-aware.
 * Different providers (Claude, Gemini, OpenAI) handle system instructions differently.
 *
 * This handler ensures system instructions are passed in the native format
 * for each provider, maximizing instruction following compliance.
 */
export class SystemInstructionHandler {
  /**
   * Extract system instruction from request if present
   */
  static extractSystemInstruction(
    request: GenerateContentParameters,
  ): string | null {
    if (!request.config?.systemInstruction) return null;

    const { systemInstruction } = request.config;

    if (typeof systemInstruction === 'string') {
      return systemInstruction;
    }

    if (Array.isArray(systemInstruction)) {
      return systemInstruction
        .map((part) => (typeof part === 'string' ? part : part.text || ''))
        .join('');
    }

    if (systemInstruction && 'parts' in systemInstruction) {
      return (
        systemInstruction.parts
          ?.map((part) => (typeof part === 'string' ? part : part.text || ''))
          .join('') || ''
      );
    }

    if (systemInstruction && 'text' in systemInstruction) {
      return systemInstruction.text || '';
    }

    return null;
  }

  /**
   * Check if this is an Anthropic Claude provider
   */
  static isAnthropicProvider(model: string, baseUrl?: string): boolean {
    const modelLower = model.toLowerCase();
    const baseLower = (baseUrl || '').toLowerCase();

    return (
      modelLower.startsWith('claude') ||
      baseLower.includes('anthropic.com') ||
      modelLower.startsWith('anthropic/')
    );
  }

  /**
   * Check if this is a Google Gemini provider
   */
  static isGeminiProvider(model: string, baseUrl?: string): boolean {
    const modelLower = model.toLowerCase();
    const baseLower = (baseUrl || '').toLowerCase();

    return (
      modelLower.startsWith('gemini') ||
      baseLower.includes('generativelanguage.googleapis.com') ||
      baseLower.includes('aiplatform.googleapis.com') ||
      modelLower.startsWith('google/')
    );
  }

  /**
   * Prepare request with system instruction handling.
   * For Claude: Extracts system instruction to be handled separately by provider
   * For Gemini: Extracts system instruction to be handled separately by provider
   * For others: Keeps system instruction in messages (OpenAI-compatible default)
   *
   * Returns both the messages and extracted system instruction
   */
  static prepareRequestWithSystemInstruction(
    request: GenerateContentParameters,
    messages: OpenAI.Chat.ChatCompletionMessageParam[],
    model: string,
    baseUrl?: string,
  ): {
    messages: OpenAI.Chat.ChatCompletionMessageParam[];
    systemInstruction: string | null;
  } {
    const systemInstruction = this.extractSystemInstruction(request);

    // For Anthropic Claude and Google Gemini, extract system instruction
    // so providers can handle it natively
    if (
      systemInstruction &&
      (this.isAnthropicProvider(model, baseUrl) ||
        this.isGeminiProvider(model, baseUrl))
    ) {
      // Remove system message from messages array if present
      const filteredMessages = messages.filter((msg) => msg.role !== 'system');

      return {
        messages: filteredMessages,
        systemInstruction,
      };
    }

    // For other providers, keep system instruction in messages
    // (OpenAI-compatible format)
    return {
      messages,
      systemInstruction: null,
    };
  }
}
