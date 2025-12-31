/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type {
  SlashCommand,
  CommandContext,
  OpenDialogActionReturn,
  MessageActionReturn,
} from './types.js';
import { CommandKind } from './types.js';
import { t } from '../../i18n/index.js';

export const providerCommand: SlashCommand = {
  name: 'provider',
  altNames: ['ai', 'switch'],
  get description() {
    return t('Switch AI provider (Claude, GPT-4, Qwen, etc.)');
  },
  kind: CommandKind.BUILT_IN,
  action: async (
    context: CommandContext,
  ): Promise<OpenDialogActionReturn | MessageActionReturn> => {
    const { services } = context;
    const { config } = services;

    if (!config) {
      return {
        type: 'message',
        messageType: 'error',
        content: t('Configuration not available.'),
      };
    }

    // Open the provider selection dialog
    return {
      type: 'dialog',
      dialog: 'provider',
    };
  },
};
