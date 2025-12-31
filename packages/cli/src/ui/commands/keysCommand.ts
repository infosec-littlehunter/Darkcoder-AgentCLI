/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type { SlashCommand, OpenDialogActionReturn } from './types.js';
import { CommandKind } from './types.js';
import { t } from '../../i18n/index.js';

export const keysCommand: SlashCommand = {
  name: 'keys',
  altNames: ['apikeys', 'credentials'],
  get description() {
    return t('Manage API keys for AI providers');
  },
  kind: CommandKind.BUILT_IN,
  action: async (): Promise<OpenDialogActionReturn> => ({
      type: 'dialog',
      dialog: 'provider_keys',
    }),
};
