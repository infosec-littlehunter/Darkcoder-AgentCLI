/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

import type { SlashCommand, OpenDialogActionReturn } from './types.js';
import { CommandKind } from './types.js';
import { t } from '../../i18n/index.js';

export const apiToolsCommand: SlashCommand = {
  name: 'apitools',
  altNames: ['security-auth', 'toolauth', 'osint-keys'],
  get description() {
    return t('Manage API keys for security tools (Censys, VirusTotal, etc.)');
  },
  kind: CommandKind.BUILT_IN,
  action: async (): Promise<OpenDialogActionReturn> => ({
    type: 'dialog',
    dialog: 'security_tools',
  }),
};
