/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { MessageType } from '../types.js';
import {
  type CommandContext,
  type SlashCommand,
  CommandKind,
} from './types.js';
import { t } from '../../i18n/index.js';

export const costCommand: SlashCommand = {
  name: 'cost',
  altNames: ['costs', 'billing'],
  get description() {
    return t('Show session cost breakdown and token usage');
  },
  kind: CommandKind.BUILT_IN,
  action: (context: CommandContext) => {
    context.ui.addItem(
      {
        type: MessageType.COST_STATS,
      },
      Date.now(),
    );
  },
};
