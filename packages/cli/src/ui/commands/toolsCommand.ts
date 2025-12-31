/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  type CommandContext,
  type SlashCommand,
  CommandKind,
} from './types.js';
import { MessageType, type HistoryItemToolsList } from '../types.js';
import { t } from '../../i18n/index.js';
import { SettingScope } from '../../config/settings.js';

/**
 * Gets the current list of disabled tools from settings (tools.disabled)
 * This is different from tools.exclude - disabled tools still appear in /tools list
 * but are hidden from the AI. tools.exclude completely removes tools from registry.
 */
function getDisabledTools(context: CommandContext): string[] {
  const settings = context.services.settings;
  const merged = settings?.merged as Record<string, unknown> | undefined;
  const toolsConfig = merged?.['tools'] as Record<string, unknown> | undefined;
  const disabled = toolsConfig?.['disabled'];
  if (Array.isArray(disabled)) {
    return disabled.filter((item): item is string => typeof item === 'string');
  }
  return [];
}

/**
 * Updates the disabled tools list in settings (tools.disabled)
 */
function setDisabledTools(
  context: CommandContext,
  disabledList: string[],
): boolean {
  const settings = context.services.settings;
  if (settings && typeof settings.setValue === 'function') {
    try {
      settings.setValue(SettingScope.User, 'tools.disabled', disabledList);
      return true;
    } catch (error) {
      console.warn('Failed to save tools.disabled setting:', error);
      return false;
    }
  }
  return false;
}

export const toolsCommand: SlashCommand = {
  name: 'tools',
  get description() {
    return t('Manage tools. Usage: /tools [desc|enable <name>|disable <name>]');
  },
  kind: CommandKind.BUILT_IN,
  action: async (context: CommandContext, args?: string): Promise<void> => {
    const subCommand = args?.trim() || '';
    const parts = subCommand.split(/\s+/);
    const action = parts[0]?.toLowerCase();
    const toolName = parts.slice(1).join(' ');

    const toolRegistry = context.services.config?.getToolRegistry();
    if (!toolRegistry) {
      context.ui.addItem(
        {
          type: MessageType.ERROR,
          text: t('Could not retrieve tool registry.'),
        },
        Date.now(),
      );
      return;
    }

    const allTools = toolRegistry.getAllTools();
    // Filter out MCP tools by checking for the absence of a serverName property
    const geminiTools = allTools.filter((tool) => !('serverName' in tool));
    const disabledTools = getDisabledTools(context);

    // Handle enable command
    if (action === 'enable') {
      if (!toolName) {
        context.ui.addItem(
          {
            type: MessageType.ERROR,
            text: t('Usage: /tools enable <tool_name>'),
          },
          Date.now(),
        );
        return;
      }

      // Find tool by name or displayName (case-insensitive)
      const tool = geminiTools.find(
        (t) =>
          t.name.toLowerCase() === toolName.toLowerCase() ||
          t.displayName.toLowerCase() === toolName.toLowerCase(),
      );
      if (!tool) {
        context.ui.addItem(
          {
            type: MessageType.ERROR,
            text: t('Tool not found: {{toolName}}', { toolName }),
          },
          Date.now(),
        );
        return;
      }

      // Remove from exclude list
      const newDisabledList = disabledTools.filter(
        (name) => name.toLowerCase() !== tool.name.toLowerCase(),
      );

      if (newDisabledList.length === disabledTools.length) {
        context.ui.addItem(
          {
            type: MessageType.INFO,
            text: t('Tool "{{toolName}}" is already enabled.', {
              toolName: tool.displayName,
            }),
          },
          Date.now(),
        );
        return;
      }

      if (setDisabledTools(context, newDisabledList)) {
        context.ui.addItem(
          {
            type: MessageType.INFO,
            text: t('✓ Enabled tool: {{toolName}}', {
              toolName: tool.displayName,
            }),
          },
          Date.now(),
        );
      } else {
        context.ui.addItem(
          {
            type: MessageType.ERROR,
            text: t(
              'Failed to save settings. Please check your configuration.',
            ),
          },
          Date.now(),
        );
      }
      return;
    }

    // Handle disable command
    if (action === 'disable') {
      if (!toolName) {
        context.ui.addItem(
          {
            type: MessageType.ERROR,
            text: t('Usage: /tools disable <tool_name>'),
          },
          Date.now(),
        );
        return;
      }

      // Find tool by name or displayName (case-insensitive)
      const tool = geminiTools.find(
        (t) =>
          t.name.toLowerCase() === toolName.toLowerCase() ||
          t.displayName.toLowerCase() === toolName.toLowerCase(),
      );
      if (!tool) {
        context.ui.addItem(
          {
            type: MessageType.ERROR,
            text: t('Tool not found: {{toolName}}', { toolName }),
          },
          Date.now(),
        );
        return;
      }

      // Check if already disabled
      const isDisabled = disabledTools.some(
        (name) => name.toLowerCase() === tool.name.toLowerCase(),
      );
      if (isDisabled) {
        context.ui.addItem(
          {
            type: MessageType.INFO,
            text: t('Tool "{{toolName}}" is already disabled.', {
              toolName: tool.displayName,
            }),
          },
          Date.now(),
        );
        return;
      }

      // Add to exclude list
      const newDisabledList = [...disabledTools, tool.name];

      if (setDisabledTools(context, newDisabledList)) {
        context.ui.addItem(
          {
            type: MessageType.INFO,
            text: t('✗ Disabled tool: {{toolName}}', {
              toolName: tool.displayName,
            }),
          },
          Date.now(),
        );
      } else {
        context.ui.addItem(
          {
            type: MessageType.ERROR,
            text: t(
              'Failed to save settings. Please check your configuration.',
            ),
          },
          Date.now(),
        );
      }
      return;
    }

    // Default: list tools
    const useShowDescriptions = action === 'desc' || action === 'descriptions';

    const toolsListItem: HistoryItemToolsList = {
      type: MessageType.TOOLS_LIST,
      tools: geminiTools.map((tool) => ({
        name: tool.name,
        displayName: tool.displayName,
        description: tool.description,
        isEnabled: !disabledTools.some(
          (excluded) => excluded.toLowerCase() === tool.name.toLowerCase(),
        ),
      })),
      showDescriptions: useShowDescriptions,
    };

    context.ui.addItem(toolsListItem, Date.now());
  },
};
