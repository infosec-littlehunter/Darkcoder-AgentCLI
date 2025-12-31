/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type React from 'react';
import { Box, Text } from 'ink';
import { theme } from '../../semantic-colors.js';
import { type ToolDefinition } from '../../types.js';
import { MarkdownDisplay } from '../../utils/MarkdownDisplay.js';
import { t } from '../../../i18n/index.js';

interface ToolsListProps {
  tools: readonly ToolDefinition[];
  showDescriptions: boolean;
  terminalWidth: number;
}

export const ToolsList: React.FC<ToolsListProps> = ({
  tools,
  showDescriptions,
  terminalWidth,
}) => {
  // Separate enabled and disabled tools
  const enabledTools = tools.filter((tool) => tool.isEnabled !== false);
  const disabledTools = tools.filter((tool) => tool.isEnabled === false);

  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text bold color={theme.text.primary}>
        {t('Available Qwen Code CLI tools:')}
      </Text>
      <Text color={theme.text.secondary} dimColor>
        {t('Use /tools enable <name> or /tools disable <name> to toggle tools')}
      </Text>
      <Box height={1} />

      {/* Enabled tools */}
      {enabledTools.length > 0 ? (
        enabledTools.map((tool) => (
          <Box key={tool.name} flexDirection="row">
            <Text color={theme.status.success}>{'  '}✓ </Text>
            <Box flexDirection="column">
              <Text bold color={theme.text.accent}>
                {tool.displayName}
                {showDescriptions ? ` (${tool.name})` : ''}
              </Text>
              {showDescriptions && tool.description && (
                <MarkdownDisplay
                  terminalWidth={terminalWidth}
                  text={tool.description}
                  isPending={false}
                />
              )}
            </Box>
          </Box>
        ))
      ) : (
        <Text color={theme.text.primary}> {t('No tools enabled')}</Text>
      )}

      {/* Disabled tools section */}
      {disabledTools.length > 0 && (
        <>
          <Box height={1} />
          <Text bold color={theme.text.secondary} dimColor>
            {t('Disabled tools:')}
          </Text>
          {disabledTools.map((tool) => (
            <Box key={tool.name} flexDirection="row">
              <Text color={theme.status.error}>{'  '}✗ </Text>
              <Box flexDirection="column">
                <Text color={theme.text.secondary} dimColor strikethrough>
                  {tool.displayName}
                  {showDescriptions ? ` (${tool.name})` : ''}
                </Text>
                {showDescriptions && tool.description && (
                  <Text color={theme.text.secondary} dimColor>
                    {tool.description.slice(0, 80)}
                    {tool.description.length > 80 ? '...' : ''}
                  </Text>
                )}
              </Box>
            </Box>
          ))}
        </>
      )}
    </Box>
  );
};
