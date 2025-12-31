/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { Text } from 'ink';
import { theme } from '../semantic-colors.js';
import { useSessionStats } from '../contexts/SessionContext.js';
import {
  calculateSessionCost,
  formatCost,
  formatTokenCount,
  getSessionTokens,
} from '../utils/costCalculator.js';

export interface CostDisplayProps {
  terminalWidth: number;
  showTokens?: boolean;
}

export const CostDisplay = ({
  terminalWidth,
  showTokens = true,
}: CostDisplayProps) => {
  const { stats } = useSessionStats();
  const tokens = getSessionTokens(stats.metrics);
  const cost = calculateSessionCost(stats.metrics);

  // If no tokens used yet, don't show anything
  if (tokens.total === 0) {
    return null;
  }

  // Compact display for narrow terminals
  if (terminalWidth < 80) {
    return (
      <Text color={theme.text.secondary}>
        {' '}
        <Text color={theme.status.success}>{formatCost(cost)}</Text>
      </Text>
    );
  }

  // Medium display
  if (terminalWidth < 120 || !showTokens) {
    return (
      <Text color={theme.text.secondary}>
        {' '}
        |{' '}
        <Text color={theme.text.primary}>
          {formatTokenCount(tokens.total)}
        </Text>{' '}
        tok <Text color={theme.status.success}>{formatCost(cost)}</Text>
      </Text>
    );
  }

  // Full display for wide terminals
  return (
    <Text color={theme.text.secondary}>
      {' '}
      | <Text color={theme.text.primary}>
        {formatTokenCount(tokens.input)}
      </Text>{' '}
      in{' '}
      <Text color={theme.text.primary}>{formatTokenCount(tokens.output)}</Text>{' '}
      out <Text color={theme.status.success}>{formatCost(cost)}</Text>
    </Text>
  );
};
