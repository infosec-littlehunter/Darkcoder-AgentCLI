/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type React from 'react';
import { Box, Text } from 'ink';
import { theme } from '../semantic-colors.js';
import { useSessionStats } from '../contexts/SessionContext.js';
import {
  getSessionCostBreakdown,
  getSessionTokens,
  calculateSessionCost,
  formatCost,
  formatTokenCount,
} from '../utils/costCalculator.js';
import { formatDuration } from '../utils/formatters.js';
import { t } from '../../i18n/index.js';

const COL_WIDTH_MODEL = 30;
const COL_WIDTH_TOKENS = 14;
const COL_WIDTH_COST = 12;

interface CostRowProps {
  model: string;
  inputTokens: string;
  outputTokens: string;
  inputCost: string;
  outputCost: string;
  totalCost: string;
  isHeader?: boolean;
  isTotal?: boolean;
}

const CostRow: React.FC<CostRowProps> = ({
  model,
  inputTokens,
  outputTokens,
  inputCost,
  outputCost,
  totalCost,
  isHeader = false,
  isTotal = false,
}) => (
  <Box>
    <Box width={COL_WIDTH_MODEL}>
      <Text
        bold={isHeader || isTotal}
        color={isTotal ? theme.status.success : theme.text.primary}
      >
        {model}
      </Text>
    </Box>
    <Box width={COL_WIDTH_TOKENS} justifyContent="flex-end">
      <Text bold={isHeader} color={theme.text.primary}>
        {inputTokens}
      </Text>
    </Box>
    <Box width={COL_WIDTH_TOKENS} justifyContent="flex-end">
      <Text bold={isHeader} color={theme.text.primary}>
        {outputTokens}
      </Text>
    </Box>
    <Box width={COL_WIDTH_COST} justifyContent="flex-end">
      <Text bold={isHeader} color={theme.text.secondary}>
        {inputCost}
      </Text>
    </Box>
    <Box width={COL_WIDTH_COST} justifyContent="flex-end">
      <Text bold={isHeader} color={theme.text.secondary}>
        {outputCost}
      </Text>
    </Box>
    <Box width={COL_WIDTH_COST} justifyContent="flex-end">
      <Text
        bold={isHeader || isTotal}
        color={isTotal ? theme.status.success : theme.text.accent}
      >
        {totalCost}
      </Text>
    </Box>
  </Box>
);

export const CostStatsDisplay: React.FC = () => {
  const { stats } = useSessionStats();
  const breakdown = getSessionCostBreakdown(stats.metrics);
  const tokens = getSessionTokens(stats.metrics);
  const totalCost = calculateSessionCost(stats.metrics);

  // Calculate session duration
  const now = new Date();
  const { sessionStartTime } = stats;
  const duration = sessionStartTime
    ? formatDuration(now.getTime() - sessionStartTime.getTime())
    : 'N/A';

  if (breakdown.length === 0) {
    return (
      <Box
        borderStyle="round"
        borderColor={theme.border.default}
        paddingY={1}
        paddingX={2}
      >
        <Text color={theme.text.primary}>
          {t('No API calls have been made in this session.')}
        </Text>
      </Box>
    );
  }

  return (
    <Box
      borderStyle="round"
      borderColor={theme.border.default}
      flexDirection="column"
      paddingY={1}
      paddingX={2}
    >
      {/* Title */}
      <Text bold color={theme.text.accent}>
        💰 {t('Session Cost Summary')}
      </Text>
      <Box height={1} />

      {/* Session Info */}
      <Box marginBottom={1}>
        <Text color={theme.text.secondary}>
          {t('Session Duration')}:{' '}
          <Text color={theme.text.primary}>{duration}</Text>
          {'  '}|{'  '}
          {t('Total Requests')}:{' '}
          <Text color={theme.text.primary}>
            {stats.metrics.tools.totalCalls}
          </Text>
        </Text>
      </Box>

      {/* Header */}
      <CostRow
        model={t('Model')}
        inputTokens={t('Input')}
        outputTokens={t('Output')}
        inputCost={t('In Cost')}
        outputCost={t('Out Cost')}
        totalCost={t('Total')}
        isHeader
      />

      {/* Divider */}
      <Box
        borderStyle="single"
        borderBottom={true}
        borderTop={false}
        borderLeft={false}
        borderRight={false}
        borderColor={theme.border.default}
      />

      {/* Model Rows */}
      {breakdown.map((item) => (
        <CostRow
          key={item.modelId}
          model={
            item.modelId.length > 28
              ? item.modelId.slice(0, 25) + '...'
              : item.modelId
          }
          inputTokens={formatTokenCount(item.inputTokens)}
          outputTokens={formatTokenCount(item.outputTokens)}
          inputCost={formatCost(item.inputCost)}
          outputCost={formatCost(item.outputCost)}
          totalCost={formatCost(item.totalCost)}
        />
      ))}

      {/* Divider */}
      <Box
        borderStyle="single"
        borderBottom={true}
        borderTop={false}
        borderLeft={false}
        borderRight={false}
        borderColor={theme.border.default}
        marginTop={1}
      />

      {/* Total */}
      <CostRow
        model={t('TOTAL')}
        inputTokens={formatTokenCount(tokens.input)}
        outputTokens={formatTokenCount(tokens.output)}
        inputCost=""
        outputCost=""
        totalCost={formatCost(totalCost)}
        isTotal
      />

      {/* Cache info if any */}
      {tokens.cached > 0 && tokens.input > 0 && (
        <Box marginTop={1}>
          <Text color={theme.text.secondary}>
            💾 {t('Cached tokens')}:{' '}
            <Text color={theme.status.success}>
              {formatTokenCount(tokens.cached)}
            </Text>{' '}
            ({((tokens.cached / tokens.input) * 100).toFixed(1)}%{' '}
            {t('cache hit rate')})
          </Text>
        </Box>
      )}

      {/* Disclaimer */}
      <Box marginTop={1}>
        <Text color={theme.text.secondary} italic>
          {t(
            '* Costs are estimates based on published pricing. Actual billing may vary.',
          )}
        </Text>
      </Box>
    </Box>
  );
};
