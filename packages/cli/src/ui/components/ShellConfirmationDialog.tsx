/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { ToolConfirmationOutcome } from '@darkcoder/darkcoder-core';
import { Box, Text } from 'ink';
import type React from 'react';
import { useState, useCallback, useEffect } from 'react';
import { theme } from '../semantic-colors.js';
import { RenderInline } from '../utils/InlineMarkdownRenderer.js';
import type { RadioSelectItem } from './shared/RadioButtonSelect.js';
import { RadioButtonSelect } from './shared/RadioButtonSelect.js';
import { useKeypress } from '../hooks/useKeypress.js';
import { t } from '../../i18n/index.js';
import { TextInput } from './shared/TextInput.js';

export interface ShellConfirmationRequest {
  commands: string[];
  onConfirm: (
    outcome: ToolConfirmationOutcome,
    approvedCommands?: string[],
    feedback?: string,
  ) => void;
}

export interface ShellConfirmationDialogProps {
  request: ShellConfirmationRequest;
}

export const ShellConfirmationDialog: React.FC<
  ShellConfirmationDialogProps
> = ({ request }) => {
  const { commands, onConfirm } = request;

  // State for edit mode
  const [isEditMode, setIsEditMode] = useState(false);
  const [editFeedback, setEditFeedback] = useState('');
  // Delay before TextInput becomes active - prevents immediate submission
  const [isEditInputActive, setIsEditInputActive] = useState(false);

  // When entering edit mode, delay activation of TextInput
  useEffect(() => {
    if (isEditMode) {
      const timer = setTimeout(() => {
        setIsEditInputActive(true);
      }, 100);
      return () => clearTimeout(timer);
    }
    setIsEditInputActive(false);
    return undefined;
  }, [isEditMode]);

  // Handle edit feedback submission
  const handleEditSubmit = useCallback(() => {
    if (!isEditInputActive) {
      return;
    }
    const feedback = editFeedback.trim();
    // Always call onConfirm - either with feedback or just as a cancel
    if (feedback) {
      // Use EditRequest outcome so the LLM continues with the feedback
      onConfirm(ToolConfirmationOutcome.EditRequest, undefined, feedback);
    } else {
      // User submitted empty feedback - treat as cancel without message
      onConfirm(ToolConfirmationOutcome.Cancel);
    }
    setIsEditMode(false);
    setEditFeedback('');
  }, [editFeedback, onConfirm, isEditInputActive]);

  // Cancel edit mode
  const handleEditCancel = useCallback(() => {
    setIsEditMode(false);
    setEditFeedback('');
  }, []);

  useKeypress(
    (key) => {
      if (isEditMode) {
        if (key.name === 'escape') {
          handleEditCancel();
        }
        return;
      }

      if (key.name === 'escape') {
        onConfirm(ToolConfirmationOutcome.Cancel);
      }
    },
    { isActive: true },
  );

  const handleSelect = (item: ToolConfirmationOutcome) => {
    if (item === ToolConfirmationOutcome.EditRequest) {
      setIsEditMode(true);
      return;
    }
    if (item === ToolConfirmationOutcome.Cancel) {
      onConfirm(item);
    } else {
      // For both ProceedOnce and ProceedAlways, we approve all the
      // commands that were requested.
      onConfirm(item, commands);
    }
  };

  const options: Array<RadioSelectItem<ToolConfirmationOutcome>> = [
    {
      label: t('Yes, allow once'),
      value: ToolConfirmationOutcome.ProceedOnce,
      key: 'Yes, allow once',
    },
    {
      label: t('Yes, allow always for this session'),
      value: ToolConfirmationOutcome.ProceedAlways,
      key: 'Yes, allow always for this session',
    },
    {
      label: t('Edit request (add feedback)'),
      value: ToolConfirmationOutcome.EditRequest,
      key: 'Edit request (add feedback)',
    },
    {
      label: t('No (esc)'),
      value: ToolConfirmationOutcome.Cancel,
      key: 'No (esc)',
    },
  ];

  // Edit mode UI
  if (isEditMode) {
    return (
      <Box
        flexDirection="column"
        borderStyle="round"
        borderColor={theme.status.warning}
        padding={1}
        width="100%"
        marginLeft={1}
      >
        <Box flexDirection="column" marginBottom={1}>
          <Text bold color={theme.text.primary}>
            {t('Shell Command Execution')}
          </Text>
          <Text color={theme.text.primary}>
            {t('A custom command wants to run the following shell commands:')}
          </Text>
          <Box
            flexDirection="column"
            borderStyle="round"
            borderColor={theme.border.default}
            paddingX={1}
            marginTop={1}
          >
            {commands.map((cmd) => (
              <Text key={cmd} color={theme.text.link}>
                <RenderInline text={cmd} />
              </Text>
            ))}
          </Box>
        </Box>

        {/* Edit Feedback Section */}
        <Box flexDirection="column" marginBottom={1}>
          <Box marginBottom={1}>
            <Text color={theme.status.warning} bold>
              {t('Edit your request:')}
            </Text>
          </Box>
          <Box marginBottom={1}>
            <Text color={theme.text.secondary} dimColor>
              {isEditInputActive
                ? t(
                    'Add your feedback or modifications below. Press Enter to submit, Esc to cancel.',
                  )
                : t('Preparing input...')}
            </Text>
          </Box>
          <Box
            borderStyle="round"
            borderColor={theme.border.focused}
            paddingX={1}
          >
            <TextInput
              value={editFeedback}
              onChange={setEditFeedback}
              onSubmit={handleEditSubmit}
              placeholder={t('Type your feedback here...')}
              height={3}
              isActive={isEditInputActive}
              inputWidth={70}
            />
          </Box>
        </Box>

        {/* Cancel hint */}
        <Box>
          <Text color={theme.text.secondary} dimColor>
            {t('Press Esc to cancel and return to options')}
          </Text>
        </Box>
      </Box>
    );
  }

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={theme.status.warning}
      padding={1}
      width="100%"
      marginLeft={1}
    >
      <Box flexDirection="column" marginBottom={1}>
        <Text bold color={theme.text.primary}>
          {t('Shell Command Execution')}
        </Text>
        <Text color={theme.text.primary}>
          {t('A custom command wants to run the following shell commands:')}
        </Text>
        <Box
          flexDirection="column"
          borderStyle="round"
          borderColor={theme.border.default}
          paddingX={1}
          marginTop={1}
        >
          {commands.map((cmd) => (
            <Text key={cmd} color={theme.text.link}>
              <RenderInline text={cmd} />
            </Text>
          ))}
        </Box>
      </Box>

      <Box marginBottom={1}>
        <Text color={theme.text.primary}>{t('Do you want to proceed?')}</Text>
      </Box>

      <RadioButtonSelect
        items={options}
        onSelect={handleSelect}
        isFocused={!isEditMode}
      />
    </Box>
  );
};
