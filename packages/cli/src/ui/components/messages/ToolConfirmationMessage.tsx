/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type React from 'react';
import { useEffect, useState, useCallback } from 'react';
import { Box, Text } from 'ink';
import { DiffRenderer } from './DiffRenderer.js';
import { RenderInline } from '../../utils/InlineMarkdownRenderer.js';
import { MarkdownDisplay } from '../../utils/MarkdownDisplay.js';
import type {
  ToolCallConfirmationDetails,
  ToolExecuteConfirmationDetails,
  ToolMcpConfirmationDetails,
  Config,
  EditorType,
} from '@darkcoder/darkcoder-core';
import { IdeClient, ToolConfirmationOutcome } from '@darkcoder/darkcoder-core';
import type { RadioSelectItem } from '../shared/RadioButtonSelect.js';
import { RadioButtonSelect } from '../shared/RadioButtonSelect.js';
import { MaxSizedBox } from '../shared/MaxSizedBox.js';
import { useKeypress } from '../../hooks/useKeypress.js';
import { useSettings } from '../../contexts/SettingsContext.js';
import { theme } from '../../semantic-colors.js';
import { t } from '../../../i18n/index.js';
import { TextInput } from '../shared/TextInput.js';

export interface ToolConfirmationMessageProps {
  confirmationDetails: ToolCallConfirmationDetails;
  config: Config;
  isFocused?: boolean;
  availableTerminalHeight?: number;
  terminalWidth: number;
  compactMode?: boolean;
}

export const ToolConfirmationMessage: React.FC<
  ToolConfirmationMessageProps
> = ({
  confirmationDetails,
  config,
  isFocused = true,
  availableTerminalHeight,
  terminalWidth,
  compactMode = false,
}) => {
  const { onConfirm } = confirmationDetails;
  const childWidth = terminalWidth - 2; // 2 for padding

  // State for edit request mode
  const [isEditMode, setIsEditMode] = useState(false);
  const [editFeedback, setEditFeedback] = useState('');
  // Delay before TextInput becomes active - prevents the Enter key that
  // selected "Edit request" from immediately triggering submission
  const [isEditInputActive, setIsEditInputActive] = useState(false);

  // When entering edit mode, delay activation of TextInput
  useEffect(() => {
    if (isEditMode) {
      const timer = setTimeout(() => {
        setIsEditInputActive(true);
      }, 100); // 100ms delay to let the Enter keypress finish processing
      return () => clearTimeout(timer);
    }
    setIsEditInputActive(false);
    return undefined;
  }, [isEditMode]);

  const settings = useSettings();
  const preferredEditor = settings.merged.general?.preferredEditor as
    | EditorType
    | undefined;

  const [ideClient, setIdeClient] = useState<IdeClient | null>(null);
  const [isDiffingEnabled, setIsDiffingEnabled] = useState(false);

  useEffect(() => {
    let isMounted = true;
    if (config.getIdeMode()) {
      const getIdeClient = async () => {
        const client = await IdeClient.getInstance();
        if (isMounted) {
          setIdeClient(client);
          setIsDiffingEnabled(client?.isDiffingEnabled() ?? false);
        }
      };
      getIdeClient();
    }
    return () => {
      isMounted = false;
    };
  }, [config]);

  const handleConfirm = async (
    outcome: ToolConfirmationOutcome,
    feedback?: string,
  ) => {
    if (confirmationDetails.type === 'edit') {
      if (config.getIdeMode() && isDiffingEnabled) {
        const cliOutcome =
          outcome === ToolConfirmationOutcome.Cancel ? 'rejected' : 'accepted';
        await ideClient?.resolveDiffFromCli(
          confirmationDetails.filePath,
          cliOutcome,
        );
      }
    }
    // Pass user feedback as cancel message when cancelling with edit request
    if (outcome === ToolConfirmationOutcome.Cancel && feedback) {
      onConfirm(outcome, { cancelMessage: feedback });
    } else {
      onConfirm(outcome);
    }
  };

  const isTrustedFolder = config.isTrustedFolder();

  // Handle edit feedback submission
  const handleEditSubmit = useCallback(() => {
    // Only process if edit input is active (prevents race condition)
    if (!isEditInputActive) {
      return;
    }
    const feedback = editFeedback.trim();
    // Always call onConfirm - either with feedback or just as a cancel
    if (feedback) {
      // Use EditRequest outcome so the LLM continues with the feedback
      onConfirm(ToolConfirmationOutcome.EditRequest, {
        cancelMessage: feedback,
      });
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
      if (!isFocused) return;

      // In edit mode, handle escape to cancel edit
      if (isEditMode) {
        if (key.name === 'escape') {
          handleEditCancel();
        }
        return;
      }

      if (key.name === 'escape' || (key.ctrl && key.name === 'c')) {
        handleConfirm(ToolConfirmationOutcome.Cancel);
      }
    },
    { isActive: isFocused },
  );

  const handleSelect = (item: ToolConfirmationOutcome) => {
    if (item === ToolConfirmationOutcome.EditRequest) {
      setIsEditMode(true);
      return;
    }
    handleConfirm(item);
  };

  // Compact mode: return simple 3-option display
  if (compactMode) {
    const compactOptions: Array<RadioSelectItem<ToolConfirmationOutcome>> = [
      {
        key: 'proceed-once',
        label: t('Yes, allow once'),
        value: ToolConfirmationOutcome.ProceedOnce,
      },
      {
        key: 'proceed-always',
        label: t('Allow always'),
        value: ToolConfirmationOutcome.ProceedAlways,
      },
      {
        key: 'cancel',
        label: t('No'),
        value: ToolConfirmationOutcome.Cancel,
      },
    ];

    return (
      <Box flexDirection="column">
        <Box>
          <Text wrap="truncate">{t('Do you want to proceed?')}</Text>
        </Box>
        <Box>
          <RadioButtonSelect
            items={compactOptions}
            onSelect={handleSelect}
            isFocused={isFocused}
          />
        </Box>
      </Box>
    );
  }

  // Original logic continues unchanged below
  let bodyContent: React.ReactNode | null = null; // Removed contextDisplay here
  let question: string;

  const options: Array<RadioSelectItem<ToolConfirmationOutcome>> = new Array<
    RadioSelectItem<ToolConfirmationOutcome>
  >();

  // Body content is now the DiffRenderer, passing filename to it
  // The bordered box is removed from here and handled within DiffRenderer

  function availableBodyContentHeight() {
    if (options.length === 0) {
      // This should not happen in practice as options are always added before this is called.
      throw new Error('Options not provided for confirmation message');
    }

    if (availableTerminalHeight === undefined) {
      return undefined;
    }

    // Calculate the vertical space (in lines) consumed by UI elements
    // surrounding the main body content.
    const PADDING_OUTER_Y = 2; // Main container has `padding={1}` (top & bottom).
    const MARGIN_BODY_BOTTOM = 1; // margin on the body container.
    const HEIGHT_QUESTION = 1; // The question text is one line.
    const MARGIN_QUESTION_BOTTOM = 1; // Margin on the question container.
    const HEIGHT_OPTIONS = options.length; // Each option in the radio select takes one line.

    const surroundingElementsHeight =
      PADDING_OUTER_Y +
      MARGIN_BODY_BOTTOM +
      HEIGHT_QUESTION +
      MARGIN_QUESTION_BOTTOM +
      HEIGHT_OPTIONS;
    return Math.max(availableTerminalHeight - surroundingElementsHeight, 1);
  }

  if (confirmationDetails.type === 'edit') {
    if (confirmationDetails.isModifying) {
      return (
        <Box
          minWidth="90%"
          borderStyle="round"
          borderColor={theme.border.default}
          justifyContent="space-around"
          padding={1}
          overflow="hidden"
        >
          <Text color={theme.text.primary}>{t('Modify in progress:')} </Text>
          <Text color={theme.status.success}>
            {t('Save and close external editor to continue')}
          </Text>
        </Box>
      );
    }

    question = t('Apply this change?');
    options.push({
      label: t('Yes, allow once'),
      value: ToolConfirmationOutcome.ProceedOnce,
      key: 'Yes, allow once',
    });
    if (isTrustedFolder) {
      options.push({
        label: t('Yes, allow always'),
        value: ToolConfirmationOutcome.ProceedAlways,
        key: 'Yes, allow always',
      });
    }
    if ((!config.getIdeMode() || !isDiffingEnabled) && preferredEditor) {
      options.push({
        label: t('Modify with external editor'),
        value: ToolConfirmationOutcome.ModifyWithEditor,
        key: 'Modify with external editor',
      });
    }

    options.push({
      label: t('Edit request (add feedback)'),
      value: ToolConfirmationOutcome.EditRequest,
      key: 'Edit request (add feedback)',
    });

    options.push({
      label: t('No, suggest changes (esc)'),
      value: ToolConfirmationOutcome.Cancel,
      key: 'No, suggest changes (esc)',
    });

    bodyContent = (
      <DiffRenderer
        diffContent={confirmationDetails.fileDiff}
        filename={confirmationDetails.fileName}
        availableTerminalHeight={availableBodyContentHeight()}
        terminalWidth={childWidth}
      />
    );
  } else if (confirmationDetails.type === 'exec') {
    const executionProps =
      confirmationDetails as ToolExecuteConfirmationDetails;

    question = t("Allow execution of: '{{command}}'?", {
      command: executionProps.rootCommand,
    });
    options.push({
      label: t('Yes, allow once'),
      value: ToolConfirmationOutcome.ProceedOnce,
      key: 'Yes, allow once',
    });
    if (isTrustedFolder) {
      options.push({
        label: t('Yes, allow always ...'),
        value: ToolConfirmationOutcome.ProceedAlways,
        key: 'Yes, allow always ...',
      });
    }
    options.push({
      label: t('Edit request (add feedback)'),
      value: ToolConfirmationOutcome.EditRequest,
      key: 'Edit request (add feedback)',
    });
    options.push({
      label: t('No, suggest changes (esc)'),
      value: ToolConfirmationOutcome.Cancel,
      key: 'No, suggest changes (esc)',
    });

    let bodyContentHeight = availableBodyContentHeight();
    if (bodyContentHeight !== undefined) {
      bodyContentHeight -= 2; // Account for padding;
    }
    bodyContent = (
      <Box flexDirection="column">
        <Box paddingX={1} marginLeft={1}>
          <MaxSizedBox
            maxHeight={bodyContentHeight}
            maxWidth={Math.max(childWidth - 4, 1)}
          >
            <Box>
              <Text color={theme.text.link}>{executionProps.command}</Text>
            </Box>
          </MaxSizedBox>
        </Box>
      </Box>
    );
  } else if (confirmationDetails.type === 'plan') {
    const planProps = confirmationDetails;

    question = planProps.title;
    options.push({
      key: 'proceed-always',
      label: t('Yes, and auto-accept edits'),
      value: ToolConfirmationOutcome.ProceedAlways,
    });
    options.push({
      key: 'proceed-once',
      label: t('Yes, and manually approve edits'),
      value: ToolConfirmationOutcome.ProceedOnce,
    });
    options.push({
      key: 'cancel',
      label: t('No, keep planning (esc)'),
      value: ToolConfirmationOutcome.Cancel,
    });

    bodyContent = (
      <Box flexDirection="column" paddingX={1} marginLeft={1}>
        <MarkdownDisplay
          text={planProps.plan}
          isPending={false}
          availableTerminalHeight={availableBodyContentHeight()}
          terminalWidth={childWidth}
        />
      </Box>
    );
  } else if (confirmationDetails.type === 'info') {
    const infoProps = confirmationDetails;
    const displayUrls =
      infoProps.urls &&
      !(infoProps.urls.length === 1 && infoProps.urls[0] === infoProps.prompt);

    question = t('Do you want to proceed?');
    options.push({
      label: t('Yes, allow once'),
      value: ToolConfirmationOutcome.ProceedOnce,
      key: 'Yes, allow once',
    });
    if (isTrustedFolder) {
      options.push({
        label: t('Yes, allow always'),
        value: ToolConfirmationOutcome.ProceedAlways,
        key: 'Yes, allow always',
      });
    }
    options.push({
      label: t('Edit request (add feedback)'),
      value: ToolConfirmationOutcome.EditRequest,
      key: 'Edit request (add feedback)',
    });
    options.push({
      label: t('No, suggest changes (esc)'),
      value: ToolConfirmationOutcome.Cancel,
      key: 'No, suggest changes (esc)',
    });

    bodyContent = (
      <Box flexDirection="column" paddingX={1} marginLeft={1}>
        <Text color={theme.text.link}>
          <RenderInline text={infoProps.prompt} />
        </Text>
        {displayUrls && infoProps.urls && infoProps.urls.length > 0 && (
          <Box flexDirection="column" marginTop={1}>
            <Text color={theme.text.primary}>{t('URLs to fetch:')}</Text>
            {infoProps.urls.map((url) => (
              <Text key={url}>
                {' '}
                - <RenderInline text={url} />
              </Text>
            ))}
          </Box>
        )}
      </Box>
    );
  } else {
    // mcp tool confirmation
    const mcpProps = confirmationDetails as ToolMcpConfirmationDetails;

    bodyContent = (
      <Box flexDirection="column" paddingX={1} marginLeft={1}>
        <Text color={theme.text.link}>
          {t('MCP Server: {{server}}', { server: mcpProps.serverName })}
        </Text>
        <Text color={theme.text.link}>
          {t('Tool: {{tool}}', { tool: mcpProps.toolName })}
        </Text>
      </Box>
    );

    question = t(
      'Allow execution of MCP tool "{{tool}}" from server "{{server}}"?',
      {
        tool: mcpProps.toolName,
        server: mcpProps.serverName,
      },
    );
    options.push({
      label: t('Yes, allow once'),
      value: ToolConfirmationOutcome.ProceedOnce,
      key: 'Yes, allow once',
    });
    if (isTrustedFolder) {
      options.push({
        label: t('Yes, always allow tool "{{tool}}" from server "{{server}}"', {
          tool: mcpProps.toolName,
          server: mcpProps.serverName,
        }),
        value: ToolConfirmationOutcome.ProceedAlwaysTool, // Cast until types are updated
        key: `Yes, always allow tool "${mcpProps.toolName}" from server "${mcpProps.serverName}"`,
      });
      options.push({
        label: t('Yes, always allow all tools from server "{{server}}"', {
          server: mcpProps.serverName,
        }),
        value: ToolConfirmationOutcome.ProceedAlwaysServer,
        key: `Yes, always allow all tools from server "${mcpProps.serverName}"`,
      });
    }
    options.push({
      label: t('Edit request (add feedback)'),
      value: ToolConfirmationOutcome.EditRequest,
      key: 'Edit request (add feedback)',
    });
    options.push({
      label: t('No, suggest changes (esc)'),
      value: ToolConfirmationOutcome.Cancel,
      key: 'No, suggest changes (esc)',
    });
  }

  // Edit mode UI - show text input for user feedback
  if (isEditMode) {
    return (
      <Box flexDirection="column" padding={1} width={childWidth}>
        {/* Body Content */}
        <Box flexGrow={1} flexShrink={1} overflow="hidden" marginBottom={1}>
          {bodyContent}
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
              inputWidth={Math.max(childWidth - 4, 20)}
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
    <Box flexDirection="column" padding={1} width={childWidth}>
      {/* Body Content (Diff Renderer or Command Info) */}
      {/* No separate context display here anymore for edits */}
      <Box flexGrow={1} flexShrink={1} overflow="hidden" marginBottom={1}>
        {bodyContent}
      </Box>

      {/* Confirmation Question */}
      <Box marginBottom={1} flexShrink={0}>
        <Text color={theme.text.primary} wrap="truncate">
          {question}
        </Text>
      </Box>

      {/* Select Input for Options */}
      <Box flexShrink={0}>
        <RadioButtonSelect
          items={options}
          onSelect={handleSelect}
          isFocused={isFocused && !isEditMode}
        />
      </Box>
    </Box>
  );
};
