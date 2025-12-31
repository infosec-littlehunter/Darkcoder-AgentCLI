/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Mock } from 'vitest';
import { describe, it, expect, vi } from 'vitest';
import { toolsCommand } from './toolsCommand.js';
import { createMockCommandContext } from '../../test-utils/mockCommandContext.js';
import { MessageType } from '../types.js';
import type { AnyDeclarativeTool } from '@darkcoder/darkcoder-core';

// Mock tools for testing
const mockTools = [
  {
    name: 'file-reader',
    displayName: 'File Reader',
    description: 'Reads files from the local system.',
    schema: {},
  },
  {
    name: 'code-editor',
    displayName: 'Code Editor',
    description: 'Edits code files.',
    schema: {},
  },
] as AnyDeclarativeTool[];

describe('toolsCommand', () => {
  it('should display an error if the tool registry is unavailable', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => undefined,
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, '');

    expect(mockContext.ui.addItem).toHaveBeenCalledWith(
      {
        type: MessageType.ERROR,
        text: 'Could not retrieve tool registry.',
      },
      expect.any(Number),
    );
  });

  it('should display "No tools available" when none are found', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => ({ getAllTools: () => [] as AnyDeclarativeTool[] }),
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, '');

    expect(mockContext.ui.addItem).toHaveBeenCalledWith(
      {
        type: MessageType.TOOLS_LIST,
        tools: [],
        showDescriptions: false,
      },
      expect.any(Number),
    );
  });

  it('should list tools without descriptions by default', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => ({ getAllTools: () => mockTools }),
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, '');

    const [message] = (mockContext.ui.addItem as Mock).mock.calls[0];
    expect(message.type).toBe(MessageType.TOOLS_LIST);
    expect(message.showDescriptions).toBe(false);
    expect(message.tools).toHaveLength(2);
    expect(message.tools[0].displayName).toBe('File Reader');
    expect(message.tools[0].isEnabled).toBe(true);
    expect(message.tools[1].displayName).toBe('Code Editor');
    expect(message.tools[1].isEnabled).toBe(true);
  });

  it('should list tools with descriptions when "desc" arg is passed', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => ({ getAllTools: () => mockTools }),
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, 'desc');

    const [message] = (mockContext.ui.addItem as Mock).mock.calls[0];
    expect(message.type).toBe(MessageType.TOOLS_LIST);
    expect(message.showDescriptions).toBe(true);
    expect(message.tools).toHaveLength(2);
    expect(message.tools[0].description).toBe(
      'Reads files from the local system.',
    );
    expect(message.tools[1].description).toBe('Edits code files.');
  });

  it('should show tool as disabled when in exclude list', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => ({ getAllTools: () => mockTools }),
        },
        settings: {
          merged: {
            tools: {
              exclude: ['file-reader'],
            },
          },
          setValue: vi.fn(),
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, '');

    const [message] = (mockContext.ui.addItem as Mock).mock.calls[0];
    expect(message.type).toBe(MessageType.TOOLS_LIST);
    expect(message.tools).toHaveLength(2);
    expect(message.tools[0].name).toBe('file-reader');
    expect(message.tools[0].isEnabled).toBe(false);
    expect(message.tools[1].name).toBe('code-editor');
    expect(message.tools[1].isEnabled).toBe(true);
  });

  it('should disable a tool when "disable" subcommand is used', async () => {
    const setValueMock = vi.fn();
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => ({ getAllTools: () => mockTools }),
        },
        settings: {
          merged: {
            tools: {
              exclude: [],
            },
          },
          setValue: setValueMock,
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, 'disable file-reader');

    expect(setValueMock).toHaveBeenCalledWith('User', 'tools.exclude', [
      'file-reader',
    ]);
    expect(mockContext.ui.addItem).toHaveBeenCalledWith(
      expect.objectContaining({
        type: MessageType.INFO,
      }),
      expect.any(Number),
    );
  });

  it('should enable a tool when "enable" subcommand is used', async () => {
    const setValueMock = vi.fn();
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => ({ getAllTools: () => mockTools }),
        },
        settings: {
          merged: {
            tools: {
              exclude: ['file-reader', 'code-editor'],
            },
          },
          setValue: setValueMock,
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, 'enable file-reader');

    expect(setValueMock).toHaveBeenCalledWith('User', 'tools.exclude', [
      'code-editor',
    ]);
    expect(mockContext.ui.addItem).toHaveBeenCalledWith(
      expect.objectContaining({
        type: MessageType.INFO,
      }),
      expect.any(Number),
    );
  });

  it('should show error when tool name not found', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getToolRegistry: () => ({ getAllTools: () => mockTools }),
        },
      },
    });

    if (!toolsCommand.action) throw new Error('Action not defined');
    await toolsCommand.action(mockContext, 'disable non-existent-tool');

    expect(mockContext.ui.addItem).toHaveBeenCalledWith(
      expect.objectContaining({
        type: MessageType.ERROR,
        text: expect.stringContaining('not found'),
      }),
      expect.any(Number),
    );
  });
});
