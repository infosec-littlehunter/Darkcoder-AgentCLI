/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi } from 'vitest';
import { getCoreSystemPrompt } from './prompts.js';
import type { ToolRegistry } from '../tools/tool-registry.js';
import { DiscoveredMCPTool } from '../tools/mcp-tool.js';
import type { CallableTool } from '@google/genai';

// Test helper: Mock MCP tool for testing
class MockMCPTool extends DiscoveredMCPTool {
  constructor(
    public override serverName: string,
    public override serverToolName: string,
    name: string,
  ) {
    super(
      {} as unknown as CallableTool,
      serverName,
      serverToolName,
      'test description',
      {},
      undefined,
      name,
    );
  }
}

describe('MCP Snapshot Injection', () => {
  it('should not include MCP snapshot when toolRegistry is not provided', () => {
    const prompt = getCoreSystemPrompt();
    expect(prompt).not.toContain('### Discovered MCP Tools');
  });

  it('should not include MCP snapshot when no MCP tools are discovered', () => {
    const mockRegistry = {
      getAllTools: vi.fn().mockReturnValue([]),
    } as unknown as ToolRegistry;

    const prompt = getCoreSystemPrompt(undefined, undefined, {
      toolRegistry: mockRegistry,
    });

    expect(prompt).not.toContain('### Discovered MCP Tools');
  });

  it('should include MCP snapshot with discovered tools grouped by server', () => {
    const mockMcpTool1 = new MockMCPTool(
      'shodan',
      'get_host_info',
      'shodan__get_host_info',
    );
    const mockMcpTool2 = new MockMCPTool(
      'shodan',
      'search_shodan',
      'shodan__search_shodan',
    );
    const mockMcpTool3 = new MockMCPTool(
      'nist',
      'get_temporal_context',
      'nist__get_temporal_context',
    );

    const getAllToolsSpy = vi
      .fn()
      .mockReturnValue([mockMcpTool1, mockMcpTool2, mockMcpTool3]);
    const mockRegistry = {
      getAllTools: getAllToolsSpy,
    } as unknown as ToolRegistry;

    const prompt = getCoreSystemPrompt(undefined, undefined, {
      toolRegistry: mockRegistry,
    });

    expect(prompt).toContain('### Discovered MCP Tools');
    expect(prompt).toContain('Currently available MCP servers and tools:');
    expect(prompt).toContain('**nist**: get_temporal_context');
    expect(prompt).toContain('**shodan**: get_host_info, search_shodan');
    expect(prompt).toContain(
      'Refer to the MCP Tool Selection Guide and Planning Protocol above for usage patterns.',
    );
  });

  it('should sort servers and tools alphabetically', () => {
    const mockMcpTool1 = new MockMCPTool('zebra', 'zoo', 'zebra__zoo');
    const mockMcpTool2 = new MockMCPTool('zebra', 'alpha', 'zebra__alpha');
    const mockMcpTool3 = new MockMCPTool('alpha', 'beta', 'alpha__beta');

    const mockRegistry = {
      getAllTools: vi
        .fn()
        .mockReturnValue([mockMcpTool1, mockMcpTool2, mockMcpTool3]),
    } as unknown as ToolRegistry;

    const prompt = getCoreSystemPrompt(undefined, undefined, {
      toolRegistry: mockRegistry,
    });

    // Check that alpha comes before zebra (servers sorted)
    const alphaIndex = prompt.indexOf('**alpha**');
    const zebraIndex = prompt.indexOf('**zebra**');
    expect(alphaIndex).toBeLessThan(zebraIndex);

    // Check that within zebra, alpha comes before zoo (tools sorted)
    expect(prompt).toContain('**zebra**: alpha, zoo');
  });

  it('should append MCP snapshot after memory and concise mode', () => {
    const mockMcpTool = new MockMCPTool('test', 'test_tool', 'test__test_tool');

    const mockRegistry = {
      getAllTools: vi.fn().mockReturnValue([mockMcpTool]),
    } as unknown as ToolRegistry;

    const prompt = getCoreSystemPrompt('User memory content', undefined, {
      conciseMode: true,
      toolRegistry: mockRegistry,
    });

    // Should contain memory
    expect(prompt).toContain('User memory content');

    // Should contain concise mode instructions
    expect(prompt).toContain('concise');

    // Should contain MCP snapshot
    expect(prompt).toContain('### Discovered MCP Tools');

    // MCP snapshot should come after memory section
    const memoryIndex = prompt.indexOf('User memory content');
    const mcpIndex = prompt.indexOf('### Discovered MCP Tools');
    expect(mcpIndex).toBeGreaterThan(memoryIndex);
  });
});
