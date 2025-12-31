/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { ToolConflictDetector } from './toolConflictDetector.js';
import type { ScheduledToolCall } from './coreToolScheduler.js';
import {
  BaseToolInvocation,
  type ToolLocation,
  type Tool,
  type ToolKind,
  type ToolSchema,
} from '../tools/tools.js';

/**
 * Mock tool invocation for testing
 */
class MockToolInvocation extends BaseToolInvocation<object, unknown> {
  constructor(private locations: ToolLocation[] = []) {
    super({});
  }

  getDescription(): string {
    return 'Mock tool';
  }

  override toolLocations(): ToolLocation[] {
    return this.locations;
  }

  async execute(): Promise<unknown> {
    return { llmContent: 'mock result' };
  }
}

/**
 * Creates a mock scheduled tool call for testing
 */
function createMockToolCall(
  name: string,
  locations: ToolLocation[],
): ScheduledToolCall {
  return {
    status: 'scheduled',
    request: {
      callId: `call_${name}`,
      name,
      args: {},
      prompt_id: 'test',
      isClientInitiated: true,
    },
    tool: {
      name,
      displayName: name,
      description: 'Mock tool',
      kind: 'generic' as ToolKind,
      schema: {} as ToolSchema,
      isOutputMarkdown: false,
      canUpdateOutput: false,
      build: () => new MockToolInvocation(locations),
    } as Tool,
    invocation: new MockToolInvocation(locations),
    startTime: Date.now(),
  };
}

describe('ToolConflictDetector', () => {
  describe('toolsConflict', () => {
    it('should detect write-write conflict', () => {
      const tool1 = createMockToolCall('write1', [
        { path: '/tmp/file.txt', operation: 'write' },
      ]);

      const tool2 = createMockToolCall('write2', [
        { path: '/tmp/file.txt', operation: 'write' },
      ]);

      const hasConflict = ToolConflictDetector.toolsConflict(tool1, tool2);

      expect(hasConflict).toBe(true);
    });

    it('should detect write-read conflict', () => {
      const tool1 = createMockToolCall('write', [
        { path: '/tmp/file.txt', operation: 'write' },
      ]);

      const tool2 = createMockToolCall('read', [
        { path: '/tmp/file.txt', operation: 'read' },
      ]);

      const hasConflict = ToolConflictDetector.toolsConflict(tool1, tool2);

      expect(hasConflict).toBe(true);
    });

    it('should NOT detect read-read conflict', () => {
      const tool1 = createMockToolCall('read1', [
        { path: '/tmp/file.txt', operation: 'read' },
      ]);

      const tool2 = createMockToolCall('read2', [
        { path: '/tmp/file.txt', operation: 'read' },
      ]);

      const hasConflict = ToolConflictDetector.toolsConflict(tool1, tool2);

      expect(hasConflict).toBe(false);
    });

    it('should NOT detect conflict for different files', () => {
      const tool1 = createMockToolCall('write1', [
        { path: '/tmp/file1.txt', operation: 'write' },
      ]);

      const tool2 = createMockToolCall('write2', [
        { path: '/tmp/file2.txt', operation: 'write' },
      ]);

      const hasConflict = ToolConflictDetector.toolsConflict(tool1, tool2);

      expect(hasConflict).toBe(false);
    });

    it('should normalize paths when checking conflicts', () => {
      const tool1 = createMockToolCall('write1', [
        { path: '/tmp/file.txt', operation: 'write' },
      ]);

      const tool2 = createMockToolCall('write2', [
        { path: '/tmp/../tmp/file.txt', operation: 'write' },
      ]);

      const hasConflict = ToolConflictDetector.toolsConflict(tool1, tool2);

      expect(hasConflict).toBe(true);
    });

    it('should handle tools with no file locations', () => {
      const tool1 = createMockToolCall('network1', []);
      const tool2 = createMockToolCall('network2', []);

      const hasConflict = ToolConflictDetector.toolsConflict(tool1, tool2);

      expect(hasConflict).toBe(false);
    });

    it('should handle tools with multiple file locations', () => {
      const tool1 = createMockToolCall('multi1', [
        { path: '/tmp/file1.txt', operation: 'read' },
        { path: '/tmp/file2.txt', operation: 'write' },
      ]);

      const tool2 = createMockToolCall('multi2', [
        { path: '/tmp/file2.txt', operation: 'read' },
        { path: '/tmp/file3.txt', operation: 'write' },
      ]);

      const hasConflict = ToolConflictDetector.toolsConflict(tool1, tool2);

      // Should detect conflict on file2.txt (write-read)
      expect(hasConflict).toBe(true);
    });
  });

  describe('groupToolsByConflicts', () => {
    it('should create single group for non-conflicting tools', () => {
      const tools = [
        createMockToolCall('read1', [
          { path: '/tmp/file1.txt', operation: 'read' },
        ]),
        createMockToolCall('read2', [
          { path: '/tmp/file2.txt', operation: 'read' },
        ]),
        createMockToolCall('read3', [
          { path: '/tmp/file3.txt', operation: 'read' },
        ]),
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      expect(groups).toHaveLength(1);
      expect(groups[0]).toHaveLength(3);
    });

    it('should create separate groups for conflicting tools', () => {
      const tools = [
        createMockToolCall('write1', [
          { path: '/tmp/file.txt', operation: 'write' },
        ]),
        createMockToolCall('write2', [
          { path: '/tmp/file.txt', operation: 'write' },
        ]),
        createMockToolCall('write3', [
          { path: '/tmp/file.txt', operation: 'write' },
        ]),
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      // Each write should be in separate group
      expect(groups).toHaveLength(3);
      expect(groups[0]).toHaveLength(1);
      expect(groups[1]).toHaveLength(1);
      expect(groups[2]).toHaveLength(1);
    });

    it('should optimize grouping for mixed conflicts', () => {
      const tools = [
        createMockToolCall('write', [
          { path: '/tmp/file1.txt', operation: 'write' },
        ]),
        createMockToolCall('read1', [
          { path: '/tmp/file1.txt', operation: 'read' },
        ]),
        createMockToolCall('network1', []), // No file access
        createMockToolCall('network2', []), // No file access
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      // Group 1: write + network tools (no conflict)
      // Group 2: read (conflicts with write)
      expect(groups).toHaveLength(2);
      expect(groups[0].length).toBeGreaterThan(1); // write + networks
    });

    it('should handle empty tool list', () => {
      const groups = ToolConflictDetector.groupToolsByConflicts([]);

      expect(groups).toHaveLength(0);
    });

    it('should handle single tool', () => {
      const tools = [
        createMockToolCall('single', [
          { path: '/tmp/file.txt', operation: 'write' },
        ]),
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      expect(groups).toHaveLength(1);
      expect(groups[0]).toHaveLength(1);
    });
  });

  describe('validateGroup', () => {
    it('should validate conflict-free group', () => {
      const group = [
        createMockToolCall('read1', [
          { path: '/tmp/file1.txt', operation: 'read' },
        ]),
        createMockToolCall('read2', [
          { path: '/tmp/file2.txt', operation: 'read' },
        ]),
      ];

      const result = ToolConflictDetector.validateGroup(group);

      expect(result.valid).toBe(true);
      expect(result.conflicts).toHaveLength(0);
    });

    it('should detect conflicts in group', () => {
      const group = [
        createMockToolCall('write', [
          { path: '/tmp/file.txt', operation: 'write' },
        ]),
        createMockToolCall('read', [
          { path: '/tmp/file.txt', operation: 'read' },
        ]),
      ];

      const result = ToolConflictDetector.validateGroup(group);

      expect(result.valid).toBe(false);
      expect(result.conflicts).toHaveLength(1);
      expect(result.conflicts[0].tool1).toBe('write');
      expect(result.conflicts[0].tool2).toBe('read');
    });

    it('should provide conflict reasons', () => {
      const group = [
        createMockToolCall('write1', [
          { path: '/tmp/file.txt', operation: 'write' },
        ]),
        createMockToolCall('write2', [
          { path: '/tmp/file.txt', operation: 'write' },
        ]),
      ];

      const result = ToolConflictDetector.validateGroup(group);

      expect(result.valid).toBe(false);
      expect(result.conflicts[0].reason).toContain('Both tools write');
    });
  });

  describe('Real-world scenarios', () => {
    it('should allow parallel network reconnaissance', () => {
      const tools = [
        createMockToolCall('censys', []), // Network API call
        createMockToolCall('urlscan', []), // Network API call
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      // All network tools should be in one group
      expect(groups).toHaveLength(1);
      expect(groups[0]).toHaveLength(3);
    });

    it('should prevent parallel file operations on same file', () => {
      const tools = [
        createMockToolCall('write_config', [
          { path: '/config/settings.json', operation: 'write' },
        ]),
        createMockToolCall('read_config', [
          { path: '/config/settings.json', operation: 'read' },
        ]),
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      // Should be in separate groups
      expect(groups).toHaveLength(2);
    });

    it('should allow parallel reads of different files', () => {
      const tools = [
        createMockToolCall('read_file1', [
          { path: '/data/file1.txt', operation: 'read' },
        ]),
        createMockToolCall('read_file2', [
          { path: '/data/file2.txt', operation: 'read' },
        ]),
        createMockToolCall('read_file3', [
          { path: '/data/file3.txt', operation: 'read' },
        ]),
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      // All reads should be in one group
      expect(groups).toHaveLength(1);
      expect(groups[0]).toHaveLength(3);
    });

    it('should handle mixed network and file operations', () => {
      const tools = [
        createMockToolCall('censys', []), // Network
        createMockToolCall('write_results', [
          { path: '/results/output.json', operation: 'write' },
        ]),
        createMockToolCall('urlscan', []), // Network
        createMockToolCall('read_config', [
          { path: '/config/settings.json', operation: 'read' },
        ]),
      ];

      const groups = ToolConflictDetector.groupToolsByConflicts(tools);

      // Network tools + file operations with different files = 1 group
      expect(groups).toHaveLength(1);
      expect(groups[0]).toHaveLength(4);
    });
  });
});
