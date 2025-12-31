/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { ScheduledToolCall } from './coreToolScheduler.js';
import type { ToolLocation } from '../tools/tools.js';
import * as path from 'node:path';

/**
 * Detects conflicts between tool calls to prevent concurrent access issues
 */
export class ToolConflictDetector {
  /**
   * Checks if two tools would conflict if executed in parallel
   */
  static toolsConflict(
    tool1: ScheduledToolCall,
    tool2: ScheduledToolCall,
  ): boolean {
    // Get file system locations for both tools
    const locations1 = tool1.invocation.toolLocations();
    const locations2 = tool2.invocation.toolLocations();

    // Check for file system conflicts
    return this.hasFileSystemConflict(locations1, locations2);
  }

  /**
   * Detects file system conflicts between two sets of tool locations
   */
  private static hasFileSystemConflict(
    locations1: ToolLocation[],
    locations2: ToolLocation[],
  ): boolean {
    for (const loc1 of locations1) {
      for (const loc2 of locations2) {
        if (this.locationsConflict(loc1, loc2)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Checks if two specific locations conflict
   */
  private static locationsConflict(
    loc1: ToolLocation,
    loc2: ToolLocation,
  ): boolean {
    // Normalize paths for comparison
    const path1 = this.normalizePath(loc1.path);
    const path2 = this.normalizePath(loc2.path);

    // Different paths = no conflict
    if (path1 !== path2) {
      return false;
    }

    // If operation is not specified, assume potential conflict (conservative approach)
    if (!loc1.operation || !loc2.operation) {
      return true;
    }

    // Same path - check operation types
    return this.operationsConflict(loc1.operation, loc2.operation);
  }

  /**
   * Determines if two operations on the same file conflict
   */
  private static operationsConflict(
    op1: 'read' | 'write',
    op2: 'read' | 'write',
  ): boolean {
    // Write conflicts with everything (write-write, write-read)
    if (op1 === 'write' || op2 === 'write') {
      return true;
    }

    // Read-read is safe
    return false;
  }

  /**
   * Normalizes a file path for consistent comparison
   */
  private static normalizePath(filePath: string): string {
    // Resolve to absolute path
    const absolute = path.resolve(filePath);

    // Normalize separators and case (for case-insensitive file systems)
    return path.normalize(absolute).toLowerCase();
  }

  /**
   * Groups tools into execution waves to maximize parallelism while avoiding conflicts
   */
  static groupToolsByConflicts(
    tools: ScheduledToolCall[],
  ): ScheduledToolCall[][] {
    const groups: ScheduledToolCall[][] = [];
    const remaining = [...tools];

    while (remaining.length > 0) {
      // Start new group with first remaining tool
      const group: ScheduledToolCall[] = [remaining.shift()!];

      // Try to add more non-conflicting tools to this group
      for (let i = remaining.length - 1; i >= 0; i--) {
        const candidateTool = remaining[i];

        // Check if candidate conflicts with any tool in current group
        const hasConflict = group.some((groupTool) =>
          this.toolsConflict(groupTool, candidateTool),
        );

        if (!hasConflict) {
          // Safe to add to this group
          group.push(candidateTool);
          remaining.splice(i, 1);
        }
      }

      groups.push(group);
    }

    return groups;
  }

  /**
   * Validates that tools in a group can safely run in parallel
   */
  static validateGroup(group: ScheduledToolCall[]): {
    valid: boolean;
    conflicts: Array<{ tool1: string; tool2: string; reason: string }>;
  } {
    const conflicts: Array<{ tool1: string; tool2: string; reason: string }> =
      [];

    // Check all pairs
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const tool1 = group[i];
        const tool2 = group[j];

        if (this.toolsConflict(tool1, tool2)) {
          const reason = this.getConflictReason(tool1, tool2);
          conflicts.push({
            tool1: tool1.request.name,
            tool2: tool2.request.name,
            reason,
          });
        }
      }
    }

    return {
      valid: conflicts.length === 0,
      conflicts,
    };
  }

  /**
   * Gets a human-readable explanation of why tools conflict
   */
  private static getConflictReason(
    tool1: ScheduledToolCall,
    tool2: ScheduledToolCall,
  ): string {
    const locs1 = tool1.invocation.toolLocations();
    const locs2 = tool2.invocation.toolLocations();

    for (const loc1 of locs1) {
      for (const loc2 of locs2) {
        if (this.locationsConflict(loc1, loc2)) {
          const path1 = this.normalizePath(loc1.path);

          // Handle cases where operation might not be specified
          if (!loc1.operation || !loc2.operation) {
            return `Both tools access ${path1} (operation type unknown)`;
          }

          if (loc1.operation === 'write' && loc2.operation === 'write') {
            return `Both tools write to ${path1}`;
          } else if (loc1.operation === 'write' || loc2.operation === 'write') {
            return `One writes, one reads ${path1}`;
          }
        }
      }
    }

    return 'Unknown conflict';
  }

  /**
   * Estimates optimal concurrency for a group of tools
   */
  static estimateOptimalConcurrency(group: ScheduledToolCall[]): number {
    // For now, return group size (all can run in parallel)
    // In future, could consider:
    // - System resources
    // - Tool categories (network vs CPU intensive)
    // - Rate limiting concerns
    return group.length;
  }
}
