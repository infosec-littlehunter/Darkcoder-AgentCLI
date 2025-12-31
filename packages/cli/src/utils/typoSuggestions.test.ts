/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  findCommandSuggestions,
  formatSuggestions,
  findSlashCommandSuggestions,
  findFlagSuggestions,
  findSubcommandSuggestions,
  commandExists,
  getCommandSuggestionMessage,
} from './typoSuggestions.js';

describe('typoSuggestions', () => {
  describe('findCommandSuggestions', () => {
    const commands = ['help', 'clear', 'quit', 'settings', 'theme', 'stats'];

    it('should find exact close matches', () => {
      const suggestions = findCommandSuggestions('halp', commands);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('help');
    });

    it('should find suggestions for common typos', () => {
      const suggestions = findCommandSuggestions('settigns', commands);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('settings');
    });

    it('should return empty array for completely unrelated input', () => {
      const suggestions = findCommandSuggestions('xyz123', commands);
      expect(suggestions.length).toBe(0);
    });

    it('should prioritize prefix matches', () => {
      const suggestions = findCommandSuggestions('set', commands);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('settings');
    });

    it('should return multiple suggestions sorted by similarity', () => {
      const suggestions = findCommandSuggestions('stat', commands);
      expect(suggestions.length).toBeGreaterThan(0);
      // Should find stats as closest match
      expect(suggestions[0].command).toBe('stats');
    });

    it('should respect maxSuggestions config', () => {
      const suggestions = findCommandSuggestions('s', commands, undefined, {
        maxSuggestions: 2,
      });
      expect(suggestions.length).toBeLessThanOrEqual(2);
    });

    it('should filter by minimum similarity', () => {
      const suggestions = findCommandSuggestions('x', commands, undefined, {
        minSimilarity: 0.8,
      });
      expect(suggestions.length).toBe(0);
    });
  });

  describe('formatSuggestions', () => {
    it('should format single suggestion correctly', () => {
      const suggestions = [{ command: 'help', distance: 1, similarity: 0.75 }];
      const formatted = formatSuggestions('halp', suggestions);
      expect(formatted).toContain("Unknown command: 'halp'");
      expect(formatted).toContain('Did you mean this?');
      expect(formatted).toContain('help');
    });

    it('should format multiple suggestions correctly', () => {
      const suggestions = [
        { command: 'settings', distance: 1, similarity: 0.8 },
        { command: 'stats', distance: 2, similarity: 0.6 },
      ];
      const formatted = formatSuggestions('set', suggestions);
      expect(formatted).toContain('Did you mean one of these?');
      expect(formatted).toContain('1. settings');
      expect(formatted).toContain('2. stats');
    });

    it('should include descriptions when provided', () => {
      const suggestions = [
        {
          command: 'help',
          distance: 1,
          similarity: 0.75,
          description: 'Show help',
        },
      ];
      const formatted = formatSuggestions('halp', suggestions, true);
      expect(formatted).toContain('help - Show help');
    });

    it('should handle empty suggestions', () => {
      const formatted = formatSuggestions('unknown', []);
      expect(formatted).toBe("Unknown command: 'unknown'");
    });
  });

  describe('findSlashCommandSuggestions', () => {
    const commands = [
      { name: 'help', description: 'Show help' },
      { name: 'clear', description: 'Clear screen' },
      { name: 'memory', description: 'Memory commands' },
    ];

    it('should find suggestions with leading slash', () => {
      const suggestions = findSlashCommandSuggestions('/halp', commands);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('help');
    });

    it('should find suggestions without leading slash', () => {
      const suggestions = findSlashCommandSuggestions('halp', commands);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('help');
    });

    it('should include descriptions in suggestions', () => {
      const suggestions = findSlashCommandSuggestions('/halp', commands);
      expect(suggestions[0].description).toBe('Show help');
    });
  });

  describe('findFlagSuggestions', () => {
    const flags = [
      '--help',
      '--version',
      '--debug',
      '--model',
      '--approval-mode',
    ];

    it('should find suggestions for long flags', () => {
      const suggestions = findFlagSuggestions('--modle', flags);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('--model');
    });

    it('should find suggestions for short flags', () => {
      const suggestions = findFlagSuggestions('-h', ['--help', '-h']);
      expect(suggestions.length).toBeGreaterThan(0);
    });

    it('should preserve dash format in suggestions', () => {
      const suggestions = findFlagSuggestions('--modle', flags);
      expect(suggestions[0].command).toMatch(/^--/);
    });

    it('should handle single dash flags', () => {
      const suggestions = findFlagSuggestions('-v', ['--version', '-v']);
      expect(suggestions[0].command).toMatch(/^-v/);
    });
  });

  describe('findSubcommandSuggestions', () => {
    const subcommands = [
      { name: 'list', description: 'List items' },
      { name: 'add', description: 'Add item' },
      { name: 'remove', description: 'Remove item' },
    ];

    it('should find subcommand suggestions', () => {
      const suggestions = findSubcommandSuggestions(
        'lst',
        'extensions',
        subcommands,
      );
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('list');
    });

    it('should include descriptions', () => {
      const suggestions = findSubcommandSuggestions(
        'lst',
        'extensions',
        subcommands,
      );
      expect(suggestions[0].description).toBe('List items');
    });
  });

  describe('commandExists', () => {
    const commands = ['help', 'clear', 'quit'];

    it('should return true for exact match', () => {
      expect(commandExists('help', commands)).toBe(true);
    });

    it('should return true for case-insensitive match', () => {
      expect(commandExists('HELP', commands)).toBe(true);
      expect(commandExists('Help', commands)).toBe(true);
    });

    it('should return false for non-existent command', () => {
      expect(commandExists('unknown', commands)).toBe(false);
    });

    it('should handle whitespace', () => {
      expect(commandExists('  help  ', commands)).toBe(true);
    });
  });

  describe('getCommandSuggestionMessage', () => {
    const commands = ['help', 'clear', 'settings'];

    it('should return formatted message for typo', () => {
      const message = getCommandSuggestionMessage('halp', commands);
      expect(message).not.toBeNull();
      expect(message).toContain('halp');
      expect(message).toContain('help');
    });

    it('should return null when no suggestions found', () => {
      const message = getCommandSuggestionMessage('xyz123', commands);
      expect(message).toBeNull();
    });

    it('should include descriptions when provided', () => {
      const descriptions = new Map([['help', 'Show help message']]);
      const message = getCommandSuggestionMessage(
        'halp',
        commands,
        descriptions,
      );
      expect(message).toContain('Show help message');
    });
  });

  describe('edge cases', () => {
    it('should handle empty command list', () => {
      const suggestions = findCommandSuggestions('test', []);
      expect(suggestions).toEqual([]);
    });

    it('should handle empty input', () => {
      const suggestions = findCommandSuggestions('', ['help', 'clear']);
      expect(suggestions).toEqual([]);
    });

    it('should handle single character input', () => {
      const suggestions = findCommandSuggestions('h', ['help', 'halt']);
      expect(suggestions.length).toBeGreaterThan(0);
    });

    it('should handle very long input', () => {
      const longInput = 'a'.repeat(100);
      const suggestions = findCommandSuggestions(longInput, ['help']);
      expect(suggestions).toEqual([]);
    });

    it('should handle special characters', () => {
      const suggestions = findCommandSuggestions('h@lp', ['help']);
      // Should still find help despite special character
      expect(suggestions.length).toBeGreaterThan(0);
    });
  });

  describe('similarity calculation', () => {
    it('should rank closer matches higher', () => {
      const commands = ['help', 'hello', 'helicopter'];
      const suggestions = findCommandSuggestions('hel', commands);

      // hel should be closest to help and hello
      expect(suggestions[0].command).toMatch(/help|hello/);
      expect(suggestions[0].similarity).toBeGreaterThan(
        suggestions[suggestions.length - 1].similarity,
      );
    });

    it('should handle transpositions', () => {
      const suggestions = findCommandSuggestions('hlep', ['help']);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('help');
    });

    it('should handle missing characters', () => {
      const suggestions = findCommandSuggestions('seting', ['settings']);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('settings');
    });

    it('should handle extra characters', () => {
      const suggestions = findCommandSuggestions('helppp', ['help']);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0].command).toBe('help');
    });
  });
});
