/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import levenshtein from 'fast-levenshtein';

/**
 * Configuration for typo suggestion algorithm
 */
interface SuggestionConfig {
  /** Maximum Levenshtein distance to consider a match */
  maxDistance: number;
  /** Maximum number of suggestions to return */
  maxSuggestions: number;
  /** Minimum similarity ratio (0-1) to include in suggestions */
  minSimilarity: number;
}

const DEFAULT_CONFIG: SuggestionConfig = {
  maxDistance: 3,
  maxSuggestions: 3,
  minSimilarity: 0.4,
};

/**
 * Suggestion result with metadata
 */
export interface Suggestion {
  /** The suggested command */
  command: string;
  /** Levenshtein distance from input */
  distance: number;
  /** Similarity ratio (0-1) */
  similarity: number;
  /** Optional description of the command */
  description?: string;
}

/**
 * Calculates similarity ratio between two strings
 * Returns a value between 0 (completely different) and 1 (identical)
 */
function calculateSimilarity(str1: string, str2: string): number {
  const maxLen = Math.max(str1.length, str2.length);
  if (maxLen === 0) return 1;
  const distance = levenshtein.get(str1, str2);
  return 1 - distance / maxLen;
}

/**
 * Checks if two strings have common prefix
 */
function hasCommonPrefix(str1: string, str2: string, minLength = 2): boolean {
  const minLen = Math.min(str1.length, str2.length);
  if (minLen < minLength) return false;

  for (let i = 0; i < minLength; i++) {
    if (str1[i] !== str2[i]) return false;
  }
  return true;
}

/**
 * Finds the best command suggestions for a typo
 */
export function findCommandSuggestions(
  input: string,
  availableCommands: string[],
  descriptions?: Map<string, string>,
  config: Partial<SuggestionConfig> = {},
): Suggestion[] {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const normalizedInput = input.toLowerCase().trim();

  if (!normalizedInput || availableCommands.length === 0) {
    return [];
  }

  // Calculate distances and similarities
  const candidates: Suggestion[] = availableCommands
    .map((cmd) => {
      const normalizedCmd = cmd.toLowerCase();
      const distance = levenshtein.get(normalizedInput, normalizedCmd);
      const similarity = calculateSimilarity(normalizedInput, normalizedCmd);

      return {
        command: cmd,
        distance,
        similarity,
        description: descriptions?.get(cmd),
      };
    })
    .filter((candidate) => {
      // Filter by max distance
      if (candidate.distance > cfg.maxDistance) return false;

      // Filter by minimum similarity
      if (candidate.similarity < cfg.minSimilarity) return false;

      // Boost common prefix matches
      if (hasCommonPrefix(normalizedInput, candidate.command.toLowerCase())) {
        return true;
      }

      return true;
    });

  // Sort by distance (lower is better), then by similarity (higher is better)
  candidates.sort((a, b) => {
    // Prioritize common prefix
    const aHasPrefix = hasCommonPrefix(normalizedInput, a.command.toLowerCase());
    const bHasPrefix = hasCommonPrefix(normalizedInput, b.command.toLowerCase());
    if (aHasPrefix && !bHasPrefix) return -1;
    if (!aHasPrefix && bHasPrefix) return 1;

    // Then by distance
    if (a.distance !== b.distance) {
      return a.distance - b.distance;
    }

    // Then by similarity
    return b.similarity - a.similarity;
  });

  // Return top suggestions
  return candidates.slice(0, cfg.maxSuggestions);
}

/**
 * Formats suggestion output for display
 */
export function formatSuggestions(
  input: string,
  suggestions: Suggestion[],
  includeDescription = true,
): string {
  if (suggestions.length === 0) {
    return `Unknown command: '${input}'`;
  }

  const lines: string[] = [`Unknown command: '${input}'`, ''];

  if (suggestions.length === 1) {
    lines.push(`Did you mean this?`);
  } else {
    lines.push(`Did you mean one of these?`);
  }

  suggestions.forEach((s, index) => {
    const prefix = suggestions.length === 1 ? '  → ' : `  ${index + 1}. `;
    if (includeDescription && s.description) {
      lines.push(`${prefix}${s.command} - ${s.description}`);
    } else {
      lines.push(`${prefix}${s.command}`);
    }
  });

  return lines.join('\n');
}

/**
 * Finds suggestions for slash commands (e.g., /help, /clear)
 */
export function findSlashCommandSuggestions(
  input: string,
  availableCommands: Array<{ name: string; description?: string }>,
  config: Partial<SuggestionConfig> = {},
): Suggestion[] {
  const commands = availableCommands.map((cmd) => cmd.name);
  const descriptions = new Map(
    availableCommands
      .filter((cmd) => cmd.description)
      .map((cmd) => [cmd.name, cmd.description!]),
  );

  // Remove leading '/' if present
  const normalizedInput = input.startsWith('/') ? input.slice(1) : input;

  return findCommandSuggestions(normalizedInput, commands, descriptions, config);
}

/**
 * Finds suggestions for CLI flags/options
 */
export function findFlagSuggestions(
  input: string,
  availableFlags: string[],
  config: Partial<SuggestionConfig> = {},
): Suggestion[] {
  // Remove leading dashes
  const normalizedInput = input.replace(/^-+/, '');
  const normalizedFlags = availableFlags.map((flag) => flag.replace(/^-+/, ''));

  const suggestions = findCommandSuggestions(
    normalizedInput,
    normalizedFlags,
    undefined,
    config,
  );

  // Restore the dashes to match the input format
  const inputHasDoubleDash = input.startsWith('--');
  const inputHasDash = input.startsWith('-');

  return suggestions.map((s) => ({
    ...s,
    command: inputHasDoubleDash
      ? `--${s.command}`
      : inputHasDash
        ? `-${s.command}`
        : s.command,
  }));
}

/**
 * Finds suggestions for subcommands
 */
export function findSubcommandSuggestions(
  input: string,
  command: string,
  availableSubcommands: Array<{ name: string; description?: string }>,
  config: Partial<SuggestionConfig> = {},
): Suggestion[] {
  const commands = availableSubcommands.map((cmd) => cmd.name);
  const descriptions = new Map(
    availableSubcommands
      .filter((cmd) => cmd.description)
      .map((cmd) => [cmd.name, cmd.description!]),
  );

  return findCommandSuggestions(input, commands, descriptions, config);
}

/**
 * Checks if a command exists exactly (case-insensitive)
 */
export function commandExists(
  input: string,
  availableCommands: string[],
): boolean {
  const normalizedInput = input.toLowerCase().trim();
  return availableCommands.some(
    (cmd) => cmd.toLowerCase() === normalizedInput,
  );
}

/**
 * Gets a suggestion message for an unknown command
 */
export function getCommandSuggestionMessage(
  input: string,
  availableCommands: string[],
  descriptions?: Map<string, string>,
): string | null {
  const suggestions = findCommandSuggestions(
    input,
    availableCommands,
    descriptions,
  );

  if (suggestions.length === 0) {
    return null;
  }

  return formatSuggestions(input, suggestions, !!descriptions);
}
