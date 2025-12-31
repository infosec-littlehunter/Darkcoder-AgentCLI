/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Tool name constants to avoid circular dependencies.
 * These constants are used across multiple files and should be kept in sync
 * with the actual tool class names.
 */
export const ToolNames = {
  EDIT: 'edit',
  WRITE_FILE: 'write_file',
  READ_FILE: 'read_file',
  READ_MANY_FILES: 'read_many_files',
  GREP: 'grep_search',
  GLOB: 'glob',
  SHELL: 'run_shell_command',
  TODO_WRITE: 'todo_write',
  MEMORY: 'save_memory',
  TASK: 'task',
  EXIT_PLAN_MODE: 'exit_plan_mode',
  WEB_SEARCH: 'web_search',
  LS: 'list_directory',
  // OSINT Tools for Red Team / Bug Bounty
  WAYBACK_MACHINE: 'wayback_machine',
  CENSYS: 'censys_search',
  URLSCAN: 'urlscan',
  SECURITY_INTEL: 'security_intel',
  CIS_BENCHMARK: 'cis_benchmark',
  API_KEY_MANAGER: 'api_key_manager',
  VULN_DB: 'vuln_db',
  CUCKOO_SANDBOX: 'cuckoo_sandbox',
  VIRUSTOTAL: 'virustotal',
  YARAIFY: 'yaraify',
  HYBRID_ANALYSIS: 'hybrid_analysis',
  TOOL_VALIDATION: 'tool_validation',
} as const;

/**
 * Tool display name constants to avoid circular dependencies.
 * These constants are used across multiple files and should be kept in sync
 * with the actual tool display names.
 */
export const ToolDisplayNames = {
  EDIT: 'Edit',
  WRITE_FILE: 'WriteFile',
  READ_FILE: 'ReadFile',
  READ_MANY_FILES: 'ReadManyFiles',
  GREP: 'Grep',
  GLOB: 'Glob',
  SHELL: 'Shell',
  TODO_WRITE: 'TodoWrite',
  MEMORY: 'SaveMemory',
  TASK: 'Task',
  EXIT_PLAN_MODE: 'ExitPlanMode',
  WEB_SEARCH: 'WebSearch',
  LS: 'ListFiles',
  // OSINT Tools for Red Team / Bug Bounty
  WAYBACK_MACHINE: 'WaybackMachine',
  CENSYS: 'Censys',
  URLSCAN: 'URLScan',
  SECURITY_INTEL: 'SecurityIntel',
  CIS_BENCHMARK: 'CISBenchmark',
  API_KEY_MANAGER: 'ApiKeyManager',
  VULN_DB: 'VulnDB',
  CUCKOO_SANDBOX: 'CuckooSandbox',
  VIRUSTOTAL: 'VirusTotal',
  YARAIFY: 'YARAify',
  HYBRID_ANALYSIS: 'HybridAnalysis',
  TOOL_VALIDATION: 'ToolValidation',
} as const;

// Migration from old tool names to new tool names
// These legacy tool names were used in earlier versions and need to be supported
// for backward compatibility with existing user configurations
export const ToolNamesMigration = {
  search_file_content: ToolNames.GREP, // Legacy name from grep tool
  replace: ToolNames.EDIT, // Legacy name from edit tool
} as const;

// Migration from old tool display names to new tool display names
// These legacy display names were used before the tool naming standardization
export const ToolDisplayNamesMigration = {
  SearchFiles: ToolDisplayNames.GREP, // Old display name for Grep
  FindFiles: ToolDisplayNames.GLOB, // Old display name for Glob
  ReadFolder: ToolDisplayNames.LS, // Old display name for ListFiles
} as const;
