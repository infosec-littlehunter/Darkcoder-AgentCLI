/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * YARAify Tool for YARA Rule Scanning and Validation
 *
 * This tool provides integration with YARAify by abuse.ch for:
 * - Scanning files with 500+ curated YARA rules from YARAhub
 * - Hash lookup in malware database
 * - YARA rule validation and testing
 * - Threat intelligence enrichment
 * - Access to community YARA rule collections
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import * as fs from 'node:fs';
import FormData from 'form-data';

const YARAIFY_TIMEOUT_MS = 180000; // 3 minutes for API calls (scanning can take time)
const YARAIFY_API_BASE = 'https://yaraify-api.abuse.ch/api/v1';

/**
 * Operation types for YARAify
 */
export type YaraifyOperationType =
  | 'scan_file' // Scan file with YARAhub rules
  | 'lookup_hash' // Lookup hash in database
  | 'lookup_yara' // Get files matching YARA rule
  | 'lookup_task' // Check scan task status
  | 'get_yarahub' // Get YARAhub rule collections
  | 'get_clamav'; // Get ClamAV signatures

/**
 * Parameters for the YARAify tool
 */
export interface YaraifyToolParams {
  operation: YaraifyOperationType;
  filePath?: string; // File to scan
  hash?: string; // MD5, SHA1, SHA256, or SHA3-384 hash
  yaraRule?: string; // YARA rule name to search
  taskId?: string; // Task ID for status check
  shareFile?: boolean; // Share file with community (default: false)
  clamav?: boolean; // Include ClamAV scan (default: false)
}

/**
 * YARAify API response structures
 */
interface YaraifyScanResponse {
  query_status: string;
  data?: {
    task_id: string;
    sha256_hash: string;
  };
}

interface YaraifyLookupResponse {
  query_status: string;
  data?: Array<{
    sha256_hash: string;
    file_name: string;
    file_size: number;
    file_type: string;
    file_type_mime: string;
    first_seen: string;
    last_seen: string;
    yara_rules: {
      [ruleName: string]: {
        rule_name: string;
        author: string;
        description: string;
        reference: string;
      };
    };
    clamav: string[];
  }>;
}

interface YaraifyTaskResponse {
  query_status: string;
  data?: {
    task_id: string;
    status: string;
    sha256_hash?: string;
    file_name?: string;
    file_size?: number;
    file_type?: string;
    file_type_mime?: string;
    yara_rules?: {
      [ruleName: string]: {
        rule_name: string;
        author: string;
        description: string;
        reference: string;
      };
    };
    clamav?: string[];
  };
}

interface YaraifyYaraLookupResponse {
  query_status: string;
  data?: Array<{
    sha256_hash: string;
    file_name: string;
    file_size: number;
    first_seen: string;
    last_seen: string;
  }>;
}

/**
 * Fetch with timeout helper
 */
async function fetchWithAbort(
  url: string,
  options: RequestInit,
  timeout: number,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Implementation of the YARAify tool invocation logic
 */
class YaraifyToolInvocation extends BaseToolInvocation<
  YaraifyToolParams,
  ToolResult
> {
  private readonly config: Config;

  constructor(config: Config, params: YaraifyToolParams) {
    super(params);
    this.config = config;
  }

  getDescription(): string {
    const { operation, filePath, hash, yaraRule, taskId } = this.params;
    switch (operation) {
      case 'scan_file':
        return `Scanning file with YARAify: ${filePath}`;
      case 'lookup_hash':
        return `Looking up hash in YARAify: ${hash}`;
      case 'lookup_yara':
        return `Searching for files matching YARA rule: ${yaraRule}`;
      case 'lookup_task':
        return `Checking YARAify task status: ${taskId}`;
      case 'get_yarahub':
        return `Getting YARAhub rule collections`;
      case 'get_clamav':
        return `Getting ClamAV signatures from YARAify`;
      default:
        return `Querying YARAify`;
    }
  }

  private getApiKey(): string | undefined {
    return this.config.getYaraifyApiKey?.() || process.env['YARAIFY_API_KEY'];
  }

  private getHeaders(): Record<string, string> {
    const apiKey = this.getApiKey();
    if (!apiKey) {
      throw new Error(
        'YARAify API key is required. Set YARAIFY_API_KEY environment variable or configure in settings.',
      );
    }

    return {
      'Auth-Key': apiKey,
      Accept: 'application/json',
    };
  }

  async execute(): Promise<ToolResult> {
    const { operation } = this.params;

    try {
      switch (operation) {
        case 'scan_file':
          return await this.scanFile();
        case 'lookup_hash':
          return await this.lookupHash();
        case 'lookup_yara':
          return await this.lookupYara();
        case 'lookup_task':
          return await this.lookupTask();
        case 'get_yarahub':
          return await this.getYarahub();
        case 'get_clamav':
          return await this.getClamAV();
        default:
          return {
            llmContent: `Error: Unknown operation: ${operation}`,
            returnDisplay: `Unknown operation: ${operation}`,
            error: {
              message: `Unknown operation: ${operation}`,
              type: ToolErrorType.INVALID_TOOL_PARAMS,
            },
          };
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return {
        llmContent: `Error: YARAify operation failed: ${errorMessage}`,
        returnDisplay: `YARAify operation failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Scan a file with YARAhub rules
   */
  private async scanFile(): Promise<ToolResult> {
    const { filePath, shareFile, clamav } = this.params;

    if (!filePath) {
      return {
        llmContent: 'Error: File path is required for file scanning',
        returnDisplay: 'File path is required',
        error: {
          message: 'File path is required for file scanning',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return {
        llmContent: `Error: File not found: ${filePath}`,
        returnDisplay: `File not found: ${filePath}`,
        error: {
          message: `File not found: ${filePath}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const url = `${YARAIFY_API_BASE}/scan/file`;

    // Create form data
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));
    if (shareFile !== undefined)
      form.append('share_file', shareFile ? '1' : '0');
    if (clamav !== undefined) form.append('clamav_scan', clamav ? '1' : '0');

    const response = await fetchWithAbort(
      url,
      {
        method: 'POST',
        headers: {
          ...this.getHeaders(),
          ...form.getHeaders(),
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        body: form as any,
      },
      YARAIFY_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `YARAify API returned status ${response.status}: ${errorText}`,
      );
    }

    const data = (await response.json()) as YaraifyScanResponse;

    if (data.query_status !== 'ok' || !data.data) {
      return {
        llmContent: `YARAify scan failed: ${data.query_status}`,
        returnDisplay: `Scan failed: ${data.query_status}`,
        error: {
          message: `Scan failed: ${data.query_status}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const summary = [
      `## YARAify - File Scan Submitted`,
      '',
      `**File:** ${filePath}`,
      `**Task ID:** ${data.data.task_id}`,
      `**SHA256:** ${data.data.sha256_hash}`,
      `**Status:** Scanning with YARAhub rules...`,
      '',
      `### Next Steps`,
      `1. Wait for scan to complete (typically 30-60 seconds)`,
      `2. Check status: \`operation: "lookup_task", taskId: "${data.data.task_id}"\``,
      `3. Or lookup results: \`operation: "lookup_hash", hash: "${data.data.sha256_hash}"\``,
      '',
      `> 💡 **Tip:** Scan results are usually available within 1 minute.`,
      shareFile
        ? `> 🌐 **Shared:** This file will be available to the YARAify community.`
        : `> 🔒 **Private:** This file is NOT shared with the community.`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Lookup a hash in YARAify database
   */
  private async lookupHash(): Promise<ToolResult> {
    const { hash } = this.params;

    if (!hash) {
      return {
        llmContent: 'Error: Hash is required for lookup',
        returnDisplay: 'Hash is required',
        error: {
          message: 'Hash is required for lookup',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${YARAIFY_API_BASE}/lookup/hash/`;

    const form = new FormData();
    form.append('query', hash);

    const response = await fetchWithAbort(
      url,
      {
        method: 'POST',
        headers: {
          ...this.getHeaders(),
          ...form.getHeaders(),
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        body: form as any,
      },
      YARAIFY_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `YARAify API returned status ${response.status}: ${errorText}`,
      );
    }

    const data = (await response.json()) as YaraifyLookupResponse;

    if (data.query_status === 'hash_not_found') {
      return {
        llmContent: `## YARAify - Hash Not Found\n\n**Hash:** ${hash}\n\n**Status:** This hash is not in the YARAify database.\n\n> 💡 **Tip:** You can submit the file for scanning with \`operation: "scan_file"\``,
        returnDisplay: `Hash not found in YARAify database: ${hash}`,
      };
    }

    if (data.query_status !== 'ok' || !data.data || data.data.length === 0) {
      return {
        llmContent: `YARAify lookup failed: ${data.query_status}`,
        returnDisplay: `Lookup failed: ${data.query_status}`,
        error: {
          message: `Lookup failed: ${data.query_status}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    // Format results
    const results = data.data.map((result) => {
      const yaraRuleCount = Object.keys(result.yara_rules || {}).length;
      const clamavCount = result.clamav?.length || 0;

      const yaraRules = Object.values(result.yara_rules || {})
        .map(
          (rule) =>
            `  - **${rule.rule_name}**\n    - Author: ${rule.author}\n    - Description: ${rule.description}${rule.reference ? `\n    - Reference: ${rule.reference}` : ''}`,
        )
        .join('\n');

      const clamavSigs =
        clamavCount > 0
          ? `\n\n### ClamAV Signatures (${clamavCount})\n${result.clamav?.map((sig) => `  - ${sig}`).join('\n')}`
          : '';

      return [
        `## YARAify - Hash Lookup Results`,
        '',
        `**Hash:** ${result.sha256_hash}`,
        `**File Name:** ${result.file_name}`,
        `**File Size:** ${result.file_size} bytes`,
        `**File Type:** ${result.file_type} (${result.file_type_mime})`,
        `**First Seen:** ${result.first_seen}`,
        `**Last Seen:** ${result.last_seen}`,
        '',
        `### YARA Rules Matched (${yaraRuleCount})`,
        yaraRules,
        clamavSigs,
        '',
        `> 🎯 **Threat Intelligence:** This file matches ${yaraRuleCount} YARA rule(s)${clamavCount > 0 ? ` and ${clamavCount} ClamAV signature(s)` : ''}.`,
      ]
        .filter(Boolean)
        .join('\n');
    });

    return {
      llmContent: results.join('\n\n---\n\n'),
      returnDisplay: results.join('\n\n---\n\n'),
    };
  }

  /**
   * Lookup files matching a YARA rule
   */
  private async lookupYara(): Promise<ToolResult> {
    const { yaraRule } = this.params;

    if (!yaraRule) {
      return {
        llmContent: 'Error: YARA rule name is required',
        returnDisplay: 'YARA rule name is required',
        error: {
          message: 'YARA rule name is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${YARAIFY_API_BASE}/lookup/yara/`;

    const form = new FormData();
    form.append('query', yaraRule);

    const response = await fetchWithAbort(
      url,
      {
        method: 'POST',
        headers: {
          ...this.getHeaders(),
          ...form.getHeaders(),
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        body: form as any,
      },
      YARAIFY_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `YARAify API returned status ${response.status}: ${errorText}`,
      );
    }

    const data = (await response.json()) as YaraifyYaraLookupResponse;

    if (data.query_status === 'yara_rule_not_found') {
      return {
        llmContent: `## YARAify - YARA Rule Not Found\n\n**Rule:** ${yaraRule}\n\n**Status:** This YARA rule has no matches in the database.`,
        returnDisplay: `YARA rule not found: ${yaraRule}`,
      };
    }

    if (data.query_status !== 'ok' || !data.data || data.data.length === 0) {
      return {
        llmContent: `YARAify YARA lookup failed: ${data.query_status}`,
        returnDisplay: `YARA lookup failed: ${data.query_status}`,
        error: {
          message: `YARA lookup failed: ${data.query_status}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const fileCount = data.data.length;
    const fileList = data.data
      .slice(0, 20) // Limit to first 20
      .map(
        (file, idx) =>
          `${idx + 1}. **${file.file_name}** (${file.file_size} bytes)\n   - SHA256: \`${file.sha256_hash}\`\n   - First Seen: ${file.first_seen}\n   - Last Seen: ${file.last_seen}`,
      )
      .join('\n\n');

    const summary = [
      `## YARAify - Files Matching YARA Rule`,
      '',
      `**YARA Rule:** ${yaraRule}`,
      `**Total Matches:** ${fileCount} file(s)`,
      '',
      `### Sample Files ${fileCount > 20 ? '(First 20)' : ''}`,
      fileList,
      '',
      fileCount > 20
        ? `> ⚠️ **Note:** Showing first 20 of ${fileCount} total matches.`
        : '',
      `> 💡 **Tip:** Use \`operation: "lookup_hash"\` to get details on any file.`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Check scan task status
   */
  private async lookupTask(): Promise<ToolResult> {
    const { taskId } = this.params;

    if (!taskId) {
      return {
        llmContent: 'Error: Task ID is required',
        returnDisplay: 'Task ID is required',
        error: {
          message: 'Task ID is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${YARAIFY_API_BASE}/lookup/task/`;

    const form = new FormData();
    form.append('query', taskId);

    const response = await fetchWithAbort(
      url,
      {
        method: 'POST',
        headers: {
          ...this.getHeaders(),
          ...form.getHeaders(),
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        body: form as any,
      },
      YARAIFY_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `YARAify API returned status ${response.status}: ${errorText}`,
      );
    }

    const data = (await response.json()) as YaraifyTaskResponse;

    if (data.query_status === 'task_not_found') {
      return {
        llmContent: `## YARAify - Task Not Found\n\n**Task ID:** ${taskId}\n\n**Status:** This task ID is not found in the database.`,
        returnDisplay: `Task not found: ${taskId}`,
      };
    }

    if (data.query_status !== 'ok' || !data.data) {
      return {
        llmContent: `YARAify task lookup failed: ${data.query_status}`,
        returnDisplay: `Task lookup failed: ${data.query_status}`,
        error: {
          message: `Task lookup failed: ${data.query_status}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const task = data.data;

    if (task.status === 'processing') {
      return {
        llmContent: `## YARAify - Scan In Progress\n\n**Task ID:** ${taskId}\n**Status:** Processing...\n\n> ⏳ Please wait and check again in a few moments.`,
        returnDisplay: `Scan still processing: ${taskId}`,
      };
    }

    // Scan completed
    const yaraRuleCount = Object.keys(task.yara_rules || {}).length;
    const clamavCount = task.clamav?.length || 0;

    const yaraRules =
      yaraRuleCount > 0
        ? `\n\n### YARA Rules Matched (${yaraRuleCount})\n${Object.values(
            task.yara_rules || {},
          )
            .map(
              (rule) =>
                `  - **${rule.rule_name}**\n    - Author: ${rule.author}\n    - Description: ${rule.description}${rule.reference ? `\n    - Reference: ${rule.reference}` : ''}`,
            )
            .join('\n')}`
        : '\n\n### YARA Rules Matched\n  ✅ No YARA rules matched (file appears clean)';

    const clamavSigs =
      clamavCount > 0
        ? `\n\n### ClamAV Signatures (${clamavCount})\n${task.clamav?.map((sig) => `  - ${sig}`).join('\n')}`
        : '';

    const summary = [
      `## YARAify - Scan Results`,
      '',
      `**Task ID:** ${task.task_id}`,
      `**Status:** ${task.status}`,
      `**SHA256:** ${task.sha256_hash}`,
      task.file_name ? `**File Name:** ${task.file_name}` : '',
      task.file_size ? `**File Size:** ${task.file_size} bytes` : '',
      task.file_type
        ? `**File Type:** ${task.file_type} (${task.file_type_mime})`
        : '',
      yaraRules,
      clamavSigs,
      '',
      yaraRuleCount > 0 || clamavCount > 0
        ? `> ⚠️ **Threat Detected:** This file matches ${yaraRuleCount} YARA rule(s)${clamavCount > 0 ? ` and ${clamavCount} ClamAV signature(s)` : ''}.`
        : `> ✅ **Clean:** No malware signatures detected.`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get YARAhub rule collections
   */
  private async getYarahub(): Promise<ToolResult> {
    const url = `${YARAIFY_API_BASE}/yarahub/ruleset-index/`;

    const response = await fetchWithAbort(
      url,
      {
        method: 'GET',
        headers: this.getHeaders(),
      },
      YARAIFY_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `YARAify API returned status ${response.status}: ${errorText}`,
      );
    }

    const text = await response.text();

    const summary = [
      `## YARAify - YARAhub Rule Collections`,
      '',
      `**Status:** Successfully retrieved YARAhub index`,
      '',
      `### Available Rule Collections`,
      text.split('\n').slice(0, 50).join('\n'), // Show first 50 lines
      '',
      `> 💡 **Tip:** Download full collections from https://yaraify.abuse.ch/yarahub/`,
      `> 📚 **Documentation:** https://yaraify.abuse.ch/api/`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get ClamAV signatures
   */
  private async getClamAV(): Promise<ToolResult> {
    const url = `${YARAIFY_API_BASE}/clamav/`;

    const response = await fetchWithAbort(
      url,
      {
        method: 'GET',
        headers: this.getHeaders(),
      },
      YARAIFY_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `YARAify API returned status ${response.status}: ${errorText}`,
      );
    }

    const text = await response.text();
    const lineCount = text.split('\n').length;

    const summary = [
      `## YARAify - ClamAV Signatures`,
      '',
      `**Status:** Successfully retrieved ClamAV signatures`,
      `**Total Lines:** ${lineCount}`,
      '',
      `### Sample Signatures (First 30 lines)`,
      '```',
      text.split('\n').slice(0, 30).join('\n'),
      '```',
      '',
      `> 💡 **Tip:** Download full signatures from https://yaraify-api.abuse.ch/api/v1/clamav/`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }
}

/**
 * YARAify tool declaration
 */
export class YaraifyTool extends BaseDeclarativeTool<
  YaraifyToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.YARAIFY;
  private readonly config: Config;

  constructor(config: Config) {
    super(
      YaraifyTool.Name,
      ToolDisplayNames.YARAIFY,
      `Scan files with 500+ curated YARA rules from YARAhub, lookup hashes in malware database, and validate YARA rules. Provides threat intelligence from abuse.ch:
- File scanning with YARAhub rule collections
- Hash lookup for known malware
- YARA rule validation and testing
- ClamAV signature integration
- Threat intelligence enrichment
- Community malware database access

Requires free API key from https://auth.abuse.ch/
Configure via settings.json (yaraifyApiKey) or YARAIFY_API_KEY environment variable.`,
      Kind.Fetch,
      {
        properties: {
          operation: {
            type: 'string',
            enum: [
              'scan_file',
              'lookup_hash',
              'lookup_yara',
              'lookup_task',
              'get_yarahub',
              'get_clamav',
            ],
            description:
              'Operation to perform: scan_file (scan with YARAhub rules), lookup_hash (check hash in database), lookup_yara (find files matching YARA rule), lookup_task (check scan status), get_yarahub (get rule collections), get_clamav (get ClamAV signatures)',
          },
          filePath: {
            type: 'string',
            description:
              'Path to file for scanning (required for scan_file operation)',
          },
          hash: {
            type: 'string',
            description:
              'MD5, SHA1, SHA256, or SHA3-384 hash to lookup (required for lookup_hash operation)',
          },
          yaraRule: {
            type: 'string',
            description:
              'YARA rule name to search for matching files (required for lookup_yara operation)',
          },
          taskId: {
            type: 'string',
            description:
              'Task ID to check status (required for lookup_task operation)',
          },
          shareFile: {
            type: 'boolean',
            description:
              'Share file with YARAify community (default: false, only for scan_file)',
          },
          clamav: {
            type: 'boolean',
            description:
              'Include ClamAV scan (default: false, only for scan_file)',
          },
        },
        required: ['operation'],
        type: 'object',
      },
    );
    this.config = config;
  }

  protected createInvocation(
    params: YaraifyToolParams,
  ): ToolInvocation<YaraifyToolParams, ToolResult> {
    return new YaraifyToolInvocation(this.config, params);
  }
}
