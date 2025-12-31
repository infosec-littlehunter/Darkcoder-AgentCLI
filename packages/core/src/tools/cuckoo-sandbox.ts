/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Cuckoo Sandbox Tool for Malware Analysis
 *
 * This tool provides integration with self-hosted Cuckoo Sandbox for:
 * - Automated malware analysis
 * - Behavioral analysis (processes, network, registry, files)
 * - YARA signature matching
 * - Network traffic capture and analysis
 * - Screenshot and memory dumps
 * - Threat intelligence and IOC extraction
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import * as fs from 'node:fs';
import FormData from 'form-data';

const CUCKOO_TIMEOUT_MS = 120000; // 2 minutes for API calls
const DEFAULT_CUCKOO_URL = 'http://localhost:8090';

/**
 * Operation types for Cuckoo Sandbox
 */
export type CuckooOperationType =
  | 'submit_file'
  | 'submit_url'
  | 'get_status'
  | 'get_report'
  | 'get_summary'
  | 'list_machines'
  | 'cuckoo_status';

/**
 * Parameters for the Cuckoo Sandbox tool
 */
export interface CuckooSandboxToolParams {
  operation: CuckooOperationType;
  filePath?: string;
  url?: string;
  taskId?: number;
  package?: string; // Analysis package (e.g., exe, dll, pdf, doc)
  timeout?: number; // Analysis timeout in seconds
  priority?: number; // Task priority (1-3)
  options?: string; // Custom options for analysis
  machine?: string; // Specific VM to use
  platform?: string; // OS platform (windows, linux)
  memory?: boolean; // Enable memory dump
  enforce_timeout?: boolean;
  tags?: string; // Comma-separated tags
}

/**
 * Cuckoo API response structures
 */
interface CuckooTaskResponse {
  task_id: number;
  task_ids?: number[];
}

interface CuckooTaskStatus {
  task: {
    id: number;
    status: string;
    target: string;
    category: string;
    added_on: string;
    started_on?: string;
    completed_on?: string;
    priority: number;
  };
}

interface CuckooReport {
  info: {
    id: number;
    category: string;
    started: string;
    ended: string;
    duration: number;
    score: number;
  };
  signatures: Array<{
    name: string;
    description: string;
    severity: number;
    marks: Array<{
      type: string;
      category: string;
    }>;
  }>;
  target: {
    file?: {
      name: string;
      size: number;
      md5: string;
      sha1: string;
      sha256: string;
      ssdeep: string;
      type: string;
    };
    url?: string;
  };
  behavior?: {
    processes: Array<{
      process_name: string;
      pid: number;
      ppid: number;
      command_line: string;
    }>;
    summary: {
      files?: string[];
      keys?: string[];
      mutexes?: string[];
    };
  };
  network?: {
    domains: Array<{
      domain: string;
      ip: string;
    }>;
    hosts: string[];
    http: Array<{
      uri: string;
      method: string;
      host: string;
    }>;
    dns: Array<{
      request: string;
      type: string;
      answers: Array<{
        data: string;
      }>;
    }>;
  };
  dropped?: Array<{
    name: string;
    path: string;
    size: number;
    md5: string;
    sha256: string;
    type: string;
  }>;
  malscore?: number;
}

interface CuckooMachine {
  name: string;
  label: string;
  platform: string;
  status: string;
  locked: boolean;
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
 * Implementation of the Cuckoo Sandbox tool invocation logic
 */
class CuckooSandboxToolInvocation extends BaseToolInvocation<
  CuckooSandboxToolParams,
  ToolResult
> {
  private readonly config: Config;

  constructor(config: Config, params: CuckooSandboxToolParams) {
    super(params);
    this.config = config;
  }

  getDescription(): string {
    const { operation, filePath, url, taskId } = this.params;
    switch (operation) {
      case 'submit_file':
        return `Submitting file to Cuckoo Sandbox: ${filePath}`;
      case 'submit_url':
        return `Submitting URL to Cuckoo Sandbox: ${url}`;
      case 'get_status':
        return `Getting Cuckoo task status: ${taskId}`;
      case 'get_report':
        return `Getting Cuckoo analysis report: ${taskId}`;
      case 'get_summary':
        return `Getting Cuckoo analysis summary: ${taskId}`;
      case 'list_machines':
        return `Listing Cuckoo sandbox machines`;
      case 'cuckoo_status':
        return `Checking Cuckoo sandbox status`;
      default:
        return `Querying Cuckoo Sandbox`;
    }
  }

  private getCuckooConfig(): { url: string; token?: string } {
    const url =
      this.config.getCuckooApiUrl?.() ||
      process.env['CUCKOO_API_URL'] ||
      DEFAULT_CUCKOO_URL;

    const token =
      this.config.getCuckooApiToken?.() || process.env['CUCKOO_API_TOKEN'];

    return { url, token };
  }

  private getHeaders(): Record<string, string> {
    const { token } = this.getCuckooConfig();
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    return headers;
  }

  async execute(): Promise<ToolResult> {
    const { operation } = this.params;

    try {
      switch (operation) {
        case 'submit_file':
          return await this.submitFile();
        case 'submit_url':
          return await this.submitUrl();
        case 'get_status':
          return await this.getTaskStatus();
        case 'get_report':
          return await this.getReport();
        case 'get_summary':
          return await this.getSummary();
        case 'list_machines':
          return await this.listMachines();
        case 'cuckoo_status':
          return await this.getCuckooStatus();
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
        llmContent: `Error: Cuckoo Sandbox operation failed: ${errorMessage}`,
        returnDisplay: `Cuckoo operation failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Submit a file for analysis
   */
  private async submitFile(): Promise<ToolResult> {
    const {
      filePath,
      package: pkg,
      timeout,
      priority,
      options,
      machine,
      platform,
      memory,
      enforce_timeout,
      tags,
    } = this.params;

    if (!filePath) {
      return {
        llmContent: 'Error: File path is required for file submission',
        returnDisplay: 'File path is required',
        error: {
          message: 'File path is required for file submission',
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

    const { url: baseUrl } = this.getCuckooConfig();
    const url = `${baseUrl}/tasks/create/file`;

    // Create form data
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));

    if (pkg) form.append('package', pkg);
    if (timeout) form.append('timeout', timeout.toString());
    if (priority) form.append('priority', priority.toString());
    if (options) form.append('options', options);
    if (machine) form.append('machine', machine);
    if (platform) form.append('platform', platform);
    if (memory !== undefined) form.append('memory', memory.toString());
    if (enforce_timeout !== undefined)
      form.append('enforce_timeout', enforce_timeout.toString());
    if (tags) form.append('tags', tags);

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
      CUCKOO_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `Cuckoo API returned status ${response.status}: ${errorText}`,
      );
    }

    const data = (await response.json()) as CuckooTaskResponse;

    const summary = [
      `## Cuckoo Sandbox - File Submitted`,
      '',
      `**File:** ${filePath}`,
      `**Task ID:** ${data.task_id}`,
      `**Status:** Pending analysis`,
      '',
      `### Analysis Configuration`,
      pkg ? `- **Package:** ${pkg}` : '',
      timeout ? `- **Timeout:** ${timeout}s` : '',
      priority ? `- **Priority:** ${priority}` : '',
      machine ? `- **Machine:** ${machine}` : '',
      platform ? `- **Platform:** ${platform}` : '',
      memory ? `- **Memory Dump:** Enabled` : '',
      '',
      `### Next Steps`,
      `1. Wait for analysis to complete (typically 2-5 minutes)`,
      `2. Check status: \`operation: "get_status", taskId: ${data.task_id}\``,
      `3. Get report: \`operation: "get_report", taskId: ${data.task_id}\``,
      '',
      `> 💡 **Tip:** Analysis typically takes 2-5 minutes depending on file complexity.`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Submit a URL for analysis
   */
  private async submitUrl(): Promise<ToolResult> {
    const {
      url: targetUrl,
      priority,
      options,
      machine,
      platform,
      timeout,
      tags,
    } = this.params;

    if (!targetUrl) {
      return {
        llmContent: 'Error: URL is required for URL submission',
        returnDisplay: 'URL is required',
        error: {
          message: 'URL is required for URL submission',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const { url: baseUrl } = this.getCuckooConfig();
    const url = `${baseUrl}/tasks/create/url`;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: Record<string, any> = { url: targetUrl };
    if (priority) body['priority'] = priority;
    if (options) body['options'] = options;
    if (machine) body['machine'] = machine;
    if (platform) body['platform'] = platform;
    if (timeout) body['timeout'] = timeout;
    if (tags) body['tags'] = tags;

    const response = await fetchWithAbort(
      url,
      {
        method: 'POST',
        headers: {
          ...this.getHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      },
      CUCKOO_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `Cuckoo API returned status ${response.status}: ${errorText}`,
      );
    }

    const data = (await response.json()) as CuckooTaskResponse;

    const summary = [
      `## Cuckoo Sandbox - URL Submitted`,
      '',
      `**URL:** ${targetUrl}`,
      `**Task ID:** ${data.task_id}`,
      `**Status:** Pending analysis`,
      '',
      `### Next Steps`,
      `Check status: \`operation: "get_status", taskId: ${data.task_id}\``,
    ].join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get task status
   */
  private async getTaskStatus(): Promise<ToolResult> {
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

    const { url: baseUrl } = this.getCuckooConfig();
    const url = `${baseUrl}/tasks/view/${taskId}`;

    const response = await fetchWithAbort(
      url,
      { headers: this.getHeaders() },
      CUCKOO_TIMEOUT_MS,
    );

    if (!response.ok) {
      throw new Error(`Cuckoo API returned status ${response.status}`);
    }

    const data = (await response.json()) as CuckooTaskStatus;
    const task = data.task;

    const statusEmoji =
      task.status === 'completed'
        ? '✅'
        : task.status === 'running'
          ? '⏳'
          : task.status === 'pending'
            ? '🕐'
            : '❌';

    const summary = [
      `## Cuckoo Task Status`,
      '',
      `**Task ID:** ${task.id}`,
      `**Status:** ${statusEmoji} ${task.status.toUpperCase()}`,
      `**Target:** ${task.target}`,
      `**Category:** ${task.category}`,
      `**Priority:** ${task.priority}`,
      '',
      `### Timeline`,
      `- **Added:** ${task.added_on}`,
      task.started_on ? `- **Started:** ${task.started_on}` : '',
      task.completed_on ? `- **Completed:** ${task.completed_on}` : '',
      '',
      task.status === 'completed'
        ? `### 📊 Analysis Complete!`
        : task.status === 'running'
          ? `### ⏳ Analysis in Progress...`
          : `### 🕐 Waiting in Queue...`,
      '',
      task.status === 'completed'
        ? `Get full report: \`operation: "get_report", taskId: ${task.id}\``
        : `Check back in a few minutes.`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get full analysis report
   */
  private async getReport(): Promise<ToolResult> {
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

    const { url: baseUrl } = this.getCuckooConfig();
    const url = `${baseUrl}/tasks/report/${taskId}/json`;

    const response = await fetchWithAbort(
      url,
      { headers: this.getHeaders() },
      CUCKOO_TIMEOUT_MS,
    );

    if (response.status === 404) {
      return {
        llmContent: `Analysis not yet complete for task ${taskId}. Please check status first.`,
        returnDisplay: `Analysis not yet complete for task ${taskId}`,
        error: {
          message: 'Analysis not yet complete',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    if (!response.ok) {
      throw new Error(`Cuckoo API returned status ${response.status}`);
    }

    const report = (await response.json()) as CuckooReport;

    const summary = this.formatReport(report);

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get analysis summary
   */
  private async getSummary(): Promise<ToolResult> {
    return await this.getReport(); // Reuse getReport but could be customized
  }

  /**
   * List available machines
   */
  private async listMachines(): Promise<ToolResult> {
    const { url: baseUrl } = this.getCuckooConfig();
    const url = `${baseUrl}/machines/list`;

    const response = await fetchWithAbort(
      url,
      { headers: this.getHeaders() },
      CUCKOO_TIMEOUT_MS,
    );

    if (!response.ok) {
      throw new Error(`Cuckoo API returned status ${response.status}`);
    }

    const data = (await response.json()) as { machines: CuckooMachine[] };

    const summary = [
      `## Cuckoo Sandbox Machines`,
      '',
      `**Total Machines:** ${data.machines.length}`,
      '',
      ...data.machines.map(
        (m) =>
          `### ${m.label}\n- **Name:** ${m.name}\n- **Platform:** ${m.platform}\n- **Status:** ${m.locked ? '🔒 Locked' : '✅ Available'}\n`,
      ),
    ].join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get Cuckoo status
   */
  private async getCuckooStatus(): Promise<ToolResult> {
    const { url: baseUrl } = this.getCuckooConfig();
    const url = `${baseUrl}/cuckoo/status`;

    const response = await fetchWithAbort(
      url,
      { headers: this.getHeaders() },
      CUCKOO_TIMEOUT_MS,
    );

    if (!response.ok) {
      return {
        llmContent: `Cuckoo Sandbox is not responding. Is it running?\n\nExpected URL: ${baseUrl}`,
        returnDisplay: `Cuckoo Sandbox is not responding`,
        error: {
          message: `Cuckoo Sandbox is not responding at ${baseUrl}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const data = await response.json();

    const summary = [
      `## ✅ Cuckoo Sandbox Status`,
      '',
      `**Status:** Online`,
      `**API URL:** ${baseUrl}`,
      `**Version:** ${data.version || 'Unknown'}`,
      '',
      `### Capacity`,
      `- **Tasks:** ${data.tasks?.total || 0} total, ${data.tasks?.pending || 0} pending`,
      `- **Machines:** ${data.machines?.total || 0} total, ${data.machines?.available || 0} available`,
      '',
      `> ✅ Cuckoo Sandbox is operational and ready for analysis.`,
    ].join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Format analysis report
   */
  private formatReport(report: CuckooReport): string {
    const summary: string[] = [
      `## 🔍 Cuckoo Sandbox Analysis Report`,
      '',
      `**Task ID:** ${report.info.id}`,
      `**Malware Score:** ${report.malscore || report.info.score}/10`,
      `**Duration:** ${report.info.duration}s`,
      `**Analyzed:** ${report.info.started} - ${report.info.ended}`,
      '',
    ];

    // Target information
    if (report.target.file) {
      const file = report.target.file;
      summary.push(`### 📁 Target File`);
      summary.push(`- **Name:** ${file.name}`);
      summary.push(`- **Type:** ${file.type}`);
      summary.push(`- **Size:** ${(file.size / 1024).toFixed(2)} KB`);
      summary.push(`- **MD5:** ${file.md5}`);
      summary.push(`- **SHA256:** ${file.sha256}`);
      summary.push('');
    }

    // Signatures (Detections)
    if (report.signatures && report.signatures.length > 0) {
      summary.push(`### 🚨 Detections (${report.signatures.length})`);
      summary.push('');
      for (const sig of report.signatures.slice(0, 10)) {
        const severityEmoji =
          sig.severity >= 3 ? '🔴' : sig.severity >= 2 ? '🟠' : '🟡';
        summary.push(`#### ${severityEmoji} ${sig.name}`);
        summary.push(`${sig.description}`);
        summary.push('');
      }
      if (report.signatures.length > 10) {
        summary.push(
          `_...and ${report.signatures.length - 10} more detections_`,
        );
        summary.push('');
      }
    }

    // Behavior
    if (report.behavior?.processes) {
      summary.push(`### 💻 Process Behavior`);
      summary.push('');
      for (const proc of report.behavior.processes.slice(0, 10)) {
        summary.push(`- **${proc.process_name}** (PID: ${proc.pid})`);
        if (proc.command_line) {
          summary.push(`  \`${proc.command_line}\``);
        }
      }
      summary.push('');
    }

    // Network activity
    if (report.network) {
      if (report.network.domains && report.network.domains.length > 0) {
        summary.push(`### 🌐 Network Activity`);
        summary.push('');
        summary.push(
          `**Contacted Domains (${report.network.domains.length}):**`,
        );
        for (const domain of report.network.domains.slice(0, 10)) {
          summary.push(`- ${domain.domain} → ${domain.ip}`);
        }
        if (report.network.domains.length > 10) {
          summary.push(
            `_...and ${report.network.domains.length - 10} more domains_`,
          );
        }
        summary.push('');
      }

      if (report.network.http && report.network.http.length > 0) {
        summary.push(`**HTTP Requests (${report.network.http.length}):**`);
        for (const http of report.network.http.slice(0, 5)) {
          summary.push(`- ${http.method} ${http.host}${http.uri}`);
        }
        summary.push('');
      }
    }

    // Dropped files
    if (report.dropped && report.dropped.length > 0) {
      summary.push(`### 📂 Dropped Files (${report.dropped.length})`);
      summary.push('');
      for (const file of report.dropped.slice(0, 5)) {
        summary.push(`- **${file.name}**`);
        summary.push(`  - Type: ${file.type}`);
        summary.push(`  - SHA256: ${file.sha256}`);
      }
      summary.push('');
    }

    // Summary
    if (report.behavior?.summary) {
      const summ = report.behavior.summary;
      summary.push(`### 📊 Behavior Summary`);
      if (summ.files?.length) {
        summary.push(`- **Files Modified:** ${summ.files.length}`);
      }
      if (summ.keys?.length) {
        summary.push(`- **Registry Keys:** ${summ.keys.length}`);
      }
      if (summ.mutexes?.length) {
        summary.push(`- **Mutexes:** ${summ.mutexes.length}`);
      }
      summary.push('');
    }

    // Verdict
    const score = report.malscore || report.info.score;
    summary.push(`### 🎯 Verdict`);
    if (score >= 7) {
      summary.push(`**🔴 MALICIOUS** (Score: ${score}/10)`);
      summary.push('This file exhibits highly suspicious behavior.');
    } else if (score >= 4) {
      summary.push(`**🟠 SUSPICIOUS** (Score: ${score}/10)`);
      summary.push('This file shows potentially malicious behavior.');
    } else {
      summary.push(`**🟢 LOW RISK** (Score: ${score}/10)`);
      summary.push('This file shows minimal suspicious behavior.');
    }

    return summary.join('\n');
  }
}

/**
 * Cuckoo Sandbox Tool for malware analysis
 */
export class CuckooSandboxTool extends BaseDeclarativeTool<
  CuckooSandboxToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.CUCKOO_SANDBOX;
  private readonly config: Config;

  constructor(config: Config) {
    super(
      CuckooSandboxTool.Name,
      ToolDisplayNames.CUCKOO_SANDBOX,
      `Analyze suspicious files and URLs using self-hosted Cuckoo Sandbox. Provides automated malware analysis including:
- Behavioral analysis (processes, network, registry, files)
- Memory dumps and screenshots
- YARA signature matching
- Network traffic capture and IOC extraction
- Dropped files analysis
- Threat scoring and verdict

Requires Cuckoo Sandbox installation (see docker/cuckoo/README.md).
Configure via settings.json (advanced.cuckooApiUrl) or CUCKOO_API_URL environment variable.`,
      Kind.Fetch,
      {
        properties: {
          operation: {
            type: 'string',
            enum: [
              'submit_file',
              'submit_url',
              'get_status',
              'get_report',
              'get_summary',
              'list_machines',
              'cuckoo_status',
            ],
            description:
              'Operation: "submit_file" to analyze file, "submit_url" for URL, "get_status" to check task, "get_report" for full report, "get_summary" for quick summary, "list_machines" to show VMs, "cuckoo_status" to check if Cuckoo is online',
          },
          filePath: {
            type: 'string',
            description:
              'Path to file for analysis (for submit_file operation)',
          },
          url: {
            type: 'string',
            description: 'URL to analyze (for submit_url operation)',
          },
          taskId: {
            type: 'number',
            description:
              'Cuckoo task ID (for get_status, get_report, get_summary operations)',
          },
          package: {
            type: 'string',
            description:
              'Analysis package (exe, dll, pdf, doc, etc.) - auto-detected if not specified',
          },
          timeout: {
            type: 'number',
            description: 'Analysis timeout in seconds (default: 120)',
          },
          priority: {
            type: 'number',
            description: 'Task priority: 1 (low), 2 (medium), 3 (high)',
          },
          machine: {
            type: 'string',
            description: 'Specific VM machine name to use',
          },
          platform: {
            type: 'string',
            description: 'Platform: windows, linux',
          },
          memory: {
            type: 'boolean',
            description: 'Enable memory dump (default: false)',
          },
          tags: {
            type: 'string',
            description: 'Comma-separated tags for categorization',
          },
        },
        required: ['operation'],
        type: 'object',
      },
    );
    this.config = config;
  }

  protected createInvocation(
    params: CuckooSandboxToolParams,
  ): ToolInvocation<CuckooSandboxToolParams, ToolResult> {
    return new CuckooSandboxToolInvocation(this.config, params);
  }
}
