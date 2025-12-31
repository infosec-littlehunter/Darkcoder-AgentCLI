/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * API Key Manager Tool
 *
 * Allows users to manage API keys for external security tools
 * directly from the CLI.
 */

import {
  apiKeyManager,
  SECURITY_TOOLS,
  type SecurityToolConfig,
} from '../config/api-keys.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';

/**
 * Operation modes
 */
export type ApiKeyOperation =
  | 'list'
  | 'status'
  | 'set'
  | 'remove'
  | 'info'
  | 'export'
  | 'test';

/**
 * Parameters for the API Key Manager tool
 */
export interface ApiKeyManagerParams {
  operation: ApiKeyOperation;
  tool?: string;
  apiKey?: string;
  apiId?: string;
  apiSecret?: string;
  format?: 'env' | 'dotenv' | 'json';
}

/**
 * API Key Manager Tool Invocation
 */
class ApiKeyManagerInvocation extends BaseToolInvocation<
  ApiKeyManagerParams,
  ToolResult
> {
  constructor(params: ApiKeyManagerParams) {
    super(params);
  }

  getDescription(): string {
    const { operation, tool } = this.params;
    switch (operation) {
      case 'list':
        return 'Listing available security tools';
      case 'status':
        return 'Checking API key status';
      case 'set':
        return `Setting API key for ${tool}`;
      case 'remove':
        return `Removing API key for ${tool}`;
      case 'info':
        return `Getting info for ${tool}`;
      case 'export':
        return 'Exporting API key template';
      case 'test':
        return `Testing API key for ${tool}`;
      default:
        return 'Managing API keys';
    }
  }

  async execute(): Promise<ToolResult> {
    await apiKeyManager.initialize();

    const { operation } = this.params;

    switch (operation) {
      case 'list':
        return this.listTools();
      case 'status':
        return this.checkStatus();
      case 'set':
        return this.setKey();
      case 'remove':
        return this.removeKey();
      case 'info':
        return this.getToolInfo();
      case 'export':
        return this.exportTemplate();
      case 'test':
        return this.testKey();
      default:
        return {
          llmContent: `Unknown operation: ${operation}`,
          returnDisplay: 'Unknown operation',
          error: {
            message: `Unknown operation: ${operation}`,
            type: ToolErrorType.INVALID_TOOL_PARAMS,
          },
        };
    }
  }

  private listTools(): ToolResult {
    const tools = apiKeyManager.getAllTools();

    const categories = {
      'Internet Scanning': [
        'censys',
        'binaryedge',
        'zoomeye',
        'fofa',
        'onyphe',
        'netlas',
        'criminalip',
      ],
      'Threat Intelligence': [
        'virustotal',
        'greynoise',
        'abuseipdb',
        'pulsedive',
        'leakix',
        'intelx',
      ],
      'Domain/DNS': ['securitytrails', 'hunter', 'publicwww'],
      'Web Analysis': ['urlscan', 'fullhunt'],
      'AI/Embedding': ['openai', 'dashscope'],
    };

    const content: string[] = [
      '# Available Security Tool Integrations',
      '',
      'DarkCoder supports integration with the following security tools:',
      '',
    ];

    for (const [category, toolNames] of Object.entries(categories)) {
      content.push(`## ${category}`);
      content.push('');
      content.push('| Tool | Description | Registration |');
      content.push('|------|-------------|--------------|');

      for (const name of toolNames) {
        const tool = SECURITY_TOOLS[name];
        if (tool) {
          const configured = apiKeyManager.isConfigured(name) ? '✅' : '⬜';
          content.push(
            `| ${configured} **${tool.displayName}** | ${tool.description} | [Sign Up](${tool.registrationUrl}) |`,
          );
        }
      }
      content.push('');
    }

    content.push('## Quick Start');
    content.push('');
    content.push(
      '1. **Set API key**: `{ "operation": "set", "tool": "censys", "apiKey": "your_key" }`',
    );
    content.push('2. **Check status**: `{ "operation": "status" }`');
    content.push(
      '3. **Export template**: `{ "operation": "export", "format": "dotenv" }`',
    );
    content.push('');

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${tools.length} security tools available`,
    };
  }

  private async checkStatus(): Promise<ToolResult> {
    const status = await apiKeyManager.getStatus();

    const configured = status.filter((s) => s.configured);
    const notConfigured = status.filter((s) => !s.configured);

    const content: string[] = [
      '# API Key Status',
      '',
      `**Configured:** ${configured.length}/${status.length} tools`,
      '',
    ];

    if (configured.length > 0) {
      content.push('## ✅ Configured');
      content.push('');
      content.push('| Tool | Source | Key |');
      content.push('|------|--------|-----|');

      for (const s of configured) {
        content.push(`| ${s.displayName} | ${s.source} | ${s.maskedKey} |`);
      }
      content.push('');
    }

    if (notConfigured.length > 0) {
      content.push('## ⬜ Not Configured');
      content.push('');

      const grouped: string[] = [];
      for (const s of notConfigured) {
        grouped.push(s.displayName);
      }
      content.push(grouped.join(', '));
      content.push('');
      content.push(
        'Use `{ "operation": "info", "tool": "toolname" }` to see how to configure.',
      );
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${configured.length}/${status.length} tools configured`,
    };
  }

  private async setKey(): Promise<ToolResult> {
    const { tool, apiKey, apiId, apiSecret } = this.params;

    if (!tool) {
      return {
        llmContent:
          'Tool name is required. Use `{ "operation": "list" }` to see available tools.',
        returnDisplay: 'Missing tool name',
        error: {
          message: 'Tool name is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const toolConfig = SECURITY_TOOLS[tool];
    if (!toolConfig) {
      return {
        llmContent: `Unknown tool: ${tool}. Use \`{ "operation": "list" }\` to see available tools.`,
        returnDisplay: `Unknown tool: ${tool}`,
        error: {
          message: `Unknown tool: ${tool}`,
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    if (toolConfig.credentials === 'apiIdSecret') {
      if (!apiId || !apiSecret) {
        return {
          llmContent: `${toolConfig.displayName} requires both apiId and apiSecret.\n\nExample: \`{ "operation": "set", "tool": "${tool}", "apiId": "your_id", "apiSecret": "your_secret" }\``,
          returnDisplay: 'Missing credentials',
          error: {
            message: 'Both apiId and apiSecret are required',
            type: ToolErrorType.INVALID_TOOL_PARAMS,
          },
        };
      }

      await apiKeyManager.setApiCredentials(tool, { apiId, apiSecret });

      return {
        llmContent: `✅ API credentials for **${toolConfig.displayName}** have been saved.\n\nYou can now use the ${toolConfig.displayName} features.`,
        returnDisplay: `${toolConfig.displayName} credentials saved`,
      };
    }

    if (!apiKey) {
      return {
        llmContent: `API key is required.\n\nExample: \`{ "operation": "set", "tool": "${tool}", "apiKey": "your_key" }\``,
        returnDisplay: 'Missing API key',
        error: {
          message: 'API key is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    await apiKeyManager.setApiKey(tool, apiKey);

    return {
      llmContent: `✅ API key for **${toolConfig.displayName}** has been saved.\n\nYou can now use the ${toolConfig.displayName} features.`,
      returnDisplay: `${toolConfig.displayName} API key saved`,
    };
  }

  private async removeKey(): Promise<ToolResult> {
    const { tool } = this.params;

    if (!tool) {
      return {
        llmContent: 'Tool name is required.',
        returnDisplay: 'Missing tool name',
        error: {
          message: 'Tool name is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const toolConfig = SECURITY_TOOLS[tool];
    if (!toolConfig) {
      return {
        llmContent: `Unknown tool: ${tool}`,
        returnDisplay: `Unknown tool: ${tool}`,
        error: {
          message: `Unknown tool: ${tool}`,
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    await apiKeyManager.removeApiKey(tool);

    return {
      llmContent: `✅ API key for **${toolConfig.displayName}** has been removed.`,
      returnDisplay: `${toolConfig.displayName} API key removed`,
    };
  }

  private getToolInfo(): ToolResult {
    const { tool } = this.params;

    if (!tool) {
      return {
        llmContent:
          'Tool name is required. Use `{ "operation": "list" }` to see available tools.',
        returnDisplay: 'Missing tool name',
        error: {
          message: 'Tool name is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const toolConfig = SECURITY_TOOLS[tool];
    if (!toolConfig) {
      return {
        llmContent: `Unknown tool: ${tool}. Use \`{ "operation": "list" }\` to see available tools.`,
        returnDisplay: `Unknown tool: ${tool}`,
        error: {
          message: `Unknown tool: ${tool}`,
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const isConfigured = apiKeyManager.isConfigured(tool);

    const content: string[] = [
      `# ${toolConfig.displayName}`,
      '',
      `**Status:** ${isConfigured ? '✅ Configured' : '⬜ Not Configured'}`,
      '',
      `**Description:** ${toolConfig.description}`,
      '',
      '## Setup',
      '',
      `1. **Register:** [${toolConfig.registrationUrl}](${toolConfig.registrationUrl})`,
      `2. **Documentation:** [${toolConfig.docsUrl}](${toolConfig.docsUrl})`,
      '',
      '### Environment Variables',
      '',
      '```bash',
      ...toolConfig.envVars.map((env) => `export ${env}="your_key_here"`),
      '```',
      '',
      '### CLI Command',
      '',
    ];

    if (toolConfig.credentials === 'apiIdSecret') {
      content.push('```json');
      content.push(
        `{ "operation": "set", "tool": "${tool}", "apiId": "your_id", "apiSecret": "your_secret" }`,
      );
      content.push('```');
    } else {
      content.push('```json');
      content.push(
        `{ "operation": "set", "tool": "${tool}", "apiKey": "your_key" }`,
      );
      content.push('```');
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${toolConfig.displayName} info`,
    };
  }

  private exportTemplate(): ToolResult {
    const { format = 'env' } = this.params;

    let content: string;
    let filename: string;

    switch (format) {
      case 'dotenv':
        content = apiKeyManager.generateEnvFile();
        filename = '.env';
        break;
      case 'json': {
        const template: Record<string, string> = {};
        for (const [_name, tool] of Object.entries(SECURITY_TOOLS)) {
          for (const env of tool.envVars) {
            template[env] = '';
          }
        }
        content = JSON.stringify(template, null, 2);
        filename = 'api-keys.json';
        break;
      }
      case 'env':
      default:
        content = apiKeyManager.generateEnvExports();
        filename = '.bashrc or .zshrc';
        break;
    }

    const output: string[] = [
      `# API Key Template (${format})`,
      '',
      `Save this to your ${filename}:`,
      '',
      '```',
      content,
      '```',
    ];

    return {
      llmContent: output.join('\n'),
      returnDisplay: `Generated ${format} template`,
    };
  }

  private async testKey(): Promise<ToolResult> {
    const { tool } = this.params;

    if (!tool) {
      return {
        llmContent: 'Tool name is required.',
        returnDisplay: 'Missing tool name',
        error: {
          message: 'Tool name is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const toolConfig = SECURITY_TOOLS[tool];
    if (!toolConfig) {
      return {
        llmContent: `Unknown tool: ${tool}`,
        returnDisplay: `Unknown tool: ${tool}`,
        error: {
          message: `Unknown tool: ${tool}`,
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    if (!apiKeyManager.isConfigured(tool)) {
      return {
        llmContent: `${toolConfig.displayName} is not configured. Set the API key first.`,
        returnDisplay: 'Not configured',
        error: {
          message: `${tool} is not configured`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    // Test the API key based on tool
    try {
      const result = await this.testApiKey(tool, toolConfig);
      return {
        llmContent: `✅ **${toolConfig.displayName}** API key is valid!\n\n${result}`,
        returnDisplay: `${toolConfig.displayName} key valid`,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        llmContent: `❌ **${toolConfig.displayName}** API key test failed.\n\nError: ${message}`,
        returnDisplay: `${toolConfig.displayName} key invalid`,
        error: {
          message: `API key test failed: ${message}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  private async testApiKey(
    tool: string,
    _config: SecurityToolConfig,
  ): Promise<string> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      switch (tool) {
        case 'censys': {
          const creds = apiKeyManager.getApiCredentials('censys');
          const auth = Buffer.from(
            `${creds.apiId}:${creds.apiSecret}`,
          ).toString('base64');
          const response = await fetch(
            'https://search.censys.io/api/v1/account',
            {
              headers: { Authorization: `Basic ${auth}` },
              signal: controller.signal,
            },
          );
          if (!response.ok) throw new Error('Invalid credentials');
          const data = (await response.json()) as {
            quota?: { used?: number; allowance?: number };
          };
          return `Quota used: ${data.quota?.used ?? 0}/${data.quota?.allowance ?? 'Unknown'}`;
        }

        case 'virustotal': {
          const key = apiKeyManager.getApiKey('virustotal');
          const response = await fetch(
            'https://www.virustotal.com/api/v3/users/current',
            {
              headers: { 'x-apikey': key || '' },
              signal: controller.signal,
            },
          );
          if (!response.ok) throw new Error('Invalid API key');
          return 'API key is valid';
        }

        case 'urlscan': {
          const key = apiKeyManager.getApiKey('urlscan');
          const response = await fetch('https://urlscan.io/user/quotas/', {
            headers: { 'API-Key': key || '' },
            signal: controller.signal,
          });
          if (!response.ok) throw new Error('Invalid API key');
          return 'API key is valid';
        }

        case 'greynoise': {
          const key = apiKeyManager.getApiKey('greynoise');
          const response = await fetch(
            'https://api.greynoise.io/v3/community/8.8.8.8',
            {
              headers: { key: key || '' },
              signal: controller.signal,
            },
          );
          if (!response.ok) throw new Error('Invalid API key');
          return 'API key is valid';
        }

        case 'abuseipdb': {
          const key = apiKeyManager.getApiKey('abuseipdb');
          const response = await fetch(
            'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8',
            {
              headers: { Key: key || '', Accept: 'application/json' },
              signal: controller.signal,
            },
          );
          if (!response.ok) throw new Error('Invalid API key');
          return 'API key is valid';
        }

        default:
          return 'API key appears to be set (no test endpoint available)';
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

/**
 * Tool schema
 */
const API_KEY_MANAGER_SCHEMA = {
  type: 'object',
  properties: {
    operation: {
      type: 'string',
      enum: ['list', 'status', 'set', 'remove', 'info', 'export', 'test'],
      description: `Operation to perform:
- list: Show all available security tools
- status: Check which tools are configured
- set: Set API key for a tool
- remove: Remove API key for a tool
- info: Get detailed info about a tool
- export: Export API key template
- test: Test if an API key is valid`,
    },
    tool: {
      type: 'string',
      description: 'Tool name (e.g., censys, virustotal)',
    },
    apiKey: {
      type: 'string',
      description: 'API key to set (for set operation)',
    },
    apiId: {
      type: 'string',
      description: 'API ID for tools requiring ID/Secret (e.g., Censys)',
    },
    apiSecret: {
      type: 'string',
      description: 'API Secret for tools requiring ID/Secret (e.g., Censys)',
    },
    format: {
      type: 'string',
      enum: ['env', 'dotenv', 'json'],
      description: 'Export format (for export operation)',
    },
  },
  required: ['operation'],
};

/**
 * API Key Manager Tool
 */
export class ApiKeyManagerTool extends BaseDeclarativeTool<
  ApiKeyManagerParams,
  ToolResult
> {
  static readonly Name = ToolNames.API_KEY_MANAGER;

  constructor() {
    super(
      ToolNames.API_KEY_MANAGER,
      ToolDisplayNames.API_KEY_MANAGER,
      `Manage API keys for external security tools (Censys, VirusTotal, etc.)

Examples:
1. List tools: { "operation": "list" }
2. Check status: { "operation": "status" }
3. Set key: { "operation": "set", "tool": "censys", "apiKey": "your_key" }
4. Set Censys: { "operation": "set", "tool": "censys", "apiId": "id", "apiSecret": "secret" }
5. Test key: { "operation": "test", "tool": "censys" }
6. Get info: { "operation": "info", "tool": "virustotal" }
7. Export template: { "operation": "export", "format": "dotenv" }`,
      Kind.Read,
      API_KEY_MANAGER_SCHEMA,
      true,
    );
  }

  override validateToolParamValues(params: ApiKeyManagerParams): string | null {
    const { operation, tool, apiKey, apiId, apiSecret } = params;

    if (operation === 'set') {
      if (!tool) return 'Tool name is required for set operation';

      const toolConfig = SECURITY_TOOLS[tool];
      if (toolConfig?.credentials === 'apiIdSecret') {
        if (!apiId || !apiSecret) {
          return `${tool} requires both apiId and apiSecret`;
        }
      } else if (!apiKey) {
        return 'API key is required for set operation';
      }
    }

    if (['remove', 'info', 'test'].includes(operation) && !tool) {
      return `Tool name is required for ${operation} operation`;
    }

    return null;
  }

  protected override createInvocation(
    params: ApiKeyManagerParams,
  ): ToolInvocation<ApiKeyManagerParams, ToolResult> {
    return new ApiKeyManagerInvocation(params);
  }
}
