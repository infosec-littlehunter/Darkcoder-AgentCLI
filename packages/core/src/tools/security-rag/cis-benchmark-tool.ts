/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * CIS Benchmark Tool for DarkCoder CLI
 *
 * Provides security hardening guidance using the Security RAG Pipeline.
 * Integrates CIS Benchmarks, Microsoft Security docs, and compliance frameworks.
 */

import type { Config } from '../../config/config.js';
import { ToolErrorType } from '../tool-error.js';
import type { ToolInvocation, ToolResult } from '../tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from '../tools.js';
import { ToolNames, ToolDisplayNames } from '../tool-names.js';
import { SecurityRAGPipeline } from './rag-pipeline.js';
import type {
  CISPlatform,
  CISProfileLevel,
  MicrosoftSecurityCategory,
  SecurityDocumentSource,
} from './types.js';

/**
 * Search mode for the CIS Benchmark tool
 */
export type CISBenchmarkSearchMode =
  | 'search'
  | 'hardening'
  | 'compliance'
  | 'microsoft'
  | 'ingest'
  | 'stats'
  | 'fetch'
  | 'list_platforms';

/**
 * Parameters for the CIS Benchmark tool
 */
export interface CISBenchmarkToolParams {
  mode: CISBenchmarkSearchMode;
  query?: string;
  platform?: CISPlatform;
  profileLevel?: CISProfileLevel;
  category?: MicrosoftSecurityCategory;
  framework?: string;
  source?: SecurityDocumentSource;
  filePath?: string;
  url?: string;
  maxResults?: number;
}

/**
 * Tool invocation implementation
 */
class CISBenchmarkToolInvocation extends BaseToolInvocation<
  CISBenchmarkToolParams,
  ToolResult
> {
  private pipeline: SecurityRAGPipeline;

  constructor(_config: Config, params: CISBenchmarkToolParams) {
    super(params);
    this.pipeline = new SecurityRAGPipeline();
  }

  getDescription(): string {
    const { mode, query, platform, category, framework, url } = this.params;

    switch (mode) {
      case 'search':
        return `Searching security documentation for: ${query}`;
      case 'hardening':
        return `Getting hardening recommendations for: ${platform || 'all platforms'}`;
      case 'compliance':
        return `Getting compliance guidance for: ${framework || 'all frameworks'}`;
      case 'microsoft':
        return `Getting Microsoft security recommendations for: ${category || 'all categories'}`;
      case 'ingest':
        return `Ingesting security documentation`;
      case 'stats':
        return `Getting security knowledge base statistics`;
      case 'fetch':
        return url
          ? `Fetching security documentation from URL: ${url}`
          : `Fetching Microsoft Learn documentation for: ${category || 'all categories'}`;
      case 'list_platforms':
        return `Listing available CIS Benchmark platforms`;
      default:
        return `Querying security documentation`;
    }
  }

  async execute(): Promise<ToolResult> {
    const { mode } = this.params;

    try {
      await this.pipeline.initialize();

      switch (mode) {
        case 'search':
          return await this.executeSearch();
        case 'hardening':
          return await this.executeHardening();
        case 'compliance':
          return await this.executeCompliance();
        case 'microsoft':
          return await this.executeMicrosoft();
        case 'ingest':
          return await this.executeIngest();
        case 'stats':
          return await this.executeStats();
        case 'fetch':
          return await this.executeFetch();
        case 'list_platforms':
          return await this.executeListPlatforms();
        default:
          return {
            llmContent: `Unknown mode: ${mode}`,
            returnDisplay: `Unknown mode: ${mode}`,
            error: {
              message: `Unknown mode: ${mode}`,
              type: ToolErrorType.INVALID_TOOL_PARAMS,
            },
          };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        llmContent: `Error: ${message}`,
        returnDisplay: `Error: ${message}`,
        error: {
          message,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  private async executeSearch(): Promise<ToolResult> {
    const { query, platform, profileLevel, category, framework, maxResults } =
      this.params;

    if (!query) {
      return {
        llmContent: 'Error: Query is required for search mode',
        returnDisplay: 'Error: Query is required for search mode',
        error: {
          message: 'Query is required for search mode',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Ensure built-in data is loaded
    await this.ensureBuiltinDataLoaded();

    const response = await this.pipeline.search({
      query,
      platforms: platform ? [platform] : undefined,
      profileLevel,
      categories: category ? [category] : undefined,
      complianceFramework: framework,
      maxResults: maxResults || 10,
    });

    return this.formatSearchResponse(response);
  }

  private async executeHardening(): Promise<ToolResult> {
    const { platform, profileLevel, query } = this.params;

    if (!platform) {
      return {
        llmContent:
          'Error: Platform is required for hardening mode. Available platforms: ubuntu_22.04, windows_server_2022, rhel_8, etc.',
        returnDisplay: 'Error: Platform is required',
        error: {
          message: 'Platform is required for hardening mode',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Ensure built-in data is loaded
    await this.ensureBuiltinDataLoaded();

    const response = await this.pipeline.getHardeningRecommendations(
      platform,
      profileLevel || 'L1',
    );

    // If a specific query is provided, filter results
    if (query) {
      const filteredResponse = await this.pipeline.search({
        query: `${query} hardening ${platform}`,
        platforms: [platform],
        profileLevel: profileLevel || 'L1',
        maxResults: 15,
      });
      return this.formatHardeningResponse(filteredResponse, platform);
    }

    return this.formatHardeningResponse(response, platform);
  }

  private async executeCompliance(): Promise<ToolResult> {
    const { framework, query, platform: _platform } = this.params;

    if (!framework) {
      return {
        llmContent: `Error: Framework is required for compliance mode. Available frameworks: NIST CSF, CIS Controls v8, PCI DSS, HIPAA, SOC2, ISO 27001`,
        returnDisplay: 'Error: Framework is required',
        error: {
          message: 'Framework is required for compliance mode',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Ensure built-in data is loaded
    await this.ensureBuiltinDataLoaded();

    const response = await this.pipeline.getComplianceGuidance(
      framework,
      query,
    );

    return this.formatComplianceResponse(response, framework);
  }

  private async executeMicrosoft(): Promise<ToolResult> {
    const { category, query } = this.params;

    if (!category) {
      return {
        llmContent: `Error: Category is required for microsoft mode. Available categories: defender_endpoint, intune, azure_security_center, sentinel, entra_id`,
        returnDisplay: 'Error: Category is required',
        error: {
          message: 'Category is required for microsoft mode',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Ensure built-in data is loaded
    await this.ensureBuiltinDataLoaded();

    const response = await this.pipeline.getMicrosoftSecurityGuidance(
      category,
      query,
    );

    return this.formatMicrosoftResponse(response, category);
  }

  private async executeIngest(): Promise<ToolResult> {
    const { source, platform, category, filePath } = this.params;

    if (!filePath) {
      // Load built-in data
      const loadedPlatforms: string[] = [];
      const loadedCategories: string[] = [];

      // Load all available CIS Benchmarks
      const cisPlatforms: CISPlatform[] = [
        'ubuntu_22.04',
        'windows_server_2022',
        'rhel_9',
        'kubernetes',
        'docker',
        'aws',
        'azure',
      ];

      for (const p of cisPlatforms) {
        try {
          await this.pipeline.ingestCISBenchmark(p, 'builtin');
          loadedPlatforms.push(p);
        } catch (_error) {
          // Ignore if platform not available or already loaded
        }
      }

      // Load Microsoft Security docs
      const msCategories: MicrosoftSecurityCategory[] = [
        'defender_endpoint',
        'intune',
        'azure_security_center',
        'sentinel',
        'entra_id',
      ];

      for (const c of msCategories) {
        try {
          await this.pipeline.ingestMicrosoftSecurityDocs(c, 'builtin');
          loadedCategories.push(c);
        } catch (_error) {
          // Ignore if category not available or already loaded
        }
      }

      const stats = this.pipeline.getStats();

      return {
        llmContent:
          `Successfully loaded built-in security documentation.\n\n` +
          `**CIS Benchmarks Loaded:** ${loadedPlatforms.join(', ')}\n` +
          `**Microsoft Categories Loaded:** ${loadedCategories.join(', ')}\n\n` +
          `## Index Statistics\n` +
          `- Total Documents: ${stats.totalDocuments}\n` +
          `- Total Chunks: ${stats.totalChunks}\n` +
          `- Sources: ${Object.keys(stats.bySource).join(', ')}\n` +
          `- Platforms: ${Object.keys(stats.byPlatform).join(', ')}`,
        returnDisplay: `Loaded ${stats.totalChunks} chunks from ${loadedPlatforms.length} platforms and ${loadedCategories.length} Microsoft categories`,
      };
    }

    // Ingest from file
    if (!source) {
      return {
        llmContent:
          'Error: Source type is required when ingesting from file. Available sources: cis_benchmark, microsoft_security, nist, custom',
        returnDisplay: 'Error: Source type is required',
        error: {
          message: 'Source type is required when ingesting from file',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const chunks = await this.pipeline.ingestFile(filePath, {
      source,
      platform,
      category,
    });

    return {
      llmContent: `Successfully ingested ${chunks} chunks from ${filePath}`,
      returnDisplay: `Ingested ${chunks} chunks`,
    };
  }

  private async executeStats(): Promise<ToolResult> {
    const stats = this.pipeline.getStats();

    const content = [
      '# Security Knowledge Base Statistics',
      '',
      `**Total Documents:** ${stats.totalDocuments}`,
      `**Total Chunks:** ${stats.totalChunks}`,
      `**Index Size:** ${(stats.indexSizeBytes / 1024).toFixed(2)} KB`,
      `**Last Updated:** ${stats.lastUpdated}`,
      '',
      '## Documents by Source',
      ...Object.entries(stats.bySource).map(
        ([source, count]) => `- ${source}: ${count}`,
      ),
      '',
      '## Documents by Platform',
      ...Object.entries(stats.byPlatform).map(
        ([platform, count]) => `- ${platform}: ${count}`,
      ),
    ];

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${stats.totalChunks} chunks indexed`,
    };
  }

  private async executeFetch(): Promise<ToolResult> {
    const { url, category, platform, source } = this.params;

    if (url) {
      // Fetch from specific URL
      try {
        const chunks = await this.pipeline.ingestFromUrl(url, {
          source: source || 'custom',
          platform,
          category,
        });

        return {
          llmContent: `Successfully fetched and indexed ${chunks} chunks from ${url}`,
          returnDisplay: `Fetched ${chunks} chunks from URL`,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          llmContent: `Error fetching URL: ${message}`,
          returnDisplay: `Error: ${message}`,
          error: {
            message,
            type: ToolErrorType.EXECUTION_FAILED,
          },
        };
      }
    }

    if (category) {
      // Fetch Microsoft Learn docs for category
      try {
        const chunks = await this.pipeline.ingestMicrosoftLearnDocs(category);

        return {
          llmContent: `Successfully fetched ${chunks} chunks of Microsoft Learn documentation for ${category}`,
          returnDisplay: `Fetched ${chunks} chunks for ${category}`,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          llmContent: `Error fetching Microsoft Learn docs: ${message}`,
          returnDisplay: `Error: ${message}`,
          error: {
            message,
            type: ToolErrorType.EXECUTION_FAILED,
          },
        };
      }
    }

    return {
      llmContent:
        'Error: Either url or category is required for fetch mode.\n\n' +
        'Examples:\n' +
        '- fetch mode with url: Fetches and indexes content from the specified URL\n' +
        '- fetch mode with category: Fetches Microsoft Learn docs for that category (defender_endpoint, intune, etc.)',
      returnDisplay: 'Error: url or category required',
      error: {
        message: 'Either url or category is required for fetch mode',
        type: ToolErrorType.INVALID_TOOL_PARAMS,
      },
    };
  }

  private async executeListPlatforms(): Promise<ToolResult> {
    const availablePlatforms = this.pipeline.getAvailableFetchPlatforms();
    const microsoftCategories = this.pipeline.getAvailableMicrosoftCategories();

    const builtinPlatforms = [
      'ubuntu_22.04',
      'windows_server_2022',
      'rhel_9',
      'kubernetes',
      'docker',
      'aws',
      'azure',
    ];

    const content = [
      '# Available Security Documentation Platforms',
      '',
      '## Built-in CIS Benchmarks',
      'These platforms have pre-loaded controls ready to use:',
      ...builtinPlatforms.map((p) => `- **${p}**`),
      '',
      '## Platforms with Web Fetching Info',
      'These platforms can be fetched from the web (requires active internet):',
      ...Object.entries(availablePlatforms).map(
        ([key, info]) => `- **${key}**: ${info.title} (${info.version})`,
      ),
      '',
      '## Microsoft Security Categories',
      'Available categories for Microsoft Learn documentation:',
      ...microsoftCategories.map((c) => `- **${c}**`),
      '',
      '## All Supported Platforms',
      'The following platforms are recognized by the tool:',
      'ubuntu_22.04, ubuntu_20.04, rhel_9, rhel_8, debian_11, centos_7,',
      'windows_server_2022, windows_server_2019, windows_11, windows_10,',
      'kubernetes, docker, aws, azure, gcp,',
      'postgresql, mysql, mongodb, oracle_database,',
      'nginx, apache, iis,',
      'macos, ios, android',
    ];

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${Object.keys(availablePlatforms).length} platforms available`,
    };
  }

  private async ensureBuiltinDataLoaded(): Promise<void> {
    const stats = this.pipeline.getStats();

    if (stats.totalChunks === 0) {
      // Load built-in data
      await this.executeIngest();
    }
  }

  private formatSearchResponse(
    response: Awaited<ReturnType<SecurityRAGPipeline['search']>>,
  ): ToolResult {
    if (response.results.length === 0) {
      return {
        llmContent:
          'No results found. Try broadening your search query or ingesting more documentation.',
        returnDisplay: 'No results found',
      };
    }

    const content = [
      `# Security Documentation Search Results`,
      '',
      `Found ${response.results.length} results (${response.processingTimeMs}ms)`,
      '',
    ];

    for (const result of response.results) {
      content.push(`## ${result.chunk.metadata.sectionTitle || 'Untitled'}`);
      content.push(`**Source:** ${result.chunk.source}`);
      content.push(`**Score:** ${(result.score * 100).toFixed(1)}%`);

      if (result.chunk.platform) {
        content.push(`**Platform:** ${result.chunk.platform}`);
      }

      if (result.chunk.metadata.profileLevel) {
        content.push(
          `**Profile Level:** ${result.chunk.metadata.profileLevel}`,
        );
      }

      content.push('');
      content.push(result.chunk.content.slice(0, 1000));

      if (result.chunk.content.length > 1000) {
        content.push('...(truncated)');
      }

      content.push('');
      content.push('---');
      content.push('');
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `Found ${response.results.length} results`,
    };
  }

  private formatHardeningResponse(
    response: Awaited<ReturnType<SecurityRAGPipeline['search']>>,
    platform: CISPlatform,
  ): ToolResult {
    const content = [
      `# Hardening Recommendations for ${platform}`,
      '',
      `Based on CIS Benchmarks and security best practices.`,
      '',
    ];

    if (response.results.length === 0) {
      content.push(
        'No specific recommendations found. Try loading the CIS Benchmark for this platform first.',
      );
    } else {
      for (const result of response.results) {
        const chunk = result.chunk;
        content.push(
          `## ${chunk.metadata.sectionId}: ${chunk.metadata.sectionTitle}`,
        );

        if (chunk.metadata.profileLevel) {
          content.push(
            `**Profile Level:** ${chunk.metadata.profileLevel} ${chunk.metadata.profileLevel === 'L1' ? '(Essential)' : '(Advanced)'}`,
          );
        }

        content.push('');
        content.push(chunk.content);
        content.push('');

        if (chunk.metadata.complianceMappings?.length) {
          content.push('**Compliance Mappings:**');
          for (const mapping of chunk.metadata.complianceMappings) {
            content.push(`- ${mapping.framework}: ${mapping.controlId}`);
          }
          content.push('');
        }

        content.push('---');
        content.push('');
      }
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${response.results.length} hardening recommendations`,
    };
  }

  private formatComplianceResponse(
    response: Awaited<ReturnType<SecurityRAGPipeline['search']>>,
    framework: string,
  ): ToolResult {
    const content = [`# Compliance Guidance for ${framework}`, ''];

    if (response.results.length === 0) {
      content.push(
        `No specific guidance found for ${framework}. The knowledge base may not contain this framework yet.`,
      );
    } else {
      for (const result of response.results) {
        const chunk = result.chunk;
        content.push(`## ${chunk.metadata.sectionTitle || 'Control'}`);

        if (chunk.metadata.sectionId) {
          content.push(`**Control ID:** ${chunk.metadata.sectionId}`);
        }

        content.push('');
        content.push(chunk.content);
        content.push('');
        content.push('---');
        content.push('');
      }
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${response.results.length} compliance controls`,
    };
  }

  private formatMicrosoftResponse(
    response: Awaited<ReturnType<SecurityRAGPipeline['search']>>,
    category: MicrosoftSecurityCategory,
  ): ToolResult {
    const content = [`# Microsoft Security Recommendations: ${category}`, ''];

    if (response.results.length === 0) {
      content.push(
        `No recommendations found for ${category}. Try loading Microsoft security documentation first.`,
      );
    } else {
      for (const result of response.results) {
        const chunk = result.chunk;
        content.push(`## ${chunk.metadata.sectionTitle}`);

        if (chunk.metadata.severity) {
          content.push(`**Severity:** ${chunk.metadata.severity}`);
        }

        content.push('');
        content.push(chunk.content);
        content.push('');

        if (chunk.metadata.complianceMappings?.length) {
          content.push('**Compliance Mappings:**');
          for (const mapping of chunk.metadata.complianceMappings) {
            content.push(`- ${mapping.framework}: ${mapping.controlId}`);
          }
          content.push('');
        }

        content.push('---');
        content.push('');
      }
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${response.results.length} Microsoft security recommendations`,
    };
  }
}

/**
 * CIS Benchmark Tool schema
 */
const CIS_BENCHMARK_TOOL_SCHEMA = {
  type: 'object',
  properties: {
    mode: {
      type: 'string',
      enum: [
        'search',
        'hardening',
        'compliance',
        'microsoft',
        'ingest',
        'stats',
        'fetch',
        'list_platforms',
      ],
      description:
        'Operation mode: search (general search), hardening (CIS recommendations), compliance (framework guidance), microsoft (MS security docs), ingest (load documents), stats (index statistics), fetch (fetch from URL or Microsoft Learn), list_platforms (show available platforms)',
    },
    query: {
      type: 'string',
      description:
        'Natural language search query. Required for search mode, optional for other modes to filter results.',
    },
    platform: {
      type: 'string',
      enum: [
        'windows_server_2022',
        'windows_server_2019',
        'windows_11',
        'windows_10',
        'ubuntu_22.04',
        'ubuntu_20.04',
        'rhel_9',
        'rhel_8',
        'centos_stream_9',
        'debian_12',
        'debian_11',
        'aws',
        'azure',
        'gcp',
        'kubernetes',
        'docker',
      ],
      description:
        'Target platform for CIS Benchmarks. Required for hardening mode.',
    },
    profileLevel: {
      type: 'string',
      enum: ['L1', 'L2'],
      description:
        'CIS Benchmark profile level. L1 = essential security, L2 = defense in depth. Default: L1',
    },
    category: {
      type: 'string',
      enum: [
        'defender_endpoint',
        'defender_cloud',
        'defender_identity',
        'azure_security_center',
        'intune',
        'entra_id',
        'sentinel',
        'purview',
        'security_baselines',
        'windows_security',
        'office_365_security',
      ],
      description: 'Microsoft security category. Required for microsoft mode.',
    },
    framework: {
      type: 'string',
      description:
        'Compliance framework name (e.g., "NIST CSF", "CIS Controls v8", "PCI DSS", "HIPAA", "SOC2", "ISO 27001"). Required for compliance mode.',
    },
    source: {
      type: 'string',
      enum: [
        'cis_benchmark',
        'microsoft_security',
        'nist',
        'disa_stig',
        'pci_dss',
        'hipaa',
        'soc2',
        'iso27001',
        'custom',
      ],
      description: 'Document source type. Required when ingesting from file.',
    },
    filePath: {
      type: 'string',
      description:
        'Path to document file for ingestion. Supports .json, .md, .txt formats.',
    },
    url: {
      type: 'string',
      description:
        'URL to fetch security documentation from. Used with fetch mode.',
    },
    maxResults: {
      type: 'number',
      description: 'Maximum number of results to return. Default: 10',
    },
  },
  required: ['mode'],
};

/**
 * CIS Benchmark Tool
 */
export class CISBenchmarkTool extends BaseDeclarativeTool<
  CISBenchmarkToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.CIS_BENCHMARK;

  constructor(private readonly config: Config) {
    super(
      ToolNames.CIS_BENCHMARK,
      ToolDisplayNames.CIS_BENCHMARK,
      `Security hardening and compliance tool powered by CIS Benchmarks, Microsoft Security documentation, and compliance frameworks.

Use this tool to:
- Search security documentation: mode="search" with query
- Get hardening recommendations: mode="hardening" with platform (e.g., ubuntu_22.04, windows_server_2022, kubernetes, aws, azure)
- Get compliance guidance: mode="compliance" with framework (e.g., "NIST CSF", "PCI DSS")
- Get Microsoft security recommendations: mode="microsoft" with category (e.g., defender_endpoint, intune)
- Ingest custom documentation: mode="ingest" with filePath and source
- Fetch from URL or Microsoft Learn: mode="fetch" with url or category
- View knowledge base statistics: mode="stats"
- List available platforms: mode="list_platforms"

Supported Platforms:
- Linux: Ubuntu 22.04/20.04, RHEL 9/8, Debian, CentOS
- Windows: Server 2022/2019, Windows 11/10
- Cloud: AWS, Azure, GCP
- Containers: Kubernetes, Docker
- Databases: PostgreSQL, MySQL, MongoDB, Oracle

Examples:
1. Search: { "mode": "search", "query": "SSH hardening best practices" }
2. Hardening: { "mode": "hardening", "platform": "ubuntu_22.04", "profileLevel": "L1" }
3. Kubernetes: { "mode": "hardening", "platform": "kubernetes" }
4. Cloud: { "mode": "hardening", "platform": "aws" }
5. Compliance: { "mode": "compliance", "framework": "PCI DSS", "query": "encryption requirements" }
6. Microsoft: { "mode": "microsoft", "category": "defender_endpoint" }
7. Fetch URL: { "mode": "fetch", "url": "https://example.com/security-guide.html" }
8. Fetch MS Learn: { "mode": "fetch", "category": "intune" }
9. List platforms: { "mode": "list_platforms" }`,
      Kind.Read,
      CIS_BENCHMARK_TOOL_SCHEMA,
      true, // isOutputMarkdown
    );
  }

  override validateToolParamValues(
    params: CISBenchmarkToolParams,
  ): string | null {
    const {
      mode,
      query,
      platform,
      category,
      framework,
      filePath,
      source,
      url,
    } = params;

    switch (mode) {
      case 'search':
        if (!query) {
          return 'Query is required for search mode';
        }
        break;
      case 'hardening':
        if (!platform) {
          return 'Platform is required for hardening mode';
        }
        break;
      case 'compliance':
        if (!framework) {
          return 'Framework is required for compliance mode';
        }
        break;
      case 'microsoft':
        if (!category) {
          return 'Category is required for microsoft mode';
        }
        break;
      case 'ingest':
        if (filePath && !source) {
          return 'Source is required when ingesting from file';
        }
        break;
      case 'fetch':
        if (!url && !category) {
          return 'Either url or category is required for fetch mode';
        }
        break;
      case 'stats':
      case 'list_platforms':
        // No validation needed
        break;
      default:
        return `Unknown mode: ${mode}`;
    }

    return null;
  }

  createInvocation(
    params: CISBenchmarkToolParams,
  ): ToolInvocation<CISBenchmarkToolParams, ToolResult> {
    return new CISBenchmarkToolInvocation(this.config, params);
  }
}
