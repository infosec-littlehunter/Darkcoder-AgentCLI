/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * URLScan.io Tool for SOC / Threat Hunting
 *
 * This tool provides access to the URLScan.io API for URL analysis
 * and threat intelligence. Useful for:
 * - Analyzing suspicious URLs and websites
 * - Finding phishing and malware infrastructure
 * - Discovering related domains and IPs
 * - Getting screenshots and DOM snapshots
 * - Threat hunting and IOC enrichment
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';

const URLSCAN_TIMEOUT_MS = 60000; // Longer timeout for scan submissions
const URLSCAN_API_BASE = 'https://urlscan.io/api/v1';

/**
 * Search types for URLScan queries
 */
export type URLScanSearchType = 'search' | 'scan' | 'result' | 'dom';

/**
 * Parameters for the URLScan tool
 */
export interface URLScanToolParams {
  searchType: URLScanSearchType;
  query?: string;
  url?: string;
  uuid?: string;
  visibility?: 'public' | 'unlisted' | 'private';
  tags?: string[];
  country?: string;
  referer?: string;
  size?: number;
}

/**
 * URLScan search result structure
 */
interface URLScanSearchResult {
  total: number;
  results: Array<{
    task: {
      uuid: string;
      url: string;
      time: string;
      visibility: string;
    };
    page: {
      url: string;
      domain: string;
      ip: string;
      country: string;
      server?: string;
      status?: number;
      title?: string;
    };
    stats?: {
      requests?: number;
      dataLength?: number;
    };
    verdicts?: {
      overall?: {
        score: number;
        malicious: boolean;
        hasVerdicts: boolean;
      };
      urlscan?: {
        score: number;
        malicious: boolean;
      };
    };
  }>;
}

/**
 * URLScan scan submission response
 */
interface URLScanSubmitResponse {
  uuid: string;
  url: string;
  visibility: string;
  message: string;
  result: string;
  api: string;
}

/**
 * URLScan result response
 */
interface URLScanResultResponse {
  task: {
    uuid: string;
    url: string;
    time: string;
    visibility: string;
    source: string;
    userAgent: string;
  };
  page: {
    url: string;
    domain: string;
    ip: string;
    country: string;
    city?: string;
    server?: string;
    status: number;
    mimeType?: string;
    title?: string;
  };
  lists?: {
    urls?: string[];
    ips?: string[];
    domains?: string[];
    asns?: string[];
    certificates?: Array<{
      issuer: string;
      subject: string;
      validFrom: string;
      validTo: string;
    }>;
  };
  verdicts?: {
    overall?: {
      score: number;
      malicious: boolean;
      hasVerdicts: boolean;
    };
    urlscan?: {
      score: number;
      malicious: boolean;
      categories?: string[];
    };
    community?: {
      score: number;
      votesMalicious: number;
      votesBenign: number;
    };
  };
  stats?: {
    secureRequests: number;
    securePercentage: number;
    IPv6Percentage: number;
    uniqCountries: number;
    uniqIPs: number;
    requests?: number;
    dataLength?: number;
  };
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
 * Implementation of the URLScan tool invocation logic
 */
class URLScanToolInvocation extends BaseToolInvocation<
  URLScanToolParams,
  ToolResult
> {
  private readonly config: Config;

  constructor(config: Config, params: URLScanToolParams) {
    super(params);
    this.config = config;
  }

  getDescription(): string {
    const { searchType, query, url, uuid } = this.params;
    switch (searchType) {
      case 'search':
        return `Searching URLScan.io: ${query}`;
      case 'scan':
        return `Submitting URL to URLScan.io: ${url}`;
      case 'result':
        return `Getting URLScan.io scan results: ${uuid}`;
      case 'dom':
        return `Getting DOM snapshot from URLScan.io: ${uuid}`;
      default:
        return `Querying URLScan.io`;
    }
  }

  private getApiKey(): string | null {
    // First check config (from settings.json), then fall back to environment variable
    return this.config.getUrlscanApiKey() || null;
  }

  async execute(): Promise<ToolResult> {
    const { searchType } = this.params;

    // Search doesn't require API key
    if (searchType !== 'search') {
      const apiKey = this.getApiKey();
      if (!apiKey) {
        return {
          llmContent: `Error: URLScan API key not found. Please configure it in settings.json (advanced.urlscanApiKey) or set URLSCAN_API_KEY environment variable.\n\nGet your API key at: https://urlscan.io/user/signup`,
          returnDisplay: `URLScan API key not configured. Configure in settings.json or set URLSCAN_API_KEY environment variable.`,
          error: {
            message: `Missing URLScan API key - configure in settings.json or URLSCAN_API_KEY environment variable`,
            type: ToolErrorType.EXECUTION_FAILED,
          },
        };
      }
    }

    try {
      switch (searchType) {
        case 'search':
          return await this.searchScans();
        case 'scan':
          return await this.submitScan();
        case 'result':
          return await this.getResult();
        case 'dom':
          return await this.getDom();
        default:
          return {
            llmContent: `Error: Unknown search type: ${searchType}`,
            returnDisplay: `Unknown search type: ${searchType}`,
            error: {
              message: `Unknown search type: ${searchType}`,
              type: ToolErrorType.INVALID_TOOL_PARAMS,
            },
          };
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return {
        llmContent: `Error: URLScan query failed: ${errorMessage}`,
        returnDisplay: `URLScan query failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Search existing scans on URLScan.io
   */
  private async searchScans(): Promise<ToolResult> {
    const { query, size } = this.params;

    if (!query) {
      return {
        llmContent: 'Error: Query parameter is required for search',
        returnDisplay: 'Query parameter is required for search',
        error: {
          message: 'Query parameter is required for search',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const params = new URLSearchParams({
      q: query,
      size: String(size || 10),
    });

    const url = `${URLSCAN_API_BASE}/search/?${params.toString()}`;

    const response = await fetchWithAbort(url, {}, URLSCAN_TIMEOUT_MS);

    if (!response.ok) {
      throw new Error(`URLScan API returned status ${response.status}`);
    }

    const data = (await response.json()) as URLScanSearchResult;

    if (!data.results || data.results.length === 0) {
      return {
        llmContent: `No results found for query: ${query}`,
        returnDisplay: `No results found for query: ${query}`,
      };
    }

    const summary = [
      `## URLScan Search Results`,
      `**Query:** ${query}`,
      `**Total Results:** ${data.total}`,
      `**Showing:** ${data.results.length}`,
      '',
      '---',
      '',
    ];

    for (const result of data.results.slice(0, 15)) {
      const verdict = result.verdicts?.overall;
      const maliciousIndicator = verdict?.malicious
        ? '🚨 MALICIOUS'
        : '✅ Clean';

      summary.push(`### ${result.page.domain || result.page.url}`);
      summary.push(`- **URL:** ${result.page.url}`);
      summary.push(`- **IP:** ${result.page.ip || 'N/A'}`);
      summary.push(`- **Country:** ${result.page.country || 'N/A'}`);
      if (result.page.title) {
        summary.push(`- **Title:** ${result.page.title}`);
      }
      if (result.page.server) {
        summary.push(`- **Server:** ${result.page.server}`);
      }
      if (result.page.status) {
        summary.push(`- **Status:** ${result.page.status}`);
      }
      summary.push(`- **Verdict:** ${maliciousIndicator}`);
      if (verdict?.score !== undefined) {
        summary.push(`- **Score:** ${verdict.score}/100`);
      }
      summary.push(`- **Scan Time:** ${result.task.time}`);
      summary.push(`- **UUID:** ${result.task.uuid}`);
      summary.push(
        `- **Report:** https://urlscan.io/result/${result.task.uuid}/`,
      );
      summary.push('');
    }

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Submit a URL for scanning
   */
  private async submitScan(): Promise<ToolResult> {
    const { url: targetUrl, visibility, tags, country, referer } = this.params;
    const apiKey = this.getApiKey()!;

    if (!targetUrl) {
      return {
        llmContent: 'Error: URL parameter is required for scan submission',
        returnDisplay: 'URL parameter is required for scan submission',
        error: {
          message: 'URL parameter is required for scan submission',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const body: Record<string, unknown> = {
      url: targetUrl,
      visibility: visibility || 'public',
    };

    if (tags && tags.length > 0) {
      body['tags'] = tags;
    }
    if (country) {
      body['country'] = country;
    }
    if (referer) {
      body['referer'] = referer;
    }

    const response = await fetchWithAbort(
      `${URLSCAN_API_BASE}/scan/`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'API-Key': apiKey,
        },
        body: JSON.stringify(body),
      },
      URLSCAN_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `URLScan API returned status ${response.status}: ${errorText}`,
      );
    }

    const data = (await response.json()) as URLScanSubmitResponse;

    const summary = [
      `## URLScan Submission Successful`,
      '',
      `**URL:** ${data.url}`,
      `**UUID:** ${data.uuid}`,
      `**Visibility:** ${data.visibility}`,
      `**Message:** ${data.message}`,
      '',
      `### View Results`,
      `- **Result Page:** ${data.result}`,
      `- **API Endpoint:** ${data.api}`,
      '',
      `> ⏳ Note: Scan results may take 10-30 seconds to complete.`,
      `> Use \`searchType: "result"\` with \`uuid: "${data.uuid}"\` to fetch results.`,
    ].join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get scan results by UUID
   */
  private async getResult(): Promise<ToolResult> {
    const { uuid } = this.params;

    if (!uuid) {
      return {
        llmContent: 'Error: UUID parameter is required for result lookup',
        returnDisplay: 'UUID parameter is required for result lookup',
        error: {
          message: 'UUID parameter is required for result lookup',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${URLSCAN_API_BASE}/result/${uuid}/`;

    const response = await fetchWithAbort(url, {}, URLSCAN_TIMEOUT_MS);

    if (response.status === 404) {
      return {
        llmContent: `Scan results not ready or not found. The scan may still be processing. Try again in a few seconds.`,
        returnDisplay: `Scan results not ready or not found for UUID: ${uuid}`,
        error: {
          message: 'Scan results not ready or not found',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    if (!response.ok) {
      throw new Error(`URLScan API returned status ${response.status}`);
    }

    const data = (await response.json()) as URLScanResultResponse;

    const verdict = data.verdicts?.overall;
    const maliciousIndicator = verdict?.malicious ? '🚨 MALICIOUS' : '✅ Clean';

    const summary = [
      `## URLScan Result: ${data.page.domain}`,
      '',
      `### Overview`,
      `- **URL:** ${data.page.url}`,
      `- **Domain:** ${data.page.domain}`,
      `- **IP:** ${data.page.ip}`,
      `- **Country:** ${data.page.country}${data.page.city ? ` (${data.page.city})` : ''}`,
      `- **Status:** ${data.page.status}`,
      `- **Server:** ${data.page.server || 'N/A'}`,
      `- **Title:** ${data.page.title || 'N/A'}`,
      '',
      `### Verdict`,
      `- **Overall:** ${maliciousIndicator}`,
    ];

    if (verdict?.score !== undefined) {
      summary.push(`- **Score:** ${verdict.score}/100`);
    }
    if (data.verdicts?.urlscan?.categories?.length) {
      summary.push(
        `- **Categories:** ${data.verdicts.urlscan.categories.join(', ')}`,
      );
    }
    if (data.verdicts?.community) {
      summary.push(
        `- **Community Votes:** 👍 ${data.verdicts.community.votesBenign} / 👎 ${data.verdicts.community.votesMalicious}`,
      );
    }

    if (data.stats) {
      summary.push('');
      summary.push(`### Statistics`);
      summary.push(`- **Requests:** ${data.stats.requests || 'N/A'}`);
      summary.push(
        `- **Data Length:** ${data.stats.dataLength ? `${(data.stats.dataLength / 1024).toFixed(2)} KB` : 'N/A'}`,
      );
      summary.push(`- **Secure Requests:** ${data.stats.securePercentage}%`);
      summary.push(`- **Unique IPs:** ${data.stats.uniqIPs}`);
      summary.push(`- **Unique Countries:** ${data.stats.uniqCountries}`);
    }

    if (data.lists) {
      if (data.lists.domains && data.lists.domains.length > 0) {
        summary.push('');
        summary.push(`### Associated Domains (${data.lists.domains.length})`);
        summary.push(
          data.lists.domains
            .slice(0, 20)
            .map((d) => `- ${d}`)
            .join('\n'),
        );
        if (data.lists.domains.length > 20) {
          summary.push(
            `_...and ${data.lists.domains.length - 20} more domains_`,
          );
        }
      }

      if (data.lists.ips && data.lists.ips.length > 0) {
        summary.push('');
        summary.push(`### Associated IPs (${data.lists.ips.length})`);
        summary.push(
          data.lists.ips
            .slice(0, 15)
            .map((ip) => `- ${ip}`)
            .join('\n'),
        );
        if (data.lists.ips.length > 15) {
          summary.push(`_...and ${data.lists.ips.length - 15} more IPs_`);
        }
      }

      if (data.lists.certificates && data.lists.certificates.length > 0) {
        summary.push('');
        summary.push(
          `### SSL Certificates (${data.lists.certificates.length})`,
        );
        for (const cert of data.lists.certificates.slice(0, 5)) {
          summary.push(`- **Subject:** ${cert.subject}`);
          summary.push(`  - Issuer: ${cert.issuer}`);
          summary.push(`  - Valid: ${cert.validFrom} to ${cert.validTo}`);
        }
      }
    }

    summary.push('');
    summary.push(`### Links`);
    summary.push(`- **Full Report:** https://urlscan.io/result/${uuid}/`);
    summary.push(
      `- **Screenshot:** https://urlscan.io/screenshots/${uuid}.png`,
    );
    summary.push(`- **DOM:** https://urlscan.io/dom/${uuid}/`);

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Get DOM snapshot from a scan
   */
  private async getDom(): Promise<ToolResult> {
    const { uuid } = this.params;

    if (!uuid) {
      return {
        llmContent: 'Error: UUID parameter is required for DOM lookup',
        returnDisplay: 'UUID parameter is required for DOM lookup',
        error: {
          message: 'UUID parameter is required for DOM lookup',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${URLSCAN_API_BASE}/dom/${uuid}/`;

    const response = await fetchWithAbort(url, {}, URLSCAN_TIMEOUT_MS);

    if (response.status === 404) {
      return {
        llmContent: `DOM snapshot not found. The scan may still be processing or DOM was not captured.`,
        returnDisplay: `DOM not found for UUID: ${uuid}`,
        error: {
          message: 'DOM snapshot not found',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    if (!response.ok) {
      throw new Error(`URLScan API returned status ${response.status}`);
    }

    const domContent = await response.text();

    // Truncate if too long
    const maxLength = 50000;
    const truncated = domContent.length > maxLength;
    const content = truncated
      ? domContent.substring(0, maxLength) + '\n\n... [DOM truncated]'
      : domContent;

    const summary = [
      `## URLScan DOM Snapshot`,
      `**UUID:** ${uuid}`,
      `**Length:** ${domContent.length} characters${truncated ? ' (truncated)' : ''}`,
      '',
      '```html',
      content,
      '```',
    ].join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }
}

/**
 * URLScan Tool for URL analysis and threat intelligence
 */
export class URLScanTool extends BaseDeclarativeTool<
  URLScanToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.URLSCAN;
  private readonly config: Config;

  constructor(config: Config) {
    super(
      URLScanTool.Name,
      ToolDisplayNames.URLSCAN,
      `Analyze URLs and websites using URLScan.io for threat hunting and SOC operations. API key can be configured in settings.json (advanced.urlscanApiKey) or via URLSCAN_API_KEY environment variable (not required for search). Useful for:
- Analyzing suspicious URLs and phishing sites
- Getting screenshots and DOM snapshots of websites
- Finding related infrastructure (IPs, domains, certificates)
- Threat intelligence and IOC enrichment
- Malware infrastructure discovery`,
      Kind.Fetch,
      {
        properties: {
          searchType: {
            type: 'string',
            enum: ['search', 'scan', 'result', 'dom'],
            description:
              'Type of operation: "search" to search existing scans, "scan" to submit new URL, "result" to get scan results, "dom" to get DOM snapshot',
          },
          query: {
            type: 'string',
            description:
              'Search query using URLScan syntax (e.g., "domain:example.com", "ip:1.2.3.4", "page.title:login", "server:nginx")',
          },
          url: {
            type: 'string',
            description: 'URL to scan (for scan operation)',
          },
          uuid: {
            type: 'string',
            description: 'Scan UUID (for result and dom operations)',
          },
          visibility: {
            type: 'string',
            enum: ['public', 'unlisted', 'private'],
            description:
              'Scan visibility: public (visible to all), unlisted (only with link), private (requires API key)',
          },
          tags: {
            type: 'array',
            items: { type: 'string' },
            description: 'Tags to add to the scan',
          },
          country: {
            type: 'string',
            description:
              'Country code for the scanner location (e.g., "us", "de", "jp")',
          },
          size: {
            type: 'number',
            description: 'Number of results to return (default: 10, max: 100)',
          },
        },
        required: ['searchType'],
        type: 'object',
      },
    );
    this.config = config;
  }

  protected createInvocation(
    params: URLScanToolParams,
  ): ToolInvocation<URLScanToolParams, ToolResult> {
    return new URLScanToolInvocation(this.config, params);
  }
}
