/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Wayback Machine Tool for OSINT / Bug Bounty
 *
 * This tool provides access to the Internet Archive's Wayback Machine API
 * for historical website data retrieval. Useful for:
 * - Finding old/forgotten endpoints
 * - Discovering historical vulnerabilities
 * - Finding removed sensitive data
 * - Subdomain enumeration via historical records
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';

const WAYBACK_TIMEOUT_MS = 30000;
const MAX_RESULTS = 100;

// Wayback Machine CDX API base URL
const WAYBACK_CDX_API = 'https://web.archive.org/cdx/search/cdx';
const WAYBACK_AVAILABILITY_API = 'https://archive.org/wayback/available';

/**
 * Search types for Wayback Machine queries
 */
export type WaybackSearchType = 'urls' | 'snapshots' | 'availability';

/**
 * Parameters for the Wayback Machine tool
 */
export interface WaybackMachineToolParams {
  target: string;
  searchType: WaybackSearchType;
  matchType?: 'exact' | 'prefix' | 'host' | 'domain';
  filter?: string;
  from?: string;
  to?: string;
  limit?: number;
  collapseByUrl?: boolean;
}

/**
 * Wayback Machine availability response
 */
interface WaybackAvailabilityResponse {
  url: string;
  archived_snapshots: {
    closest?: {
      status: string;
      available: boolean;
      url: string;
      timestamp: string;
    };
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
 * Implementation of the Wayback Machine tool invocation logic
 */
class WaybackMachineToolInvocation extends BaseToolInvocation<
  WaybackMachineToolParams,
  ToolResult
> {
  constructor(params: WaybackMachineToolParams) {
    super(params);
  }

  getDescription(): string {
    const { target, searchType, matchType } = this.params;
    switch (searchType) {
      case 'urls':
        return `Searching Wayback Machine for archived URLs from ${target} (match: ${matchType || 'domain'})`;
      case 'snapshots':
        return `Getting snapshot history for ${target} from Wayback Machine`;
      case 'availability':
        return `Checking Wayback Machine availability for ${target}`;
      default:
        return `Querying Wayback Machine for ${target}`;
    }
  }

  async execute(): Promise<ToolResult> {
    const { searchType } = this.params;

    try {
      switch (searchType) {
        case 'urls':
          return await this.searchUrls();
        case 'snapshots':
          return await this.getSnapshots();
        case 'availability':
          return await this.checkAvailability();
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
        llmContent: `Error: Wayback Machine query failed: ${errorMessage}`,
        returnDisplay: `Wayback Machine query failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Search for archived URLs (endpoint discovery)
   */
  private async searchUrls(): Promise<ToolResult> {
    const {
      target,
      matchType = 'domain',
      filter,
      from,
      to,
      limit = MAX_RESULTS,
      collapseByUrl = true,
    } = this.params;

    const params = new URLSearchParams({
      url: target,
      output: 'json',
      fl: 'original,timestamp,statuscode,mimetype,digest',
      limit: String(limit),
      matchType,
    });

    if (filter) {
      params.append('filter', `mimetype:.*${filter}.*`);
    }
    if (from) {
      params.append('from', from);
    }
    if (to) {
      params.append('to', to);
    }
    if (collapseByUrl) {
      params.append('collapse', 'urlkey');
    }

    const url = `${WAYBACK_CDX_API}?${params.toString()}`;
    const response = await fetchWithAbort(url, {}, WAYBACK_TIMEOUT_MS);

    if (!response.ok) {
      throw new Error(`Wayback Machine API returned status ${response.status}`);
    }

    const data = (await response.json()) as string[][];

    // CDX API returns array of arrays, first row is header
    if (!data || data.length <= 1) {
      return {
        llmContent: `No archived URLs found for ${target}`,
        returnDisplay: `No archived URLs found for ${target}`,
      };
    }

    // Skip header row
    const entries = data.slice(1);

    // Parse results
    const results = entries.map((entry) => ({
      url: entry[0],
      timestamp: this.formatTimestamp(entry[1]),
      status: entry[2],
      type: entry[3],
      archiveUrl: `https://web.archive.org/web/${entry[1]}/${entry[0]}`,
    }));

    // Extract unique URLs
    const uniqueUrls = [...new Set(results.map((r) => r.url))];

    // Format output
    const summary = [
      `## Wayback Machine URL Discovery`,
      `**Target:** ${target}`,
      `**Match Type:** ${matchType}`,
      `**Total Unique URLs:** ${uniqueUrls.length}`,
      `**Total Snapshots:** ${results.length}`,
      '',
      '### Discovered URLs',
      '',
      uniqueUrls
        .slice(0, 30)
        .map((url, i) => `${i + 1}. ${url}`)
        .join('\n'),
      '',
      uniqueUrls.length > 30
        ? `_...and ${uniqueUrls.length - 30} more URLs_`
        : '',
      '',
      '### Bug Bounty Tips',
      '- Look for API endpoints, admin panels, config files',
      '- Check for .env, .git, backup files that may have been exposed',
      '- Compare old versions to find removed functionality',
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get snapshots for a specific URL
   */
  private async getSnapshots(): Promise<ToolResult> {
    const { target, from, to, limit = MAX_RESULTS } = this.params;

    const params = new URLSearchParams({
      url: target,
      output: 'json',
      fl: 'timestamp,statuscode,digest',
      limit: String(limit),
    });

    if (from) params.append('from', from);
    if (to) params.append('to', to);

    const url = `${WAYBACK_CDX_API}?${params.toString()}`;
    const response = await fetchWithAbort(url, {}, WAYBACK_TIMEOUT_MS);

    if (!response.ok) {
      throw new Error(`Wayback Machine API returned status ${response.status}`);
    }

    const data = (await response.json()) as string[][];

    if (!data || data.length <= 1) {
      return {
        llmContent: `No snapshots found for ${target}`,
        returnDisplay: `No snapshots found for ${target}`,
      };
    }

    const entries = data.slice(1);
    const snapshots = entries.map((entry) => ({
      timestamp: this.formatTimestamp(entry[0]),
      rawTimestamp: entry[0],
      status: entry[1],
      contentHash: entry[2],
      archiveUrl: `https://web.archive.org/web/${entry[0]}/${target}`,
    }));

    const summary = [
      `## Wayback Machine Snapshot History`,
      `**URL:** ${target}`,
      `**Total Snapshots:** ${snapshots.length}`,
      '',
      '### Recent Snapshots',
      '',
      ...snapshots
        .slice(0, 20)
        .map(
          (s, i) =>
            `${i + 1}. **${s.timestamp}** (Status: ${s.status}) [View](${s.archiveUrl})`,
        ),
      '',
      snapshots.length > 20
        ? `_...and ${snapshots.length - 20} more snapshots_`
        : '',
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Check if a URL has been archived
   */
  private async checkAvailability(): Promise<ToolResult> {
    const { target } = this.params;

    const url = `${WAYBACK_AVAILABILITY_API}?url=${encodeURIComponent(target)}`;
    const response = await fetchWithAbort(url, {}, WAYBACK_TIMEOUT_MS);

    if (!response.ok) {
      throw new Error(`Wayback Machine API returned status ${response.status}`);
    }

    const data = (await response.json()) as WaybackAvailabilityResponse;

    if (!data.archived_snapshots?.closest) {
      return {
        llmContent: `**URL:** ${target}\n**Status:** Not archived in Wayback Machine`,
        returnDisplay: `${target} is not archived in Wayback Machine`,
      };
    }

    const snapshot = data.archived_snapshots.closest;
    const summary = [
      `## Wayback Machine Availability`,
      `**URL:** ${target}`,
      `**Status:** Archived`,
      `**Latest Snapshot:** ${this.formatTimestamp(snapshot.timestamp)}`,
      `**Archive URL:** ${snapshot.url}`,
    ].join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Format timestamp from YYYYMMDDHHMMSS to readable format
   */
  private formatTimestamp(timestamp: string): string {
    if (!timestamp || timestamp.length < 8) return timestamp;
    const year = timestamp.substring(0, 4);
    const month = timestamp.substring(4, 6);
    const day = timestamp.substring(6, 8);
    const hour = timestamp.substring(8, 10) || '00';
    const minute = timestamp.substring(10, 12) || '00';
    const second = timestamp.substring(12, 14) || '00';
    return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
  }
}

/**
 * Wayback Machine Tool for historical website data retrieval
 */
export class WaybackMachineTool extends BaseDeclarativeTool<
  WaybackMachineToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.WAYBACK_MACHINE;

  constructor(_config: Config) {
    super(
      WaybackMachineTool.Name,
      ToolDisplayNames.WAYBACK_MACHINE,
      `Search the Wayback Machine (Internet Archive) for historical website data. Useful for OSINT, bug bounty, and security research to find:
- Old/forgotten endpoints and APIs
- Historical versions of pages
- Removed sensitive data
- Subdomain enumeration via archived URLs
- Configuration files and backups that were once exposed`,
      Kind.Fetch,
      {
        properties: {
          target: {
            type: 'string',
            description:
              'The target URL or domain to search (e.g., "example.com" or "https://example.com/api/")',
          },
          searchType: {
            type: 'string',
            enum: ['urls', 'snapshots', 'availability'],
            description:
              'Type of search: "urls" for endpoint discovery, "snapshots" for version history, "availability" to check if archived',
          },
          matchType: {
            type: 'string',
            enum: ['exact', 'prefix', 'host', 'domain'],
            description:
              'URL match type (for "urls" search): "domain" includes subdomains, "host" for single host, "prefix" for URL prefix, "exact" for exact match',
          },
          filter: {
            type: 'string',
            description:
              'Filter by file type (e.g., "js", "json", "xml", "php", "env")',
          },
          from: {
            type: 'string',
            description: 'Start date for search (format: YYYYMMDD)',
          },
          to: {
            type: 'string',
            description: 'End date for search (format: YYYYMMDD)',
          },
          limit: {
            type: 'number',
            description: `Maximum number of results to return (default: ${MAX_RESULTS})`,
          },
          collapseByUrl: {
            type: 'boolean',
            description:
              'Remove duplicate URLs keeping only one snapshot per URL (default: true)',
          },
        },
        required: ['target', 'searchType'],
        type: 'object',
      },
    );
  }

  protected createInvocation(
    params: WaybackMachineToolParams,
  ): ToolInvocation<WaybackMachineToolParams, ToolResult> {
    return new WaybackMachineToolInvocation(params);
  }
}
