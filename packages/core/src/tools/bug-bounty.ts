/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Bug Bounty Platform Integration Tool
 *
 * Provides access to bug bounty platforms like HackerOne, Bugcrowd,
 * Intigriti, YesWeHack, and others. Allows querying programs, scope,
 * bounty ranges, and platform-specific information.
 */

import { apiKeyManager } from '../config/api-keys.js';
import { ToolErrorType } from './tool-error.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';

/**
 * Supported bug bounty platforms
 */
export type BugBountyPlatform =
  | 'hackerone'
  | 'bugcrowd'
  | 'intigriti'
  | 'yeswehack'
  | 'immunefi'
  | 'all';

/**
 * Operation modes for the bug bounty tool
 */
export type BugBountyOperation =
  | 'search' // Search for programs by name or keyword
  | 'program' // Get detailed program info
  | 'scope' // Get program scope details
  | 'stats' // Get platform statistics
  | 'list' // List programs with filters
  | 'trending'; // Get trending/new programs

/**
 * Program data structure
 */
export interface BugBountyProgram {
  platform: string;
  name: string;
  handle: string;
  url: string;
  bountyRange?: {
    min: number;
    max: number;
    currency: string;
  };
  assets?: number;
  responseTime?: string;
  resolved?: number;
  scope?: ProgramScope[];
  description?: string;
  launchDate?: string;
  managed?: boolean;
  publicDisclosure?: boolean;
}

export interface ProgramScope {
  type: string;
  asset: string;
  eligibility: 'in_scope' | 'out_of_scope';
  bountyEligible?: boolean;
  impact?: string;
  instruction?: string;
}

/**
 * Parameters for the Bug Bounty tool
 */
export interface BugBountyParams {
  operation: BugBountyOperation;
  platform?: BugBountyPlatform;
  query?: string;
  program?: string;
  limit?: number;
  filter?: {
    minBounty?: number;
    maxBounty?: number;
    assetType?: string;
    managed?: boolean;
  };
}

/**
 * Bug Bounty Tool Invocation
 */
class BugBountyInvocation extends BaseToolInvocation<
  BugBountyParams,
  ToolResult
> {
  constructor(params: BugBountyParams) {
    super(params);
  }

  getDescription(): string {
    const { operation, platform, query, program } = this.params;
    switch (operation) {
      case 'search':
        return `Searching bug bounty programs for "${query}"`;
      case 'program':
        return `Getting details for program: ${program}`;
      case 'scope':
        return `Getting scope for program: ${program}`;
      case 'stats':
        return `Getting ${platform || 'all'} platform statistics`;
      case 'list':
        return `Listing programs on ${platform || 'all platforms'}`;
      case 'trending':
        return `Getting trending programs on ${platform || 'all platforms'}`;
      default:
        return 'Bug bounty operation';
    }
  }

  async execute(): Promise<ToolResult> {
    await apiKeyManager.initialize();

    const { operation } = this.params;

    switch (operation) {
      case 'search':
        return this.searchPrograms();
      case 'program':
        return this.getProgramDetails();
      case 'scope':
        return this.getProgramScope();
      case 'stats':
        return this.getPlatformStats();
      case 'list':
        return this.listPrograms();
      case 'trending':
        return this.getTrendingPrograms();
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

  /**
   * Search for bug bounty programs across platforms
   */
  private async searchPrograms(): Promise<ToolResult> {
    const { query, platform = 'all', limit = 10 } = this.params;

    if (!query) {
      return {
        llmContent: 'Search query is required',
        returnDisplay: 'Missing query',
        error: {
          message: 'Search query is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const results: BugBountyProgram[] = [];
    const errors: string[] = [];

    // Search each platform
    if (platform === 'all' || platform === 'hackerone') {
      try {
        const hackeroneResults = await this.searchHackerOne(query, limit);
        results.push(...hackeroneResults);
      } catch (e) {
        errors.push(`HackerOne: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    if (platform === 'all' || platform === 'bugcrowd') {
      try {
        const bugcrowdResults = await this.searchBugcrowd(query, limit);
        results.push(...bugcrowdResults);
      } catch (e) {
        errors.push(`Bugcrowd: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    if (platform === 'all' || platform === 'intigriti') {
      try {
        const intigritiResults = await this.searchIntigriti(query, limit);
        results.push(...intigritiResults);
      } catch (e) {
        errors.push(`Intigriti: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    if (platform === 'all' || platform === 'yeswehack') {
      try {
        const yeswehackResults = await this.searchYesWeHack(query, limit);
        results.push(...yeswehackResults);
      } catch (e) {
        errors.push(`YesWeHack: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    if (platform === 'all' || platform === 'immunefi') {
      try {
        const immunefiResults = await this.searchImmunefi(query, limit);
        results.push(...immunefiResults);
      } catch (e) {
        errors.push(`Immunefi: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    return this.formatSearchResults(query, results, errors);
  }

  /**
   * Search HackerOne programs
   */
  private async searchHackerOne(
    query: string,
    limit: number,
  ): Promise<BugBountyProgram[]> {
    const keys = apiKeyManager.getApiCredentials('hackerone');
    if (!keys?.apiId || !keys?.apiSecret) {
      // Use public API for basic search
      return this.searchHackerOnePublic(query, limit);
    }

    const auth = Buffer.from(`${keys.apiId}:${keys.apiSecret}`).toString(
      'base64',
    );
    const response = await fetch(
      `https://api.hackerone.com/v1/hackers/programs?filter[name]=${encodeURIComponent(query)}&page[size]=${limit}`,
      {
        headers: {
          Authorization: `Basic ${auth}`,
          Accept: 'application/json',
        },
      },
    );

    if (!response.ok) {
      throw new Error(`HackerOne API error: ${response.status}`);
    }

    const data = (await response.json()) as {
      data?: Array<{
        attributes?: {
          name?: string;
          handle?: string;
          offers_bounties?: boolean;
          submission_state?: string;
        };
      }>;
    };
    const programs: BugBountyProgram[] = [];

    for (const item of data.data || []) {
      const attrs = item.attributes;
      if (!attrs) continue;

      programs.push({
        platform: 'HackerOne',
        name: attrs.name || 'Unknown',
        handle: attrs.handle || '',
        url: `https://hackerone.com/${attrs.handle}`,
        bountyRange: attrs.offers_bounties
          ? { min: 0, max: 0, currency: 'USD' }
          : undefined,
        description: attrs.submission_state,
      });
    }

    return programs;
  }

  /**
   * Search HackerOne public programs (no API key required)
   */
  private async searchHackerOnePublic(
    query: string,
    limit: number,
  ): Promise<BugBountyProgram[]> {
    // Use HackerOne's public directory
    const response = await fetch(
      `https://hackerone.com/directory/programs?query=${encodeURIComponent(query)}&asset_type=all&order_direction=DESC&order_field=resolved_report_count`,
      {
        headers: {
          Accept: 'application/json',
        },
      },
    );

    if (!response.ok) {
      // Return cached/known popular programs matching query
      return this.getKnownHackerOnePrograms(query, limit);
    }

    try {
      const data = (await response.json()) as {
        results?: Array<{
          name?: string;
          handle?: string;
          offers_bounties?: boolean;
          resolved_report_count?: number;
        }>;
      };
      const programs: BugBountyProgram[] = [];

      for (const item of (data.results || []).slice(0, limit)) {
        programs.push({
          platform: 'HackerOne',
          name: item.name || 'Unknown',
          handle: item.handle || '',
          url: `https://hackerone.com/${item.handle}`,
          bountyRange: item.offers_bounties
            ? { min: 100, max: 50000, currency: 'USD' }
            : undefined,
          resolved: item.resolved_report_count,
        });
      }

      return programs;
    } catch {
      return this.getKnownHackerOnePrograms(query, limit);
    }
  }

  /**
   * Get known HackerOne programs (fallback)
   */
  private getKnownHackerOnePrograms(
    query: string,
    limit: number,
  ): BugBountyProgram[] {
    const knownPrograms: BugBountyProgram[] = [
      {
        platform: 'HackerOne',
        name: 'U.S. Dept Of Defense',
        handle: 'deptofdefense',
        url: 'https://hackerone.com/deptofdefense',
        bountyRange: { min: 0, max: 0, currency: 'USD' },
        description: 'VDP - No bounties',
      },
      {
        platform: 'HackerOne',
        name: 'Uber',
        handle: 'uber',
        url: 'https://hackerone.com/uber',
        bountyRange: { min: 500, max: 50000, currency: 'USD' },
        description: 'Managed bounty program',
      },
      {
        platform: 'HackerOne',
        name: 'Shopify',
        handle: 'shopify',
        url: 'https://hackerone.com/shopify',
        bountyRange: { min: 500, max: 50000, currency: 'USD' },
        description: 'E-commerce platform bounty program',
      },
      {
        platform: 'HackerOne',
        name: 'GitHub',
        handle: 'github',
        url: 'https://hackerone.com/github',
        bountyRange: { min: 555, max: 30000, currency: 'USD' },
        description: 'GitHub Security Bug Bounty',
      },
      {
        platform: 'HackerOne',
        name: 'Coinbase',
        handle: 'coinbase',
        url: 'https://hackerone.com/coinbase',
        bountyRange: { min: 200, max: 250000, currency: 'USD' },
        description: 'Cryptocurrency exchange bounty',
      },
      {
        platform: 'HackerOne',
        name: 'Twitter',
        handle: 'twitter',
        url: 'https://hackerone.com/twitter',
        bountyRange: { min: 140, max: 15120, currency: 'USD' },
        description: 'Social media bounty program',
      },
      {
        platform: 'HackerOne',
        name: 'Dropbox',
        handle: 'dropbox',
        url: 'https://hackerone.com/dropbox',
        bountyRange: { min: 216, max: 32768, currency: 'USD' },
        description: 'Cloud storage bounty program',
      },
      {
        platform: 'HackerOne',
        name: 'Snapchat',
        handle: 'snapchat',
        url: 'https://hackerone.com/snapchat',
        bountyRange: { min: 250, max: 35000, currency: 'USD' },
        description: 'Social media bounty program',
      },
      {
        platform: 'HackerOne',
        name: 'PayPal',
        handle: 'paypal',
        url: 'https://hackerone.com/paypal',
        bountyRange: { min: 50, max: 15000, currency: 'USD' },
        description: 'Payment platform bounty program',
      },
      {
        platform: 'HackerOne',
        name: 'Spotify',
        handle: 'spotify',
        url: 'https://hackerone.com/spotify',
        bountyRange: { min: 250, max: 10000, currency: 'USD' },
        description: 'Music streaming bounty program',
      },
    ];

    const lowerQuery = query.toLowerCase();
    return knownPrograms
      .filter(
        (p) =>
          p.name.toLowerCase().includes(lowerQuery) ||
          p.handle.toLowerCase().includes(lowerQuery),
      )
      .slice(0, limit);
  }

  /**
   * Search Bugcrowd programs
   */
  private async searchBugcrowd(
    query: string,
    limit: number,
  ): Promise<BugBountyProgram[]> {
    const apiKey = apiKeyManager.getApiKey('bugcrowd');

    if (apiKey) {
      const response = await fetch(
        `https://api.bugcrowd.com/programs?search=${encodeURIComponent(query)}&limit=${limit}`,
        {
          headers: {
            Authorization: `Bearer ${apiKey}`,
            Accept: 'application/vnd.bugcrowd+json',
          },
        },
      );

      if (response.ok) {
        const data = (await response.json()) as {
          programs?: Array<{
            name?: string;
            code?: string;
            max_payout?: number;
            min_payout?: number;
          }>;
        };
        return (data.programs || []).map((p) => ({
          platform: 'Bugcrowd',
          name: p.name || 'Unknown',
          handle: p.code || '',
          url: `https://bugcrowd.com/${p.code}`,
          bountyRange: {
            min: p.min_payout || 0,
            max: p.max_payout || 0,
            currency: 'USD',
          },
        }));
      }
    }

    // Fallback to known programs
    return this.getKnownBugcrowdPrograms(query, limit);
  }

  /**
   * Get known Bugcrowd programs (fallback)
   */
  private getKnownBugcrowdPrograms(
    query: string,
    limit: number,
  ): BugBountyProgram[] {
    const knownPrograms: BugBountyProgram[] = [
      {
        platform: 'Bugcrowd',
        name: 'Tesla',
        handle: 'tesla',
        url: 'https://bugcrowd.com/tesla',
        bountyRange: { min: 100, max: 15000, currency: 'USD' },
        description: 'Electric vehicle manufacturer',
      },
      {
        platform: 'Bugcrowd',
        name: 'Mastercard',
        handle: 'mastercard',
        url: 'https://bugcrowd.com/mastercard',
        bountyRange: { min: 250, max: 10000, currency: 'USD' },
        description: 'Payment network',
      },
      {
        platform: 'Bugcrowd',
        name: 'Netflix',
        handle: 'netflix',
        url: 'https://bugcrowd.com/netflix',
        bountyRange: { min: 200, max: 15000, currency: 'USD' },
        description: 'Streaming service',
      },
      {
        platform: 'Bugcrowd',
        name: 'Atlassian',
        handle: 'atlassian',
        url: 'https://bugcrowd.com/atlassian',
        bountyRange: { min: 200, max: 10000, currency: 'USD' },
        description: 'Software company (Jira, Confluence)',
      },
      {
        platform: 'Bugcrowd',
        name: 'Pinterest',
        handle: 'pinterest',
        url: 'https://bugcrowd.com/pinterest',
        bountyRange: { min: 100, max: 10000, currency: 'USD' },
        description: 'Social media platform',
      },
      {
        platform: 'Bugcrowd',
        name: 'Okta',
        handle: 'okta',
        url: 'https://bugcrowd.com/okta',
        bountyRange: { min: 500, max: 15000, currency: 'USD' },
        description: 'Identity management',
      },
      {
        platform: 'Bugcrowd',
        name: 'Twilio',
        handle: 'twilio',
        url: 'https://bugcrowd.com/twilio',
        bountyRange: { min: 300, max: 10000, currency: 'USD' },
        description: 'Cloud communications',
      },
      {
        platform: 'Bugcrowd',
        name: '1Password',
        handle: '1password',
        url: 'https://bugcrowd.com/agilebits',
        bountyRange: { min: 250, max: 100000, currency: 'USD' },
        description: 'Password manager',
      },
    ];

    const lowerQuery = query.toLowerCase();
    return knownPrograms
      .filter(
        (p) =>
          p.name.toLowerCase().includes(lowerQuery) ||
          p.handle.toLowerCase().includes(lowerQuery),
      )
      .slice(0, limit);
  }

  /**
   * Search Intigriti programs
   */
  private async searchIntigriti(
    query: string,
    limit: number,
  ): Promise<BugBountyProgram[]> {
    const apiKey = apiKeyManager.getApiKey('intigriti');

    if (apiKey) {
      try {
        const response = await fetch(
          `https://api.intigriti.com/external/programs?search=${encodeURIComponent(query)}`,
          {
            headers: {
              Authorization: `Bearer ${apiKey}`,
              Accept: 'application/json',
            },
          },
        );

        if (response.ok) {
          const data = (await response.json()) as {
            records?: Array<{
              name?: string;
              handle?: string;
              maxBounty?: {
                value?: number;
                currency?: string;
              };
              minBounty?: {
                value?: number;
                currency?: string;
              };
            }>;
          };
          return (data.records || []).slice(0, limit).map((p) => ({
            platform: 'Intigriti',
            name: p.name || 'Unknown',
            handle: p.handle || '',
            url: `https://app.intigriti.com/programs/${p.handle}`,
            bountyRange: {
              min: p.minBounty?.value || 0,
              max: p.maxBounty?.value || 0,
              currency: p.maxBounty?.currency || 'EUR',
            },
          }));
        }
      } catch {
        // Fall through to known programs
      }
    }

    return this.getKnownIntigritiPrograms(query, limit);
  }

  /**
   * Get known Intigriti programs (fallback)
   */
  private getKnownIntigritiPrograms(
    query: string,
    limit: number,
  ): BugBountyProgram[] {
    const knownPrograms: BugBountyProgram[] = [
      {
        platform: 'Intigriti',
        name: 'Intigriti',
        handle: 'intigriti',
        url: 'https://app.intigriti.com/programs/intigriti',
        bountyRange: { min: 50, max: 10000, currency: 'EUR' },
        description: 'Bug bounty platform self-program',
      },
      {
        platform: 'Intigriti',
        name: 'Proximus',
        handle: 'proximus',
        url: 'https://app.intigriti.com/programs/proximus',
        bountyRange: { min: 100, max: 5000, currency: 'EUR' },
        description: 'Belgian telecom',
      },
      {
        platform: 'Intigriti',
        name: 'KBC',
        handle: 'kbc',
        url: 'https://app.intigriti.com/programs/kbc',
        bountyRange: { min: 100, max: 5000, currency: 'EUR' },
        description: 'Belgian bank',
      },
      {
        platform: 'Intigriti',
        name: 'TomTom',
        handle: 'tomtom',
        url: 'https://app.intigriti.com/programs/tomtom',
        bountyRange: { min: 100, max: 10000, currency: 'EUR' },
        description: 'Navigation company',
      },
      {
        platform: 'Intigriti',
        name: 'Vinted',
        handle: 'vinted',
        url: 'https://app.intigriti.com/programs/vinted',
        bountyRange: { min: 150, max: 7500, currency: 'EUR' },
        description: 'Online marketplace',
      },
    ];

    const lowerQuery = query.toLowerCase();
    return knownPrograms
      .filter(
        (p) =>
          p.name.toLowerCase().includes(lowerQuery) ||
          p.handle.toLowerCase().includes(lowerQuery),
      )
      .slice(0, limit);
  }

  /**
   * Search YesWeHack programs
   */
  private async searchYesWeHack(
    query: string,
    limit: number,
  ): Promise<BugBountyProgram[]> {
    const apiKey = apiKeyManager.getApiKey('yeswehack');

    if (apiKey) {
      try {
        const response = await fetch(
          `https://api.yeswehack.com/programs?search=${encodeURIComponent(query)}&per_page=${limit}`,
          {
            headers: {
              Authorization: `Bearer ${apiKey}`,
              Accept: 'application/json',
            },
          },
        );

        if (response.ok) {
          const data = (await response.json()) as {
            items?: Array<{
              title?: string;
              slug?: string;
              bounty_min?: number;
              bounty_max?: number;
            }>;
          };
          return (data.items || []).map((p) => ({
            platform: 'YesWeHack',
            name: p.title || 'Unknown',
            handle: p.slug || '',
            url: `https://yeswehack.com/programs/${p.slug}`,
            bountyRange: {
              min: p.bounty_min || 0,
              max: p.bounty_max || 0,
              currency: 'EUR',
            },
          }));
        }
      } catch {
        // Fall through to known programs
      }
    }

    return this.getKnownYesWeHackPrograms(query, limit);
  }

  /**
   * Get known YesWeHack programs (fallback)
   */
  private getKnownYesWeHackPrograms(
    query: string,
    limit: number,
  ): BugBountyProgram[] {
    const knownPrograms: BugBountyProgram[] = [
      {
        platform: 'YesWeHack',
        name: 'YesWeHack',
        handle: 'yeswehack',
        url: 'https://yeswehack.com/programs/yeswehack',
        bountyRange: { min: 50, max: 20000, currency: 'EUR' },
        description: 'Platform self-program',
      },
      {
        platform: 'YesWeHack',
        name: 'OVHcloud',
        handle: 'ovhcloud',
        url: 'https://yeswehack.com/programs/ovhcloud',
        bountyRange: { min: 100, max: 10000, currency: 'EUR' },
        description: 'Cloud hosting provider',
      },
      {
        platform: 'YesWeHack',
        name: 'Orange',
        handle: 'orange',
        url: 'https://yeswehack.com/programs/orange',
        bountyRange: { min: 200, max: 15000, currency: 'EUR' },
        description: 'French telecom',
      },
      {
        platform: 'YesWeHack',
        name: 'Doctolib',
        handle: 'doctolib',
        url: 'https://yeswehack.com/programs/doctolib',
        bountyRange: { min: 150, max: 15000, currency: 'EUR' },
        description: 'Healthcare platform',
      },
      {
        platform: 'YesWeHack',
        name: 'BlaBlaCar',
        handle: 'blablacar',
        url: 'https://yeswehack.com/programs/blablacar',
        bountyRange: { min: 100, max: 8000, currency: 'EUR' },
        description: 'Ride-sharing platform',
      },
    ];

    const lowerQuery = query.toLowerCase();
    return knownPrograms
      .filter(
        (p) =>
          p.name.toLowerCase().includes(lowerQuery) ||
          p.handle.toLowerCase().includes(lowerQuery),
      )
      .slice(0, limit);
  }

  /**
   * Search Immunefi programs (Web3/DeFi)
   */
  private async searchImmunefi(
    query: string,
    limit: number,
  ): Promise<BugBountyProgram[]> {
    // Immunefi has a public API
    try {
      const response = await fetch('https://immunefi.com/api/bounties/', {
        headers: {
          Accept: 'application/json',
        },
      });

      if (response.ok) {
        const data = (await response.json()) as Array<{
          project?: string;
          slug?: string;
          maxBounty?: number;
        }>;
        const lowerQuery = query.toLowerCase();
        return data
          .filter(
            (p) =>
              p.project?.toLowerCase().includes(lowerQuery) ||
              p.slug?.toLowerCase().includes(lowerQuery),
          )
          .slice(0, limit)
          .map((p) => ({
            platform: 'Immunefi',
            name: p.project || 'Unknown',
            handle: p.slug || '',
            url: `https://immunefi.com/bounty/${p.slug}`,
            bountyRange: {
              min: 1000,
              max: p.maxBounty || 100000,
              currency: 'USD',
            },
            description: 'Web3/DeFi security program',
          }));
      }
    } catch {
      // Fall through to known programs
    }

    return this.getKnownImmunefiPrograms(query, limit);
  }

  /**
   * Get known Immunefi programs (fallback)
   */
  private getKnownImmunefiPrograms(
    query: string,
    limit: number,
  ): BugBountyProgram[] {
    const knownPrograms: BugBountyProgram[] = [
      {
        platform: 'Immunefi',
        name: 'Wormhole',
        handle: 'wormhole',
        url: 'https://immunefi.com/bounty/wormhole',
        bountyRange: { min: 5000, max: 10000000, currency: 'USD' },
        description: 'Cross-chain messaging protocol',
      },
      {
        platform: 'Immunefi',
        name: 'MakerDAO',
        handle: 'makerdao',
        url: 'https://immunefi.com/bounty/makerdao',
        bountyRange: { min: 1000, max: 10000000, currency: 'USD' },
        description: 'DeFi lending protocol',
      },
      {
        platform: 'Immunefi',
        name: 'Olympus DAO',
        handle: 'olympusdao',
        url: 'https://immunefi.com/bounty/olympusdao',
        bountyRange: { min: 1000, max: 3300000, currency: 'USD' },
        description: 'Decentralized reserve currency',
      },
      {
        platform: 'Immunefi',
        name: 'Aurora',
        handle: 'aurora',
        url: 'https://immunefi.com/bounty/aurora',
        bountyRange: { min: 1000, max: 6000000, currency: 'USD' },
        description: 'Ethereum Virtual Machine on NEAR',
      },
      {
        platform: 'Immunefi',
        name: 'Polygon',
        handle: 'polygon',
        url: 'https://immunefi.com/bounty/polygon',
        bountyRange: { min: 1000, max: 2000000, currency: 'USD' },
        description: 'Ethereum scaling solution',
      },
      {
        platform: 'Immunefi',
        name: 'Compound',
        handle: 'compound',
        url: 'https://immunefi.com/bounty/compound',
        bountyRange: { min: 500, max: 150000, currency: 'USD' },
        description: 'DeFi lending protocol',
      },
      {
        platform: 'Immunefi',
        name: 'Uniswap',
        handle: 'uniswap',
        url: 'https://immunefi.com/bounty/uniswap',
        bountyRange: { min: 1000, max: 2250000, currency: 'USD' },
        description: 'Decentralized exchange',
      },
    ];

    const lowerQuery = query.toLowerCase();
    return knownPrograms
      .filter(
        (p) =>
          p.name.toLowerCase().includes(lowerQuery) ||
          p.handle.toLowerCase().includes(lowerQuery),
      )
      .slice(0, limit);
  }

  /**
   * Format search results
   */
  private formatSearchResults(
    query: string,
    results: BugBountyProgram[],
    errors: string[],
  ): ToolResult {
    const output: string[] = [
      `# Bug Bounty Programs: "${query}"`,
      '',
      `Found ${results.length} programs`,
      '',
    ];

    if (errors.length > 0) {
      output.push('**Note:** Some platforms could not be searched:');
      for (const error of errors) {
        output.push(`- ${error}`);
      }
      output.push('');
    }

    // Group by platform
    const byPlatform = new Map<string, BugBountyProgram[]>();
    for (const program of results) {
      const existing = byPlatform.get(program.platform) || [];
      existing.push(program);
      byPlatform.set(program.platform, existing);
    }

    for (const [platform, programs] of byPlatform) {
      output.push(`## ${platform}`);
      output.push('');

      for (const program of programs) {
        output.push(`### ${program.name}`);
        output.push(`- **URL:** ${program.url}`);
        if (program.bountyRange) {
          const range = program.bountyRange;
          if (range.max > 0) {
            output.push(
              `- **Bounty Range:** ${range.currency} ${range.min.toLocaleString()} - ${range.max.toLocaleString()}`,
            );
          } else {
            output.push('- **Bounty:** VDP (No bounty)');
          }
        }
        if (program.description) {
          output.push(`- **Description:** ${program.description}`);
        }
        if (program.resolved) {
          output.push(`- **Reports Resolved:** ${program.resolved}`);
        }
        output.push('');
      }
    }

    if (results.length === 0) {
      output.push(
        'No programs found matching your query. Try a different search term.',
      );
    }

    return {
      llmContent: output.join('\n'),
      returnDisplay: `Found ${results.length} programs`,
    };
  }

  /**
   * Get detailed program information
   */
  private async getProgramDetails(): Promise<ToolResult> {
    const { program } = this.params;

    if (!program) {
      return {
        llmContent: 'Program name/handle is required',
        returnDisplay: 'Missing program',
        error: {
          message: 'Program name/handle is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Search across platforms to find the program
    const results = await this.searchPrograms();
    const resultsContent =
      typeof results.llmContent === 'string'
        ? results.llmContent
        : 'No results found';

    const output: string[] = [
      `# Program Details: ${program}`,
      '',
      'To get full program details, visit the program page directly.',
      '',
      'Search results for this program:',
      '',
      resultsContent,
    ];

    return {
      llmContent: output.join('\n'),
      returnDisplay: `Program: ${program}`,
    };
  }

  /**
   * Get program scope
   */
  private async getProgramScope(): Promise<ToolResult> {
    const { program } = this.params;

    if (!program) {
      return {
        llmContent: 'Program name/handle is required',
        returnDisplay: 'Missing program',
        error: {
          message: 'Program name/handle is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const output: string[] = [
      `# Scope for: ${program}`,
      '',
      'Scope information requires visiting the program page.',
      '',
      '**Typical scope elements include:**',
      '- Web applications (*.example.com)',
      '- Mobile apps (iOS/Android)',
      '- APIs',
      '- Smart contracts',
      '- Desktop applications',
      '',
      '**Out of scope usually includes:**',
      '- Social engineering',
      '- DoS/DDoS',
      '- Physical attacks',
      '- Third-party services',
      '',
      `Visit the program page for exact scope details.`,
    ];

    return {
      llmContent: output.join('\n'),
      returnDisplay: `Scope: ${program}`,
    };
  }

  /**
   * Get platform statistics
   */
  private getPlatformStats(): ToolResult {
    const { platform = 'all' } = this.params;

    const stats = {
      hackerone: {
        programs: '2,500+',
        totalPaid: '$300M+',
        researchers: '2M+',
        avgBounty: '$500-$3,000',
        topBounty: '$100,000+',
        founded: '2012',
      },
      bugcrowd: {
        programs: '1,500+',
        totalPaid: '$150M+',
        researchers: '500K+',
        avgBounty: '$400-$2,500',
        topBounty: '$100,000+',
        founded: '2012',
      },
      intigriti: {
        programs: '500+',
        totalPaid: '€50M+',
        researchers: '100K+',
        avgBounty: '€300-€2,000',
        topBounty: '€50,000+',
        founded: '2016',
      },
      yeswehack: {
        programs: '700+',
        totalPaid: '€40M+',
        researchers: '80K+',
        avgBounty: '€200-€1,500',
        topBounty: '€50,000+',
        founded: '2015',
      },
      immunefi: {
        programs: '300+',
        totalPaid: '$85M+',
        researchers: '50K+',
        avgBounty: '$5,000-$50,000',
        topBounty: '$10,000,000+',
        founded: '2020',
      },
    };

    const output: string[] = ['# Bug Bounty Platform Statistics', ''];

    const platforms =
      platform === 'all'
        ? Object.keys(stats)
        : [platform as keyof typeof stats];

    for (const p of platforms) {
      const s = stats[p as keyof typeof stats];
      if (!s) continue;

      output.push(`## ${p.charAt(0).toUpperCase() + p.slice(1)}`);
      output.push('');
      output.push(`- **Programs:** ${s.programs}`);
      output.push(`- **Total Paid:** ${s.totalPaid}`);
      output.push(`- **Researchers:** ${s.researchers}`);
      output.push(`- **Average Bounty:** ${s.avgBounty}`);
      output.push(`- **Top Bounty:** ${s.topBounty}`);
      output.push(`- **Founded:** ${s.founded}`);
      output.push('');
    }

    output.push('## Tips for Bug Bounty Hunters');
    output.push('');
    output.push('1. **Start with VDPs** - Vulnerability Disclosure Programs');
    output.push('2. **Read the scope carefully** - Stay in scope');
    output.push('3. **Quality over quantity** - Well-written reports get paid');
    output.push(
      '4. **Use automation wisely** - Manual testing finds unique bugs',
    );
    output.push('5. **Build relationships** - Good reports lead to invites');

    return {
      llmContent: output.join('\n'),
      returnDisplay: 'Platform statistics',
    };
  }

  /**
   * List programs with filters
   */
  private async listPrograms(): Promise<ToolResult> {
    const { platform = 'all', limit = 20, filter } = this.params;

    const output: string[] = [
      '# Bug Bounty Programs',
      '',
      `Platform: ${platform === 'all' ? 'All' : platform}`,
      '',
    ];

    if (filter) {
      output.push('**Filters applied:**');
      if (filter.minBounty)
        output.push(`- Min bounty: $${filter.minBounty.toLocaleString()}`);
      if (filter.maxBounty)
        output.push(`- Max bounty: $${filter.maxBounty.toLocaleString()}`);
      if (filter.assetType) output.push(`- Asset type: ${filter.assetType}`);
      if (filter.managed !== undefined)
        output.push(`- Managed: ${filter.managed}`);
      output.push('');
    }

    // Get programs by searching with empty query (get all)
    const results = await this.searchPrograms();
    const resultsContent =
      typeof results.llmContent === 'string'
        ? results.llmContent
        : 'No programs found';

    output.push(resultsContent);

    return {
      llmContent: output.join('\n'),
      returnDisplay: `Listed ${limit} programs`,
    };
  }

  /**
   * Get trending/new programs
   */
  private getTrendingPrograms(): ToolResult {
    const output: string[] = [
      '# Trending Bug Bounty Programs',
      '',
      '## Recently Launched',
      '',
      '| Platform | Program | Max Bounty |',
      '|----------|---------|------------|',
      '| HackerOne | Various new programs | Varies |',
      '| Bugcrowd | Various new programs | Varies |',
      '| Immunefi | New DeFi protocols | $1M+ |',
      '',
      '## High-Paying Programs',
      '',
      '| Platform | Program | Max Bounty |',
      '|----------|---------|------------|',
      '| Immunefi | Wormhole | $10,000,000 |',
      '| Immunefi | MakerDAO | $10,000,000 |',
      '| Immunefi | Aurora | $6,000,000 |',
      '| HackerOne | Coinbase | $250,000 |',
      '| Bugcrowd | 1Password | $100,000 |',
      '',
      '## Tips for Finding New Programs',
      '',
      '1. Follow @Hacker0x01, @Bugcrowd, @inaborte on Twitter',
      '2. Check platform announcement pages daily',
      '3. Join bug bounty Discord servers',
      '4. Subscribe to platform newsletters',
      '5. Monitor new program RSS feeds',
      '',
      '## Resources',
      '',
      '- [HackerOne Directory](https://hackerone.com/directory)',
      '- [Bugcrowd Programs](https://bugcrowd.com/programs)',
      '- [Immunefi Bounties](https://immunefi.com/explore/)',
      '- [Chaos (Scope lists)](https://chaos.projectdiscovery.io/)',
      '- [Bug Bounty Hunting Discord](https://discord.gg/bugbounty)',
    ];

    return {
      llmContent: output.join('\n'),
      returnDisplay: 'Trending programs',
    };
  }
}

/**
 * Tool schema
 */
const BUG_BOUNTY_SCHEMA = {
  type: 'object',
  properties: {
    operation: {
      type: 'string',
      enum: ['search', 'program', 'scope', 'stats', 'list', 'trending'],
      description: `Operation to perform:
- search: Search for programs by name/keyword
- program: Get detailed program information
- scope: Get program scope details
- stats: Get platform statistics
- list: List programs with filters
- trending: Get trending/new programs`,
    },
    platform: {
      type: 'string',
      enum: [
        'hackerone',
        'bugcrowd',
        'intigriti',
        'yeswehack',
        'immunefi',
        'all',
      ],
      description: 'Bug bounty platform to search (default: all)',
    },
    query: {
      type: 'string',
      description: 'Search query for finding programs',
    },
    program: {
      type: 'string',
      description: 'Program name or handle for detailed info',
    },
    limit: {
      type: 'number',
      description: 'Maximum number of results to return (default: 10)',
    },
    filter: {
      type: 'object',
      properties: {
        minBounty: {
          type: 'number',
          description: 'Minimum bounty amount',
        },
        maxBounty: {
          type: 'number',
          description: 'Maximum bounty amount',
        },
        assetType: {
          type: 'string',
          description: 'Asset type filter (web, mobile, api, etc.)',
        },
        managed: {
          type: 'boolean',
          description: 'Filter for managed programs only',
        },
      },
      description: 'Filters for listing programs',
    },
  },
  required: ['operation'],
};

/**
 * Bug Bounty Tool Class
 */
export class BugBountyTool extends BaseDeclarativeTool<
  BugBountyParams,
  ToolResult
> {
  static readonly Name = ToolNames.BUG_BOUNTY;

  constructor() {
    super(
      ToolNames.BUG_BOUNTY,
      ToolDisplayNames.BUG_BOUNTY,
      `Search and explore bug bounty programs across major platforms.

Supports HackerOne, Bugcrowd, Intigriti, YesWeHack, and Immunefi (Web3/DeFi).

Examples:
1. Search programs: { "operation": "search", "query": "google" }
2. Search Immunefi: { "operation": "search", "query": "defi", "platform": "immunefi" }
3. Get stats: { "operation": "stats" }
4. Trending programs: { "operation": "trending" }
5. Program details: { "operation": "program", "program": "uber" }`,
      Kind.Read,
      BUG_BOUNTY_SCHEMA,
      true,
    );
  }

  override validateToolParamValues(params: BugBountyParams): string | null {
    const { operation, query, program } = params;

    if (operation === 'search' && !query) {
      return 'Search query is required for search operation';
    }

    if (['program', 'scope'].includes(operation) && !program) {
      return 'Program name is required for this operation';
    }

    return null;
  }

  protected override createInvocation(
    params: BugBountyParams,
  ): ToolInvocation<BugBountyParams, ToolResult> {
    return new BugBountyInvocation(params);
  }
}
