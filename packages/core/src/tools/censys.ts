/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Censys Tool for OSINT / Bug Bounty
 *
 * This tool provides access to the Censys API for internet asset discovery
 * and certificate search. Useful for:
 * - Finding hosts and services associated with a target
 * - SSL/TLS certificate discovery
 * - Subdomain enumeration via certificate transparency
 * - Infrastructure mapping
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import {
  formatCVEIntelligenceSection,
  type DetectedProduct,
} from './cve-intelligence-helper.js';

const CENSYS_TIMEOUT_MS = 30000;
// Use Platform API v3 for Personal Access Token authentication
const CENSYS_API_V3_BASE = 'https://api.platform.censys.io/v3';
// Legacy Search API v2 for API ID/Secret authentication
const CENSYS_API_V2_BASE = 'https://search.censys.io/api/v2';

// Environment variables for Censys API credentials
const CENSYS_API_ID_ENV = 'CENSYS_API_ID';
const CENSYS_API_SECRET_ENV = 'CENSYS_API_SECRET';
const CENSYS_API_KEY_ENV = 'CENSYS_API_KEY';

/**
 * Search types for Censys queries
 */
export type CensysSearchType = 'hosts' | 'certificates' | 'host' | 'cert';

/**
 * Parameters for the Censys tool
 */
export interface CensysToolParams {
  searchType: CensysSearchType;
  query?: string;
  ip?: string;
  fingerprint?: string;
  perPage?: number;
  cursor?: string;
  virtualHosts?: 'INCLUDE' | 'EXCLUDE' | 'ONLY';
}

/**
 * Fetch with timeout and auth helper
 */
async function fetchWithAuth(
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
 * Implementation of the Censys tool invocation logic
 */
class CensysToolInvocation extends BaseToolInvocation<
  CensysToolParams,
  ToolResult
> {
  private readonly config: Config;

  constructor(config: Config, params: CensysToolParams) {
    super(params);
    this.config = config;
  }

  getDescription(): string {
    const { searchType, query, ip, fingerprint } = this.params;
    switch (searchType) {
      case 'hosts':
        return `Searching Censys hosts: ${query}`;
      case 'certificates':
        return `Searching Censys certificates: ${query}`;
      case 'host':
        return `Getting Censys host details for: ${ip}`;
      case 'cert':
        return `Getting Censys certificate details for: ${fingerprint}`;
      default:
        return `Querying Censys`;
    }
  }

  /**
   * Credentials can be either:
   * 1. Personal Access Token (new format): starts with 'censys_'
   * 2. API ID + Secret (legacy format): requires both values
   */
  private getCredentials():
    | { type: 'token'; token: string }
    | { type: 'basic'; apiId: string; apiSecret: string }
    | null {
    // First check for new Personal Access Token format
    const apiKey =
      this.config.getCensysApiKey() || process.env[CENSYS_API_KEY_ENV];
    if (apiKey) {
      return { type: 'token', token: apiKey };
    }

    // Fall back to legacy API ID + Secret format
    const apiId = this.config.getCensysApiId();
    const apiSecret = this.config.getCensysApiSecret();

    if (apiId && apiSecret) {
      return { type: 'basic', apiId, apiSecret };
    }

    return null;
  }

  private getAuthHeader(
    credentials:
      | { type: 'token'; token: string }
      | { type: 'basic'; apiId: string; apiSecret: string },
  ): string {
    if (credentials.type === 'token') {
      return `Bearer ${credentials.token}`;
    }
    const basicCredentials = Buffer.from(
      `${credentials.apiId}:${credentials.apiSecret}`,
    ).toString('base64');
    return `Basic ${basicCredentials}`;
  }
  async execute(): Promise<ToolResult> {
    const credentials = this.getCredentials();

    if (!credentials) {
      return {
        llmContent: `Error: Censys API credentials not found. Please configure either:\n1. Personal Access Token: advanced.censysApiKey or ${CENSYS_API_KEY_ENV} env var\n2. Legacy API ID/Secret: advanced.censysApiId + advanced.censysApiSecret or ${CENSYS_API_ID_ENV} + ${CENSYS_API_SECRET_ENV} env vars\n\nGet your API credentials at: https://search.censys.io/account/api`,
        returnDisplay: `Censys API credentials not configured. Configure in settings.json or set environment variables.`,
        error: {
          message: `Missing Censys API credentials - configure in settings.json or environment variables`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const { searchType } = this.params;

    try {
      switch (searchType) {
        case 'hosts':
          return await this.searchHosts(credentials);
        case 'certificates':
          return await this.searchCertificates(credentials);
        case 'host':
          return await this.getHost(credentials);
        case 'cert':
          return await this.getCertificate(credentials);
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
        llmContent: `Error: Censys query failed: ${errorMessage}`,
        returnDisplay: `Censys query failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Search for hosts matching a query
   * Note: Search is only available with API ID/Secret (v2 API).
   * Personal Access Tokens (v3 API) only support host lookups, not searches.
   */
  private async searchHosts(
    credentials:
      | { type: 'token'; token: string }
      | { type: 'basic'; apiId: string; apiSecret: string },
  ): Promise<ToolResult> {
    // v3 API (Personal Access Token) doesn't support search, only host lookups
    if (credentials.type === 'token') {
      return {
        llmContent: `Error: Censys search is not available with Personal Access Tokens (free tier).\n\nThe Censys Platform API v3 only supports host lookups by IP address, not searches.\n\n**Available options:**\n1. Use \`searchType: "host"\` with a specific IP address\n2. Obtain API ID/Secret credentials for search functionality\n3. Use URLScan or other tools for search-based reconnaissance`,
        returnDisplay: `Censys search requires API ID/Secret credentials. Use searchType: "host" with an IP for lookups.`,
        error: {
          message:
            'Search not available with Personal Access Token - use host lookup instead',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const {
      query,
      perPage = 25,
      cursor,
      virtualHosts = 'EXCLUDE',
    } = this.params;

    if (!query) {
      return {
        llmContent: 'Error: Search query is required',
        returnDisplay: 'Search query is required',
        error: {
          message: 'Search query is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const requestBody: Record<string, unknown> = {
      q: query,
      per_page: Math.min(perPage, 100),
      virtual_hosts: virtualHosts,
    };

    if (cursor) {
      requestBody['cursor'] = cursor;
    }

    const response = await fetchWithAuth(
      `${CENSYS_API_V2_BASE}/hosts/search`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: this.getAuthHeader(credentials),
        },
        body: JSON.stringify(requestBody),
      },
      CENSYS_TIMEOUT_MS,
    );

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Invalid Censys API credentials');
      }
      throw new Error(`Censys API returned status ${response.status}`);
    }

    const data = (await response.json()) as {
      result: {
        query: string;
        total: number;
        hits: Array<{
          ip: string;
          services?: Array<{
            port: number;
            service_name: string;
            transport_protocol: string;
          }>;
          autonomous_system?: {
            asn: number;
            name: string;
          };
          location?: {
            country?: string;
            country_code?: string;
          };
        }>;
        links: {
          next?: string;
        };
      };
    };

    if (!data.result.hits || data.result.hits.length === 0) {
      return {
        llmContent: `No hosts found for query: ${query}`,
        returnDisplay: `No hosts found for query: ${query}`,
      };
    }

    // Format results
    const results = data.result.hits.slice(0, 20).map((hit, index) => {
      const services =
        hit.services
          ?.map((s) => `${s.port}/${s.transport_protocol} (${s.service_name})`)
          .join(', ') || 'N/A';

      return [
        `### ${index + 1}. ${hit.ip}`,
        `- **Services:** ${services}`,
        hit.autonomous_system
          ? `- **ASN:** AS${hit.autonomous_system.asn} (${hit.autonomous_system.name})`
          : '',
        hit.location?.country
          ? `- **Location:** ${hit.location.country} (${hit.location.country_code})`
          : '',
      ]
        .filter(Boolean)
        .join('\n');
    });

    const summary = [
      `## Censys Host Search Results`,
      `**Query:** \`${query}\``,
      `**Total Results:** ${data.result.total}`,
      `**Showing:** ${Math.min(data.result.hits.length, 20)} results`,
      '',
      ...results,
      '',
      '### Useful Censys Query Filters',
      '- `services.port: 443` - Filter by port',
      '- `services.http.response.html_title: "Admin"` - Search by page title',
      '- `location.country: US` - Filter by country',
    ].join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Search for certificates
   * Note: Search is only available with API ID/Secret (v2 API).
   * Personal Access Tokens (v3 API) only support host lookups, not searches.
   */
  private async searchCertificates(
    credentials:
      | { type: 'token'; token: string }
      | { type: 'basic'; apiId: string; apiSecret: string },
  ): Promise<ToolResult> {
    // v3 API (Personal Access Token) doesn't support certificate search
    if (credentials.type === 'token') {
      return {
        llmContent: `Error: Censys certificate search is not available with Personal Access Tokens (free tier).\n\nThe Censys Platform API v3 only supports host lookups by IP address.\n\n**Available options:**\n1. Use \`searchType: "host"\` with a specific IP address to get certificate info\n2. Obtain API ID/Secret credentials for certificate search functionality\n3. Use other certificate transparency tools`,
        returnDisplay: `Censys certificate search requires API ID/Secret credentials. Use searchType: "host" for IP lookups.`,
        error: {
          message:
            'Certificate search not available with Personal Access Token - use host lookup instead',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const { query, perPage = 25, cursor } = this.params;

    if (!query) {
      return {
        llmContent: 'Error: Search query is required',
        returnDisplay: 'Search query is required',
        error: {
          message: 'Search query is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const requestBody: Record<string, unknown> = {
      q: query,
      per_page: Math.min(perPage, 100),
    };

    if (cursor) {
      requestBody['cursor'] = cursor;
    }

    const response = await fetchWithAuth(
      `${CENSYS_API_V2_BASE}/certificates/search`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: this.getAuthHeader(credentials),
        },
        body: JSON.stringify(requestBody),
      },
      CENSYS_TIMEOUT_MS,
    );

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Invalid Censys API credentials');
      }
      throw new Error(`Censys API returned status ${response.status}`);
    }

    const data = (await response.json()) as {
      result: {
        total: number;
        hits: Array<{
          fingerprint_sha256?: string;
          names?: string[];
          parsed?: {
            subject_dn?: string;
            issuer_dn?: string;
            validity?: {
              start?: string;
              end?: string;
            };
          };
        }>;
        links: {
          next?: string;
        };
      };
    };

    if (!data.result.hits || data.result.hits.length === 0) {
      return {
        llmContent: `No certificates found for query: ${query}`,
        returnDisplay: `No certificates found for query: ${query}`,
      };
    }

    // Extract unique domain names from certificates
    const allDomains: Set<string> = new Set();
    data.result.hits.forEach((hit) => {
      hit.names?.forEach((name) => allDomains.add(name));
    });

    const results = data.result.hits.slice(0, 15).map((hit, index) => {
      const names = hit.names?.slice(0, 5).join(', ') || 'N/A';
      return [
        `### ${index + 1}. ${hit.fingerprint_sha256?.substring(0, 16)}...`,
        `- **Subject:** ${hit.parsed?.subject_dn || 'N/A'}`,
        `- **Names:** ${names}`,
      ].join('\n');
    });

    const sortedDomains = [...allDomains].sort();

    const summary = [
      `## Censys Certificate Search Results`,
      `**Query:** \`${query}\``,
      `**Total Results:** ${data.result.total}`,
      '',
      '### Discovered Domains/Subdomains',
      `Found **${sortedDomains.length}** unique domain names:`,
      '',
      sortedDomains.slice(0, 50).join(', '),
      sortedDomains.length > 50
        ? `\n... and ${sortedDomains.length - 50} more`
        : '',
      '',
      '### Certificate Details',
      ...results,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }

  /**
   * Get details for a specific host IP
   */
  private async getHost(
    credentials:
      | { type: 'token'; token: string }
      | { type: 'basic'; apiId: string; apiSecret: string },
  ): Promise<ToolResult> {
    const { ip } = this.params;

    if (!ip) {
      return {
        llmContent: 'Error: IP address is required for host lookup',
        returnDisplay: 'IP address is required for host lookup',
        error: {
          message: 'IP address is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Use different API endpoints based on credential type
    const url =
      credentials.type === 'token'
        ? `${CENSYS_API_V3_BASE}/global/asset/host/${ip}`
        : `${CENSYS_API_V2_BASE}/hosts/${ip}`;

    const response = await fetchWithAuth(
      url,
      {
        headers: {
          Authorization: this.getAuthHeader(credentials),
          Accept: 'application/json',
        },
      },
      CENSYS_TIMEOUT_MS,
    );

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `No information found for IP: ${ip}`,
          returnDisplay: `No information found for IP: ${ip}`,
        };
      }
      throw new Error(`Censys API returned status ${response.status}`);
    }

    const rawData = await response.json();

    // Handle v3 API response format (nested under result.resource)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data =
      credentials.type === 'token'
        ? (rawData as any).result?.resource
        : (rawData as any).result;

    if (!data) {
      return {
        llmContent: `No information found for IP: ${ip}`,
        returnDisplay: `No information found for IP: ${ip}`,
      };
    }

    const reverseDns = data.dns?.reverse_dns?.names?.join(', ') || 'N/A';

    const services = data.services || [];

    // Extract detected products for CVE intelligence
    // 🔒 MEMORY OPTIMIZATION: Use Set and limit array size
    const detectedProducts: DetectedProduct[] = [];
    const seenProducts = new Set<string>();
    const MAX_PRODUCTS = 20;
    const servicesToScan = services.slice(0, 10);

    for (const service of servicesToScan) {
      if (detectedProducts.length >= MAX_PRODUCTS) break;

      const serviceName =
        (
          service as {
            protocol?: string;
            extended_service_name?: string;
            service_name?: string;
          }
        ).protocol ||
        (
          service as {
            protocol?: string;
            extended_service_name?: string;
            service_name?: string;
          }
        ).extended_service_name ||
        (
          service as {
            protocol?: string;
            extended_service_name?: string;
            service_name?: string;
          }
        ).service_name ||
        'unknown';

      // Extract software information if available
      const serviceSoftware = (
        service as {
          software?: Array<{
            product?: string;
            version?: string;
            vendor?: string;
          }>;
        }
      ).software;
      if (serviceSoftware && serviceSoftware.length > 0) {
        for (const sw of serviceSoftware) {
          if (detectedProducts.length >= MAX_PRODUCTS) break;
          if (sw.product) {
            const productKey =
              `${sw.product}:${sw.version || ''}`.toLowerCase();
            if (!seenProducts.has(productKey)) {
              seenProducts.add(productKey);
              detectedProducts.push({
                name: sw.product,
                version: sw.version || '',
                vendor: sw.vendor || '',
                confidence: sw.version ? 'high' : 'medium',
                source: `censys service on port ${(service as { port: number }).port}`,
              });
            }
          }
        }
      } else if (
        serviceName !== 'unknown' &&
        detectedProducts.length < MAX_PRODUCTS
      ) {
        // Add service name as potential product
        const productKey = serviceName.toLowerCase();
        if (!seenProducts.has(productKey)) {
          seenProducts.add(productKey);
          detectedProducts.push({
            name: serviceName,
            version: '',
            vendor: '',
            confidence: 'low',
            source: `censys service on port ${(service as { port: number }).port}`,
          });
        }
      }
    }

    const serviceInfo = services
      .slice(0, 10)
      .map(
        (service: {
          port: number;
          transport_protocol: string;
          protocol?: string;
          service_name?: string;
          extended_service_name?: string;
        }) => {
          const serviceName =
            service.protocol ||
            service.extended_service_name ||
            service.service_name ||
            'unknown';
          return `- Port ${service.port}/${service.transport_protocol}: ${serviceName}`;
        },
      );

    const summary = [
      `## Censys Host Report: ${data.ip}`,
      '',
      '### General Information',
      `- **IP:** ${data.ip}`,
      `- **Reverse DNS:** ${reverseDns}`,
      data.autonomous_system
        ? `- **ASN:** AS${data.autonomous_system.asn} (${data.autonomous_system.name || data.autonomous_system.description})`
        : '',
      data.location?.country
        ? `- **Location:** ${data.location.city || ''}, ${data.location.province || ''}, ${data.location.country}`
        : '',
      data.last_updated_at ? `- **Last Updated:** ${data.last_updated_at}` : '',
      '',
      '### Services',
      serviceInfo.length > 0 ? serviceInfo.join('\n') : '- No services found',
    ]
      .filter(Boolean)
      .join('\n');

    // Add CVE intelligence section if products detected
    const cveIntelligence =
      detectedProducts.length > 0
        ? '\n\n' + formatCVEIntelligenceSection(detectedProducts, true)
        : '';

    const fullReport = summary + cveIntelligence;

    return {
      llmContent: fullReport,
      returnDisplay: fullReport,
    };
  }

  /**
   * Get details for a specific certificate
   * Note: Certificate lookup is only available with API ID/Secret (v2 API).
   * Personal Access Tokens (v3 API) only support host lookups.
   */
  private async getCertificate(
    credentials:
      | { type: 'token'; token: string }
      | { type: 'basic'; apiId: string; apiSecret: string },
  ): Promise<ToolResult> {
    // v3 API (Personal Access Token) doesn't support certificate lookups
    if (credentials.type === 'token') {
      return {
        llmContent: `Error: Censys certificate lookup is not available with Personal Access Tokens (free tier).\n\nThe Censys Platform API v3 only supports host lookups by IP address.\n\n**Available options:**\n1. Use \`searchType: "host"\` with a specific IP address to get certificate info from services\n2. Obtain API ID/Secret credentials for direct certificate lookups`,
        returnDisplay: `Censys certificate lookup requires API ID/Secret credentials. Use searchType: "host" for IP lookups.`,
        error: {
          message:
            'Certificate lookup not available with Personal Access Token - use host lookup instead',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const { fingerprint } = this.params;

    if (!fingerprint) {
      return {
        llmContent: 'Error: Certificate fingerprint is required',
        returnDisplay: 'Certificate fingerprint is required',
        error: {
          message: 'Certificate fingerprint is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const response = await fetchWithAuth(
      `${CENSYS_API_V2_BASE}/certificates/${fingerprint}`,
      {
        headers: {
          Authorization: this.getAuthHeader(credentials),
        },
      },
      CENSYS_TIMEOUT_MS,
    );

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `No certificate found with fingerprint: ${fingerprint}`,
          returnDisplay: `No certificate found with fingerprint: ${fingerprint}`,
        };
      }
      throw new Error(`Censys API returned status ${response.status}`);
    }

    const data = (await response.json()) as {
      result: {
        fingerprint_sha256: string;
        names?: string[];
        parsed: {
          subject_dn: string;
          issuer_dn: string;
          serial_number: string;
          validity: {
            start: string;
            end: string;
          };
          extensions?: {
            subject_alt_name?: {
              dns_names?: string[];
              ip_addresses?: string[];
            };
          };
        };
      };
    };

    const cert = data.result;
    const sanDns = cert.parsed.extensions?.subject_alt_name?.dns_names || [];
    const sanIps = cert.parsed.extensions?.subject_alt_name?.ip_addresses || [];

    const summary = [
      `## Censys Certificate Details`,
      '',
      '### Certificate Information',
      `- **Fingerprint (SHA256):** ${cert.fingerprint_sha256}`,
      `- **Subject:** ${cert.parsed.subject_dn}`,
      `- **Issuer:** ${cert.parsed.issuer_dn}`,
      '',
      '### Validity Period',
      `- **Not Before:** ${cert.parsed.validity.start}`,
      `- **Not After:** ${cert.parsed.validity.end}`,
      '',
      '### Subject Alternative Names (SANs)',
      sanDns.length > 0
        ? `**DNS Names:** ${sanDns.slice(0, 20).join(', ')}`
        : '**DNS Names:** None',
      sanIps.length > 0 ? `**IP Addresses:** ${sanIps.join(', ')}` : '',
      '',
      '### All Associated Names',
      cert.names && cert.names.length > 0
        ? cert.names.slice(0, 30).join(', ')
        : 'None',
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
 * Censys Tool for internet asset discovery and certificate search
 */
export class CensysTool extends BaseDeclarativeTool<
  CensysToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.CENSYS;
  private readonly config: Config;

  constructor(config: Config) {
    super(
      CensysTool.Name,
      ToolDisplayNames.CENSYS,
      `Search Censys for internet-connected hosts and SSL certificates. API credentials can be configured either as:
1. Personal Access Token: advanced.censysApiKey or CENSYS_API_KEY env var
2. Legacy API ID/Secret: advanced.censysApiId + advanced.censysApiSecret or CENSYS_API_ID + CENSYS_API_SECRET env vars
Useful for:
- Host reconnaissance and service discovery
- SSL/TLS certificate transparency search
- Subdomain enumeration via certificate SANs
- Infrastructure mapping and ASN analysis
- Finding exposed services and misconfigurations`,
      Kind.Fetch,
      {
        properties: {
          searchType: {
            type: 'string',
            enum: ['hosts', 'certificates', 'host', 'cert'],
            description:
              'Type of search: "hosts" to search hosts, "certificates" to search certs, "host" for specific IP details, "cert" for specific certificate details',
          },
          query: {
            type: 'string',
            description:
              'Search query using Censys syntax (e.g., "services.port: 443 and services.http.response.html_title: admin")',
          },
          ip: {
            type: 'string',
            description: 'Target IP address (for host lookup)',
          },
          fingerprint: {
            type: 'string',
            description: 'Certificate SHA256 fingerprint (for cert lookup)',
          },
          perPage: {
            type: 'number',
            description: 'Number of results per page (max 100, default 25)',
          },
          cursor: {
            type: 'string',
            description: 'Pagination cursor from previous results',
          },
          virtualHosts: {
            type: 'string',
            enum: ['INCLUDE', 'EXCLUDE', 'ONLY'],
            description: 'Virtual hosts setting (default: EXCLUDE)',
          },
        },
        required: ['searchType'],
        type: 'object',
      },
    );
    this.config = config;
  }

  protected createInvocation(
    params: CensysToolParams,
  ): ToolInvocation<CensysToolParams, ToolResult> {
    return new CensysToolInvocation(this.config, params);
  }
}
