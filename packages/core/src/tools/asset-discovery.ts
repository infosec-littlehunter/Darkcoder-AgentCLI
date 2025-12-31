/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Subdomain & Asset Discovery Tool
 *
 * Discovers subdomains and assets using:
 * - Certificate Transparency (crt.sh)
 * - SecurityTrails API
 * - DNS enumeration
 * - ASN lookup and IP range discovery
 */

import { apiKeyManager } from '../config/api-keys.js';
import { ToolErrorType } from './tool-error.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';

/**
 * Operation modes
 */
export type AssetDiscoveryOperation =
  | 'subdomains' // Find subdomains
  | 'crtsh' // Certificate Transparency lookup
  | 'dns' // DNS records enumeration
  | 'asn' // ASN lookup
  | 'ip_range' // IP range for ASN
  | 'reverse_dns' // Reverse DNS lookup
  | 'whois' // WHOIS information
  | 'history'; // Historical DNS data

/**
 * Subdomain data structure
 */
export interface SubdomainData {
  subdomain: string;
  source: string;
  firstSeen?: string;
  lastSeen?: string;
  ip?: string;
}

export interface DNSRecord {
  type: string;
  name: string;
  value: string;
  ttl?: number;
}

export interface ASNData {
  asn: string;
  name: string;
  country: string;
  ipRanges?: string[];
  description?: string;
}

export interface WhoisData {
  domain: string;
  registrar?: string;
  createdDate?: string;
  expiryDate?: string;
  nameServers?: string[];
  status?: string[];
  registrant?: {
    name?: string;
    organization?: string;
    country?: string;
  };
}

/**
 * Parameters for the Asset Discovery tool
 */
export interface AssetDiscoveryParams {
  operation: AssetDiscoveryOperation;
  domain?: string;
  ip?: string;
  asn?: string;
  recordType?: 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME' | 'SOA' | 'ALL';
  limit?: number;
  includeDns?: boolean;
}

/**
 * Asset Discovery Tool Invocation
 */
class AssetDiscoveryInvocation extends BaseToolInvocation<
  AssetDiscoveryParams,
  ToolResult
> {
  constructor(params: AssetDiscoveryParams) {
    super(params);
  }

  getDescription(): string {
    const { operation, domain, ip, asn } = this.params;
    switch (operation) {
      case 'subdomains':
        return `Discovering subdomains for: ${domain}`;
      case 'crtsh':
        return `Querying Certificate Transparency for: ${domain}`;
      case 'dns':
        return `Enumerating DNS records for: ${domain}`;
      case 'asn':
        return `Looking up ASN for: ${ip || asn}`;
      case 'ip_range':
        return `Getting IP ranges for ASN: ${asn}`;
      case 'reverse_dns':
        return `Reverse DNS lookup for: ${ip}`;
      case 'whois':
        return `WHOIS lookup for: ${domain}`;
      case 'history':
        return `Historical DNS for: ${domain}`;
      default:
        return 'Asset discovery operation';
    }
  }

  async execute(): Promise<ToolResult> {
    await apiKeyManager.initialize();

    const { operation } = this.params;

    switch (operation) {
      case 'subdomains':
        return this.discoverSubdomains();
      case 'crtsh':
        return this.queryCrtsh();
      case 'dns':
        return this.enumerateDns();
      case 'asn':
        return this.lookupAsn();
      case 'ip_range':
        return this.getIpRanges();
      case 'reverse_dns':
        return this.reverseDns();
      case 'whois':
        return this.whoisLookup();
      case 'history':
        return this.historicalDns();
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
   * Discover subdomains using multiple sources
   */
  private async discoverSubdomains(): Promise<ToolResult> {
    const { domain, limit = 100, includeDns = false } = this.params;

    if (!domain) {
      return {
        llmContent: 'Domain is required',
        returnDisplay: 'Missing domain',
        error: {
          message: 'Domain is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const subdomains = new Map<string, SubdomainData>();
    const errors: string[] = [];

    // Source 1: crt.sh (Certificate Transparency)
    try {
      const crtshResults = await this.fetchCrtsh(domain);
      for (const sub of crtshResults) {
        if (!subdomains.has(sub.subdomain)) {
          subdomains.set(sub.subdomain, sub);
        }
      }
    } catch (e) {
      errors.push(`crt.sh: ${e instanceof Error ? e.message : String(e)}`);
    }

    // Source 2: SecurityTrails (if API key available)
    try {
      const securityTrailsResults = await this.fetchSecurityTrails(domain);
      for (const sub of securityTrailsResults) {
        if (!subdomains.has(sub.subdomain)) {
          subdomains.set(sub.subdomain, sub);
        }
      }
    } catch (e) {
      errors.push(
        `SecurityTrails: ${e instanceof Error ? e.message : String(e)}`,
      );
    }

    // Source 3: HackerTarget (free)
    try {
      const hackerTargetResults = await this.fetchHackerTarget(domain);
      for (const sub of hackerTargetResults) {
        if (!subdomains.has(sub.subdomain)) {
          subdomains.set(sub.subdomain, sub);
        }
      }
    } catch (e) {
      errors.push(
        `HackerTarget: ${e instanceof Error ? e.message : String(e)}`,
      );
    }

    // Resolve DNS if requested
    const results = Array.from(subdomains.values()).slice(0, limit);

    if (includeDns) {
      for (const sub of results.slice(0, 20)) {
        try {
          const ip = await this.resolveIp(sub.subdomain);
          if (ip) {
            sub.ip = ip;
          }
        } catch {
          // Ignore DNS resolution errors
        }
      }
    }

    return this.formatSubdomainResults(domain, results, errors);
  }

  /**
   * Fetch subdomains from crt.sh
   */
  private async fetchCrtsh(domain: string): Promise<SubdomainData[]> {
    const response = await fetch(
      `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`,
      {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'DarkCoder-CLI/1.0',
        },
      },
    );

    if (!response.ok) {
      throw new Error(`crt.sh error: ${response.status}`);
    }

    const data = (await response.json()) as Array<{
      common_name?: string;
      name_value?: string;
      entry_timestamp?: string;
    }>;

    const subdomains = new Set<string>();
    const results: SubdomainData[] = [];

    for (const entry of data) {
      // Handle multiple names in name_value
      const names = (entry.name_value || entry.common_name || '')
        .split('\n')
        .map((n) => n.trim().toLowerCase())
        .filter((n) => n.endsWith(domain.toLowerCase()));

      for (const name of names) {
        if (!subdomains.has(name) && !name.startsWith('*')) {
          subdomains.add(name);
          results.push({
            subdomain: name,
            source: 'crt.sh',
            firstSeen: entry.entry_timestamp,
          });
        }
      }
    }

    return results;
  }

  /**
   * Fetch subdomains from SecurityTrails
   */
  private async fetchSecurityTrails(domain: string): Promise<SubdomainData[]> {
    const apiKey = apiKeyManager.getApiKey('securitytrails');
    if (!apiKey) {
      return [];
    }

    const response = await fetch(
      `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`,
      {
        headers: {
          APIKEY: apiKey,
          Accept: 'application/json',
        },
      },
    );

    if (!response.ok) {
      throw new Error(`SecurityTrails error: ${response.status}`);
    }

    const data = (await response.json()) as {
      subdomains?: string[];
    };

    return (data.subdomains || []).map((sub) => ({
      subdomain: `${sub}.${domain}`,
      source: 'SecurityTrails',
    }));
  }

  /**
   * Fetch subdomains from HackerTarget
   */
  private async fetchHackerTarget(domain: string): Promise<SubdomainData[]> {
    const response = await fetch(
      `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
      {
        headers: {
          'User-Agent': 'DarkCoder-CLI/1.0',
        },
      },
    );

    if (!response.ok) {
      throw new Error(`HackerTarget error: ${response.status}`);
    }

    const text = await response.text();
    const lines = text.split('\n').filter((l) => l.trim());

    return lines
      .map((line) => {
        const [subdomain, ip] = line.split(',');
        return {
          subdomain: subdomain?.trim() || '',
          source: 'HackerTarget',
          ip: ip?.trim(),
        };
      })
      .filter((s) => s.subdomain);
  }

  /**
   * Resolve IP for a hostname
   */
  private async resolveIp(hostname: string): Promise<string | null> {
    try {
      const response = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`,
        {
          headers: { Accept: 'application/json' },
        },
      );

      if (!response.ok) return null;

      const data = (await response.json()) as {
        Answer?: Array<{ data?: string }>;
      };

      return data.Answer?.[0]?.data || null;
    } catch {
      return null;
    }
  }

  /**
   * Format subdomain results
   */
  private formatSubdomainResults(
    domain: string,
    subdomains: SubdomainData[],
    errors: string[],
  ): ToolResult {
    const output: string[] = [
      `# Subdomain Discovery: ${domain}`,
      '',
      `Found **${subdomains.length}** subdomains`,
      '',
    ];

    if (errors.length > 0) {
      output.push('**Note:** Some sources had errors:');
      for (const error of errors) {
        output.push(`- ${error}`);
      }
      output.push('');
    }

    // Group by source
    const bySource = new Map<string, SubdomainData[]>();
    for (const sub of subdomains) {
      const existing = bySource.get(sub.source) || [];
      existing.push(sub);
      bySource.set(sub.source, existing);
    }

    output.push('## Sources');
    output.push('');
    for (const [source, subs] of bySource) {
      output.push(`- **${source}:** ${subs.length} subdomains`);
    }
    output.push('');

    output.push('## Subdomains');
    output.push('');

    if (subdomains.some((s) => s.ip)) {
      output.push('| Subdomain | IP | Source |');
      output.push('|-----------|-----|--------|');
      for (const sub of subdomains) {
        output.push(
          `| ${sub.subdomain} | ${sub.ip || 'N/A'} | ${sub.source} |`,
        );
      }
    } else {
      output.push('| Subdomain | Source |');
      output.push('|-----------|--------|');
      for (const sub of subdomains) {
        output.push(`| ${sub.subdomain} | ${sub.source} |`);
      }
    }

    return {
      llmContent: output.join('\n'),
      returnDisplay: `Found ${subdomains.length} subdomains`,
    };
  }

  /**
   * Query crt.sh directly
   */
  private async queryCrtsh(): Promise<ToolResult> {
    const { domain, limit = 100 } = this.params;

    if (!domain) {
      return {
        llmContent: 'Domain is required',
        returnDisplay: 'Missing domain',
        error: {
          message: 'Domain is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    try {
      const results = await this.fetchCrtsh(domain);
      const limitedResults = results.slice(0, limit);

      const output: string[] = [
        `# Certificate Transparency: ${domain}`,
        '',
        `Found **${results.length}** certificates (showing ${limitedResults.length})`,
        '',
        '## Subdomains from Certificates',
        '',
        '| Subdomain | First Seen |',
        '|-----------|------------|',
      ];

      for (const result of limitedResults) {
        const date = result.firstSeen
          ? new Date(result.firstSeen).toLocaleDateString()
          : 'N/A';
        output.push(`| ${result.subdomain} | ${date} |`);
      }

      output.push('');
      output.push('## What is Certificate Transparency?');
      output.push('');
      output.push(
        'Certificate Transparency (CT) is a system where CAs must log all issued SSL certificates.',
      );
      output.push(
        'This allows discovery of subdomains that have SSL certificates, even internal ones.',
      );
      output.push('');
      output.push(`[View on crt.sh](https://crt.sh/?q=%.${domain})`);

      return {
        llmContent: output.join('\n'),
        returnDisplay: `${results.length} certificates found`,
      };
    } catch (e) {
      return {
        llmContent: `Failed to query crt.sh: ${e instanceof Error ? e.message : String(e)}`,
        returnDisplay: 'Query failed',
        error: {
          message: `crt.sh query failed: ${e instanceof Error ? e.message : String(e)}`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Enumerate DNS records
   */
  private async enumerateDns(): Promise<ToolResult> {
    const { domain, recordType = 'ALL' } = this.params;

    if (!domain) {
      return {
        llmContent: 'Domain is required',
        returnDisplay: 'Missing domain',
        error: {
          message: 'Domain is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const records: DNSRecord[] = [];
    const recordTypes =
      recordType === 'ALL'
        ? ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        : [recordType];

    for (const type of recordTypes) {
      try {
        const response = await fetch(
          `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
          {
            headers: { Accept: 'application/json' },
          },
        );

        if (response.ok) {
          const data = (await response.json()) as {
            Answer?: Array<{
              name?: string;
              type?: number;
              TTL?: number;
              data?: string;
            }>;
          };

          for (const answer of data.Answer || []) {
            records.push({
              type,
              name: answer.name || domain,
              value: answer.data || '',
              ttl: answer.TTL,
            });
          }
        }
      } catch {
        // Continue with other record types
      }
    }

    const output: string[] = [
      `# DNS Records: ${domain}`,
      '',
      `Found **${records.length}** DNS records`,
      '',
      '| Type | Name | Value | TTL |',
      '|------|------|-------|-----|',
    ];

    for (const record of records) {
      output.push(
        `| ${record.type} | ${record.name} | ${record.value} | ${record.ttl || 'N/A'} |`,
      );
    }

    output.push('');
    output.push('## Record Type Explanation');
    output.push('');
    output.push('- **A:** IPv4 address');
    output.push('- **AAAA:** IPv6 address');
    output.push('- **MX:** Mail server');
    output.push('- **TXT:** Text records (SPF, DKIM, etc.)');
    output.push('- **NS:** Name servers');
    output.push('- **CNAME:** Canonical name (alias)');
    output.push('- **SOA:** Start of Authority');

    return {
      llmContent: output.join('\n'),
      returnDisplay: `${records.length} DNS records`,
    };
  }

  /**
   * ASN lookup
   */
  private async lookupAsn(): Promise<ToolResult> {
    const { ip, asn } = this.params;

    if (!ip && !asn) {
      return {
        llmContent: 'IP address or ASN is required',
        returnDisplay: 'Missing IP/ASN',
        error: {
          message: 'IP address or ASN is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    try {
      let asnData: ASNData;

      if (ip) {
        // Lookup ASN by IP
        const response = await fetch(
          `https://api.hackertarget.com/aslookup/?q=${encodeURIComponent(ip)}`,
        );

        if (!response.ok) {
          throw new Error(`ASN lookup failed: ${response.status}`);
        }

        const text = await response.text();
        const parts = text.split(',').map((p) => p.trim().replace(/"/g, ''));

        asnData = {
          asn: parts[1] || 'Unknown',
          name: parts[2] || 'Unknown',
          country: parts[3] || 'Unknown',
        };
      } else {
        // Lookup ASN details
        const response = await fetch(
          `https://api.hackertarget.com/aslookup/?q=${encodeURIComponent(asn!)}`,
        );

        if (!response.ok) {
          throw new Error(`ASN lookup failed: ${response.status}`);
        }

        const text = await response.text();
        const lines = text.split('\n').filter((l) => l.trim());

        asnData = {
          asn: asn!,
          name: lines[0] || 'Unknown',
          country: 'Unknown',
        };
      }

      const output: string[] = [
        `# ASN Information`,
        '',
        `**ASN:** ${asnData.asn}`,
        `**Name:** ${asnData.name}`,
        `**Country:** ${asnData.country}`,
        '',
        '## Additional Resources',
        '',
        `- [BGP.he.net](https://bgp.he.net/${asnData.asn})`,
        `- [PeeringDB](https://www.peeringdb.com/search?q=${asnData.asn})`,
        `- [RIPEstat](https://stat.ripe.net/${asnData.asn})`,
      ];

      return {
        llmContent: output.join('\n'),
        returnDisplay: `ASN: ${asnData.asn}`,
      };
    } catch (e) {
      return {
        llmContent: `ASN lookup failed: ${e instanceof Error ? e.message : String(e)}`,
        returnDisplay: 'Lookup failed',
        error: {
          message: `ASN lookup failed`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Get IP ranges for ASN
   */
  private async getIpRanges(): Promise<ToolResult> {
    const { asn } = this.params;

    if (!asn) {
      return {
        llmContent: 'ASN is required',
        returnDisplay: 'Missing ASN',
        error: {
          message: 'ASN is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    try {
      const response = await fetch(
        `https://api.hackertarget.com/aslookup/?q=${encodeURIComponent(asn)}`,
      );

      if (!response.ok) {
        throw new Error(`IP range lookup failed: ${response.status}`);
      }

      const text = await response.text();
      const lines = text.split('\n').filter((l) => l.trim());

      const output: string[] = [
        `# IP Ranges for ${asn}`,
        '',
        `Found **${lines.length}** IP ranges`,
        '',
        '## CIDR Blocks',
        '',
      ];

      for (const line of lines) {
        output.push(`- ${line}`);
      }

      output.push('');
      output.push('## Usage');
      output.push('');
      output.push('These IP ranges can be used for:');
      output.push('- Network scanning (with permission)');
      output.push('- Asset inventory');
      output.push('- Attack surface mapping');

      return {
        llmContent: output.join('\n'),
        returnDisplay: `${lines.length} IP ranges`,
      };
    } catch (e) {
      return {
        llmContent: `IP range lookup failed: ${e instanceof Error ? e.message : String(e)}`,
        returnDisplay: 'Lookup failed',
        error: {
          message: 'IP range lookup failed',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Reverse DNS lookup
   */
  private async reverseDns(): Promise<ToolResult> {
    const { ip } = this.params;

    if (!ip) {
      return {
        llmContent: 'IP address is required',
        returnDisplay: 'Missing IP',
        error: {
          message: 'IP address is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    try {
      // Construct reverse DNS query
      const reverseName = ip.split('.').reverse().join('.') + '.in-addr.arpa';

      const response = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(reverseName)}&type=PTR`,
        {
          headers: { Accept: 'application/json' },
        },
      );

      if (!response.ok) {
        throw new Error(`Reverse DNS failed: ${response.status}`);
      }

      const data = (await response.json()) as {
        Answer?: Array<{ data?: string }>;
      };

      const hostnames = data.Answer?.map((a) => a.data).filter(Boolean) || [];

      const output: string[] = [`# Reverse DNS: ${ip}`, ''];

      if (hostnames.length > 0) {
        output.push(`Found **${hostnames.length}** PTR records`);
        output.push('');
        output.push('## Hostnames');
        output.push('');
        for (const hostname of hostnames) {
          output.push(`- ${hostname}`);
        }
      } else {
        output.push('No PTR records found for this IP.');
      }

      return {
        llmContent: output.join('\n'),
        returnDisplay: `${hostnames.length} PTR records`,
      };
    } catch (e) {
      return {
        llmContent: `Reverse DNS failed: ${e instanceof Error ? e.message : String(e)}`,
        returnDisplay: 'Lookup failed',
        error: {
          message: 'Reverse DNS failed',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * WHOIS lookup
   */
  private async whoisLookup(): Promise<ToolResult> {
    const { domain } = this.params;

    if (!domain) {
      return {
        llmContent: 'Domain is required',
        returnDisplay: 'Missing domain',
        error: {
          message: 'Domain is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    try {
      const response = await fetch(
        `https://api.hackertarget.com/whois/?q=${encodeURIComponent(domain)}`,
      );

      if (!response.ok) {
        throw new Error(`WHOIS lookup failed: ${response.status}`);
      }

      const text = await response.text();

      const output: string[] = [
        `# WHOIS: ${domain}`,
        '',
        '```',
        text.substring(0, 3000), // Limit output
        '```',
        '',
        '## Key Information',
        '',
        this.parseWhoisHighlights(text),
      ];

      return {
        llmContent: output.join('\n'),
        returnDisplay: `WHOIS for ${domain}`,
      };
    } catch (e) {
      return {
        llmContent: `WHOIS lookup failed: ${e instanceof Error ? e.message : String(e)}`,
        returnDisplay: 'Lookup failed',
        error: {
          message: 'WHOIS lookup failed',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Parse WHOIS highlights
   */
  private parseWhoisHighlights(whoisText: string): string {
    const highlights: string[] = [];
    const lines = whoisText.toLowerCase();

    if (lines.includes('registrar:')) {
      const match = whoisText.match(/Registrar:\s*(.+)/i);
      if (match) highlights.push(`- **Registrar:** ${match[1].trim()}`);
    }

    if (lines.includes('creation date:')) {
      const match = whoisText.match(/Creation Date:\s*(.+)/i);
      if (match) highlights.push(`- **Created:** ${match[1].trim()}`);
    }

    if (lines.includes('expiry date:') || lines.includes('expiration date:')) {
      const match = whoisText.match(/Expir(?:y|ation) Date:\s*(.+)/i);
      if (match) highlights.push(`- **Expires:** ${match[1].trim()}`);
    }

    if (lines.includes('name server:')) {
      const matches = whoisText.match(/Name Server:\s*(.+)/gi);
      if (matches) {
        highlights.push(`- **Name Servers:** ${matches.length} found`);
      }
    }

    return highlights.join('\n') || 'No highlights extracted';
  }

  /**
   * Historical DNS data
   */
  private async historicalDns(): Promise<ToolResult> {
    const { domain } = this.params;

    if (!domain) {
      return {
        llmContent: 'Domain is required',
        returnDisplay: 'Missing domain',
        error: {
          message: 'Domain is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const apiKey = apiKeyManager.getApiKey('securitytrails');

    if (!apiKey) {
      return {
        llmContent: `Historical DNS requires a SecurityTrails API key.

To get started:
1. Register at https://securitytrails.com/app/signup
2. Get your API key from the dashboard
3. Set it: { "tool": "api_key_manager", "operation": "set", "tool": "securitytrails", "apiKey": "your_key" }

Or use environment variable:
\`\`\`bash
export SECURITYTRAILS_API_KEY="your_key"
\`\`\``,
        returnDisplay: 'API key required',
      };
    }

    try {
      const response = await fetch(
        `https://api.securitytrails.com/v1/history/${encodeURIComponent(domain)}/dns/a`,
        {
          headers: {
            APIKEY: apiKey,
            Accept: 'application/json',
          },
        },
      );

      if (!response.ok) {
        throw new Error(`SecurityTrails error: ${response.status}`);
      }

      const data = (await response.json()) as {
        records?: Array<{
          values?: Array<{ ip?: string }>;
          first_seen?: string;
          last_seen?: string;
        }>;
      };

      const output: string[] = [
        `# Historical DNS: ${domain}`,
        '',
        `Found **${data.records?.length || 0}** historical A records`,
        '',
        '| IP Address | First Seen | Last Seen |',
        '|------------|------------|-----------|',
      ];

      for (const record of data.records || []) {
        const ip = record.values?.[0]?.ip || 'N/A';
        const firstSeen = record.first_seen || 'N/A';
        const lastSeen = record.last_seen || 'N/A';
        output.push(`| ${ip} | ${firstSeen} | ${lastSeen} |`);
      }

      output.push('');
      output.push('## Why Historical DNS Matters');
      output.push('');
      output.push('- Identify previous hosting providers');
      output.push('- Discover related infrastructure');
      output.push('- Track domain ownership changes');
      output.push('- Find abandoned/forgotten assets');

      return {
        llmContent: output.join('\n'),
        returnDisplay: `${data.records?.length || 0} historical records`,
      };
    } catch (e) {
      return {
        llmContent: `Historical DNS failed: ${e instanceof Error ? e.message : String(e)}`,
        returnDisplay: 'Lookup failed',
        error: {
          message: 'Historical DNS failed',
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }
}

/**
 * Tool schema
 */
const ASSET_DISCOVERY_SCHEMA = {
  type: 'object',
  properties: {
    operation: {
      type: 'string',
      enum: [
        'subdomains',
        'crtsh',
        'dns',
        'asn',
        'ip_range',
        'reverse_dns',
        'whois',
        'history',
      ],
      description: `Operation to perform:
- subdomains: Discover subdomains using multiple sources
- crtsh: Query Certificate Transparency logs
- dns: Enumerate DNS records
- asn: ASN lookup for IP or ASN
- ip_range: Get IP ranges for an ASN
- reverse_dns: Reverse DNS lookup
- whois: WHOIS information
- history: Historical DNS data (requires SecurityTrails API)`,
    },
    domain: {
      type: 'string',
      description: 'Target domain (e.g., example.com)',
    },
    ip: {
      type: 'string',
      description: 'IP address for lookup',
    },
    asn: {
      type: 'string',
      description: 'ASN number (e.g., AS15169)',
    },
    recordType: {
      type: 'string',
      enum: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'ALL'],
      description: 'DNS record type to query (default: ALL)',
    },
    limit: {
      type: 'number',
      description: 'Maximum number of results (default: 100)',
    },
    includeDns: {
      type: 'boolean',
      description: 'Resolve IPs for subdomains (default: false)',
    },
  },
  required: ['operation'],
};

/**
 * Asset Discovery Tool
 */
export class AssetDiscoveryTool extends BaseDeclarativeTool<
  AssetDiscoveryParams,
  ToolResult
> {
  constructor() {
    super(
      ToolNames.ASSET_DISCOVERY,
      ToolDisplayNames.ASSET_DISCOVERY,
      `Discover subdomains and assets using Certificate Transparency, DNS, and more.

Examples:
1. Find subdomains: { "operation": "subdomains", "domain": "example.com" }
2. Certificate search: { "operation": "crtsh", "domain": "example.com" }
3. DNS records: { "operation": "dns", "domain": "example.com" }
4. ASN lookup: { "operation": "asn", "ip": "8.8.8.8" }
5. WHOIS: { "operation": "whois", "domain": "example.com" }
6. Reverse DNS: { "operation": "reverse_dns", "ip": "8.8.8.8" }`,
      Kind.Read,
      ASSET_DISCOVERY_SCHEMA,
      true,
    );
  }

  override validateToolParamValues(
    params: AssetDiscoveryParams,
  ): string | null {
    const { operation, domain, ip, asn } = params;

    if (
      ['subdomains', 'crtsh', 'dns', 'whois', 'history'].includes(operation) &&
      !domain
    ) {
      return 'Domain is required for this operation';
    }

    if (operation === 'reverse_dns' && !ip) {
      return 'IP address is required for reverse DNS';
    }

    if (operation === 'ip_range' && !asn) {
      return 'ASN is required for IP range lookup';
    }

    if (operation === 'asn' && !ip && !asn) {
      return 'IP address or ASN is required';
    }

    return null;
  }

  protected override createInvocation(
    params: AssetDiscoveryParams,
  ): ToolInvocation<AssetDiscoveryParams, ToolResult> {
    return new AssetDiscoveryInvocation(params);
  }
}
