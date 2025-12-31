/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Security Intelligence Tool for SOC & Red Team Operations
 *
 * This tool provides comprehensive security intelligence capabilities:
 * - CVE lookup with CVSS scores from NVD/NIST
 * - HackerNews security discussions and exploit news
 * - Red team exploitation strategy generation
 * - SOC remediation and patching guidance
 * - Exploit database search
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';

const TIMEOUT_MS = 30000;

// API endpoints
const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const HACKERNEWS_API = 'https://hn.algolia.com/api/v1';
const GITHUB_ADVISORY_API = 'https://api.github.com/advisories';
// Note: EXPLOITDB_SEARCH is not used directly due to no public API
// const EXPLOITDB_SEARCH = 'https://www.exploit-db.com/search';

/**
 * Search types for security intelligence queries
 */
export type SecurityIntelSearchType =
  | 'cve'
  | 'hackernews'
  | 'exploit'
  | 'redteam'
  | 'soc'
  | 'advisory';

/**
 * Parameters for the Security Intel tool
 */
export interface SecurityIntelToolParams {
  searchType: SecurityIntelSearchType;
  cveId?: string;
  query?: string;
  product?: string;
  vendor?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  days?: number;
}

/**
 * NVD CVE response structure
 */
interface NvdCveResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{
    cve: {
      id: string;
      sourceIdentifier: string;
      published: string;
      lastModified: string;
      vulnStatus: string;
      descriptions: Array<{
        lang: string;
        value: string;
      }>;
      metrics?: {
        cvssMetricV31?: Array<{
          source: string;
          type: string;
          cvssData: {
            version: string;
            vectorString: string;
            attackVector: string;
            attackComplexity: string;
            privilegesRequired: string;
            userInteraction: string;
            scope: string;
            confidentialityImpact: string;
            integrityImpact: string;
            availabilityImpact: string;
            baseScore: number;
            baseSeverity: string;
          };
          exploitabilityScore: number;
          impactScore: number;
        }>;
        cvssMetricV2?: Array<{
          source: string;
          type: string;
          cvssData: {
            version: string;
            vectorString: string;
            baseScore: number;
          };
          baseSeverity: string;
          exploitabilityScore: number;
          impactScore: number;
        }>;
      };
      weaknesses?: Array<{
        source: string;
        type: string;
        description: Array<{
          lang: string;
          value: string;
        }>;
      }>;
      configurations?: Array<{
        nodes: Array<{
          operator: string;
          negate: boolean;
          cpeMatch: Array<{
            vulnerable: boolean;
            criteria: string;
            matchCriteriaId: string;
          }>;
        }>;
      }>;
      references: Array<{
        url: string;
        source: string;
        tags?: string[];
      }>;
    };
  }>;
}

/**
 * HackerNews search response
 */
interface HackerNewsResponse {
  hits: Array<{
    objectID: string;
    title: string;
    url?: string;
    author: string;
    points: number;
    num_comments: number;
    created_at: string;
    story_text?: string;
  }>;
  nbHits: number;
  page: number;
  nbPages: number;
}

/**
 * GitHub Advisory response
 */
interface GitHubAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: string;
  published_at: string;
  updated_at: string;
  vulnerabilities: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    vulnerable_version_range: string;
    first_patched_version: string | null;
  }>;
  references: Array<{
    url: string;
  }>;
}

/**
 * Fetch with timeout helper
 */
async function fetchWithAbort(
  url: string,
  options: RequestInit = {},
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
 * Implementation of the Security Intel tool invocation logic
 */
class SecurityIntelToolInvocation extends BaseToolInvocation<
  SecurityIntelToolParams,
  ToolResult
> {
  constructor(_config: Config, params: SecurityIntelToolParams) {
    super(params);
  }

  getDescription(): string {
    const { searchType, cveId, query, product } = this.params;
    switch (searchType) {
      case 'cve':
        return `Looking up CVE details: ${cveId || query || product}`;
      case 'hackernews':
        return `Searching HackerNews for security news: ${query}`;
      case 'exploit':
        return `Searching for exploits: ${cveId || query}`;
      case 'redteam':
        return `Generating red team strategy for: ${cveId || query}`;
      case 'soc':
        return `Generating SOC remediation guide for: ${cveId || query}`;
      case 'advisory':
        return `Searching GitHub security advisories: ${query || product}`;
      default:
        return `Querying security intelligence`;
    }
  }

  async execute(): Promise<ToolResult> {
    const { searchType } = this.params;

    try {
      switch (searchType) {
        case 'cve':
          return await this.lookupCve();
        case 'hackernews':
          return await this.searchHackerNews();
        case 'exploit':
          return await this.searchExploits();
        case 'redteam':
          return await this.generateRedTeamStrategy();
        case 'soc':
          return await this.generateSocGuidance();
        case 'advisory':
          return await this.searchAdvisories();
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
        llmContent: `Error: Security intel query failed: ${errorMessage}`,
        returnDisplay: `Security intel query failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Lookup CVE details from NVD/NIST
   */
  private async lookupCve(): Promise<ToolResult> {
    const { cveId, query, product, vendor, severity } = this.params;

    let url = NVD_API_BASE;
    const params = new URLSearchParams();

    if (cveId) {
      params.set('cveId', cveId.toUpperCase());
    } else if (query) {
      params.set('keywordSearch', query);
    }
    if (product) {
      params.set('keywordSearch', product);
    }
    if (vendor) {
      params.set('keywordSearch', `${vendor} ${product || ''}`);
    }
    if (severity) {
      params.set('cvssV3Severity', severity);
    }

    params.set('resultsPerPage', '20');
    url += `?${params.toString()}`;

    const response = await fetchWithAbort(
      url,
      {
        headers: {
          Accept: 'application/json',
        },
      },
      TIMEOUT_MS,
    );

    if (!response.ok) {
      throw new Error(`NVD API returned status ${response.status}`);
    }

    const data = (await response.json()) as NvdCveResponse;

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      return {
        llmContent: `No CVE results found for: ${cveId || query || product}`,
        returnDisplay: `No CVE results found`,
      };
    }

    const summary: string[] = [
      `## CVE Intelligence Report`,
      `**Total Results:** ${data.totalResults}`,
      `**Showing:** ${data.vulnerabilities.length}`,
      '',
      '---',
      '',
    ];

    for (const vuln of data.vulnerabilities.slice(0, 10)) {
      const cve = vuln.cve;
      const description =
        cve.descriptions.find((d) => d.lang === 'en')?.value ||
        'No description';

      // Get CVSS info
      const cvss3 = cve.metrics?.cvssMetricV31?.[0];
      const cvss2 = cve.metrics?.cvssMetricV2?.[0];
      const cvssScore = cvss3?.cvssData.baseScore || cvss2?.cvssData.baseScore;
      const severity =
        cvss3?.cvssData.baseSeverity || cvss2?.baseSeverity || 'Unknown';

      // Get CWE
      const cwe = cve.weaknesses?.[0]?.description.find(
        (d) => d.lang === 'en',
      )?.value;

      // Severity emoji
      const severityEmoji = this.getSeverityEmoji(severity);

      summary.push(`### ${severityEmoji} ${cve.id}`);
      summary.push(`**Severity:** ${severity} (Score: ${cvssScore || 'N/A'})`);
      summary.push(`**Published:** ${cve.published}`);
      summary.push(`**Status:** ${cve.vulnStatus}`);
      summary.push('');
      summary.push(`**Description:**`);
      summary.push(
        description.substring(0, 500) + (description.length > 500 ? '...' : ''),
      );
      summary.push('');

      if (cvss3) {
        summary.push(`**CVSS v3.1 Vector:**`);
        summary.push(`- Attack Vector: ${cvss3.cvssData.attackVector}`);
        summary.push(`- Attack Complexity: ${cvss3.cvssData.attackComplexity}`);
        summary.push(
          `- Privileges Required: ${cvss3.cvssData.privilegesRequired}`,
        );
        summary.push(`- User Interaction: ${cvss3.cvssData.userInteraction}`);
        summary.push(`- Scope: ${cvss3.cvssData.scope}`);
        summary.push(`- Exploitability Score: ${cvss3.exploitabilityScore}`);
        summary.push(`- Impact Score: ${cvss3.impactScore}`);
        summary.push('');
      }

      if (cwe) {
        summary.push(`**Weakness:** ${cwe}`);
      }

      // Affected products
      if (cve.configurations && cve.configurations.length > 0) {
        summary.push('');
        summary.push(`**Affected Products:**`);
        const products = new Set<string>();
        for (const config of cve.configurations) {
          for (const node of config.nodes) {
            for (const cpe of node.cpeMatch.slice(0, 5)) {
              const parts = cpe.criteria.split(':');
              if (parts.length >= 5) {
                products.add(`${parts[3]}:${parts[4]}`);
              }
            }
          }
        }
        for (const prod of Array.from(products).slice(0, 10)) {
          summary.push(`- ${prod}`);
        }
      }

      // References
      if (cve.references && cve.references.length > 0) {
        summary.push('');
        summary.push(`**References:**`);
        for (const ref of cve.references.slice(0, 5)) {
          const tags = ref.tags?.join(', ') || '';
          summary.push(`- [${tags || 'Link'}](${ref.url})`);
        }
      }

      summary.push('');
      summary.push('---');
      summary.push('');
    }

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Search HackerNews for security discussions
   */
  private async searchHackerNews(): Promise<ToolResult> {
    const { query, cveId, days } = this.params;

    const searchQuery = cveId || query || 'CVE security vulnerability';
    const params = new URLSearchParams({
      query: searchQuery,
      tags: 'story',
      hitsPerPage: '20',
    });

    if (days) {
      const timestamp = Math.floor(Date.now() / 1000) - days * 86400;
      params.set('numericFilters', `created_at_i>${timestamp}`);
    }

    const url = `${HACKERNEWS_API}/search?${params.toString()}`;

    const response = await fetchWithAbort(url, {}, TIMEOUT_MS);

    if (!response.ok) {
      throw new Error(`HackerNews API returned status ${response.status}`);
    }

    const data = (await response.json()) as HackerNewsResponse;

    if (!data.hits || data.hits.length === 0) {
      return {
        llmContent: `No HackerNews discussions found for: ${searchQuery}`,
        returnDisplay: `No HackerNews results found`,
      };
    }

    const summary: string[] = [
      `## HackerNews Security Intelligence`,
      `**Query:** ${searchQuery}`,
      `**Total Results:** ${data.nbHits}`,
      `**Showing:** ${data.hits.length}`,
      '',
      '---',
      '',
    ];

    for (const hit of data.hits) {
      const date = new Date(hit.created_at).toLocaleDateString();

      summary.push(`### ${hit.title}`);
      summary.push(
        `- **Points:** ${hit.points} | **Comments:** ${hit.num_comments}`,
      );
      summary.push(`- **Author:** ${hit.author} | **Date:** ${date}`);
      if (hit.url) {
        summary.push(`- **URL:** ${hit.url}`);
      }
      summary.push(
        `- **HN Link:** https://news.ycombinator.com/item?id=${hit.objectID}`,
      );
      summary.push('');
    }

    summary.push('');
    summary.push(
      `> 💡 **Tip:** Check the comments on high-engagement posts for technical details, exploit code, and mitigation discussions.`,
    );

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Search for exploits
   */
  private async searchExploits(): Promise<ToolResult> {
    const { cveId, query, product } = this.params;

    // Search GitHub for exploit code
    const searchQuery = encodeURIComponent(
      `${cveId || ''} ${query || ''} ${product || ''} exploit poc`.trim(),
    );

    const githubUrl = `https://api.github.com/search/repositories?q=${searchQuery}&sort=stars&per_page=15`;

    const response = await fetchWithAbort(
      githubUrl,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'DarkCoder-SecurityIntel',
        },
      },
      TIMEOUT_MS,
    );

    const summary: string[] = [
      `## Exploit Intelligence Report`,
      `**Search:** ${cveId || query || product}`,
      '',
      '---',
      '',
    ];

    if (response.ok) {
      interface GitHubRepoSearchResponse {
        total_count: number;
        items: Array<{
          full_name: string;
          description: string | null;
          html_url: string;
          stargazers_count: number;
          forks_count: number;
          updated_at: string;
          language: string | null;
          topics?: string[];
        }>;
      }
      const data = (await response.json()) as GitHubRepoSearchResponse;

      if (data.items && data.items.length > 0) {
        summary.push(`### GitHub Exploit Repositories`);
        summary.push(`**Found:** ${data.total_count} repositories`);
        summary.push('');

        for (const repo of data.items) {
          summary.push(`#### [${repo.full_name}](${repo.html_url})`);
          summary.push(
            `⭐ ${repo.stargazers_count} | 🍴 ${repo.forks_count} | ${repo.language || 'N/A'}`,
          );
          if (repo.description) {
            summary.push(`> ${repo.description.substring(0, 200)}`);
          }
          if (repo.topics && repo.topics.length > 0) {
            summary.push(`Tags: ${repo.topics.slice(0, 5).join(', ')}`);
          }
          summary.push('');
        }
      }
    }

    // Add exploit-db search suggestion
    summary.push('');
    summary.push(`### Additional Resources`);
    summary.push(
      `- **Exploit-DB:** https://www.exploit-db.com/search?cve=${cveId || ''}`,
    );
    summary.push(
      `- **Packet Storm:** https://packetstormsecurity.com/search/?q=${encodeURIComponent(cveId || query || '')}`,
    );
    summary.push(
      `- **Rapid7 DB:** https://www.rapid7.com/db/?q=${encodeURIComponent(cveId || query || '')}`,
    );
    summary.push(
      `- **PoC-in-GitHub:** https://github.com/nomi-sec/PoC-in-GitHub`,
    );

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Generate red team exploitation strategy
   */
  private async generateRedTeamStrategy(): Promise<ToolResult> {
    const { cveId, query, product } = this.params;

    // First, get CVE details if available
    let cveData: NvdCveResponse | null = null;
    if (cveId) {
      try {
        const url = `${NVD_API_BASE}?cveId=${cveId.toUpperCase()}`;
        const response = await fetchWithAbort(
          url,
          { headers: { Accept: 'application/json' } },
          TIMEOUT_MS,
        );
        if (response.ok) {
          cveData = (await response.json()) as NvdCveResponse;
        }
      } catch {
        // Continue without CVE data
      }
    }

    const cve = cveData?.vulnerabilities?.[0]?.cve;
    const cvss3 = cve?.metrics?.cvssMetricV31?.[0];
    const description =
      cve?.descriptions.find((d) => d.lang === 'en')?.value || '';
    const cwe = cve?.weaknesses?.[0]?.description.find(
      (d) => d.lang === 'en',
    )?.value;

    const summary: string[] = [
      `## 🔴 Red Team Exploitation Strategy`,
      `**Target:** ${cveId || query || product}`,
      '',
      '---',
      '',
    ];

    if (cve) {
      summary.push(`### Vulnerability Overview`);
      summary.push(`- **CVE ID:** ${cve.id}`);
      summary.push(
        `- **CVSS Score:** ${cvss3?.cvssData.baseScore || 'N/A'} (${cvss3?.cvssData.baseSeverity || 'Unknown'})`,
      );
      summary.push(`- **CWE:** ${cwe || 'Not specified'}`);
      summary.push('');
      summary.push(`**Description:**`);
      summary.push(description.substring(0, 400));
      summary.push('');
    }

    // Generate attack strategy based on CVSS vector
    summary.push(`### Attack Strategy`);
    summary.push('');

    if (cvss3) {
      const av = cvss3.cvssData.attackVector;
      const ac = cvss3.cvssData.attackComplexity;
      const pr = cvss3.cvssData.privilegesRequired;
      const ui = cvss3.cvssData.userInteraction;

      summary.push(`#### 1. Initial Access`);
      if (av === 'NETWORK') {
        summary.push(`- **Vector:** Network-based attack`);
        summary.push(`- Scan for exposed services using Censys`);
        summary.push(`- Identify target ports and services`);
        summary.push(`- Check for public-facing applications`);
      } else if (av === 'ADJACENT_NETWORK') {
        summary.push(`- **Vector:** Adjacent network required`);
        summary.push(`- Requires network proximity (same LAN/VLAN)`);
        summary.push(`- Consider pivoting from compromised host`);
      } else if (av === 'LOCAL') {
        summary.push(`- **Vector:** Local access required`);
        summary.push(`- Need initial foothold on target system`);
        summary.push(`- Consider phishing or other initial access techniques`);
      } else if (av === 'PHYSICAL') {
        summary.push(`- **Vector:** Physical access required`);
        summary.push(`- Social engineering for physical access`);
        summary.push(`- Consider supply chain attacks`);
      }
      summary.push('');

      summary.push(`#### 2. Exploitation Complexity`);
      if (ac === 'LOW') {
        summary.push(`- **Complexity:** Low - Reliable exploitation expected`);
        summary.push(`- Exploit should work consistently`);
        summary.push(`- Automated exploitation feasible`);
      } else {
        summary.push(
          `- **Complexity:** High - May require specific conditions`,
        );
        summary.push(`- Target configuration dependent`);
        summary.push(`- May require multiple attempts`);
        summary.push(`- Consider race conditions or timing`);
      }
      summary.push('');

      summary.push(`#### 3. Prerequisites`);
      if (pr === 'NONE') {
        summary.push(`- **Privileges:** No authentication required`);
        summary.push(`- Unauthenticated attack possible`);
      } else if (pr === 'LOW') {
        summary.push(`- **Privileges:** Low-level user access required`);
        summary.push(`- Need valid credentials or session`);
        summary.push(`- Consider credential spraying/phishing`);
      } else {
        summary.push(`- **Privileges:** High-level/admin access required`);
        summary.push(`- Requires privilege escalation first`);
        summary.push(`- Target administrative accounts`);
      }
      summary.push('');

      if (ui === 'REQUIRED') {
        summary.push(`#### 4. User Interaction`);
        summary.push(`- **Requires user interaction**`);
        summary.push(`- Craft convincing phishing/social engineering`);
        summary.push(`- Consider watering hole attacks`);
        summary.push(`- Malicious document delivery`);
        summary.push('');
      }
    }

    // CWE-specific attack techniques
    if (cwe) {
      summary.push(`#### Attack Techniques for ${cwe}`);
      const techniques = this.getCweAttackTechniques(cwe);
      for (const technique of techniques) {
        summary.push(`- ${technique}`);
      }
      summary.push('');
    }

    summary.push(`### Exploitation Procedure`);
    summary.push('```');
    summary.push(`# 1. Reconnaissance`);
    summary.push(`nmap -sV -sC -p- <target>`);
    summary.push(`censys search "${product || cveId || 'target'}"`);
    summary.push('');
    summary.push(`# 2. Vulnerability Validation`);
    summary.push(`# Check if target is vulnerable`);
    summary.push(`nuclei -t cves/ -target <target>`);
    summary.push('');
    summary.push(`# 3. Search for Public Exploits`);
    summary.push(`searchsploit "${cveId || product || ''}"`);
    summary.push(`msfconsole -q -x "search ${cveId || product || ''}"`);
    summary.push('');
    summary.push(`# 4. Execute Exploit`);
    summary.push(`# [Customize based on specific exploit]`);
    summary.push('```');
    summary.push('');

    summary.push(`### Post-Exploitation`);
    summary.push(`1. Establish persistence`);
    summary.push(`2. Escalate privileges if needed`);
    summary.push(`3. Lateral movement`);
    summary.push(`4. Data exfiltration (if in scope)`);
    summary.push(`5. Clean up and document findings`);
    summary.push('');

    summary.push(`### OPSEC Considerations`);
    summary.push(`- Use proxy chains/VPN`);
    summary.push(`- Avoid detection by EDR/AV`);
    summary.push(`- Time attacks during low-monitoring periods`);
    summary.push(`- Document all actions for report`);

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Generate SOC remediation guidance
   */
  private async generateSocGuidance(): Promise<ToolResult> {
    const { cveId, query, product } = this.params;

    // First, get CVE details if available
    let cveData: NvdCveResponse | null = null;
    if (cveId) {
      try {
        const url = `${NVD_API_BASE}?cveId=${cveId.toUpperCase()}`;
        const response = await fetchWithAbort(
          url,
          { headers: { Accept: 'application/json' } },
          TIMEOUT_MS,
        );
        if (response.ok) {
          cveData = (await response.json()) as NvdCveResponse;
        }
      } catch {
        // Continue without CVE data
      }
    }

    const cve = cveData?.vulnerabilities?.[0]?.cve;
    const cvss3 = cve?.metrics?.cvssMetricV31?.[0];
    const description =
      cve?.descriptions.find((d) => d.lang === 'en')?.value || '';
    const cwe = cve?.weaknesses?.[0]?.description.find(
      (d) => d.lang === 'en',
    )?.value;
    const severity = cvss3?.cvssData.baseSeverity || 'Unknown';

    const summary: string[] = [
      `## 🔵 SOC Remediation & Patching Guide`,
      `**Vulnerability:** ${cveId || query || product}`,
      '',
      '---',
      '',
    ];

    if (cve) {
      const severityEmoji = this.getSeverityEmoji(severity);
      summary.push(`### Vulnerability Assessment`);
      summary.push(`- **CVE ID:** ${cve.id}`);
      summary.push(
        `- **Severity:** ${severityEmoji} ${severity} (CVSS: ${cvss3?.cvssData.baseScore || 'N/A'})`,
      );
      summary.push(`- **Published:** ${cve.published}`);
      summary.push(`- **Status:** ${cve.vulnStatus}`);
      summary.push('');
      summary.push(`**Description:**`);
      summary.push(description.substring(0, 400));
      summary.push('');

      // Priority calculation
      const priority = this.calculatePriority(cvss3?.cvssData.baseScore || 0);
      summary.push(`### ⏰ Response Priority: ${priority.level}`);
      summary.push(`**Recommended SLA:** ${priority.sla}`);
      summary.push('');
    }

    summary.push(`### 🔍 Detection`);
    summary.push('');
    summary.push(`#### SIEM/Log Queries`);
    summary.push('```');
    summary.push(`# Splunk - Search for exploitation attempts`);
    summary.push(`index=* sourcetype=*firewall* OR sourcetype=*ids*`);
    summary.push(`| search "${cveId || product || 'exploit'}"`);
    summary.push('');
    summary.push(`# Elastic/Kibana`);
    summary.push(
      `event.category:intrusion_detection AND message:"${cveId || ''}"`,
    );
    summary.push('```');
    summary.push('');

    summary.push(`#### Network Indicators`);
    summary.push(`- Monitor for unusual outbound connections`);
    summary.push(`- Check for suspicious port scanning`);
    summary.push(`- Look for data exfiltration patterns`);
    summary.push('');

    summary.push(`#### Endpoint Indicators`);
    summary.push(`- Unusual process execution`);
    summary.push(`- File system changes in sensitive directories`);
    summary.push(`- Registry modifications (Windows)`);
    summary.push(`- New scheduled tasks/cron jobs`);
    summary.push('');

    summary.push(`### 🛡️ Immediate Mitigation`);
    summary.push('');

    if (cvss3) {
      const av = cvss3.cvssData.attackVector;
      if (av === 'NETWORK') {
        summary.push(`#### Network-Level Controls`);
        summary.push(
          `1. **Firewall Rules:** Block external access to vulnerable service`,
        );
        summary.push('```');
        summary.push(`# iptables example`);
        summary.push(
          `iptables -A INPUT -p tcp --dport <vulnerable_port> -j DROP`,
        );
        summary.push('');
        summary.push(`# Windows Firewall`);
        summary.push(
          `netsh advfirewall firewall add rule name="Block CVE" dir=in action=block protocol=tcp localport=<port>`,
        );
        summary.push('```');
        summary.push(`2. **WAF Rules:** Deploy virtual patches`);
        summary.push(`3. **Network Segmentation:** Isolate affected systems`);
        summary.push('');
      }
    }

    summary.push(`#### System-Level Controls`);
    summary.push(`1. Disable vulnerable feature if not critical`);
    summary.push(`2. Apply configuration hardening`);
    summary.push(`3. Enable enhanced logging`);
    summary.push(`4. Implement application allowlisting`);
    summary.push('');

    summary.push(`### 🔧 Patching Procedure`);
    summary.push('');
    summary.push(`#### Pre-Patch Checklist`);
    summary.push(`- [ ] Identify all affected systems (asset inventory)`);
    summary.push(`- [ ] Verify backup integrity`);
    summary.push(`- [ ] Test patch in staging environment`);
    summary.push(`- [ ] Schedule maintenance window`);
    summary.push(`- [ ] Prepare rollback plan`);
    summary.push(`- [ ] Notify stakeholders`);
    summary.push('');

    summary.push(`#### Patch Commands`);
    summary.push('```bash');
    summary.push(`# Linux - Update specific package`);
    summary.push(`apt-get update && apt-get install --only-upgrade <package>`);
    summary.push(`yum update <package>`);
    summary.push('');
    summary.push(`# Windows - Check for updates`);
    summary.push(`Get-WindowsUpdate -KBArticleID "KB*****"`);
    summary.push(`Install-WindowsUpdate -KBArticleID "KB*****" -AcceptAll`);
    summary.push('');
    summary.push(`# Verify patch installation`);
    summary.push(`dpkg -l | grep <package>`);
    summary.push(`rpm -qa | grep <package>`);
    summary.push(`Get-HotFix | Where-Object {$_.HotFixID -eq "KB*****"}`);
    summary.push('```');
    summary.push('');

    summary.push(`#### Post-Patch Verification`);
    summary.push(`- [ ] Verify service functionality`);
    summary.push(`- [ ] Run vulnerability scan to confirm remediation`);
    summary.push(`- [ ] Monitor for any issues`);
    summary.push(`- [ ] Update asset management system`);
    summary.push(`- [ ] Document completion`);
    summary.push('');

    // CWE-specific mitigations
    if (cwe) {
      summary.push(`### Specific Mitigations for ${cwe}`);
      const mitigations = this.getCweMitigations(cwe);
      for (const mitigation of mitigations) {
        summary.push(`- ${mitigation}`);
      }
      summary.push('');
    }

    summary.push(`### 📚 References`);
    if (cve?.references) {
      for (const ref of cve.references.slice(0, 5)) {
        const tags = ref.tags?.join(', ') || 'Reference';
        summary.push(`- [${tags}](${ref.url})`);
      }
    }
    summary.push(
      `- [NVD Entry](https://nvd.nist.gov/vuln/detail/${cveId || ''})`,
    );
    summary.push(
      `- [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId || ''})`,
    );

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Search GitHub Security Advisories
   */
  private async searchAdvisories(): Promise<ToolResult> {
    const { query, product, severity } = this.params;

    const params = new URLSearchParams({
      per_page: '20',
    });

    if (query || product) {
      // GitHub advisory search doesn't have a direct query param,
      // we'll need to filter results
    }
    if (severity) {
      params.set('severity', severity.toLowerCase());
    }

    const url = `${GITHUB_ADVISORY_API}?${params.toString()}`;

    const response = await fetchWithAbort(
      url,
      {
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': 'DarkCoder-SecurityIntel',
        },
      },
      TIMEOUT_MS,
    );

    if (!response.ok) {
      throw new Error(`GitHub API returned status ${response.status}`);
    }

    const data = (await response.json()) as GitHubAdvisory[];

    // Filter by query if provided
    let filtered = data;
    if (query || product) {
      const searchTerm = (query || product || '').toLowerCase();
      filtered = data.filter(
        (adv) =>
          adv.summary.toLowerCase().includes(searchTerm) ||
          adv.description.toLowerCase().includes(searchTerm) ||
          adv.cve_id?.toLowerCase().includes(searchTerm) ||
          adv.vulnerabilities.some(
            (v) =>
              v.package.name.toLowerCase().includes(searchTerm) ||
              v.package.ecosystem.toLowerCase().includes(searchTerm),
          ),
      );
    }

    if (filtered.length === 0) {
      return {
        llmContent: `No GitHub security advisories found for: ${query || product || 'recent'}`,
        returnDisplay: `No advisories found`,
      };
    }

    const summary: string[] = [
      `## GitHub Security Advisories`,
      `**Search:** ${query || product || 'Recent advisories'}`,
      `**Found:** ${filtered.length}`,
      '',
      '---',
      '',
    ];

    for (const adv of filtered.slice(0, 15)) {
      const severityEmoji = this.getSeverityEmoji(adv.severity.toUpperCase());

      summary.push(`### ${severityEmoji} ${adv.ghsa_id}`);
      if (adv.cve_id) {
        summary.push(`**CVE:** ${adv.cve_id}`);
      }
      summary.push(`**Severity:** ${adv.severity.toUpperCase()}`);
      summary.push(`**Published:** ${adv.published_at}`);
      summary.push('');
      summary.push(`**Summary:** ${adv.summary}`);
      summary.push('');

      if (adv.vulnerabilities.length > 0) {
        summary.push(`**Affected Packages:**`);
        for (const vuln of adv.vulnerabilities.slice(0, 5)) {
          summary.push(
            `- ${vuln.package.ecosystem}/${vuln.package.name}: ${vuln.vulnerable_version_range}`,
          );
          if (vuln.first_patched_version) {
            summary.push(`  - Patched in: ${vuln.first_patched_version}`);
          }
        }
      }
      summary.push('');
      summary.push('---');
      summary.push('');
    }

    const output = summary.join('\n');

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Get severity emoji
   */
  private getSeverityEmoji(severity: string): string {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return '🔴';
      case 'HIGH':
        return '🟠';
      case 'MEDIUM':
        return '🟡';
      case 'LOW':
        return '🟢';
      default:
        return '⚪';
    }
  }

  /**
   * Calculate response priority based on CVSS score
   */
  private calculatePriority(cvssScore: number): { level: string; sla: string } {
    if (cvssScore >= 9.0) {
      return {
        level: '🔴 CRITICAL - Immediate Action Required',
        sla: '24 hours',
      };
    } else if (cvssScore >= 7.0) {
      return { level: '🟠 HIGH - Urgent', sla: '7 days' };
    } else if (cvssScore >= 4.0) {
      return { level: '🟡 MEDIUM - Planned', sla: '30 days' };
    } else {
      return { level: '🟢 LOW - Scheduled', sla: '90 days' };
    }
  }

  /**
   * Get CWE-specific attack techniques
   */
  private getCweAttackTechniques(cwe: string): string[] {
    const techniques: Record<string, string[]> = {
      'CWE-79': [
        'Inject <script> tags in input fields',
        'Test DOM-based XSS vectors',
        'Use encoding bypass techniques',
        'Check for stored XSS in user profiles',
      ],
      'CWE-89': [
        'Use sqlmap for automated injection',
        'Test UNION-based injection',
        'Try time-based blind SQLi',
        'Check for second-order injection',
      ],
      'CWE-78': [
        'Chain commands with ; | && ||',
        'Test command substitution $()',
        'Try newline injection %0a',
        'Look for argument injection',
      ],
      'CWE-22': [
        'Use ../ sequences for traversal',
        'Try URL encoding (%2e%2e%2f)',
        'Test null byte injection %00',
        'Check for absolute path injection',
      ],
      'CWE-287': [
        'Test for default credentials',
        'Check for authentication bypass',
        'Try session fixation attacks',
        'Look for insecure password reset',
      ],
      'CWE-94': [
        'Look for eval() or similar functions',
        'Test template injection',
        'Check for deserialization flaws',
        'Try polyglot payloads',
      ],
    };

    // Find matching CWE
    for (const [key, value] of Object.entries(techniques)) {
      if (cwe.includes(key)) {
        return value;
      }
    }

    return [
      'Research specific attack vectors for this CWE',
      'Check MITRE ATT&CK for related techniques',
      'Search for public exploits and PoCs',
      'Test common bypass techniques',
    ];
  }

  /**
   * Get CWE-specific mitigations
   */
  private getCweMitigations(cwe: string): string[] {
    const mitigations: Record<string, string[]> = {
      'CWE-79': [
        'Implement Content Security Policy (CSP)',
        'Use output encoding/escaping',
        'Enable HttpOnly and Secure cookie flags',
        'Implement input validation',
      ],
      'CWE-89': [
        'Use parameterized queries/prepared statements',
        'Implement input validation',
        'Apply principle of least privilege to DB accounts',
        'Use WAF with SQL injection rules',
      ],
      'CWE-78': [
        'Avoid passing user input to shell commands',
        'Use allowlist for permitted commands',
        'Implement strict input validation',
        'Use safe API alternatives',
      ],
      'CWE-22': [
        'Use realpath() to validate paths',
        'Implement allowlist for file access',
        'Avoid user input in file operations',
        'Chroot/sandbox file operations',
      ],
      'CWE-287': [
        'Implement MFA',
        'Use strong session management',
        'Implement account lockout',
        'Use secure password hashing',
      ],
      'CWE-94': [
        'Avoid dynamic code execution',
        'Implement strict input validation',
        'Use sandboxing for code execution',
        'Apply allowlist for permitted operations',
      ],
    };

    for (const [key, value] of Object.entries(mitigations)) {
      if (cwe.includes(key)) {
        return value;
      }
    }

    return [
      'Apply vendor-recommended patches',
      'Implement defense in depth',
      'Enable enhanced logging and monitoring',
      'Follow security best practices for this vulnerability class',
    ];
  }
}

/**
 * Security Intelligence Tool for SOC and Red Team operations
 */
export class SecurityIntelTool extends BaseDeclarativeTool<
  SecurityIntelToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.SECURITY_INTEL;
  private readonly config: Config;

  constructor(config: Config) {
    super(
      SecurityIntelTool.Name,
      ToolDisplayNames.SECURITY_INTEL,
      `Security intelligence tool for SOC analysts and red teamers. Provides CVE lookup, HackerNews security discussions, exploit search, red team strategies, and SOC remediation guidance. Useful for:
- Looking up CVE details with CVSS scores from NVD/NIST
- Finding security discussions on HackerNews
- Searching for public exploits and PoCs
- Generating red team exploitation strategies
- Creating SOC remediation and patching guides
- Searching GitHub security advisories`,
      Kind.Fetch,
      {
        properties: {
          searchType: {
            type: 'string',
            enum: [
              'cve',
              'hackernews',
              'exploit',
              'redteam',
              'soc',
              'advisory',
            ],
            description:
              'Type of query: "cve" for NVD lookup, "hackernews" for security news, "exploit" for PoC search, "redteam" for attack strategy, "soc" for remediation guide, "advisory" for GitHub advisories',
          },
          cveId: {
            type: 'string',
            description: 'CVE identifier (e.g., CVE-2024-1234)',
          },
          query: {
            type: 'string',
            description:
              'Search query (keywords, product name, vulnerability type)',
          },
          product: {
            type: 'string',
            description: 'Product name to search for vulnerabilities',
          },
          vendor: {
            type: 'string',
            description: 'Vendor name for CVE search',
          },
          severity: {
            type: 'string',
            enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            description: 'Filter by CVSS severity level',
          },
          days: {
            type: 'number',
            description:
              'Limit HackerNews search to recent days (default: all time)',
          },
        },
        required: ['searchType'],
        type: 'object',
      },
    );
    this.config = config;
  }

  protected createInvocation(
    params: SecurityIntelToolParams,
  ): ToolInvocation<SecurityIntelToolParams, ToolResult> {
    return new SecurityIntelToolInvocation(this.config, params);
  }
}
