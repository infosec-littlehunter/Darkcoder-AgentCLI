/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * VirusTotal Tool for Malware Analysis & Threat Intelligence
 *
 * This tool provides access to the VirusTotal API v3 for comprehensive
 * threat intelligence. Useful for:
 * - File hash analysis (MD5, SHA1, SHA256)
 * - URL scanning and reputation lookup
 * - Domain reputation and WHOIS data
 * - IP address threat intelligence
 * - IOC enrichment for SOC operations
 * - Malware behavior analysis
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';

const VT_TIMEOUT_MS = 30000;
const VT_API_BASE = 'https://www.virustotal.com/api/v3';

// Environment variable for API key
const VT_API_KEY_ENV = 'VIRUSTOTAL_API_KEY';

// Rate limiting configuration (VirusTotal free tier: 4 requests/minute)
const VT_RATE_LIMIT_REQUESTS = 4;
const VT_RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const VT_RETRY_ATTEMPTS = 3;
const VT_RETRY_DELAY_MS = 1000;
const VT_RETRY_BACKOFF_MULTIPLIER = 2;

// Cache configuration (5 minute TTL for results)
const VT_CACHE_TTL_MS = 5 * 60 * 1000;
const VT_CACHE_MAX_SIZE = 100;

/**
 * Simple in-memory cache for VirusTotal results
 */
interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

class VTCache {
  private cache: Map<string, CacheEntry<ToolResult>> = new Map();
  private readonly ttl: number;
  private readonly maxSize: number;

  constructor(
    ttl: number = VT_CACHE_TTL_MS,
    maxSize: number = VT_CACHE_MAX_SIZE,
  ) {
    this.ttl = ttl;
    this.maxSize = maxSize;
  }

  private generateKey(searchType: string, identifier: string): string {
    return `${searchType}:${identifier.toLowerCase()}`;
  }

  get(searchType: string, identifier: string): ToolResult | null {
    const key = this.generateKey(searchType, identifier);
    const entry = this.cache.get(key);

    if (!entry) return null;

    // Check if entry has expired
    if (Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data;
  }

  set(searchType: string, identifier: string, data: ToolResult): void {
    const key = this.generateKey(searchType, identifier);

    // Evict oldest entries if cache is full
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      data,
      timestamp: Date.now(),
    });
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}

/**
 * Rate limiter for VirusTotal API requests
 * Implements token bucket algorithm
 */
class VTRateLimiter {
  private timestamps: number[] = [];
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(
    maxRequests: number = VT_RATE_LIMIT_REQUESTS,
    windowMs: number = VT_RATE_LIMIT_WINDOW_MS,
  ) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  /**
   * Check if a request can be made now
   */
  canMakeRequest(): boolean {
    this.cleanupOldTimestamps();
    return this.timestamps.length < this.maxRequests;
  }

  /**
   * Get the wait time in ms before next request can be made
   */
  getWaitTime(): number {
    this.cleanupOldTimestamps();

    if (this.timestamps.length < this.maxRequests) {
      return 0;
    }

    // Calculate when the oldest request will expire
    const oldestTimestamp = this.timestamps[0];
    const waitTime = oldestTimestamp + this.windowMs - Date.now();
    return Math.max(0, waitTime);
  }

  /**
   * Record a request timestamp
   */
  recordRequest(): void {
    this.timestamps.push(Date.now());
  }

  /**
   * Wait until a request can be made
   */
  async waitForSlot(): Promise<void> {
    const waitTime = this.getWaitTime();
    if (waitTime > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitTime));
    }
  }

  private cleanupOldTimestamps(): void {
    const cutoff = Date.now() - this.windowMs;
    this.timestamps = this.timestamps.filter((ts) => ts > cutoff);
  }

  /**
   * Get current rate limit status
   */
  getStatus(): { remaining: number; resetInMs: number } {
    this.cleanupOldTimestamps();
    const remaining = Math.max(0, this.maxRequests - this.timestamps.length);
    const resetInMs =
      this.timestamps.length > 0
        ? Math.max(0, this.timestamps[0] + this.windowMs - Date.now())
        : 0;
    return { remaining, resetInMs };
  }
}

// Global instances for rate limiting and caching
const vtRateLimiter = new VTRateLimiter();
const vtCache = new VTCache();

/**
 * Get VirusTotal rate limit status
 * Useful for debugging and monitoring API usage
 */
export function getVirusTotalRateLimitStatus(): {
  remaining: number;
  resetInMs: number;
  maxRequests: number;
  windowMs: number;
} {
  const status = vtRateLimiter.getStatus();
  return {
    ...status,
    maxRequests: VT_RATE_LIMIT_REQUESTS,
    windowMs: VT_RATE_LIMIT_WINDOW_MS,
  };
}

/**
 * Get VirusTotal cache statistics
 * Useful for debugging and monitoring cache usage
 */
export function getVirusTotalCacheStats(): {
  size: number;
  maxSize: number;
  ttlMs: number;
} {
  return {
    size: vtCache.size,
    maxSize: VT_CACHE_MAX_SIZE,
    ttlMs: VT_CACHE_TTL_MS,
  };
}

/**
 * Clear VirusTotal cache
 * Useful for forcing fresh lookups
 */
export function clearVirusTotalCache(): void {
  vtCache.clear();
}

/**
 * Search types for VirusTotal queries
 */
export type VirusTotalSearchType =
  | 'file' // Get file report by hash
  | 'url' // Scan or get URL report
  | 'domain' // Get domain report
  | 'ip' // Get IP address report
  | 'search' // Search for IOCs
  | 'behavior'; // Get file behavior report

/**
 * Parameters for the VirusTotal tool
 */
export interface VirusTotalToolParams {
  searchType: VirusTotalSearchType;
  hash?: string; // MD5, SHA1, or SHA256
  url?: string; // URL to scan or lookup
  domain?: string; // Domain to lookup
  ip?: string; // IP address to lookup
  query?: string; // Search query
  relationships?: string[]; // Related data to fetch
}

/**
 * VirusTotal analysis stats
 */
interface VTAnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}

/**
 * VirusTotal file report structure
 */
interface VTFileReport {
  data: {
    id: string;
    type: string;
    attributes: {
      md5: string;
      sha1: string;
      sha256: string;
      size: number;
      type_description?: string;
      type_tag?: string;
      meaningful_name?: string;
      names?: string[];
      reputation?: number;
      times_submitted?: number;
      first_submission_date?: number;
      last_submission_date?: number;
      last_analysis_date?: number;
      last_analysis_stats?: VTAnalysisStats;
      last_analysis_results?: Record<
        string,
        {
          category: string;
          engine_name: string;
          engine_version?: string;
          result?: string;
          method?: string;
        }
      >;
      tags?: string[];
      sandbox_verdicts?: Record<
        string,
        {
          category: string;
          confidence: number;
          sandbox_name: string;
          malware_names?: string[];
        }
      >;
      sigma_analysis_stats?: {
        critical: number;
        high: number;
        medium: number;
        low: number;
      };
      popular_threat_classification?: {
        suggested_threat_label?: string;
        popular_threat_category?: Array<{ value: string; count: number }>;
        popular_threat_name?: Array<{ value: string; count: number }>;
      };
      threat_severity?: {
        threat_severity_level?: string;
        level_description?: string;
      };
      crowdsourced_yara_results?: Array<{
        rule_name: string;
        ruleset_name: string;
        description?: string;
        source?: string;
      }>;
    };
  };
}

/**
 * VirusTotal URL report structure
 */
interface VTUrlReport {
  data: {
    id: string;
    type: string;
    attributes: {
      url: string;
      last_final_url?: string;
      last_http_response_code?: number;
      last_http_response_content_length?: number;
      title?: string;
      reputation?: number;
      times_submitted?: number;
      first_submission_date?: number;
      last_submission_date?: number;
      last_analysis_date?: number;
      last_analysis_stats?: VTAnalysisStats;
      last_analysis_results?: Record<
        string,
        {
          category: string;
          engine_name: string;
          result?: string;
        }
      >;
      categories?: Record<string, string>;
      tags?: string[];
      threat_names?: string[];
    };
  };
}

/**
 * VirusTotal domain report structure
 */
interface VTDomainReport {
  data: {
    id: string;
    type: string;
    attributes: {
      last_dns_records?: Array<{
        type: string;
        value: string;
        ttl?: number;
      }>;
      last_https_certificate?: {
        issuer?: { CN?: string; O?: string };
        subject?: { CN?: string };
        validity?: { not_after?: string; not_before?: string };
      };
      whois?: string;
      whois_date?: number;
      registrar?: string;
      creation_date?: number;
      last_modification_date?: number;
      reputation?: number;
      last_analysis_stats?: VTAnalysisStats;
      last_analysis_results?: Record<
        string,
        {
          category: string;
          engine_name: string;
          result?: string;
        }
      >;
      categories?: Record<string, string>;
      tags?: string[];
      popularity_ranks?: Record<string, { rank: number; timestamp: number }>;
    };
  };
}

/**
 * VirusTotal IP report structure
 */
interface VTIpReport {
  data: {
    id: string;
    type: string;
    attributes: {
      as_owner?: string;
      asn?: number;
      continent?: string;
      country?: string;
      network?: string;
      regional_internet_registry?: string;
      reputation?: number;
      whois?: string;
      whois_date?: number;
      last_analysis_stats?: VTAnalysisStats;
      last_analysis_results?: Record<
        string,
        {
          category: string;
          engine_name: string;
          result?: string;
        }
      >;
      tags?: string[];
      last_https_certificate?: {
        issuer?: { CN?: string; O?: string };
        subject?: { CN?: string };
      };
    };
  };
}

/**
 * VirusTotal search response
 */
interface VTSearchResponse {
  data: Array<{
    id: string;
    type: string;
    attributes: Record<string, unknown>;
  }>;
  meta?: {
    cursor?: string;
    count?: number;
  };
}

/**
 * VirusTotal behavior report structure
 */
interface VTBehaviorReport {
  data: Array<{
    id: string;
    attributes: {
      sandbox_name?: string;
      analysis_date?: number;
      command_executions?: string[];
      processes_injected?: string[];
      processes_terminated?: string[];
      processes_tree?: Array<{
        name: string;
        process_id: string;
        children?: unknown[];
      }>;
      registry_keys_set?: Array<{
        key: string;
        value?: string;
      }>;
      registry_keys_deleted?: string[];
      files_written?: string[];
      files_deleted?: string[];
      files_dropped?: Array<{
        path: string;
        sha256?: string;
      }>;
      ip_traffic?: Array<{
        destination_ip: string;
        destination_port: number;
        transport_layer_protocol?: string;
      }>;
      dns_lookups?: Array<{
        hostname: string;
        resolved_ips?: string[];
      }>;
      http_conversations?: Array<{
        url: string;
        request_method?: string;
        response_status_code?: number;
      }>;
      mitre_attack_techniques?: Array<{
        id: string;
        signature_description?: string;
      }>;
      tags?: string[];
      verdicts?: string[];
    };
  }>;
}

/**
 * Check if an error is retryable (network errors, rate limits, server errors)
 */
function isRetryableError(error: unknown, response?: Response): boolean {
  // Network errors are retryable
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    if (
      message.includes('network') ||
      message.includes('econnreset') ||
      message.includes('econnrefused') ||
      message.includes('etimedout') ||
      message.includes('socket')
    ) {
      return true;
    }
  }

  // HTTP status codes that are retryable
  if (response) {
    // 429 = Rate limited, 500-599 = Server errors
    return (
      response.status === 429 ||
      (response.status >= 500 && response.status < 600)
    );
  }

  return false;
}

/**
 * Sleep for a specified duration
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch with timeout, auth, rate limiting, and retry logic
 */
async function fetchWithAuth(
  url: string,
  apiKey: string,
  timeout: number,
  options: RequestInit = {},
): Promise<Response> {
  let lastError: Error | null = null;
  let lastResponse: Response | null = null;

  for (let attempt = 0; attempt < VT_RETRY_ATTEMPTS; attempt++) {
    // Wait for rate limit slot
    await vtRateLimiter.waitForSlot();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      // Record the request for rate limiting
      vtRateLimiter.recordRequest();

      const response = await fetch(url, {
        ...options,
        headers: {
          'x-apikey': apiKey,
          Accept: 'application/json',
          ...options.headers,
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Check if we got rate limited (429)
      if (response.status === 429) {
        lastResponse = response;
        const retryAfter = response.headers.get('Retry-After');
        const waitTime = retryAfter
          ? parseInt(retryAfter, 10) * 1000
          : VT_RETRY_DELAY_MS * Math.pow(VT_RETRY_BACKOFF_MULTIPLIER, attempt);

        if (attempt < VT_RETRY_ATTEMPTS - 1) {
          await sleep(waitTime);
          continue;
        }
      }

      // Check for server errors (5xx)
      if (response.status >= 500 && response.status < 600) {
        lastResponse = response;
        if (attempt < VT_RETRY_ATTEMPTS - 1) {
          const waitTime =
            VT_RETRY_DELAY_MS * Math.pow(VT_RETRY_BACKOFF_MULTIPLIER, attempt);
          await sleep(waitTime);
          continue;
        }
      }

      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      lastError = error instanceof Error ? error : new Error(String(error));

      // Check if it's a retryable error
      if (isRetryableError(error) && attempt < VT_RETRY_ATTEMPTS - 1) {
        const waitTime =
          VT_RETRY_DELAY_MS * Math.pow(VT_RETRY_BACKOFF_MULTIPLIER, attempt);
        await sleep(waitTime);
        continue;
      }

      // If it's an abort error (timeout), wrap it with a better message
      if (lastError.name === 'AbortError') {
        throw new Error(`Request timed out after ${timeout}ms`);
      }

      throw lastError;
    }
  }

  // If we exhausted all retries
  if (lastResponse?.status === 429) {
    const status = vtRateLimiter.getStatus();
    throw new Error(
      `Rate limited by VirusTotal API. Remaining quota: ${status.remaining}/${VT_RATE_LIMIT_REQUESTS}. ` +
        `Try again in ${Math.ceil(status.resetInMs / 1000)} seconds.`,
    );
  }

  if (lastResponse && lastResponse.status >= 500) {
    throw new Error(
      `VirusTotal server error (${lastResponse.status}). Please try again later.`,
    );
  }

  throw lastError || new Error('Request failed after all retry attempts');
}

/**
 * Format analysis stats into a human-readable summary
 */
function formatAnalysisStats(stats: VTAnalysisStats): string {
  const total =
    stats.harmless +
    stats.malicious +
    stats.suspicious +
    stats.undetected +
    stats.timeout;
  const detections = stats.malicious + stats.suspicious;

  let severity = '✅ Clean';
  if (stats.malicious > 0) {
    if (stats.malicious > 10) {
      severity = '🔴 HIGH RISK - Malicious';
    } else if (stats.malicious > 5) {
      severity = '🟠 MEDIUM RISK - Likely Malicious';
    } else {
      severity = '🟡 LOW RISK - Some Detections';
    }
  } else if (stats.suspicious > 0) {
    severity = '🟡 Suspicious';
  }

  return `${severity} (${detections}/${total} detections: ${stats.malicious} malicious, ${stats.suspicious} suspicious)`;
}

/**
 * Format Unix timestamp to readable date
 */
function formatTimestamp(timestamp?: number): string {
  if (!timestamp) return 'Unknown';
  return new Date(timestamp * 1000).toISOString().split('T')[0];
}

/**
 * Implementation of the VirusTotal tool invocation logic
 */
class VirusTotalToolInvocation extends BaseToolInvocation<
  VirusTotalToolParams,
  ToolResult
> {
  private readonly config: Config;

  constructor(config: Config, params: VirusTotalToolParams) {
    super(params);
    this.config = config;
  }

  getDescription(): string {
    const { searchType, hash, url, domain, ip, query } = this.params;
    switch (searchType) {
      case 'file':
        return `Analyzing file hash on VirusTotal: ${hash}`;
      case 'url':
        return `Analyzing URL on VirusTotal: ${url}`;
      case 'domain':
        return `Getting VirusTotal domain report for: ${domain}`;
      case 'ip':
        return `Getting VirusTotal IP report for: ${ip}`;
      case 'search':
        return `Searching VirusTotal: ${query}`;
      case 'behavior':
        return `Getting behavior report for file: ${hash}`;
      default:
        return 'Querying VirusTotal';
    }
  }

  private getApiKey(): string | null {
    // First check config (from settings.json), then fall back to environment variable
    return (
      this.config.getVirusTotalApiKey() || process.env[VT_API_KEY_ENV] || null
    );
  }

  async execute(): Promise<ToolResult> {
    const apiKey = this.getApiKey();

    if (!apiKey) {
      return {
        llmContent: `Error: VirusTotal API key not found. Please configure it in settings.json (advanced.virusTotalApiKey) or set ${VT_API_KEY_ENV} environment variable.\n\nGet your API key at: https://www.virustotal.com/gui/my-apikey`,
        returnDisplay: `VirusTotal API key not configured. Configure in settings.json or set ${VT_API_KEY_ENV} environment variable.`,
        error: {
          message: `Missing VirusTotal API key - configure in settings.json or ${VT_API_KEY_ENV} environment variable`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const { searchType, hash, url: targetUrl, domain, ip, query } = this.params;

    // Determine the cache key based on search type
    const cacheIdentifier = hash || targetUrl || domain || ip || query || '';

    // Check cache first (skip for 'search' as results may change)
    if (searchType !== 'search' && cacheIdentifier) {
      const cachedResult = vtCache.get(searchType, cacheIdentifier);
      if (cachedResult) {
        // Add cache hit indicator to the result
        const cachedContent =
          typeof cachedResult.llmContent === 'string'
            ? `${cachedResult.llmContent}\n\n*📦 Result from cache (TTL: ${Math.round(VT_CACHE_TTL_MS / 60000)} minutes)*`
            : cachedResult.llmContent;
        return {
          ...cachedResult,
          llmContent: cachedContent,
          returnDisplay: `${cachedResult.returnDisplay} (cached)`,
        };
      }
    }

    // Show rate limit status
    const rateStatus = vtRateLimiter.getStatus();
    if (rateStatus.remaining === 0) {
      const waitSecs = Math.ceil(rateStatus.resetInMs / 1000);
      return {
        llmContent: `Rate limit reached. VirusTotal free tier allows ${VT_RATE_LIMIT_REQUESTS} requests per minute. Please wait ${waitSecs} seconds before retrying.`,
        returnDisplay: `Rate limited - wait ${waitSecs}s`,
        error: {
          message: `Rate limit reached. Wait ${waitSecs} seconds.`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    try {
      let result: ToolResult;

      switch (searchType) {
        case 'file':
          result = await this.getFileReport(apiKey);
          break;
        case 'url':
          result = await this.analyzeUrl(apiKey);
          break;
        case 'domain':
          result = await this.getDomainReport(apiKey);
          break;
        case 'ip':
          result = await this.getIpReport(apiKey);
          break;
        case 'search':
          result = await this.search(apiKey);
          break;
        case 'behavior':
          result = await this.getBehaviorReport(apiKey);
          break;
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

      // Cache successful results (skip errors and search results)
      if (!result.error && searchType !== 'search' && cacheIdentifier) {
        vtCache.set(searchType, cacheIdentifier, result);
      }

      return result;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return {
        llmContent: `Error: VirusTotal query failed: ${errorMessage}`,
        returnDisplay: `VirusTotal query failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Get file report by hash (MD5, SHA1, SHA256)
   */
  private async getFileReport(apiKey: string): Promise<ToolResult> {
    const { hash } = this.params;

    if (!hash) {
      return {
        llmContent: 'Error: File hash is required for file analysis',
        returnDisplay: 'Missing file hash parameter',
        error: {
          message: 'File hash is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // Validate hash format
    const hashLower = hash.toLowerCase();
    if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hashLower)) {
      return {
        llmContent:
          'Error: Invalid hash format. Please provide MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars)',
        returnDisplay: 'Invalid hash format',
        error: {
          message: 'Invalid hash format',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${VT_API_BASE}/files/${hashLower}`;
    const response = await fetchWithAuth(url, apiKey, VT_TIMEOUT_MS);

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `File not found in VirusTotal database.\n\nHash: ${hash}\n\nThis file has not been previously submitted to VirusTotal. Consider submitting it for analysis.`,
          returnDisplay: 'File not found in VirusTotal',
        };
      }
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as VTFileReport;
    const attrs = data.data.attributes;

    // Build comprehensive report
    const content: string[] = [
      '# VirusTotal File Analysis Report',
      '',
      '## File Information',
      `- **SHA256:** ${attrs.sha256}`,
      `- **SHA1:** ${attrs.sha1}`,
      `- **MD5:** ${attrs.md5}`,
      `- **Size:** ${(attrs.size / 1024).toFixed(2)} KB`,
      `- **Type:** ${attrs.type_description || attrs.type_tag || 'Unknown'}`,
    ];

    if (attrs.meaningful_name) {
      content.push(`- **Name:** ${attrs.meaningful_name}`);
    }
    if (attrs.names && attrs.names.length > 0) {
      content.push(`- **Known Names:** ${attrs.names.slice(0, 5).join(', ')}`);
    }

    content.push('');
    content.push('## Analysis Summary');

    if (attrs.last_analysis_stats) {
      content.push(
        `- **Verdict:** ${formatAnalysisStats(attrs.last_analysis_stats)}`,
      );
    }

    if (attrs.reputation !== undefined) {
      content.push(`- **Community Reputation:** ${attrs.reputation}`);
    }

    content.push(`- **Times Submitted:** ${attrs.times_submitted || 0}`);
    content.push(
      `- **First Seen:** ${formatTimestamp(attrs.first_submission_date)}`,
    );
    content.push(
      `- **Last Analysis:** ${formatTimestamp(attrs.last_analysis_date)}`,
    );

    // Threat classification
    if (attrs.popular_threat_classification) {
      content.push('');
      content.push('## Threat Classification');
      if (attrs.popular_threat_classification.suggested_threat_label) {
        content.push(
          `- **Suggested Label:** ${attrs.popular_threat_classification.suggested_threat_label}`,
        );
      }
      if (attrs.popular_threat_classification.popular_threat_name) {
        const names = attrs.popular_threat_classification.popular_threat_name
          .slice(0, 5)
          .map((n) => `${n.value} (${n.count})`)
          .join(', ');
        content.push(`- **Threat Names:** ${names}`);
      }
    }

    // Threat severity
    if (attrs.threat_severity) {
      content.push(
        `- **Severity Level:** ${attrs.threat_severity.threat_severity_level || 'Unknown'}`,
      );
      if (attrs.threat_severity.level_description) {
        content.push(
          `- **Severity Details:** ${attrs.threat_severity.level_description}`,
        );
      }
    }

    // Sandbox verdicts
    if (
      attrs.sandbox_verdicts &&
      Object.keys(attrs.sandbox_verdicts).length > 0
    ) {
      content.push('');
      content.push('## Sandbox Analysis');
      for (const [name, verdict] of Object.entries(attrs.sandbox_verdicts)) {
        const malwareNames =
          verdict.malware_names?.join(', ') || 'None identified';
        content.push(
          `- **${verdict.sandbox_name || name}:** ${verdict.category} (confidence: ${verdict.confidence}%) - ${malwareNames}`,
        );
      }
    }

    // Sigma analysis
    if (attrs.sigma_analysis_stats) {
      const sigma = attrs.sigma_analysis_stats;
      if (sigma.critical > 0 || sigma.high > 0 || sigma.medium > 0) {
        content.push('');
        content.push('## SIGMA Rule Matches');
        content.push(
          `- Critical: ${sigma.critical}, High: ${sigma.high}, Medium: ${sigma.medium}, Low: ${sigma.low}`,
        );
      }
    }

    // YARA matches
    if (
      attrs.crowdsourced_yara_results &&
      attrs.crowdsourced_yara_results.length > 0
    ) {
      content.push('');
      content.push('## YARA Rule Matches');
      for (const yara of attrs.crowdsourced_yara_results.slice(0, 10)) {
        content.push(
          `- **${yara.rule_name}** (${yara.ruleset_name}): ${yara.description || 'No description'}`,
        );
      }
    }

    // Detection details (top detections)
    if (attrs.last_analysis_results) {
      const detections = Object.entries(attrs.last_analysis_results)
        .filter(
          ([, r]) => r.category === 'malicious' || r.category === 'suspicious',
        )
        .slice(0, 15);

      if (detections.length > 0) {
        content.push('');
        content.push('## Detection Details');
        content.push('| Engine | Category | Detection |');
        content.push('|--------|----------|-----------|');
        for (const [engine, result] of detections) {
          content.push(
            `| ${engine} | ${result.category} | ${result.result || 'N/A'} |`,
          );
        }
      }
    }

    // Tags
    if (attrs.tags && attrs.tags.length > 0) {
      content.push('');
      content.push(`## Tags: ${attrs.tags.join(', ')}`);
    }

    content.push('');
    content.push(
      `[View on VirusTotal](https://www.virustotal.com/gui/file/${attrs.sha256})`,
    );

    return {
      llmContent: content.join('\n'),
      returnDisplay: attrs.last_analysis_stats
        ? formatAnalysisStats(attrs.last_analysis_stats)
        : 'File report retrieved',
    };
  }

  /**
   * Analyze URL or get URL report
   */
  private async analyzeUrl(apiKey: string): Promise<ToolResult> {
    const { url: targetUrl } = this.params;

    if (!targetUrl) {
      return {
        llmContent: 'Error: URL is required for URL analysis',
        returnDisplay: 'Missing URL parameter',
        error: {
          message: 'URL is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    // URL ID is base64 encoded URL without padding
    const urlId = Buffer.from(targetUrl)
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    const url = `${VT_API_BASE}/urls/${urlId}`;
    const response = await fetchWithAuth(url, apiKey, VT_TIMEOUT_MS);

    if (!response.ok) {
      if (response.status === 404) {
        // URL not found, submit for scanning
        const submitUrl = `${VT_API_BASE}/urls`;
        const submitResponse = await fetchWithAuth(
          submitUrl,
          apiKey,
          VT_TIMEOUT_MS,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `url=${encodeURIComponent(targetUrl)}`,
          },
        );

        if (!submitResponse.ok) {
          throw new Error(
            `Failed to submit URL: ${submitResponse.status} ${submitResponse.statusText}`,
          );
        }

        return {
          llmContent: `URL submitted for analysis.\n\n**URL:** ${targetUrl}\n\nThe URL has been submitted to VirusTotal for scanning. Results will be available shortly. Please query again in a few minutes.`,
          returnDisplay: 'URL submitted for analysis',
        };
      }
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as VTUrlReport;
    const attrs = data.data.attributes;

    const content: string[] = [
      '# VirusTotal URL Analysis Report',
      '',
      '## URL Information',
      `- **URL:** ${attrs.url}`,
    ];

    if (attrs.last_final_url && attrs.last_final_url !== attrs.url) {
      content.push(`- **Final URL:** ${attrs.last_final_url}`);
    }
    if (attrs.title) {
      content.push(`- **Page Title:** ${attrs.title}`);
    }
    if (attrs.last_http_response_code) {
      content.push(`- **HTTP Status:** ${attrs.last_http_response_code}`);
    }

    content.push('');
    content.push('## Analysis Summary');

    if (attrs.last_analysis_stats) {
      content.push(
        `- **Verdict:** ${formatAnalysisStats(attrs.last_analysis_stats)}`,
      );
    }

    if (attrs.reputation !== undefined) {
      content.push(`- **Community Reputation:** ${attrs.reputation}`);
    }

    content.push(`- **Times Submitted:** ${attrs.times_submitted || 0}`);
    content.push(
      `- **First Seen:** ${formatTimestamp(attrs.first_submission_date)}`,
    );
    content.push(
      `- **Last Analysis:** ${formatTimestamp(attrs.last_analysis_date)}`,
    );

    // Categories
    if (attrs.categories && Object.keys(attrs.categories).length > 0) {
      content.push('');
      content.push('## Categories');
      for (const [source, category] of Object.entries(attrs.categories)) {
        content.push(`- **${source}:** ${category}`);
      }
    }

    // Threat names
    if (attrs.threat_names && attrs.threat_names.length > 0) {
      content.push('');
      content.push(`## Threat Names: ${attrs.threat_names.join(', ')}`);
    }

    // Tags
    if (attrs.tags && attrs.tags.length > 0) {
      content.push('');
      content.push(`## Tags: ${attrs.tags.join(', ')}`);
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: attrs.last_analysis_stats
        ? formatAnalysisStats(attrs.last_analysis_stats)
        : 'URL report retrieved',
    };
  }

  /**
   * Get domain report
   */
  private async getDomainReport(apiKey: string): Promise<ToolResult> {
    const { domain } = this.params;

    if (!domain) {
      return {
        llmContent: 'Error: Domain is required for domain analysis',
        returnDisplay: 'Missing domain parameter',
        error: {
          message: 'Domain is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${VT_API_BASE}/domains/${domain}`;
    const response = await fetchWithAuth(url, apiKey, VT_TIMEOUT_MS);

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `Domain not found in VirusTotal database: ${domain}`,
          returnDisplay: 'Domain not found',
        };
      }
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as VTDomainReport;
    const attrs = data.data.attributes;

    const content: string[] = [
      '# VirusTotal Domain Report',
      '',
      '## Domain Information',
      `- **Domain:** ${domain}`,
    ];

    if (attrs.registrar) {
      content.push(`- **Registrar:** ${attrs.registrar}`);
    }
    if (attrs.creation_date) {
      content.push(`- **Created:** ${formatTimestamp(attrs.creation_date)}`);
    }

    content.push('');
    content.push('## Analysis Summary');

    if (attrs.last_analysis_stats) {
      content.push(
        `- **Verdict:** ${formatAnalysisStats(attrs.last_analysis_stats)}`,
      );
    }

    if (attrs.reputation !== undefined) {
      content.push(`- **Community Reputation:** ${attrs.reputation}`);
    }

    // DNS records
    if (attrs.last_dns_records && attrs.last_dns_records.length > 0) {
      content.push('');
      content.push('## DNS Records');
      for (const record of attrs.last_dns_records.slice(0, 10)) {
        content.push(`- **${record.type}:** ${record.value}`);
      }
    }

    // SSL Certificate
    if (attrs.last_https_certificate) {
      const cert = attrs.last_https_certificate;
      content.push('');
      content.push('## SSL Certificate');
      if (cert.subject?.CN) {
        content.push(`- **Subject:** ${cert.subject.CN}`);
      }
      if (cert.issuer?.O) {
        content.push(`- **Issuer:** ${cert.issuer.O}`);
      }
      if (cert.validity?.not_after) {
        content.push(`- **Expires:** ${cert.validity.not_after}`);
      }
    }

    // Popularity ranks
    if (
      attrs.popularity_ranks &&
      Object.keys(attrs.popularity_ranks).length > 0
    ) {
      content.push('');
      content.push('## Popularity Rankings');
      for (const [source, rank] of Object.entries(attrs.popularity_ranks)) {
        content.push(`- **${source}:** #${rank.rank}`);
      }
    }

    // Categories
    if (attrs.categories && Object.keys(attrs.categories).length > 0) {
      content.push('');
      content.push('## Categories');
      for (const [source, category] of Object.entries(attrs.categories)) {
        content.push(`- **${source}:** ${category}`);
      }
    }

    // Tags
    if (attrs.tags && attrs.tags.length > 0) {
      content.push('');
      content.push(`## Tags: ${attrs.tags.join(', ')}`);
    }

    content.push('');
    content.push(
      `[View on VirusTotal](https://www.virustotal.com/gui/domain/${domain})`,
    );

    return {
      llmContent: content.join('\n'),
      returnDisplay: attrs.last_analysis_stats
        ? formatAnalysisStats(attrs.last_analysis_stats)
        : 'Domain report retrieved',
    };
  }

  /**
   * Get IP address report
   */
  private async getIpReport(apiKey: string): Promise<ToolResult> {
    const { ip } = this.params;

    if (!ip) {
      return {
        llmContent: 'Error: IP address is required for IP analysis',
        returnDisplay: 'Missing IP parameter',
        error: {
          message: 'IP address is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${VT_API_BASE}/ip_addresses/${ip}`;
    const response = await fetchWithAuth(url, apiKey, VT_TIMEOUT_MS);

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `IP address not found in VirusTotal database: ${ip}`,
          returnDisplay: 'IP not found',
        };
      }
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as VTIpReport;
    const attrs = data.data.attributes;

    const content: string[] = [
      '# VirusTotal IP Address Report',
      '',
      '## IP Information',
      `- **IP Address:** ${ip}`,
    ];

    if (attrs.as_owner) {
      content.push(`- **AS Owner:** ${attrs.as_owner}`);
    }
    if (attrs.asn) {
      content.push(`- **ASN:** ${attrs.asn}`);
    }
    if (attrs.network) {
      content.push(`- **Network:** ${attrs.network}`);
    }
    if (attrs.country) {
      content.push(`- **Country:** ${attrs.country}`);
    }
    if (attrs.continent) {
      content.push(`- **Continent:** ${attrs.continent}`);
    }

    content.push('');
    content.push('## Analysis Summary');

    if (attrs.last_analysis_stats) {
      content.push(
        `- **Verdict:** ${formatAnalysisStats(attrs.last_analysis_stats)}`,
      );
    }

    if (attrs.reputation !== undefined) {
      content.push(`- **Community Reputation:** ${attrs.reputation}`);
    }

    // Tags
    if (attrs.tags && attrs.tags.length > 0) {
      content.push('');
      content.push(`## Tags: ${attrs.tags.join(', ')}`);
    }

    content.push('');
    content.push(
      `[View on VirusTotal](https://www.virustotal.com/gui/ip-address/${ip})`,
    );

    return {
      llmContent: content.join('\n'),
      returnDisplay: attrs.last_analysis_stats
        ? formatAnalysisStats(attrs.last_analysis_stats)
        : 'IP report retrieved',
    };
  }

  /**
   * Search VirusTotal for IOCs
   */
  private async search(apiKey: string): Promise<ToolResult> {
    const { query } = this.params;

    if (!query) {
      return {
        llmContent: 'Error: Search query is required',
        returnDisplay: 'Missing search query',
        error: {
          message: 'Search query is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const url = `${VT_API_BASE}/search?query=${encodeURIComponent(query)}&limit=10`;
    const response = await fetchWithAuth(url, apiKey, VT_TIMEOUT_MS);

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as VTSearchResponse;

    if (!data.data || data.data.length === 0) {
      return {
        llmContent: `No results found for query: ${query}`,
        returnDisplay: 'No results found',
      };
    }

    const content: string[] = [
      '# VirusTotal Search Results',
      '',
      `**Query:** ${query}`,
      `**Results:** ${data.data.length}`,
      '',
    ];

    for (const item of data.data) {
      content.push(`## ${item.type}: ${item.id}`);
      const attrs = item.attributes as Record<string, unknown>;
      if (attrs['last_analysis_stats']) {
        content.push(
          `- Analysis: ${formatAnalysisStats(attrs['last_analysis_stats'] as VTAnalysisStats)}`,
        );
      }
      content.push('');
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `Found ${data.data.length} results`,
    };
  }

  /**
   * Get file behavior report (sandbox analysis)
   */
  private async getBehaviorReport(apiKey: string): Promise<ToolResult> {
    const { hash } = this.params;

    if (!hash) {
      return {
        llmContent: 'Error: File hash is required for behavior report',
        returnDisplay: 'Missing file hash parameter',
        error: {
          message: 'File hash is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const hashLower = hash.toLowerCase();
    const url = `${VT_API_BASE}/files/${hashLower}/behaviours`;
    const response = await fetchWithAuth(url, apiKey, VT_TIMEOUT_MS);

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `No behavior data available for file: ${hash}\n\nThe file may not have been analyzed in a sandbox.`,
          returnDisplay: 'No behavior data available',
        };
      }
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as VTBehaviorReport;

    if (!data.data || data.data.length === 0) {
      return {
        llmContent: `No behavior data available for file: ${hash}`,
        returnDisplay: 'No behavior data',
      };
    }

    const content: string[] = [
      '# VirusTotal Behavior Analysis Report',
      '',
      `**File Hash:** ${hash}`,
      `**Sandbox Reports:** ${data.data.length}`,
      '',
    ];

    for (const report of data.data.slice(0, 3)) {
      const attrs = report.attributes;
      content.push(`## Sandbox: ${attrs.sandbox_name || 'Unknown'}`);
      content.push(
        `**Analysis Date:** ${formatTimestamp(attrs.analysis_date)}`,
      );
      content.push('');

      // MITRE ATT&CK
      if (
        attrs.mitre_attack_techniques &&
        attrs.mitre_attack_techniques.length > 0
      ) {
        content.push('### MITRE ATT&CK Techniques');
        for (const technique of attrs.mitre_attack_techniques.slice(0, 10)) {
          content.push(
            `- **${technique.id}**: ${technique.signature_description || 'No description'}`,
          );
        }
        content.push('');
      }

      // Network activity
      if (attrs.dns_lookups && attrs.dns_lookups.length > 0) {
        content.push('### DNS Lookups');
        for (const dns of attrs.dns_lookups.slice(0, 10)) {
          const ips = dns.resolved_ips?.join(', ') || 'Not resolved';
          content.push(`- ${dns.hostname} → ${ips}`);
        }
        content.push('');
      }

      if (attrs.ip_traffic && attrs.ip_traffic.length > 0) {
        content.push('### Network Connections');
        for (const conn of attrs.ip_traffic.slice(0, 10)) {
          content.push(
            `- ${conn.destination_ip}:${conn.destination_port} (${conn.transport_layer_protocol || 'TCP'})`,
          );
        }
        content.push('');
      }

      // File system
      if (attrs.files_written && attrs.files_written.length > 0) {
        content.push('### Files Written');
        for (const file of attrs.files_written.slice(0, 10)) {
          content.push(`- ${file}`);
        }
        content.push('');
      }

      if (attrs.files_dropped && attrs.files_dropped.length > 0) {
        content.push('### Files Dropped');
        for (const file of attrs.files_dropped.slice(0, 10)) {
          content.push(`- ${file.path}`);
        }
        content.push('');
      }

      // Registry
      if (attrs.registry_keys_set && attrs.registry_keys_set.length > 0) {
        content.push('### Registry Keys Modified');
        for (const key of attrs.registry_keys_set.slice(0, 10)) {
          content.push(`- ${key.key}`);
        }
        content.push('');
      }

      // Commands
      if (attrs.command_executions && attrs.command_executions.length > 0) {
        content.push('### Commands Executed');
        for (const cmd of attrs.command_executions.slice(0, 10)) {
          content.push(`- \`${cmd}\``);
        }
        content.push('');
      }

      // Verdicts
      if (attrs.verdicts && attrs.verdicts.length > 0) {
        content.push(`### Verdicts: ${attrs.verdicts.join(', ')}`);
        content.push('');
      }

      // Tags
      if (attrs.tags && attrs.tags.length > 0) {
        content.push(`### Tags: ${attrs.tags.join(', ')}`);
        content.push('');
      }
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `${data.data.length} sandbox report(s) retrieved`,
    };
  }
}

/**
 * VirusTotal Tool - Malware analysis and threat intelligence
 */
export class VirusTotalTool extends BaseDeclarativeTool<
  VirusTotalToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.VIRUSTOTAL;
  private readonly config: Config;

  constructor(config: Config) {
    super(
      VirusTotalTool.Name,
      ToolDisplayNames.VIRUSTOTAL,
      `Query VirusTotal for comprehensive malware analysis and threat intelligence. API key can be configured in settings.json (advanced.virusTotalApiKey) or via VIRUSTOTAL_API_KEY environment variable. Supports:
- File hash analysis (MD5, SHA1, SHA256)
- URL scanning and reputation
- Domain threat intelligence
- IP address reports
- Malware behavior analysis
- IOC searching`,
      Kind.Fetch,
      {
        type: 'object',
        properties: {
          searchType: {
            type: 'string',
            enum: ['file', 'url', 'domain', 'ip', 'search', 'behavior'],
            description:
              'Type of VirusTotal query: file (hash lookup), url (scan/lookup), domain (report), ip (report), search (IOC search), behavior (sandbox analysis)',
          },
          hash: {
            type: 'string',
            description:
              'File hash (MD5, SHA1, or SHA256) for file or behavior analysis',
          },
          url: {
            type: 'string',
            description: 'URL to scan or lookup',
          },
          domain: {
            type: 'string',
            description: 'Domain name to lookup',
          },
          ip: {
            type: 'string',
            description: 'IP address to lookup',
          },
          query: {
            type: 'string',
            description: 'Search query for IOC searching',
          },
        },
        required: ['searchType'],
      },
    );
    this.config = config;
  }

  protected createInvocation(
    params: VirusTotalToolParams,
  ): ToolInvocation<VirusTotalToolParams, ToolResult> {
    return new VirusTotalToolInvocation(this.config, params);
  }
}
