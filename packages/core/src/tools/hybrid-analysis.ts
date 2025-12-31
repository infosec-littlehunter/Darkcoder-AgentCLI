/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Hybrid Analysis Tool for Advanced Malware Analysis
 *
 * This tool provides integration with Hybrid Analysis (CrowdStrike's free
 * malware analysis service) for comprehensive behavioral analysis. Features:
 * - File submission for dynamic analysis
 * - Hash lookup for existing reports
 * - Detailed behavioral reports (processes, files, network, registry)
 * - MITRE ATT&CK technique mapping
 * - Threat scoring and classification
 * - IOC extraction from analysis reports
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import FormData from 'form-data';

const HA_TIMEOUT_MS = 120000; // 2 minutes for API calls
const HA_API_BASE = 'https://www.hybrid-analysis.com/api/v2';

// Environment variable for API key
const HA_API_KEY_ENV = 'HYBRID_ANALYSIS_API_KEY';

// Rate limiting configuration (Hybrid Analysis: 5 requests/minute for free tier)
const HA_RATE_LIMIT_REQUESTS = 5;
const HA_RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const HA_RETRY_ATTEMPTS = 3;
const HA_RETRY_DELAY_MS = 2000;

// Cache configuration (10 minute TTL for results)
const HA_CACHE_TTL_MS = 10 * 60 * 1000;
const HA_CACHE_MAX_SIZE = 50;

/**
 * Simple in-memory cache for Hybrid Analysis results
 */
interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

class HACache {
  private cache: Map<string, CacheEntry<ToolResult>> = new Map();
  private readonly ttl: number;
  private readonly maxSize: number;

  constructor(
    ttl: number = HA_CACHE_TTL_MS,
    maxSize: number = HA_CACHE_MAX_SIZE,
  ) {
    this.ttl = ttl;
    this.maxSize = maxSize;
  }

  private generateKey(operation: string, identifier: string): string {
    return `${operation}:${identifier.toLowerCase()}`;
  }

  get(operation: string, identifier: string): ToolResult | null {
    const key = this.generateKey(operation, identifier);
    const entry = this.cache.get(key);

    if (!entry) return null;

    if (Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data;
  }

  set(operation: string, identifier: string, data: ToolResult): void {
    const key = this.generateKey(operation, identifier);

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
 * Rate limiter for Hybrid Analysis API requests
 */
class HARateLimiter {
  private timestamps: number[] = [];
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(
    maxRequests: number = HA_RATE_LIMIT_REQUESTS,
    windowMs: number = HA_RATE_LIMIT_WINDOW_MS,
  ) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  canMakeRequest(): boolean {
    this.cleanupOldTimestamps();
    return this.timestamps.length < this.maxRequests;
  }

  getWaitTime(): number {
    this.cleanupOldTimestamps();

    if (this.timestamps.length < this.maxRequests) {
      return 0;
    }

    const oldestTimestamp = this.timestamps[0];
    const waitTime = oldestTimestamp + this.windowMs - Date.now();
    return Math.max(0, waitTime);
  }

  recordRequest(): void {
    this.timestamps.push(Date.now());
  }

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

// Global instances
const haRateLimiter = new HARateLimiter();
const haCache = new HACache();

/**
 * Get Hybrid Analysis rate limit status
 */
export function getHybridAnalysisRateLimitStatus(): {
  remaining: number;
  resetInMs: number;
  maxRequests: number;
  windowMs: number;
} {
  const status = haRateLimiter.getStatus();
  return {
    ...status,
    maxRequests: HA_RATE_LIMIT_REQUESTS,
    windowMs: HA_RATE_LIMIT_WINDOW_MS,
  };
}

/**
 * Clear Hybrid Analysis cache
 */
export function clearHybridAnalysisCache(): void {
  haCache.clear();
}

/**
 * Operation types for Hybrid Analysis
 */
export type HybridAnalysisOperationType =
  | 'lookup_hash' // Get report by hash
  | 'submit_file' // Submit file for analysis
  | 'submit_url' // Submit URL for analysis
  | 'get_report' // Get full analysis report
  | 'search' // Search for samples
  | 'get_state' // Check analysis state
  | 'quick_scan'; // Quick scan with VirusTotal-like results

/**
 * Environment IDs for Hybrid Analysis
 */
export type HybridAnalysisEnvironment =
  | 300 // Linux (Ubuntu 16.04, 64-bit)
  | 200 // Android Static Analysis
  | 120 // Windows 7, 64-bit
  | 110 // Windows 7, 32-bit
  | 100 // Windows 7, 32-bit (HWP Support)
  | 160 // Windows 10, 64-bit
  | 140; // Windows 11, 64-bit

/**
 * Parameters for the Hybrid Analysis tool
 */
export interface HybridAnalysisToolParams {
  operation: HybridAnalysisOperationType;
  hash?: string; // MD5, SHA1, or SHA256
  filePath?: string; // File to submit
  url?: string; // URL to submit
  jobId?: string; // Job ID for status check
  query?: string; // Search query
  environmentId?: HybridAnalysisEnvironment; // Analysis environment
  noShareThirdParty?: boolean; // Don't share with third parties
  allowCommunityAccess?: boolean; // Allow community access
  comment?: string; // Comment for submission
}

/**
 * Hybrid Analysis response structures
 */
interface HASubmitResponse {
  job_id: string;
  environment_id: number;
  sha256: string;
}

interface HAReportResponse {
  job_id: string;
  environment_id: number;
  sha256: string;
  md5: string;
  sha1: string;
  sha512: string;
  size: number;
  type: string;
  type_short: string[];
  analysis_start_time: string;
  threat_score: number;
  threat_level: number;
  verdict: string;
  av_detect: number;
  vx_family: string;
  tags: string[];
  mitre_attcks?: Array<{
    tactic: string;
    technique: string;
    attck_id: string;
    attck_id_wiki: string;
    malicious_identifiers_count: number;
    malicious_identifiers: string[];
  }>;
  processes?: Array<{
    uid: string;
    name: string;
    normalized_path: string;
    command_line: string;
    sha256: string;
  }>;
  extracted_files?: Array<{
    name: string;
    file_path: string;
    sha256: string;
    type: string;
    threat_level: number;
  }>;
  network?: Array<{
    protocol: string;
    destination_ip: string;
    destination_port: number;
    domain?: string;
  }>;
  registry?: Array<{
    key: string;
    value?: string;
    operation: string;
  }>;
  file_operations?: Array<{
    path: string;
    operation: string;
    type: string;
  }>;
  domains?: string[];
  hosts?: string[];
  compromised_hosts?: string[];
  submit_name?: string;
  classification_tags?: string[];
  certificates?: Array<{
    owner: string;
    issuer: string;
    valid_from: string;
    valid_to: string;
  }>;
  total_network_connections?: number;
  total_processes?: number;
  total_signatures?: number;
  signatures?: Array<{
    name: string;
    threat_level: number;
    threat_level_human: string;
    category: string;
  }>;
  error_type?: string;
  error_origin?: string;
}

interface HASearchResponse {
  count: number;
  result: Array<{
    sha256: string;
    sha1: string;
    md5: string;
    verdict: string;
    threat_score: number;
    av_detect: number;
    vx_family: string;
    analysis_start_time: string;
    type_short: string[];
    size: number;
    environment_id: number;
    tags: string[];
  }>;
  search_terms: string[];
}

interface HAStateResponse {
  state: string;
  error?: string;
  related_reports?: string[];
}

/**
 * Fetch with timeout and retry helper
 */
async function fetchWithRetry(
  url: string,
  options: RequestInit,
  timeout: number,
  retries: number = HA_RETRY_ATTEMPTS,
): Promise<Response> {
  let lastError: Error | null = null;
  let delay = HA_RETRY_DELAY_MS;

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        // Rate limit handling
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          const waitTime = retryAfter ? parseInt(retryAfter, 10) * 1000 : delay;
          await new Promise((resolve) => setTimeout(resolve, waitTime));
          delay *= 2;
          continue;
        }

        return response;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (attempt < retries - 1) {
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2;
      }
    }
  }

  throw lastError || new Error('Request failed after retries');
}

/**
 * Implementation of the Hybrid Analysis tool invocation logic
 */
class HybridAnalysisToolInvocation extends BaseToolInvocation<
  HybridAnalysisToolParams,
  ToolResult
> {
  private readonly config: Config;

  constructor(config: Config, params: HybridAnalysisToolParams) {
    super(params);
    this.config = config;
  }

  getDescription(): string {
    const { operation, hash, filePath, url, jobId, query } = this.params;
    switch (operation) {
      case 'lookup_hash':
        return `Looking up hash in Hybrid Analysis: ${hash}`;
      case 'submit_file':
        return `Submitting file for Hybrid Analysis: ${filePath}`;
      case 'submit_url':
        return `Submitting URL for Hybrid Analysis: ${url}`;
      case 'get_report':
        return `Getting Hybrid Analysis report for: ${hash || jobId}`;
      case 'search':
        return `Searching Hybrid Analysis: ${query}`;
      case 'get_state':
        return `Checking analysis state: ${jobId}`;
      case 'quick_scan':
        return `Quick scanning hash: ${hash}`;
      default:
        return 'Querying Hybrid Analysis';
    }
  }

  private getApiKey(): string | null {
    return (
      this.config.getHybridAnalysisApiKey?.() ||
      process.env[HA_API_KEY_ENV] ||
      null
    );
  }

  private getHeaders(): Record<string, string> {
    const apiKey = this.getApiKey();
    if (!apiKey) {
      throw new Error(
        `Hybrid Analysis API key not found. Configure in settings.json (hybridAnalysisApiKey) or set ${HA_API_KEY_ENV} environment variable.`,
      );
    }

    return {
      'api-key': apiKey,
      'User-Agent': 'DarkCoder/1.0',
      Accept: 'application/json',
    };
  }

  async execute(): Promise<ToolResult> {
    const apiKey = this.getApiKey();

    if (!apiKey) {
      return {
        llmContent: `Error: Hybrid Analysis API key not found. Please configure it in settings.json (hybridAnalysisApiKey) or set ${HA_API_KEY_ENV} environment variable.\n\nGet your free API key at: https://www.hybrid-analysis.com/signup`,
        returnDisplay: `Hybrid Analysis API key not configured`,
        error: {
          message: `Missing Hybrid Analysis API key`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    const { operation, hash, jobId } = this.params;

    // Check rate limit
    const rateStatus = haRateLimiter.getStatus();
    if (rateStatus.remaining === 0) {
      const waitSecs = Math.ceil(rateStatus.resetInMs / 1000);
      return {
        llmContent: `Rate limit reached. Hybrid Analysis allows ${HA_RATE_LIMIT_REQUESTS} requests per minute. Please wait ${waitSecs} seconds.`,
        returnDisplay: `Rate limited - wait ${waitSecs}s`,
        error: {
          message: `Rate limit reached. Wait ${waitSecs} seconds.`,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }

    // Check cache for lookup operations
    const cacheIdentifier = hash || jobId || '';
    if (
      ['lookup_hash', 'get_report', 'quick_scan'].includes(operation) &&
      cacheIdentifier
    ) {
      const cachedResult = haCache.get(operation, cacheIdentifier);
      if (cachedResult) {
        const cachedContent =
          typeof cachedResult.llmContent === 'string'
            ? `${cachedResult.llmContent}\n\n*📦 Result from cache (TTL: ${Math.round(HA_CACHE_TTL_MS / 60000)} minutes)*`
            : cachedResult.llmContent;
        return {
          ...cachedResult,
          llmContent: cachedContent,
          returnDisplay: `${cachedResult.returnDisplay} (cached)`,
        };
      }
    }

    try {
      let result: ToolResult;

      switch (operation) {
        case 'lookup_hash':
          result = await this.lookupHash();
          break;
        case 'submit_file':
          result = await this.submitFile();
          break;
        case 'submit_url':
          result = await this.submitUrl();
          break;
        case 'get_report':
          result = await this.getReport();
          break;
        case 'search':
          result = await this.searchSamples();
          break;
        case 'get_state':
          result = await this.getState();
          break;
        case 'quick_scan':
          result = await this.quickScan();
          break;
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

      // Cache successful results
      if (
        !result.error &&
        cacheIdentifier &&
        ['lookup_hash', 'get_report', 'quick_scan'].includes(operation)
      ) {
        haCache.set(operation, cacheIdentifier, result);
      }

      return result;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return {
        llmContent: `Error: Hybrid Analysis query failed: ${errorMessage}`,
        returnDisplay: `Hybrid Analysis query failed: ${errorMessage}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  /**
   * Lookup a hash in Hybrid Analysis database
   */
  private async lookupHash(): Promise<ToolResult> {
    const { hash } = this.params;

    if (!hash) {
      return {
        llmContent: 'Error: Hash is required for lookup operation',
        returnDisplay: 'Missing hash parameter',
        error: {
          message: 'Hash is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const hashLower = hash.toLowerCase();
    if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hashLower)) {
      return {
        llmContent: 'Error: Invalid hash format. Provide MD5, SHA1, or SHA256.',
        returnDisplay: 'Invalid hash format',
        error: {
          message: 'Invalid hash format',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    haRateLimiter.recordRequest();

    const formData = new FormData();
    formData.append('hash', hashLower);

    const response = await fetchWithRetry(
      `${HA_API_BASE}/search/hash`,
      {
        method: 'POST',
        headers: this.getHeaders(),
        body: formData as unknown as BodyInit,
      },
      HA_TIMEOUT_MS,
    );

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `Hash not found in Hybrid Analysis database.\n\nHash: ${hash}\n\nThis sample has not been previously analyzed. Consider submitting it for analysis.`,
          returnDisplay: 'Hash not found in Hybrid Analysis',
        };
      }
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as HAReportResponse[];

    if (!data || data.length === 0) {
      return {
        llmContent: `No analysis reports found for hash: ${hash}`,
        returnDisplay: 'No reports found',
      };
    }

    return this.formatReportList(data);
  }

  /**
   * Submit a file for analysis
   */
  private async submitFile(): Promise<ToolResult> {
    const {
      filePath,
      environmentId,
      noShareThirdParty,
      allowCommunityAccess,
      comment,
    } = this.params;

    if (!filePath) {
      return {
        llmContent: 'Error: File path is required for submission',
        returnDisplay: 'Missing file path',
        error: {
          message: 'File path is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    if (!fs.existsSync(filePath)) {
      return {
        llmContent: `Error: File not found: ${filePath}`,
        returnDisplay: 'File not found',
        error: {
          message: `File not found: ${filePath}`,
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    const stats = fs.statSync(filePath);
    const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB limit
    if (stats.size > MAX_FILE_SIZE) {
      return {
        llmContent: `Error: File too large. Maximum size is 100MB.`,
        returnDisplay: 'File too large',
        error: {
          message: 'File exceeds 100MB limit',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    haRateLimiter.recordRequest();

    const formData = new FormData();
    formData.append('file', fs.createReadStream(filePath));
    formData.append('environment_id', String(environmentId || 160)); // Default: Windows 10 64-bit

    if (noShareThirdParty) {
      formData.append('no_share_third_party', 'true');
    }
    if (allowCommunityAccess !== undefined) {
      formData.append(
        'allow_community_access',
        allowCommunityAccess ? 'true' : 'false',
      );
    }
    if (comment) {
      formData.append('comment', comment);
    }

    const response = await fetchWithRetry(
      `${HA_API_BASE}/submit/file`,
      {
        method: 'POST',
        headers: this.getHeaders(),
        body: formData as unknown as BodyInit,
      },
      HA_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Submission failed: ${response.status} - ${errorText}`);
    }

    const data = (await response.json()) as HASubmitResponse;

    const content = [
      '# Hybrid Analysis - File Submitted Successfully',
      '',
      '## Submission Details',
      `- **Job ID:** ${data.job_id}`,
      `- **SHA256:** ${data.sha256}`,
      `- **Environment:** ${this.getEnvironmentName(data.environment_id)}`,
      `- **File:** ${path.basename(filePath)}`,
      '',
      '## Next Steps',
      '1. Use `get_state` operation with the job_id to check analysis progress',
      '2. Once complete, use `get_report` to retrieve the full analysis report',
      '',
      '**Note:** Analysis typically takes 5-15 minutes depending on file complexity.',
    ];

    return {
      llmContent: content.join('\n'),
      returnDisplay: `File submitted - Job ID: ${data.job_id}`,
    };
  }

  /**
   * Submit a URL for analysis
   */
  private async submitUrl(): Promise<ToolResult> {
    const { url, environmentId } = this.params;

    if (!url) {
      return {
        llmContent: 'Error: URL is required for submission',
        returnDisplay: 'Missing URL',
        error: {
          message: 'URL is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    haRateLimiter.recordRequest();

    const formData = new FormData();
    formData.append('url', url);
    formData.append('environment_id', String(environmentId || 160));

    const response = await fetchWithRetry(
      `${HA_API_BASE}/submit/url-for-analysis`,
      {
        method: 'POST',
        headers: this.getHeaders(),
        body: formData as unknown as BodyInit,
      },
      HA_TIMEOUT_MS,
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `URL submission failed: ${response.status} - ${errorText}`,
      );
    }

    const data = (await response.json()) as HASubmitResponse;

    const content = [
      '# Hybrid Analysis - URL Submitted Successfully',
      '',
      '## Submission Details',
      `- **Job ID:** ${data.job_id}`,
      `- **SHA256:** ${data.sha256}`,
      `- **Environment:** ${this.getEnvironmentName(data.environment_id)}`,
      `- **URL:** ${url}`,
      '',
      '## Next Steps',
      'Use `get_state` or `get_report` with the job_id to retrieve results.',
    ];

    return {
      llmContent: content.join('\n'),
      returnDisplay: `URL submitted - Job ID: ${data.job_id}`,
    };
  }

  /**
   * Get full analysis report
   */
  private async getReport(): Promise<ToolResult> {
    const { hash, jobId } = this.params;
    const identifier = hash || jobId;

    if (!identifier) {
      return {
        llmContent: 'Error: Hash or Job ID is required',
        returnDisplay: 'Missing identifier',
        error: {
          message: 'Hash or Job ID is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    haRateLimiter.recordRequest();

    // First, search for the hash to get environment_id
    const formData = new FormData();
    formData.append('hash', identifier);

    const searchResponse = await fetchWithRetry(
      `${HA_API_BASE}/search/hash`,
      {
        method: 'POST',
        headers: this.getHeaders(),
        body: formData as unknown as BodyInit,
      },
      HA_TIMEOUT_MS,
    );

    if (!searchResponse.ok) {
      if (searchResponse.status === 404) {
        return {
          llmContent: `No reports found for: ${identifier}`,
          returnDisplay: 'No reports found',
        };
      }
      throw new Error(`API error: ${searchResponse.status}`);
    }

    const reports = (await searchResponse.json()) as HAReportResponse[];

    if (!reports || reports.length === 0) {
      return {
        llmContent: `No analysis reports found for: ${identifier}`,
        returnDisplay: 'No reports found',
      };
    }

    // Get the most recent report (usually highest threat score or most recent)
    const report = reports.sort(
      (a, b) => (b.threat_score || 0) - (a.threat_score || 0),
    )[0];

    return this.formatDetailedReport(report);
  }

  /**
   * Search for samples
   */
  private async searchSamples(): Promise<ToolResult> {
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

    haRateLimiter.recordRequest();

    const formData = new FormData();
    formData.append('query', query);

    const response = await fetchWithRetry(
      `${HA_API_BASE}/search/terms`,
      {
        method: 'POST',
        headers: this.getHeaders(),
        body: formData as unknown as BodyInit,
      },
      HA_TIMEOUT_MS,
    );

    if (!response.ok) {
      throw new Error(`Search failed: ${response.status}`);
    }

    const data = (await response.json()) as HASearchResponse;

    if (!data.result || data.result.length === 0) {
      return {
        llmContent: `No samples found for query: "${query}"`,
        returnDisplay: 'No results found',
      };
    }

    const content = [
      '# Hybrid Analysis Search Results',
      '',
      `**Query:** ${query}`,
      `**Results:** ${data.count} samples found`,
      '',
      '## Samples',
      '',
      '| SHA256 | Verdict | Threat Score | Family | Type |',
      '|--------|---------|--------------|--------|------|',
    ];

    for (const sample of data.result.slice(0, 20)) {
      content.push(
        `| \`${sample.sha256.slice(0, 16)}...\` | ${sample.verdict || 'Unknown'} | ${sample.threat_score || 0}/100 | ${sample.vx_family || 'N/A'} | ${(sample.type_short || []).join(', ') || 'Unknown'} |`,
      );
    }

    if (data.count > 20) {
      content.push('', `*Showing 20 of ${data.count} results*`);
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `Found ${data.count} samples`,
    };
  }

  /**
   * Get analysis state
   */
  private async getState(): Promise<ToolResult> {
    const { jobId } = this.params;

    if (!jobId) {
      return {
        llmContent: 'Error: Job ID is required',
        returnDisplay: 'Missing job ID',
        error: {
          message: 'Job ID is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    haRateLimiter.recordRequest();

    const response = await fetchWithRetry(
      `${HA_API_BASE}/report/${jobId}/state`,
      {
        method: 'GET',
        headers: this.getHeaders(),
      },
      HA_TIMEOUT_MS,
    );

    if (!response.ok) {
      throw new Error(`State check failed: ${response.status}`);
    }

    const data = (await response.json()) as HAStateResponse;

    const stateEmoji: Record<string, string> = {
      IN_QUEUE: '⏳',
      IN_PROGRESS: '🔄',
      SUCCESS: '✅',
      ERROR: '❌',
    };

    const content = [
      '# Hybrid Analysis - Job State',
      '',
      `**Job ID:** ${jobId}`,
      `**State:** ${stateEmoji[data.state] || '❓'} ${data.state}`,
    ];

    if (data.error) {
      content.push(`**Error:** ${data.error}`);
    }

    if (data.related_reports && data.related_reports.length > 0) {
      content.push('', '## Related Reports');
      for (const report of data.related_reports) {
        content.push(`- ${report}`);
      }
    }

    if (data.state === 'SUCCESS') {
      content.push(
        '',
        '✅ Analysis complete! Use `get_report` operation to retrieve full results.',
      );
    } else if (data.state === 'IN_PROGRESS' || data.state === 'IN_QUEUE') {
      content.push(
        '',
        '⏳ Analysis still in progress. Check again in a few minutes.',
      );
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `State: ${data.state}`,
    };
  }

  /**
   * Quick scan - simplified lookup for rapid triage
   */
  private async quickScan(): Promise<ToolResult> {
    const { hash } = this.params;

    if (!hash) {
      return {
        llmContent: 'Error: Hash is required for quick scan',
        returnDisplay: 'Missing hash',
        error: {
          message: 'Hash is required',
          type: ToolErrorType.INVALID_TOOL_PARAMS,
        },
      };
    }

    haRateLimiter.recordRequest();

    const response = await fetchWithRetry(
      `${HA_API_BASE}/quick-scan/file`,
      {
        method: 'POST',
        headers: {
          ...this.getHeaders(),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `scan_type=lookup&sha256=${hash}`,
      },
      HA_TIMEOUT_MS,
    );

    if (!response.ok) {
      if (response.status === 404) {
        return {
          llmContent: `Hash not found in quick scan database: ${hash}`,
          returnDisplay: 'Hash not found',
        };
      }
      throw new Error(`Quick scan failed: ${response.status}`);
    }

    const data = await response.json();

    const content = [
      '# Hybrid Analysis - Quick Scan Results',
      '',
      `**Hash:** ${hash}`,
      '',
      '```json',
      JSON.stringify(data, null, 2),
      '```',
    ];

    return {
      llmContent: content.join('\n'),
      returnDisplay: 'Quick scan complete',
    };
  }

  /**
   * Format a list of reports
   */
  private formatReportList(reports: HAReportResponse[]): ToolResult {
    const content = [
      '# Hybrid Analysis - Report Summary',
      '',
      `Found **${reports.length}** analysis report(s)`,
      '',
    ];

    for (const report of reports.slice(0, 5)) {
      content.push(
        `## Analysis: ${report.job_id || report.sha256.slice(0, 16)}`,
        '',
        `- **SHA256:** \`${report.sha256}\``,
        `- **Verdict:** ${this.getVerdictEmoji(report.verdict)} ${report.verdict || 'Unknown'}`,
        `- **Threat Score:** ${report.threat_score || 0}/100`,
        `- **AV Detection:** ${report.av_detect || 0}%`,
        `- **Family:** ${report.vx_family || 'Unknown'}`,
        `- **Type:** ${(report.type_short || []).join(', ') || report.type || 'Unknown'}`,
        `- **Size:** ${this.formatFileSize(report.size)}`,
        `- **Environment:** ${this.getEnvironmentName(report.environment_id)}`,
        `- **Analysis Time:** ${report.analysis_start_time || 'Unknown'}`,
        '',
      );

      if (report.tags && report.tags.length > 0) {
        content.push(`- **Tags:** ${report.tags.slice(0, 10).join(', ')}`);
      }

      content.push('');
    }

    if (reports.length > 5) {
      content.push(`*Showing 5 of ${reports.length} reports*`);
    }

    return {
      llmContent: content.join('\n'),
      returnDisplay: `Found ${reports.length} report(s)`,
    };
  }

  /**
   * Format a detailed single report
   */
  private formatDetailedReport(report: HAReportResponse): ToolResult {
    const content = [
      '# Hybrid Analysis - Detailed Report',
      '',
      '## Overview',
      `- **SHA256:** \`${report.sha256}\``,
      `- **SHA1:** \`${report.sha1}\``,
      `- **MD5:** \`${report.md5}\``,
      `- **Size:** ${this.formatFileSize(report.size)}`,
      `- **Type:** ${report.type || (report.type_short || []).join(', ')}`,
      '',
      '## Threat Assessment',
      `- **Verdict:** ${this.getVerdictEmoji(report.verdict)} **${report.verdict || 'Unknown'}**`,
      `- **Threat Score:** ${report.threat_score || 0}/100 ${this.getThreatScoreBar(report.threat_score || 0)}`,
      `- **Threat Level:** ${report.threat_level || 0}/5`,
      `- **AV Detection Rate:** ${report.av_detect || 0}%`,
      `- **Malware Family:** ${report.vx_family || 'Unknown'}`,
      '',
    ];

    // MITRE ATT&CK Techniques
    if (report.mitre_attcks && report.mitre_attcks.length > 0) {
      content.push('## MITRE ATT&CK Techniques', '');
      content.push('| ID | Technique | Tactic | Indicators |');
      content.push('|----|-----------|--------|------------|');
      for (const attack of report.mitre_attcks.slice(0, 15)) {
        content.push(
          `| [${attack.attck_id}](${attack.attck_id_wiki}) | ${attack.technique} | ${attack.tactic} | ${attack.malicious_identifiers_count} |`,
        );
      }
      content.push('');
    }

    // Signatures
    if (report.signatures && report.signatures.length > 0) {
      content.push('## Behavioral Signatures', '');
      const highSigs = report.signatures.filter((s) => s.threat_level >= 3);
      const medSigs = report.signatures.filter((s) => s.threat_level === 2);

      if (highSigs.length > 0) {
        content.push('### High Severity');
        for (const sig of highSigs.slice(0, 10)) {
          content.push(`- 🔴 **${sig.name}** (${sig.category})`);
        }
        content.push('');
      }

      if (medSigs.length > 0) {
        content.push('### Medium Severity');
        for (const sig of medSigs.slice(0, 10)) {
          content.push(`- 🟡 ${sig.name} (${sig.category})`);
        }
        content.push('');
      }
    }

    // Processes
    if (report.processes && report.processes.length > 0) {
      content.push('## Spawned Processes', '');
      for (const proc of report.processes.slice(0, 10)) {
        content.push(
          `- **${proc.name}**: \`${proc.command_line || proc.normalized_path}\``,
        );
      }
      content.push('');
    }

    // Network IOCs
    if (report.network && report.network.length > 0) {
      content.push('## Network Indicators', '');
      content.push('| Protocol | Destination | Port | Domain |');
      content.push('|----------|-------------|------|--------|');
      for (const conn of report.network.slice(0, 15)) {
        content.push(
          `| ${conn.protocol || 'TCP'} | ${conn.destination_ip} | ${conn.destination_port} | ${conn.domain || '-'} |`,
        );
      }
      content.push('');
    }

    // Domains
    if (report.domains && report.domains.length > 0) {
      content.push('## Contacted Domains', '');
      for (const domain of report.domains.slice(0, 20)) {
        content.push(`- ${domain}`);
      }
      content.push('');
    }

    // Hosts/IPs
    if (report.hosts && report.hosts.length > 0) {
      content.push('## Contacted IPs', '');
      for (const host of report.hosts.slice(0, 20)) {
        content.push(`- ${host}`);
      }
      content.push('');
    }

    // File Operations
    if (report.file_operations && report.file_operations.length > 0) {
      content.push('## File Operations', '');
      const writes = report.file_operations.filter(
        (f) => f.operation === 'write' || f.operation === 'create',
      );
      if (writes.length > 0) {
        content.push('### Files Created/Written');
        for (const file of writes.slice(0, 10)) {
          content.push(`- \`${file.path}\``);
        }
        content.push('');
      }
    }

    // Extracted Files
    if (report.extracted_files && report.extracted_files.length > 0) {
      content.push('## Extracted Files', '');
      content.push('| Name | Type | Threat Level | SHA256 |');
      content.push('|------|------|--------------|--------|');
      for (const file of report.extracted_files.slice(0, 10)) {
        content.push(
          `| ${file.name} | ${file.type} | ${file.threat_level}/5 | \`${file.sha256.slice(0, 16)}...\` |`,
        );
      }
      content.push('');
    }

    // Registry Operations
    if (report.registry && report.registry.length > 0) {
      content.push('## Registry Operations', '');
      for (const reg of report.registry.slice(0, 15)) {
        content.push(
          `- **${reg.operation}:** \`${reg.key}\`${reg.value ? ` = \`${reg.value}\`` : ''}`,
        );
      }
      content.push('');
    }

    // Tags
    if (report.tags && report.tags.length > 0) {
      content.push('## Tags', '');
      content.push(report.tags.join(', '));
      content.push('');
    }

    // Statistics
    content.push('## Statistics', '');
    content.push(`- Total Processes: ${report.total_processes || 0}`);
    content.push(
      `- Total Network Connections: ${report.total_network_connections || 0}`,
    );
    content.push(`- Total Signatures: ${report.total_signatures || 0}`);
    content.push(
      `- Environment: ${this.getEnvironmentName(report.environment_id)}`,
    );
    content.push(`- Analysis Time: ${report.analysis_start_time || 'Unknown'}`);

    return {
      llmContent: content.join('\n'),
      returnDisplay: `Threat Score: ${report.threat_score || 0}/100 - ${report.verdict || 'Unknown'}`,
    };
  }

  private getVerdictEmoji(verdict: string | undefined): string {
    switch (verdict?.toLowerCase()) {
      case 'malicious':
        return '🔴';
      case 'suspicious':
        return '🟡';
      case 'no specific threat':
      case 'whitelisted':
        return '🟢';
      default:
        return '⚪';
    }
  }

  private getThreatScoreBar(score: number): string {
    const filled = Math.round(score / 10);
    const empty = 10 - filled;
    const color = score >= 70 ? '🔴' : score >= 40 ? '🟡' : '🟢';
    return `[${color.repeat(filled)}${'⚪'.repeat(empty)}]`;
  }

  private formatFileSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  private getEnvironmentName(envId: number): string {
    const environments: Record<number, string> = {
      300: 'Linux (Ubuntu 16.04, 64-bit)',
      200: 'Android Static Analysis',
      120: 'Windows 7, 64-bit',
      110: 'Windows 7, 32-bit',
      100: 'Windows 7, 32-bit (HWP)',
      160: 'Windows 10, 64-bit',
      140: 'Windows 11, 64-bit',
    };
    return environments[envId] || `Environment ${envId}`;
  }
}

/**
 * Hybrid Analysis Tool - Advanced Malware Analysis
 */
export class HybridAnalysisTool extends BaseDeclarativeTool<
  HybridAnalysisToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.HYBRID_ANALYSIS;
  private readonly config: Config;

  constructor(config: Config) {
    super(
      HybridAnalysisTool.Name,
      ToolDisplayNames.HYBRID_ANALYSIS,
      `Query Hybrid Analysis (CrowdStrike) for advanced malware analysis and behavioral reports. 
API key can be configured in settings.json (hybridAnalysisApiKey) or via HYBRID_ANALYSIS_API_KEY environment variable.

**Capabilities:**
- Hash lookup for existing analysis reports
- File submission for dynamic sandbox analysis
- URL submission for analysis
- Behavioral analysis with MITRE ATT&CK mapping
- Network IOC extraction (IPs, domains, connections)
- Process tree and file operation analysis
- Registry modification tracking
- Threat scoring and classification

**Free API:** Get your API key at https://www.hybrid-analysis.com/signup`,
      Kind.Fetch,
      {
        type: 'object',
        properties: {
          operation: {
            type: 'string',
            enum: [
              'lookup_hash',
              'submit_file',
              'submit_url',
              'get_report',
              'search',
              'get_state',
              'quick_scan',
            ],
            description:
              'Operation to perform: lookup_hash (check existing), submit_file (analyze file), submit_url (analyze URL), get_report (full report), search (find samples), get_state (check job status), quick_scan (rapid triage)',
          },
          hash: {
            type: 'string',
            description:
              'File hash (MD5, SHA1, or SHA256) for lookup/report operations',
          },
          filePath: {
            type: 'string',
            description: 'Path to file for submission',
          },
          url: {
            type: 'string',
            description: 'URL to submit for analysis',
          },
          jobId: {
            type: 'string',
            description: 'Job ID for state check or report retrieval',
          },
          query: {
            type: 'string',
            description:
              'Search query (filename:, domain:, ip:, vx_family:, etc.)',
          },
          environmentId: {
            type: 'number',
            enum: [300, 200, 120, 110, 100, 160, 140],
            description:
              'Analysis environment: 160 (Win10-64), 140 (Win11-64), 120 (Win7-64), 110 (Win7-32), 300 (Linux), 200 (Android)',
          },
          noShareThirdParty: {
            type: 'boolean',
            description: 'Do not share with third parties (premium feature)',
          },
          allowCommunityAccess: {
            type: 'boolean',
            description: 'Allow community access to the sample',
          },
          comment: {
            type: 'string',
            description: 'Comment for file submission',
          },
        },
        required: ['operation'],
      },
    );
    this.config = config;
  }

  protected createInvocation(
    params: HybridAnalysisToolParams,
  ): ToolInvocation<HybridAnalysisToolParams, ToolResult> {
    return new HybridAnalysisToolInvocation(this.config, params);
  }
}
