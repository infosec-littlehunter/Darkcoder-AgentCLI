/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * API Key Management System
 *
 * Centralized management for external security tool API keys.
 * Supports environment variables, config file, and runtime configuration.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

/**
 * Supported security tool integrations
 */
export interface SecurityToolConfig {
  name: string;
  displayName: string;
  envVars: string[];
  description: string;
  registrationUrl: string;
  docsUrl: string;
  required: boolean;
  credentials: 'apiKey' | 'apiIdSecret' | 'bearer' | 'basic';
}

/**
 * All supported security tools and their configurations
 */
export const SECURITY_TOOLS: Record<string, SecurityToolConfig> = {
  censys: {
    name: 'censys',
    displayName: 'Censys',
    envVars: ['CENSYS_API_KEY', 'CENSYS_API_ID', 'CENSYS_API_SECRET'],
    description: 'Internet asset discovery and certificate search',
    registrationUrl: 'https://search.censys.io/register',
    docsUrl: 'https://search.censys.io/api',
    required: false,
    credentials: 'apiKey',
  },
  urlscan: {
    name: 'urlscan',
    displayName: 'URLScan.io',
    envVars: ['URLSCAN_API_KEY'],
    description: 'Website scanning and threat analysis',
    registrationUrl: 'https://urlscan.io/user/signup',
    docsUrl: 'https://urlscan.io/docs/api/',
    required: false,
    credentials: 'apiKey',
  },
  virustotal: {
    name: 'virustotal',
    displayName: 'VirusTotal',
    envVars: ['VIRUSTOTAL_API_KEY'],
    description: 'File, URL, and domain malware analysis',
    registrationUrl: 'https://www.virustotal.com/gui/join-us',
    docsUrl: 'https://developers.virustotal.com/reference/overview',
    required: false,
    credentials: 'apiKey',
  },
  cuckoo: {
    name: 'cuckoo',
    displayName: 'Cuckoo Sandbox',
    envVars: ['CUCKOO_API_URL', 'CUCKOO_API_TOKEN'],
    description:
      'Self-hosted malware analysis sandbox with behavioral analysis',
    registrationUrl: 'https://cuckoo.readthedocs.io/en/latest/installation/',
    docsUrl: 'https://cuckoo.readthedocs.io/',
    required: false,
    credentials: 'apiKey',
  },
  yaraify: {
    name: 'yaraify',
    displayName: 'YARAify',
    envVars: ['YARAIFY_API_KEY'],
    description: 'YARA rule scanning with 500+ curated rules from YARAhub',
    registrationUrl: 'https://auth.abuse.ch/',
    docsUrl: 'https://yaraify.abuse.ch/api/',
    required: false,
    credentials: 'apiKey',
  },
  hunter: {
    name: 'hunter',
    displayName: 'Hunter.io',
    envVars: ['HUNTER_API_KEY'],
    description: 'Email finder and verification for OSINT',
    registrationUrl: 'https://hunter.io/users/sign_up',
    docsUrl: 'https://hunter.io/api-documentation/v2',
    required: false,
    credentials: 'apiKey',
  },
  securitytrails: {
    name: 'securitytrails',
    displayName: 'SecurityTrails',
    envVars: ['SECURITYTRAILS_API_KEY'],
    description: 'DNS, subdomain, and historical data lookup',
    registrationUrl: 'https://securitytrails.com/app/signup',
    docsUrl: 'https://securitytrails.com/corp/api',
    required: false,
    credentials: 'apiKey',
  },
  greynoise: {
    name: 'greynoise',
    displayName: 'GreyNoise',
    envVars: ['GREYNOISE_API_KEY'],
    description: 'IP threat intelligence and internet scanner identification',
    registrationUrl: 'https://viz.greynoise.io/signup',
    docsUrl: 'https://docs.greynoise.io/reference/get_v3-community-ip',
    required: false,
    credentials: 'apiKey',
  },
  abuseipdb: {
    name: 'abuseipdb',
    displayName: 'AbuseIPDB',
    envVars: ['ABUSEIPDB_API_KEY'],
    description: 'IP address reputation and abuse reporting',
    registrationUrl: 'https://www.abuseipdb.com/register',
    docsUrl: 'https://docs.abuseipdb.com/',
    required: false,
    credentials: 'apiKey',
  },
  binaryedge: {
    name: 'binaryedge',
    displayName: 'BinaryEdge',
    envVars: ['BINARYEDGE_API_KEY'],
    description: 'Internet scanning and threat intelligence',
    registrationUrl: 'https://app.binaryedge.io/sign-up',
    docsUrl: 'https://docs.binaryedge.io/',
    required: false,
    credentials: 'apiKey',
  },
  fullhunt: {
    name: 'fullhunt',
    displayName: 'FullHunt',
    envVars: ['FULLHUNT_API_KEY'],
    description: 'Attack surface discovery and management',
    registrationUrl: 'https://fullhunt.io/sign-up',
    docsUrl: 'https://api-docs.fullhunt.io/',
    required: false,
    credentials: 'apiKey',
  },
  leakix: {
    name: 'leakix',
    displayName: 'LeakIX',
    envVars: ['LEAKIX_API_KEY'],
    description: 'Data leak and misconfiguration discovery',
    registrationUrl: 'https://leakix.net/auth/register',
    docsUrl: 'https://leakix.net/api-documentation',
    required: false,
    credentials: 'apiKey',
  },
  intelx: {
    name: 'intelx',
    displayName: 'Intelligence X',
    envVars: ['INTELX_API_KEY'],
    description: 'Search engine for leaked data and OSINT',
    registrationUrl: 'https://intelx.io/signup',
    docsUrl: 'https://intelx.io/integrations',
    required: false,
    credentials: 'apiKey',
  },
  netlas: {
    name: 'netlas',
    displayName: 'Netlas.io',
    envVars: ['NETLAS_API_KEY'],
    description: 'Internet intelligence and attack surface discovery',
    registrationUrl: 'https://app.netlas.io/registration/',
    docsUrl: 'https://netlas.io/api',
    required: false,
    credentials: 'apiKey',
  },
  criminalip: {
    name: 'criminalip',
    displayName: 'Criminal IP',
    envVars: ['CRIMINALIP_API_KEY'],
    description: 'Cyber threat intelligence search engine',
    registrationUrl: 'https://www.criminalip.io/register',
    docsUrl: 'https://www.criminalip.io/developer/api/get-asset-ip-report',
    required: false,
    credentials: 'apiKey',
  },
  zoomeye: {
    name: 'zoomeye',
    displayName: 'ZoomEye',
    envVars: ['ZOOMEYE_API_KEY'],
    description: 'Cyberspace search engine (Chinese alternative to Censys)',
    registrationUrl: 'https://www.zoomeye.org/register',
    docsUrl: 'https://www.zoomeye.org/doc',
    required: false,
    credentials: 'apiKey',
  },
  fofa: {
    name: 'fofa',
    displayName: 'FOFA',
    envVars: ['FOFA_EMAIL', 'FOFA_API_KEY'],
    description: 'Cyberspace search engine (Chinese)',
    registrationUrl: 'https://fofa.info/userRegister',
    docsUrl: 'https://en.fofa.info/api',
    required: false,
    credentials: 'apiIdSecret',
  },
  onyphe: {
    name: 'onyphe',
    displayName: 'ONYPHE',
    envVars: ['ONYPHE_API_KEY'],
    description: 'Cyber defense search engine',
    registrationUrl: 'https://www.onyphe.io/signup',
    docsUrl: 'https://www.onyphe.io/documentation/api',
    required: false,
    credentials: 'apiKey',
  },
  pulsedive: {
    name: 'pulsedive',
    displayName: 'Pulsedive',
    envVars: ['PULSEDIVE_API_KEY'],
    description: 'Threat intelligence platform',
    registrationUrl: 'https://pulsedive.com/register',
    docsUrl: 'https://pulsedive.com/api/',
    required: false,
    credentials: 'apiKey',
  },
  publicwww: {
    name: 'publicwww',
    displayName: 'PublicWWW',
    envVars: ['PUBLICWWW_API_KEY'],
    description: 'Source code search engine',
    registrationUrl: 'https://publicwww.com/profile/signup.html',
    docsUrl: 'https://publicwww.com/api.html',
    required: false,
    credentials: 'apiKey',
  },

  // Bug Bounty Platforms
  hackerone: {
    name: 'hackerone',
    displayName: 'HackerOne',
    envVars: ['HACKERONE_API_TOKEN', 'HACKERONE_API_USERNAME'],
    description:
      'Bug bounty platform - access programs, reports, and researcher stats',
    registrationUrl: 'https://hackerone.com/users/sign_up',
    docsUrl: 'https://api.hackerone.com/',
    required: false,
    credentials: 'apiIdSecret',
  },
  bugcrowd: {
    name: 'bugcrowd',
    displayName: 'Bugcrowd',
    envVars: ['BUGCROWD_API_TOKEN'],
    description:
      'Bug bounty platform - access programs, submissions, and bounty data',
    registrationUrl: 'https://bugcrowd.com/user/sign_up',
    docsUrl: 'https://docs.bugcrowd.com/api/getting-started/',
    required: false,
    credentials: 'bearer',
  },
  intigriti: {
    name: 'intigriti',
    displayName: 'Intigriti',
    envVars: ['INTIGRITI_API_TOKEN'],
    description:
      'European bug bounty platform - access programs and submissions',
    registrationUrl: 'https://login.intigriti.com/account/register',
    docsUrl: 'https://kb.intigriti.com/en/articles/3759275-intigriti-api',
    required: false,
    credentials: 'bearer',
  },
  yeswehack: {
    name: 'yeswehack',
    displayName: 'YesWeHack',
    envVars: ['YESWEHACK_API_TOKEN'],
    description:
      'European bug bounty platform - programs, reports, and leaderboards',
    registrationUrl: 'https://yeswehack.com/auth/register/hacker',
    docsUrl: 'https://api.yeswehack.com/docs',
    required: false,
    credentials: 'bearer',
  },
  synack: {
    name: 'synack',
    displayName: 'Synack Red Team',
    envVars: ['SYNACK_API_TOKEN'],
    description:
      'Elite bug bounty platform - vetted researcher access required',
    registrationUrl: 'https://www.synack.com/red-team-application/',
    docsUrl: 'https://www.synack.com/',
    required: false,
    credentials: 'bearer',
  },
  immunefi: {
    name: 'immunefi',
    displayName: 'Immunefi',
    envVars: ['IMMUNEFI_API_KEY'],
    description: 'Web3/DeFi bug bounty platform - blockchain security programs',
    registrationUrl: 'https://immunefi.com/signup/',
    docsUrl: 'https://immunefi.com/',
    required: false,
    credentials: 'apiKey',
  },

  // Embedding providers
  openai: {
    name: 'openai',
    displayName: 'OpenAI',
    envVars: ['OPENAI_API_KEY'],
    description: 'OpenAI API for embeddings and completions',
    registrationUrl: 'https://platform.openai.com/signup',
    docsUrl: 'https://platform.openai.com/docs/api-reference',
    required: false,
    credentials: 'apiKey',
  },
  dashscope: {
    name: 'dashscope',
    displayName: 'DashScope (Alibaba)',
    envVars: ['DASHSCOPE_API_KEY'],
    description: 'Alibaba Cloud AI services for Qwen models',
    registrationUrl: 'https://dashscope.console.aliyun.com/',
    docsUrl: 'https://help.aliyun.com/document_detail/2400395.html',
    required: false,
    credentials: 'apiKey',
  },
};

/**
 * Stored API key configuration
 */
export interface StoredApiKeys {
  [tool: string]: {
    apiKey?: string;
    apiId?: string;
    apiSecret?: string;
    email?: string;
    lastUpdated?: string;
  };
}

/**
 * Maximum allowed length for API keys to prevent abuse
 */
const MAX_API_KEY_LENGTH = 512;

/**
 * Minimum length for valid API keys
 */
const MIN_API_KEY_LENGTH = 8;

/**
 * Validate an API key string
 * @param apiKey - The API key to validate
 * @returns true if valid, throws Error if invalid
 */
function validateApiKey(apiKey: string): boolean {
  if (!apiKey || typeof apiKey !== 'string') {
    throw new Error('API key must be a non-empty string');
  }

  const trimmed = apiKey.trim();
  if (trimmed.length === 0) {
    throw new Error('API key cannot be empty or whitespace only');
  }

  if (trimmed.length < MIN_API_KEY_LENGTH) {
    throw new Error(
      `API key must be at least ${MIN_API_KEY_LENGTH} characters`,
    );
  }

  if (trimmed.length > MAX_API_KEY_LENGTH) {
    throw new Error(
      `API key exceeds maximum length of ${MAX_API_KEY_LENGTH} characters`,
    );
  }

  // Check for control characters or null bytes
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new Error('API key contains invalid control characters');
  }

  return true;
}

/**
 * Validate stored API keys structure
 * @param data - The data to validate
 * @returns validated StoredApiKeys object
 */
function validateStoredKeys(data: unknown): StoredApiKeys {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return {};
  }

  const validated: StoredApiKeys = {};

  for (const [toolName, value] of Object.entries(
    data as Record<string, unknown>,
  )) {
    // Only process known tools
    if (!SECURITY_TOOLS[toolName]) {
      continue;
    }

    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      continue;
    }

    const entry = value as Record<string, unknown>;
    const validatedEntry: StoredApiKeys[string] = {};

    // Validate each field using bracket notation for index signature access
    if (typeof entry['apiKey'] === 'string' && entry['apiKey'].length > 0) {
      validatedEntry.apiKey = entry['apiKey'].slice(0, MAX_API_KEY_LENGTH);
    }
    if (typeof entry['apiId'] === 'string' && entry['apiId'].length > 0) {
      validatedEntry.apiId = entry['apiId'].slice(0, MAX_API_KEY_LENGTH);
    }
    if (
      typeof entry['apiSecret'] === 'string' &&
      entry['apiSecret'].length > 0
    ) {
      validatedEntry.apiSecret = entry['apiSecret'].slice(
        0,
        MAX_API_KEY_LENGTH,
      );
    }
    if (typeof entry['email'] === 'string' && entry['email'].length > 0) {
      validatedEntry.email = entry['email'].slice(0, 256);
    }
    if (typeof entry['lastUpdated'] === 'string') {
      validatedEntry.lastUpdated = entry['lastUpdated'];
    }

    // Only add if we have at least one credential
    if (validatedEntry.apiKey || validatedEntry.apiId) {
      validated[toolName] = validatedEntry;
    }
  }

  return validated;
}

/**
 * API Key status for a tool
 */
export interface ApiKeyStatus {
  tool: string;
  displayName: string;
  configured: boolean;
  source: 'env' | 'config' | 'none';
  maskedKey?: string;
}

/**
 * API Key Manager
 *
 * Manages API keys for security tools with support for:
 * - Environment variables
 * - Config file storage
 * - Runtime configuration
 */
export class ApiKeyManager {
  private static instance: ApiKeyManager;
  private configPath: string;
  private keys: StoredApiKeys = {};
  private initialized: boolean = false;

  private constructor() {
    this.configPath = ''; // Initialized in initialize()
  }

  static getInstance(): ApiKeyManager {
    if (!ApiKeyManager.instance) {
      ApiKeyManager.instance = new ApiKeyManager();
    }
    return ApiKeyManager.instance;
  }

  /**
   * Initialize the API key manager
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Use default path if not already set (e.g. for testing)
    if (!this.configPath) {
      const homedir = os.homedir();
      if (!homedir) {
        // Fallback for environments where homedir is not available (e.g. some CI/CD or mocked tests)
        this.configPath = path.join('.darkcoder', 'api-keys.json');
      } else {
        this.configPath = path.join(homedir, '.darkcoder', 'api-keys.json');
      }
    }

    try {
      const configDir = path.dirname(this.configPath);
      // Create directory with restricted permissions (owner only)
      await fs.mkdir(configDir, { recursive: true, mode: 0o700 });

      try {
        const content = await fs.readFile(this.configPath, 'utf-8');
        const parsed = JSON.parse(content);
        // Validate the loaded data structure
        this.keys = validateStoredKeys(parsed);
      } catch {
        // File doesn't exist or is invalid, start fresh
        this.keys = {};
      }
    } catch {
      // Cannot create config dir, use memory only
      this.keys = {};
    }

    this.initialized = true;
  }

  /**
   * Save API keys to config file with restricted permissions
   * File is written with mode 0o600 (owner read/write only) for security
   */
  private async saveKeys(): Promise<void> {
    try {
      await fs.writeFile(this.configPath, JSON.stringify(this.keys, null, 2), {
        encoding: 'utf-8',
        mode: 0o600,
      });
    } catch {
      // Silently fail if cannot save
    }
  }

  /**
   * Get API key for a tool
   */
  getApiKey(toolName: string): string | undefined {
    const tool = SECURITY_TOOLS[toolName];
    if (!tool) return undefined;

    // Check environment first (takes priority)
    for (const envVar of tool.envVars) {
      const value = process.env[envVar];
      if (value) return value;
    }

    // Check stored config
    const stored = this.keys[toolName];
    if (stored?.apiKey) return stored.apiKey;

    return undefined;
  }

  /**
   * Get API credentials for tools requiring ID and secret
   */
  getApiCredentials(toolName: string): {
    apiId?: string;
    apiSecret?: string;
    email?: string;
  } {
    const tool = SECURITY_TOOLS[toolName];
    if (!tool) return {};

    // Check environment first
    const result: { apiId?: string; apiSecret?: string; email?: string } = {};

    if (tool.credentials === 'apiIdSecret') {
      // For tools like Censys that need ID + Secret
      if (tool.envVars[0]) {
        result.apiId = process.env[tool.envVars[0]];
      }
      if (tool.envVars[1]) {
        result.apiSecret = process.env[tool.envVars[1]];
      }

      // Check stored config
      const stored = this.keys[toolName];
      if (!result.apiId && stored?.apiId) result.apiId = stored.apiId;
      if (!result.apiSecret && stored?.apiSecret)
        result.apiSecret = stored.apiSecret;
      if (stored?.email) result.email = stored.email;
    }

    return result;
  }

  /**
   * Set API key for a tool
   * @throws Error if toolName is unknown or apiKey is invalid
   */
  async setApiKey(toolName: string, apiKey: string): Promise<void> {
    await this.initialize();

    // Validate tool name
    if (!SECURITY_TOOLS[toolName]) {
      throw new Error(`Unknown tool: ${toolName}`);
    }

    // Validate API key
    validateApiKey(apiKey);

    if (!this.keys[toolName]) {
      this.keys[toolName] = {};
    }

    this.keys[toolName]!.apiKey = apiKey.trim();
    this.keys[toolName]!.lastUpdated = new Date().toISOString();

    await this.saveKeys();
  }

  /**
   * Set API credentials for a tool
   * @throws Error if toolName is unknown or credentials are invalid
   */
  async setApiCredentials(
    toolName: string,
    credentials: { apiId?: string; apiSecret?: string; email?: string },
  ): Promise<void> {
    await this.initialize();

    // Validate tool name
    if (!SECURITY_TOOLS[toolName]) {
      throw new Error(`Unknown tool: ${toolName}`);
    }

    // Validate credentials
    if (credentials.apiId) {
      validateApiKey(credentials.apiId);
    }
    if (credentials.apiSecret) {
      validateApiKey(credentials.apiSecret);
    }

    if (!this.keys[toolName]) {
      this.keys[toolName] = {};
    }

    if (credentials.apiId)
      this.keys[toolName]!.apiId = credentials.apiId.trim();
    if (credentials.apiSecret)
      this.keys[toolName]!.apiSecret = credentials.apiSecret.trim();
    if (credentials.email)
      this.keys[toolName]!.email = credentials.email.trim();
    this.keys[toolName]!.lastUpdated = new Date().toISOString();

    await this.saveKeys();
  }

  /**
   * Remove API key for a tool
   */
  async removeApiKey(toolName: string): Promise<void> {
    await this.initialize();
    delete this.keys[toolName];
    await this.saveKeys();
  }

  /**
   * Get status of all API keys
   */
  async getStatus(): Promise<ApiKeyStatus[]> {
    await this.initialize();

    const status: ApiKeyStatus[] = [];

    for (const [name, tool] of Object.entries(SECURITY_TOOLS)) {
      const apiKey = this.getApiKey(name);
      const creds = this.getApiCredentials(name);
      const configured = !!(apiKey || creds.apiId);

      let source: 'env' | 'config' | 'none' = 'none';
      let maskedKey: string | undefined;

      if (configured) {
        // Check if from env
        const fromEnv = tool.envVars.some((env) => !!process.env[env]);
        source = fromEnv ? 'env' : 'config';

        // Mask the key
        const keyToMask = apiKey || creds.apiId || '';
        if (keyToMask.length > 8) {
          maskedKey = keyToMask.slice(0, 4) + '****' + keyToMask.slice(-4);
        } else if (keyToMask.length > 0) {
          maskedKey = '****';
        }
      }

      status.push({
        tool: name,
        displayName: tool.displayName,
        configured,
        source,
        maskedKey,
      });
    }

    return status;
  }

  /**
   * Get tool info
   */
  getToolInfo(toolName: string): SecurityToolConfig | undefined {
    return SECURITY_TOOLS[toolName];
  }

  /**
   * Get all available tools
   */
  getAllTools(): SecurityToolConfig[] {
    return Object.values(SECURITY_TOOLS);
  }

  /**
   * Check if a tool is configured
   */
  isConfigured(toolName: string): boolean {
    const apiKey = this.getApiKey(toolName);
    const creds = this.getApiCredentials(toolName);
    return !!(apiKey || creds.apiId);
  }

  /**
   * Generate environment export commands for bash/zsh
   */
  generateEnvExports(): string {
    const exports: string[] = [
      '# DarkCoder Security Tools API Keys',
      '# Add these to your ~/.bashrc or ~/.zshrc',
      '',
    ];

    for (const [name, tool] of Object.entries(SECURITY_TOOLS)) {
      exports.push(`# ${tool.displayName} - ${tool.description}`);
      exports.push(`# Register: ${tool.registrationUrl}`);
      for (const envVar of tool.envVars) {
        exports.push(`export ${envVar}="your_${name}_key_here"`);
      }
      exports.push('');
    }

    return exports.join('\n');
  }

  /**
   * Generate .env file template
   */
  generateEnvFile(): string {
    const lines: string[] = [
      '# DarkCoder Security Tools API Keys',
      '# Save this file as .env in your project root or ~/.darkcoder/.env',
      '',
    ];

    for (const [_name, tool] of Object.entries(SECURITY_TOOLS)) {
      lines.push(`# ${tool.displayName}`);
      lines.push(`# ${tool.description}`);
      lines.push(`# Register: ${tool.registrationUrl}`);
      for (const envVar of tool.envVars) {
        lines.push(`${envVar}=`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }
}

// Export singleton instance
export const apiKeyManager = ApiKeyManager.getInstance();
