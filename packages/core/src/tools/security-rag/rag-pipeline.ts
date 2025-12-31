/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Security RAG Pipeline
 *
 * Main orchestrator for the Security Documentation RAG system.
 * Coordinates document ingestion, indexing, and retrieval.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type {
  CISPlatform,
  CISProfileLevel,
  IndexStats,
  IngestionOptions,
  MicrosoftSecurityCategory,
  SecurityDocumentSource,
  SecurityRAGConfig,
  SecurityRAGQuery,
  SecurityRAGResponse,
} from './types.js';
import { VectorStore } from './vector-store.js';
import { DocumentProcessor } from './document-processor.js';
import { WebFetcher } from './web-fetcher.js';

/**
 * Default configuration for the RAG pipeline
 */
export const DEFAULT_RAG_CONFIG: SecurityRAGConfig = {
  dataDirectory: path.join(
    process.env['HOME'] || '~',
    '.darkcoder',
    'security-rag',
  ),
  embeddingModel: 'local', // 'openai', 'dashscope', or 'local'
  chunkSize: 1000, // tokens
  chunkOverlap: 200, // tokens
  maxResults: 10,
  similarityThreshold: 0.5,
  enableCache: true,
  cacheTtlSeconds: 3600,
};

/**
 * Security RAG Pipeline
 *
 * Provides end-to-end RAG capabilities for security documentation:
 * - Document ingestion and indexing
 * - Semantic search
 * - Compliance checking
 * - Hardening recommendations
 */
export class SecurityRAGPipeline {
  private config: SecurityRAGConfig;
  private vectorStore: VectorStore;
  private documentProcessor: DocumentProcessor;
  private webFetcher: WebFetcher;
  private initialized: boolean = false;

  constructor(config: Partial<SecurityRAGConfig> = {}) {
    this.config = { ...DEFAULT_RAG_CONFIG, ...config };
    this.vectorStore = new VectorStore(this.config);
    this.documentProcessor = new DocumentProcessor(this.config);
    this.webFetcher = new WebFetcher();
  }

  /**
   * Initialize the pipeline
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Ensure data directory exists
    await fs.mkdir(this.config.dataDirectory, { recursive: true });

    // Initialize vector store
    await this.vectorStore.initialize();

    this.initialized = true;
  }

  /**
   * Ensure pipeline is initialized
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  /**
   * Ingest a document file
   */
  async ingestFile(
    filePath: string,
    options: IngestionOptions,
  ): Promise<number> {
    await this.ensureInitialized();

    const chunks = await this.documentProcessor.processFile(filePath, options);
    await this.vectorStore.addChunks(chunks);
    await this.vectorStore.saveToDisk();

    return chunks.length;
  }

  /**
   * Ingest a directory of documents
   */
  async ingestDirectory(
    dirPath: string,
    options: IngestionOptions,
    extensions: string[] = ['.json', '.md', '.txt'],
  ): Promise<{ files: number; chunks: number }> {
    await this.ensureInitialized();

    let totalFiles = 0;
    let totalChunks = 0;

    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        // Recurse into subdirectories
        const result = await this.ingestDirectory(
          fullPath,
          options,
          extensions,
        );
        totalFiles += result.files;
        totalChunks += result.chunks;
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions.includes(ext)) {
          try {
            const chunks = await this.ingestFile(fullPath, options);
            totalFiles++;
            totalChunks += chunks;
          } catch (error) {
            console.error(`Failed to ingest ${fullPath}:`, error);
          }
        }
      }
    }

    return { files: totalFiles, chunks: totalChunks };
  }

  /**
   * Ingest CIS Benchmark from URL or built-in data
   */
  async ingestCISBenchmark(
    platform: CISPlatform,
    source: 'builtin' | 'url' | 'file' = 'builtin',
    pathOrUrl?: string,
  ): Promise<number> {
    await this.ensureInitialized();

    if (source === 'builtin') {
      const chunks = this.getBuiltinCISBenchmarkChunks(platform);
      await this.vectorStore.addChunks(chunks);
      await this.vectorStore.saveToDisk();
      return chunks.length;
    }

    if (source === 'url') {
      // Fetch from provided URL
      if (!pathOrUrl) {
        throw new Error('URL is required when source is "url"');
      }

      const fetchedDoc =
        await this.webFetcher.fetchGenericDocumentation(pathOrUrl);

      // Process the fetched content
      const chunks = this.documentProcessor.processMarkdownContent(
        fetchedDoc.content,
        {
          source: 'cis_benchmark',
          platform,
          fetchedFromUrl: pathOrUrl,
          fetchedAt: fetchedDoc.fetchedAt,
        },
      );

      await this.vectorStore.addChunks(chunks);
      await this.vectorStore.saveToDisk();
      return chunks.length;
    }

    if (source === 'file' && pathOrUrl) {
      return this.ingestFile(pathOrUrl, {
        source: 'cis_benchmark',
        platform,
      });
    }

    throw new Error(`Unsupported source: ${source}`);
  }

  /**
   * Ingest CIS Benchmark from URL directly
   */
  async ingestFromUrl(
    url: string,
    options: {
      source?: SecurityDocumentSource;
      platform?: CISPlatform;
      category?: MicrosoftSecurityCategory;
    } = {},
  ): Promise<number> {
    await this.ensureInitialized();

    const fetchedDoc = await this.webFetcher.fetchGenericDocumentation(url);
    const chunks = this.documentProcessor.processMarkdownContent(
      fetchedDoc.content,
      {
        source: options.source || 'custom',
        platform: options.platform,
        category: options.category,
        fetchedFromUrl: url,
        fetchedAt: fetchedDoc.fetchedAt,
      },
    );

    await this.vectorStore.addChunks(chunks);
    await this.vectorStore.saveToDisk();
    return chunks.length;
  }

  /**
   * Ingest Microsoft Learn documentation for a category
   */
  async ingestMicrosoftLearnDocs(
    category: MicrosoftSecurityCategory,
    urls?: string[],
  ): Promise<number> {
    await this.ensureInitialized();

    // Use provided URLs or default URLs for the category
    const urlsToFetch =
      urls || this.webFetcher.getMicrosoftLearnSecurityUrls()[category] || [];

    if (urlsToFetch.length === 0) {
      throw new Error(`No URLs available for category: ${category}`);
    }

    const articles = await this.webFetcher.fetchMicrosoftLearnArticles(
      urlsToFetch,
      category,
    );
    const chunks = this.webFetcher.createMicrosoftLearnChunks(articles);

    await this.vectorStore.addChunks(chunks);
    await this.vectorStore.saveToDisk();
    return chunks.length;
  }

  /**
   * Get available platforms for web fetching
   */
  getAvailableFetchPlatforms(): Record<
    string,
    { title: string; version: string; description: string }
  > {
    return this.webFetcher.getCISBenchmarkInfoUrls();
  }

  /**
   * Get available Microsoft Learn categories
   */
  getAvailableMicrosoftCategories(): MicrosoftSecurityCategory[] {
    return Object.keys(
      this.webFetcher.getMicrosoftLearnSecurityUrls(),
    ) as MicrosoftSecurityCategory[];
  }

  /**
   * Get built-in CIS Benchmark chunks for common platforms
   */
  private getBuiltinCISBenchmarkChunks(
    platform: CISPlatform,
  ): ReturnType<DocumentProcessor['processFile']> extends Promise<infer T>
    ? T
    : never {
    // These are sample controls - in production, you'd load from actual CIS Benchmark files
    const benchmarks = this.getBuiltinBenchmarks();
    const benchmark = benchmarks[platform];

    if (!benchmark) {
      throw new Error(
        `No built-in benchmark available for platform: ${platform}`,
      );
    }

    return this.documentProcessor.createCISBenchmarkChunks(benchmark);
  }

  /**
   * Built-in benchmark data for common platforms
   */
  private getBuiltinBenchmarks(): Record<
    string,
    Parameters<DocumentProcessor['createCISBenchmarkChunks']>[0]
  > {
    return {
      ubuntu_22_04: {
        title: 'CIS Ubuntu Linux 22.04 LTS Benchmark',
        version: 'v1.0.0',
        platform: 'ubuntu_22.04',
        releaseDate: '2023-01-01',
        controls: [
          {
            id: '1.1.1.1',
            title: 'Ensure mounting of cramfs filesystems is disabled',
            description:
              'The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems.',
            rationale:
              'Removing support for unneeded filesystem types reduces the local attack surface.',
            impact: 'None - cramfs is not commonly used.',
            auditProcedure:
              'Run: modprobe -n -v cramfs | grep -E "(cramfs|install)"',
            remediation:
              'Edit /etc/modprobe.d/cramfs.conf and add: install cramfs /bin/true',
            profileLevel: 'L1',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Filesystem Configuration',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '1.1.1.2',
            title: 'Ensure mounting of squashfs filesystems is disabled',
            description:
              'The squashfs filesystem type is a compressed read-only Linux filesystem.',
            rationale:
              'Removing support for unneeded filesystem types reduces the local attack surface.',
            impact:
              'Snap packages use squashfs. If snaps are required, do not disable squashfs.',
            auditProcedure:
              'Run: modprobe -n -v squashfs | grep -E "(squashfs|install)"',
            remediation:
              'Edit /etc/modprobe.d/squashfs.conf and add: install squashfs /bin/true',
            profileLevel: 'L2',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Filesystem Configuration',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '1.3.1',
            title: 'Ensure AIDE is installed',
            description:
              'AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes.',
            rationale:
              'File integrity checking software is essential for detecting unauthorized file changes.',
            impact: 'AIDE must be configured correctly and regularly updated.',
            auditProcedure:
              "Run: dpkg-query -W -f='${binary:Package}\\t${Status}\\t${db:Status-Status}\\n' aide aide-common",
            remediation: 'Run: apt install aide aide-common && aideinit',
            profileLevel: 'L1',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Filesystem Integrity Checking',
            cisControlsV8: ['3.14'],
            nistCsf: ['PR.DS-6'],
          },
          {
            id: '1.4.1',
            title: 'Ensure bootloader password is set',
            description:
              'Setting the boot loader password protects against unauthorized users from entering single user mode.',
            rationale:
              'Requiring a boot password prevents unauthorized physical attackers from rebooting the server.',
            impact:
              'You must provide the password to modify boot entries during system start.',
            auditProcedure: 'Run: grep "^set superusers" /boot/grub/grub.cfg',
            remediation:
              'Create /etc/grub.d/01_users with superuser credentials and run update-grub',
            profileLevel: 'L1',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Secure Boot Settings',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '2.1.1',
            title: 'Ensure time synchronization is in use',
            description:
              'System time should be synchronized between all systems.',
            rationale:
              'Time synchronization is important for authentication protocols, log analysis, and forensics.',
            impact: 'None - time synchronization should always be enabled.',
            auditProcedure: 'Run: systemctl is-enabled systemd-timesyncd',
            remediation:
              'Run: apt install systemd-timesyncd && systemctl enable --now systemd-timesyncd',
            profileLevel: 'L1',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Services',
            cisControlsV8: ['8.4'],
            nistCsf: ['PR.PT-1'],
          },
          {
            id: '3.1.1',
            title: 'Ensure IPv6 is disabled if not required',
            description: 'IPv6 can be disabled if not needed on the system.',
            rationale:
              'If IPv6 is not required, disabling it reduces the attack surface.',
            impact: 'IPv6 connectivity will not be available.',
            auditProcedure: 'Run: sysctl net.ipv6.conf.all.disable_ipv6',
            remediation:
              'Add to /etc/sysctl.conf: net.ipv6.conf.all.disable_ipv6 = 1',
            profileLevel: 'L2',
            scored: false,
            platform: 'ubuntu_22.04',
            section: 'Network Configuration',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '4.1.1.1',
            title: 'Ensure auditd is installed',
            description:
              'auditd is the userspace component to the Linux Auditing System.',
            rationale:
              'Audit records provide evidence of system activities and help detect security violations.',
            impact: 'Audit logs consume disk space and require management.',
            auditProcedure:
              "Run: dpkg-query -W -f='${binary:Package}\\t${Status}\\n' auditd audispd-plugins",
            remediation: 'Run: apt install auditd audispd-plugins',
            profileLevel: 'L2',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Logging and Auditing',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '5.1.1',
            title: 'Ensure cron daemon is enabled and running',
            description: 'The cron daemon is used to execute batch jobs.',
            rationale:
              'Cron is used for many system tasks and should be enabled.',
            impact: 'None - cron should be enabled for system maintenance.',
            auditProcedure: 'Run: systemctl is-enabled cron',
            remediation: 'Run: systemctl --now enable cron',
            profileLevel: 'L1',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Access, Authentication and Authorization',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '5.2.1',
            title: 'Ensure sudo is installed',
            description:
              'sudo allows a permitted user to execute a command as the superuser.',
            rationale:
              'sudo provides a mechanism for delegation of privileges.',
            impact:
              'None - sudo should be installed for privileged access control.',
            auditProcedure:
              "Run: dpkg-query -W -f='${binary:Package}\\t${Status}\\n' sudo",
            remediation: 'Run: apt install sudo',
            profileLevel: 'L1',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Access, Authentication and Authorization',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '5.3.1',
            title: 'Ensure permissions on /etc/ssh/sshd_config are configured',
            description:
              'The /etc/ssh/sshd_config file contains configuration specifications for sshd.',
            rationale:
              'The sshd_config file needs to be protected from unauthorized changes.',
            impact: 'None - this is a security best practice.',
            auditProcedure: 'Run: stat /etc/ssh/sshd_config',
            remediation:
              'Run: chown root:root /etc/ssh/sshd_config && chmod og-rwx /etc/ssh/sshd_config',
            profileLevel: 'L1',
            scored: true,
            platform: 'ubuntu_22.04',
            section: 'Access, Authentication and Authorization',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
        ],
      },
      windows_server_2022: {
        title: 'CIS Microsoft Windows Server 2022 Benchmark',
        version: 'v1.0.0',
        platform: 'windows_server_2022',
        releaseDate: '2023-01-01',
        controls: [
          {
            id: '1.1.1',
            title:
              'Ensure "Enforce password history" is set to "24 or more password(s)"',
            description:
              'This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password.',
            rationale:
              'Password histories help prevent users from reusing the same passwords repeatedly.',
            impact:
              'Users must create new passwords every time they change passwords.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy',
            remediation:
              'Set "Enforce password history" to 24 or more passwords',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Account Policies',
            cisControlsV8: ['5.2'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.1.2',
            title:
              'Ensure "Maximum password age" is set to "365 or fewer days, but not 0"',
            description:
              'This policy setting defines how long a user can use their password before it expires.',
            rationale:
              'Passwords should be changed regularly but not so often that users cannot remember them.',
            impact:
              'Users must change their passwords at the specified interval.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy',
            remediation:
              'Set "Maximum password age" to 365 or fewer days, but not 0',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Account Policies',
            cisControlsV8: ['5.2'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.1.3',
            title: 'Ensure "Minimum password age" is set to "1 or more day(s)"',
            description:
              'This policy setting determines the number of days that you must use a password before you can change it.',
            rationale:
              'Prevents users from cycling through passwords to reuse a favorite.',
            impact: 'Users cannot change passwords more than once per day.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy',
            remediation: 'Set "Minimum password age" to 1 or more day(s)',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Account Policies',
            cisControlsV8: ['5.2'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.1.4',
            title:
              'Ensure "Minimum password length" is set to "14 or more character(s)"',
            description:
              'This policy setting determines the least number of characters that make up a password.',
            rationale:
              'Longer passwords are exponentially more difficult to crack than shorter ones.',
            impact: 'Users must create passwords with at least 14 characters.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy',
            remediation:
              'Set "Minimum password length" to 14 or more character(s)',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Account Policies',
            cisControlsV8: ['5.2'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '2.2.1',
            title:
              'Ensure "Access Credential Manager as a trusted caller" is set to "No One"',
            description:
              'This security setting is used by Credential Manager during Backup and Restore.',
            rationale: 'This privilege should not be assigned to any accounts.',
            impact: 'None under normal circumstances.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment',
            remediation:
              'Set "Access Credential Manager as a trusted caller" to include no accounts',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Local Policies',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '2.3.1.1',
            title:
              'Ensure "Accounts: Administrator account status" is set to "Disabled"',
            description:
              'This policy setting enables or disables the Administrator account during normal operation.',
            rationale:
              'The built-in Administrator account is a well-known target for attacks.',
            impact: 'Administrators must use alternate accounts.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options',
            remediation:
              'Set "Accounts: Administrator account status" to Disabled',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Security Options',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '9.1.1',
            title:
              'Ensure "Windows Firewall: Domain: Firewall state" is set to "On"',
            description:
              'Select On to have Windows Firewall with Advanced Security use the settings for this profile.',
            rationale:
              'The firewall should always be enabled to protect against network attacks.',
            impact: 'Network traffic will be filtered by the firewall.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Firewall with Advanced Security',
            remediation: 'Set "Windows Firewall: Domain: Firewall state" to On',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Windows Firewall',
            cisControlsV8: ['4.4'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '17.1.1',
            title:
              'Ensure "Audit Credential Validation" is set to "Success and Failure"',
            description:
              'This subcategory reports the results of validation tests on credentials submitted for a user account logon request.',
            rationale:
              'Auditing credential validation helps detect password guessing attacks.',
            impact: 'Additional audit logs will be generated.',
            auditProcedure:
              'Run: auditpol /get /subcategory:"Credential Validation"',
            remediation:
              'Configure Audit Credential Validation to Success and Failure',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Advanced Audit Policy Configuration',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '18.1.1.1',
            title:
              'Ensure "Prevent enabling lock screen camera" is set to "Enabled"',
            description:
              'Disables the lock screen camera toggle switch in PC Settings.',
            rationale:
              'The camera should be disabled on the lock screen for privacy.',
            impact: 'Users cannot access camera from lock screen.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Administrative Templates\\Control Panel\\Personalization',
            remediation: 'Set "Prevent enabling lock screen camera" to Enabled',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Administrative Templates',
            cisControlsV8: ['4.8'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '18.9.5.1',
            title:
              'Ensure "Turn On Virtualization Based Security" is set to "Enabled"',
            description:
              'This policy setting specifies whether Virtualization Based Security is enabled.',
            rationale:
              'VBS provides additional protection for credentials and kernel integrity.',
            impact:
              'VBS requires compatible hardware and may affect performance.',
            auditProcedure:
              'Navigate to Computer Configuration\\Policies\\Administrative Templates\\System\\Device Guard',
            remediation:
              'Set "Turn On Virtualization Based Security" to Enabled',
            profileLevel: 'L1',
            scored: true,
            platform: 'windows_server_2022',
            section: 'Administrative Templates',
            cisControlsV8: ['10.5'],
            nistCsf: ['PR.DS-5'],
          },
        ],
      },

      // RHEL 9 Benchmark
      rhel_9: {
        title: 'CIS Red Hat Enterprise Linux 9 Benchmark',
        version: 'v1.0.0',
        platform: 'rhel_9',
        releaseDate: '2023-06-01',
        controls: [
          {
            id: '1.1.1.1',
            title: 'Ensure mounting of cramfs filesystems is disabled',
            description:
              'The cramfs filesystem type is a compressed read-only Linux filesystem.',
            rationale:
              'Removing support for unneeded filesystem types reduces the local attack surface.',
            impact: 'None - cramfs is not commonly used.',
            auditProcedure:
              'Run: modprobe -n -v cramfs | grep -E "(cramfs|install)"',
            remediation:
              'Edit /etc/modprobe.d/cramfs.conf and add: install cramfs /bin/false',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Filesystem Configuration',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '1.2.1',
            title: 'Ensure GPG keys are configured',
            description:
              'Most packages managers implement GPG key signing to verify package integrity.',
            rationale:
              'Verifying package signatures ensures that packages come from a trusted source.',
            impact: 'None.',
            auditProcedure: 'Run: rpm -q gpg-pubkey --qf "%{name}-%{version}"',
            remediation:
              'Run: rpm --import https://www.redhat.com/security/team/key/',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Package Management',
            cisControlsV8: ['2.2'],
            nistCsf: ['PR.DS-6'],
          },
          {
            id: '1.3.1',
            title: 'Ensure AIDE is installed',
            description:
              'AIDE takes a snapshot of filesystem state including modification times and file hashes.',
            rationale:
              'File integrity checking is essential for detecting unauthorized changes.',
            impact: 'Requires initial configuration and periodic updates.',
            auditProcedure: 'Run: rpm -q aide',
            remediation: 'Run: dnf install aide && aide --init',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Filesystem Integrity Checking',
            cisControlsV8: ['3.14'],
            nistCsf: ['PR.DS-6'],
          },
          {
            id: '1.4.1',
            title: 'Ensure bootloader password is set',
            description:
              'Setting the boot loader password protects against unauthorized users.',
            rationale:
              'Prevents unauthorized users from booting into single user mode.',
            impact: 'Password required for boot parameter changes.',
            auditProcedure: 'Run: grep "^GRUB2_PASSWORD" /boot/grub2/user.cfg',
            remediation: 'Run: grub2-setpassword',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Secure Boot Settings',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.5.1',
            title: 'Ensure SELinux is installed',
            description:
              'SELinux provides mandatory access control mechanisms.',
            rationale:
              'SELinux provides fine-grained access control beyond standard Unix permissions.',
            impact: 'Applications may need SELinux policies configured.',
            auditProcedure: 'Run: rpm -q libselinux',
            remediation: 'Run: dnf install libselinux',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Mandatory Access Control',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.5.2',
            title: 'Ensure SELinux is not disabled in bootloader configuration',
            description:
              'SELinux should not be disabled through the bootloader.',
            rationale:
              'Disabling SELinux removes mandatory access control protections.',
            impact: 'None when SELinux is properly configured.',
            auditProcedure:
              'Run: grep -E "kernelopts=.*(selinux=0|enforcing=0)" /boot/grub2/grubenv',
            remediation:
              'Remove selinux=0 and enforcing=0 from kernel parameters',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Mandatory Access Control',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '2.1.1',
            title: 'Ensure time synchronization is in use',
            description:
              'Time synchronization is critical for authentication and logging.',
            rationale:
              'Accurate time is essential for log analysis and authentication protocols.',
            impact: 'None.',
            auditProcedure: 'Run: systemctl is-enabled chronyd',
            remediation:
              'Run: dnf install chrony && systemctl enable --now chronyd',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Services',
            cisControlsV8: ['8.4'],
            nistCsf: ['PR.PT-1'],
          },
          {
            id: '3.1.1',
            title: 'Ensure IP forwarding is disabled',
            description: 'IP forwarding allows the system to act as a router.',
            rationale:
              'Unless the system is a router, IP forwarding should be disabled.',
            impact: 'Cannot route traffic between interfaces.',
            auditProcedure: 'Run: sysctl net.ipv4.ip_forward',
            remediation:
              'Add to /etc/sysctl.d/60-netipv4_sysctl.conf: net.ipv4.ip_forward = 0',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Network Configuration',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '4.1.1',
            title: 'Ensure firewalld is installed',
            description: 'firewalld provides a dynamically managed firewall.',
            rationale:
              'A firewall provides a line of defense against network attacks.',
            impact: 'Network traffic will be filtered.',
            auditProcedure: 'Run: rpm -q firewalld',
            remediation: 'Run: dnf install firewalld',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Firewall Configuration',
            cisControlsV8: ['4.4'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '5.1.1',
            title: 'Ensure cron daemon is enabled and running',
            description:
              'The cron daemon schedules system jobs and user crontabs.',
            rationale: 'Cron is required for many automated security tasks.',
            impact: 'None.',
            auditProcedure: 'Run: systemctl is-enabled crond',
            remediation: 'Run: systemctl enable --now crond',
            profileLevel: 'L1',
            scored: true,
            platform: 'rhel_9',
            section: 'Access Control',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
        ],
      },

      // Kubernetes Benchmark
      kubernetes: {
        title: 'CIS Kubernetes Benchmark',
        version: 'v1.8.0',
        platform: 'kubernetes',
        releaseDate: '2023-09-01',
        controls: [
          {
            id: '1.1.1',
            title:
              'Ensure that the API server pod specification file permissions are set to 644 or more restrictive',
            description:
              'The API server pod specification file is a critical Kubernetes configuration file.',
            rationale:
              'Restricting file permissions prevents unauthorized modification.',
            impact: 'None.',
            auditProcedure:
              'Run: stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml',
            remediation:
              'Run: chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'Control Plane Components',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.1.2',
            title:
              'Ensure that the API server pod specification file ownership is set to root:root',
            description:
              'The API server pod specification file should be owned by root.',
            rationale: 'Prevents unauthorized users from modifying the file.',
            impact: 'None.',
            auditProcedure:
              'Run: stat -c %U:%G /etc/kubernetes/manifests/kube-apiserver.yaml',
            remediation:
              'Run: chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'Control Plane Components',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.2.1',
            title: 'Ensure that the --anonymous-auth argument is set to false',
            description:
              'Disable anonymous requests to the Kubernetes API server.',
            rationale:
              'Anonymous requests should be disabled to prevent unauthenticated access.',
            impact: 'Anonymous requests will be rejected.',
            auditProcedure:
              'Check kube-apiserver.yaml for: --anonymous-auth=false',
            remediation:
              'Set --anonymous-auth=false in kube-apiserver configuration',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'API Server',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.2.2',
            title: 'Ensure that the --token-auth-file parameter is not set',
            description: 'Do not use static token authentication.',
            rationale:
              'Static tokens cannot be revoked and are stored in plain text.',
            impact: 'Must use alternative authentication methods.',
            auditProcedure: 'Check kube-apiserver.yaml for: --token-auth-file',
            remediation:
              'Remove --token-auth-file from kube-apiserver configuration',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'API Server',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.2.6',
            title:
              'Ensure that the --kubelet-certificate-authority argument is set as appropriate',
            description: 'Verify kubelet certificates using the proper CA.',
            rationale: 'TLS certificate verification ensures kubelet identity.',
            impact: 'Requires PKI infrastructure.',
            auditProcedure:
              'Check kube-apiserver.yaml for: --kubelet-certificate-authority',
            remediation:
              'Set --kubelet-certificate-authority=/path/to/ca.crt in kube-apiserver',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'API Server',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.2.16',
            title: 'Ensure that the --audit-log-path argument is set',
            description: 'Enable auditing and specify the audit log path.',
            rationale: 'Audit logging provides evidence of system activities.',
            impact: 'Audit logs consume disk space.',
            auditProcedure: 'Check kube-apiserver.yaml for: --audit-log-path',
            remediation:
              'Set --audit-log-path=/var/log/apiserver/audit.log in kube-apiserver',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'API Server',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '2.1',
            title:
              'Ensure that the --cert-file and --key-file arguments are set as appropriate',
            description: 'Configure TLS encryption for etcd.',
            rationale: 'Etcd contains sensitive data and should use TLS.',
            impact: 'None when TLS is properly configured.',
            auditProcedure: 'Check etcd.yaml for: --cert-file and --key-file',
            remediation:
              'Set --cert-file=/path/to/etcd-server.crt and --key-file=/path/to/etcd-server.key',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'etcd',
            cisControlsV8: ['3.10'],
            nistCsf: ['PR.DS-2'],
          },
          {
            id: '3.2.1',
            title: 'Ensure that a minimal audit policy is created',
            description:
              'Create an audit policy with at least metadata level logging.',
            rationale: 'Audit policies define what to log in the cluster.',
            impact: 'Disk space for audit logs.',
            auditProcedure:
              'Check for audit policy file referenced by --audit-policy-file',
            remediation:
              'Create /etc/kubernetes/audit-policy.yaml with minimal audit rules',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'Control Plane Configuration',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '4.1.1',
            title:
              'Ensure that the kubelet service file permissions are set to 644 or more restrictive',
            description:
              'Kubelet service file contains important configuration.',
            rationale: 'Restricts unauthorized modification of kubelet config.',
            impact: 'None.',
            auditProcedure:
              'Run: stat -c %a /etc/systemd/system/kubelet.service.d/10-kubeadm.conf',
            remediation:
              'Run: chmod 644 /etc/systemd/system/kubelet.service.d/10-kubeadm.conf',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'Worker Nodes',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '5.1.1',
            title:
              'Ensure that the cluster-admin role is only used where required',
            description:
              'The cluster-admin role provides full access to the cluster.',
            rationale:
              'Least privilege principle - avoid excessive permissions.',
            impact: 'Must create appropriate roles for users.',
            auditProcedure:
              'Run: kubectl get clusterrolebindings -o json | jq \'.items[] | select(.roleRef.name=="cluster-admin")\'',
            remediation: 'Review and remove unnecessary cluster-admin bindings',
            profileLevel: 'L1',
            scored: true,
            platform: 'kubernetes',
            section: 'Policies',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
        ],
      },

      // Docker Benchmark
      docker: {
        title: 'CIS Docker Benchmark',
        version: 'v1.6.0',
        platform: 'docker',
        releaseDate: '2023-07-01',
        controls: [
          {
            id: '1.1.1',
            title:
              'Ensure a separate partition for containers has been created',
            description:
              'Docker stores container data in /var/lib/docker by default.',
            rationale:
              'A separate partition prevents container data from filling the root filesystem.',
            impact: 'Requires disk partitioning during setup.',
            auditProcedure: 'Run: grep /var/lib/docker /etc/fstab',
            remediation:
              'Create a separate partition for /var/lib/docker and mount it',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Host Configuration',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
          {
            id: '1.1.2',
            title:
              'Ensure only trusted users are allowed to control Docker daemon',
            description: 'The Docker daemon requires root privileges.',
            rationale: 'Docker group members can effectively gain root access.',
            impact: 'Carefully manage Docker group membership.',
            auditProcedure: 'Run: getent group docker',
            remediation:
              'Review Docker group membership: gpasswd -d <user> docker',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Host Configuration',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '2.1',
            title: 'Run the Docker daemon as a non-root user, if possible',
            description:
              'Rootless Docker runs the daemon without root privileges.',
            rationale:
              'Reduces the attack surface if the daemon is compromised.',
            impact: 'Some features may not work in rootless mode.',
            auditProcedure: "Run: docker info --format '{{.SecurityOptions}}'",
            remediation:
              'Configure rootless Docker following official documentation',
            profileLevel: 'L2',
            scored: false,
            platform: 'docker',
            section: 'Docker Daemon Configuration',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '2.2',
            title:
              'Ensure network traffic is restricted between containers on the default bridge',
            description:
              'By default, containers on the same bridge can communicate.',
            rationale:
              'Restricting inter-container communication limits lateral movement.',
            impact:
              'May require custom networks for inter-container communication.',
            auditProcedure: 'Run: docker network inspect bridge',
            remediation: 'Set "com.docker.network.bridge.enable_icc": "false"',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Docker Daemon Configuration',
            cisControlsV8: ['12.3'],
            nistCsf: ['PR.AC-5'],
          },
          {
            id: '2.5',
            title:
              'Ensure auditd is configured to audit Docker files and directories',
            description: 'Audit Docker files and directories to track changes.',
            rationale:
              'Auditing provides evidence of changes to Docker configuration.',
            impact: 'Additional log storage required.',
            auditProcedure: 'Run: auditctl -l | grep docker',
            remediation:
              'Add audit rules: -w /var/lib/docker -k docker -w /etc/docker -k docker',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Docker Daemon Configuration',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '3.1',
            title:
              'Ensure that the docker.service file ownership is set to root:root',
            description:
              'The docker.service file controls Docker daemon behavior.',
            rationale: 'Prevents unauthorized modification of Docker service.',
            impact: 'None.',
            auditProcedure:
              'Run: stat -c %U:%G /usr/lib/systemd/system/docker.service',
            remediation:
              'Run: chown root:root /usr/lib/systemd/system/docker.service',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Docker Daemon Configuration Files',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '4.1',
            title: 'Ensure that a user for the container has been created',
            description: 'Create a non-root user for running containers.',
            rationale:
              'Running as non-root reduces the impact of container escape.',
            impact: 'May require application changes.',
            auditProcedure:
              "Run: docker inspect --format '{{.Config.User}}' <container>",
            remediation: 'Add USER directive to Dockerfile: USER non-root-user',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Container Images and Build File',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '4.5',
            title: 'Ensure Content trust for Docker is Enabled',
            description:
              'Content trust provides cryptographic verification of images.',
            rationale: 'Ensures images come from trusted sources.',
            impact: 'Only signed images can be pulled.',
            auditProcedure: 'Run: echo $DOCKER_CONTENT_TRUST',
            remediation: 'Set: export DOCKER_CONTENT_TRUST=1',
            profileLevel: 'L2',
            scored: true,
            platform: 'docker',
            section: 'Container Images and Build File',
            cisControlsV8: ['2.2'],
            nistCsf: ['PR.DS-6'],
          },
          {
            id: '5.1',
            title: 'Ensure that, if applicable, an AppArmor Profile is enabled',
            description:
              'AppArmor provides mandatory access control for containers.',
            rationale: 'AppArmor can prevent container breakout attacks.',
            impact: 'AppArmor profiles must be created for applications.',
            auditProcedure:
              "Run: docker inspect --format '{{.AppArmorProfile}}' <container>",
            remediation:
              'Run container with: docker run --security-opt apparmor=<profile>',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Container Runtime',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '5.10',
            title: 'Ensure that the memory usage for containers is limited',
            description:
              'Memory limits prevent container resource exhaustion attacks.',
            rationale: 'Prevents denial of service through memory exhaustion.',
            impact: 'Container may be killed if limit exceeded.',
            auditProcedure:
              "Run: docker inspect --format '{{.HostConfig.Memory}}' <container>",
            remediation: 'Run container with: docker run -m <memory_limit>',
            profileLevel: 'L1',
            scored: true,
            platform: 'docker',
            section: 'Container Runtime',
            cisControlsV8: ['4.1'],
            nistCsf: ['PR.IP-1'],
          },
        ],
      },

      // AWS Foundations Benchmark
      aws: {
        title: 'CIS Amazon Web Services Foundations Benchmark',
        version: 'v2.0.0',
        platform: 'aws',
        releaseDate: '2023-08-01',
        controls: [
          {
            id: '1.1',
            title: 'Maintain current contact details',
            description:
              'Ensure contact email and telephone details for AWS accounts are current.',
            rationale:
              'AWS uses contact details for important security notifications.',
            impact: 'None.',
            auditProcedure:
              'AWS Console > Account Settings > Contact Information',
            remediation: 'Update contact information in AWS Account Settings',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Identity and Access Management',
            cisControlsV8: ['1.1'],
            nistCsf: ['ID.AM-6'],
          },
          {
            id: '1.4',
            title: 'Ensure no root user access key exists',
            description: 'The root account should not have access keys.',
            rationale:
              'Root access keys provide unrestricted access and cannot be limited.',
            impact: 'Must use IAM users for programmatic access.',
            auditProcedure:
              'Run: aws iam get-account-summary | grep "AccountAccessKeysPresent"',
            remediation:
              'Delete root access keys: AWS Console > Security Credentials',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Identity and Access Management',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '1.5',
            title: 'Ensure MFA is enabled for the root user',
            description:
              'The root account should have multi-factor authentication enabled.',
            rationale:
              'MFA provides additional authentication security for the root account.',
            impact: 'Requires hardware or virtual MFA device.',
            auditProcedure:
              'Run: aws iam get-account-summary | grep "AccountMFAEnabled"',
            remediation: 'Enable MFA: AWS Console > Security Credentials > MFA',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Identity and Access Management',
            cisControlsV8: ['6.5'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.8',
            title:
              'Ensure IAM password policy requires minimum length of 14 or greater',
            description:
              'Password policy should require passwords of at least 14 characters.',
            rationale: 'Longer passwords are exponentially harder to crack.',
            impact: 'Users must create longer passwords.',
            auditProcedure: 'Run: aws iam get-account-password-policy',
            remediation:
              'Run: aws iam update-account-password-policy --minimum-password-length 14',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Identity and Access Management',
            cisControlsV8: ['5.2'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.14',
            title: 'Ensure access keys are rotated every 90 days or less',
            description: 'IAM access keys should be rotated regularly.',
            rationale:
              'Regular rotation limits the window of exposure for compromised keys.',
            impact: 'Applications must be updated with new keys.',
            auditProcedure: 'Run: aws iam list-access-keys --user-name <user>',
            remediation: 'Create new key, update applications, delete old key',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Identity and Access Management',
            cisControlsV8: ['5.2'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '2.1.1',
            title: 'Ensure S3 Bucket Policy is set to deny HTTP requests',
            description: 'S3 buckets should require HTTPS for all requests.',
            rationale: 'HTTPS encrypts data in transit to S3.',
            impact: 'Applications must use HTTPS.',
            auditProcedure:
              'Review bucket policy for aws:SecureTransport condition',
            remediation:
              'Add bucket policy denying actions when aws:SecureTransport is false',
            profileLevel: 'L2',
            scored: true,
            platform: 'aws',
            section: 'Storage',
            cisControlsV8: ['3.10'],
            nistCsf: ['PR.DS-2'],
          },
          {
            id: '2.1.2',
            title: 'Ensure MFA Delete is enabled on S3 buckets',
            description:
              'MFA Delete requires MFA to delete objects or bucket versioning.',
            rationale: 'Prevents accidental or malicious deletion of data.',
            impact: 'MFA required for delete operations.',
            auditProcedure:
              'Run: aws s3api get-bucket-versioning --bucket <bucket>',
            remediation:
              'Enable MFA Delete using AWS CLI with root credentials',
            profileLevel: 'L2',
            scored: false,
            platform: 'aws',
            section: 'Storage',
            cisControlsV8: ['3.3'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '2.3.1',
            title: 'Ensure that encryption is enabled for RDS Instances',
            description:
              'RDS instances should have encryption at rest enabled.',
            rationale: 'Encryption protects data if storage is compromised.',
            impact: 'Slight performance overhead.',
            auditProcedure:
              'Run: aws rds describe-db-instances --query "DBInstances[*].StorageEncrypted"',
            remediation: 'Create new encrypted RDS instance and migrate data',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Storage',
            cisControlsV8: ['3.11'],
            nistCsf: ['PR.DS-1'],
          },
          {
            id: '3.1',
            title: 'Ensure CloudTrail is enabled in all regions',
            description:
              'CloudTrail provides API call logging across all regions.',
            rationale: 'Multi-region trails ensure complete audit coverage.',
            impact: 'Storage costs for logs.',
            auditProcedure:
              'Run: aws cloudtrail describe-trails --query "trailList[*].IsMultiRegionTrail"',
            remediation:
              'Run: aws cloudtrail create-trail --name <name> --s3-bucket-name <bucket> --is-multi-region-trail',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Logging',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '4.1',
            title:
              'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
            description:
              'Security groups should not allow unrestricted SSH access.',
            rationale:
              'Open SSH access exposes instances to brute force attacks.',
            impact: 'Must specify allowed source IPs.',
            auditProcedure:
              'Run: aws ec2 describe-security-groups with filters for SSH rules',
            remediation:
              'Modify security groups to restrict SSH to specific IPs',
            profileLevel: 'L1',
            scored: true,
            platform: 'aws',
            section: 'Networking',
            cisControlsV8: ['12.1'],
            nistCsf: ['PR.AC-5'],
          },
        ],
      },

      // Azure Foundations Benchmark
      azure: {
        title: 'CIS Microsoft Azure Foundations Benchmark',
        version: 'v2.0.0',
        platform: 'azure',
        releaseDate: '2023-08-01',
        controls: [
          {
            id: '1.1',
            title:
              'Ensure Security Defaults is enabled on Azure Active Directory',
            description: 'Security defaults provide basic identity security.',
            rationale:
              'Security defaults enable MFA and block legacy authentication.',
            impact: 'May affect legacy applications.',
            auditProcedure:
              'Azure Portal > Azure AD > Properties > Manage Security defaults',
            remediation: 'Enable Security defaults in Azure AD Properties',
            profileLevel: 'L1',
            scored: true,
            platform: 'azure',
            section: 'Identity and Access Management',
            cisControlsV8: ['6.5'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.2',
            title:
              'Ensure that Multi-Factor Auth Status is Enabled for all Privileged Users',
            description: 'Privileged users should have MFA enabled.',
            rationale: 'MFA significantly reduces account compromise risk.',
            impact: 'Requires MFA device for privileged users.',
            auditProcedure: 'Azure Portal > Azure AD > Users > Per-user MFA',
            remediation: 'Enable MFA for all privileged accounts',
            profileLevel: 'L1',
            scored: true,
            platform: 'azure',
            section: 'Identity and Access Management',
            cisControlsV8: ['6.5'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.3',
            title:
              'Ensure that Multi-Factor Auth Status is Enabled for all Non-Privileged Users',
            description: 'All users should have MFA enabled.',
            rationale:
              'Any compromised account can be used for lateral movement.',
            impact: 'Requires MFA device for all users.',
            auditProcedure: 'Azure Portal > Azure AD > Users > Per-user MFA',
            remediation: 'Enable MFA for all user accounts',
            profileLevel: 'L2',
            scored: true,
            platform: 'azure',
            section: 'Identity and Access Management',
            cisControlsV8: ['6.5'],
            nistCsf: ['PR.AC-1'],
          },
          {
            id: '1.21',
            title:
              'Ensure that no custom subscription administrator roles are created',
            description: 'Avoid creating custom roles with broad permissions.',
            rationale:
              'Custom roles may inadvertently grant excessive permissions.',
            impact: 'Must use built-in roles.',
            auditProcedure:
              'Run: az role definition list --custom-role-only true',
            remediation: 'Review and remove unnecessary custom roles',
            profileLevel: 'L1',
            scored: true,
            platform: 'azure',
            section: 'Identity and Access Management',
            cisControlsV8: ['5.4'],
            nistCsf: ['PR.AC-4'],
          },
          {
            id: '2.1',
            title:
              'Ensure that Microsoft Defender for Cloud is set to On for Servers',
            description:
              'Defender for Servers provides threat detection for VMs.',
            rationale:
              'Provides advanced threat detection and security recommendations.',
            impact: 'Additional cost per server.',
            auditProcedure:
              'Azure Portal > Defender for Cloud > Environment settings',
            remediation: 'Enable Defender for Servers in environment settings',
            profileLevel: 'L1',
            scored: true,
            platform: 'azure',
            section: 'Security Center',
            cisControlsV8: ['10.1'],
            nistCsf: ['DE.AE-1'],
          },
          {
            id: '2.2',
            title:
              'Ensure that Microsoft Defender for Cloud is set to On for App Service',
            description: 'Defender for App Service protects web applications.',
            rationale: 'Detects attacks against web applications.',
            impact: 'Additional cost per app.',
            auditProcedure:
              'Azure Portal > Defender for Cloud > Environment settings',
            remediation:
              'Enable Defender for App Service in environment settings',
            profileLevel: 'L2',
            scored: true,
            platform: 'azure',
            section: 'Security Center',
            cisControlsV8: ['10.1'],
            nistCsf: ['DE.AE-1'],
          },
          {
            id: '3.1',
            title: 'Ensure that "Secure transfer required" is set to "Enabled"',
            description:
              'Storage accounts should require secure (HTTPS) connections.',
            rationale: 'HTTPS encrypts data in transit.',
            impact: 'Applications must use HTTPS.',
            auditProcedure:
              'Run: az storage account list --query "[].{name:name, secureTransferEnabled:enableHttpsTrafficOnly}"',
            remediation:
              'Run: az storage account update --name <name> --https-only true',
            profileLevel: 'L1',
            scored: true,
            platform: 'azure',
            section: 'Storage Accounts',
            cisControlsV8: ['3.10'],
            nistCsf: ['PR.DS-2'],
          },
          {
            id: '4.1',
            title: 'Ensure that "Auditing" is set to "On"',
            description: 'Enable auditing for Azure SQL databases.',
            rationale: 'Auditing provides visibility into database activities.',
            impact: 'Storage cost for audit logs.',
            auditProcedure: 'Run: az sql server audit-policy show',
            remediation:
              'Run: az sql server audit-policy update --state Enabled',
            profileLevel: 'L1',
            scored: true,
            platform: 'azure',
            section: 'Database Services',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '5.1',
            title:
              'Ensure that Network Security Group Flow Log retention period is "greater than 90 days"',
            description:
              'NSG flow logs should be retained for at least 90 days.',
            rationale:
              'Sufficient retention enables historical analysis of network traffic.',
            impact: 'Storage cost for logs.',
            auditProcedure: 'Azure Portal > Network Watcher > NSG flow logs',
            remediation: 'Configure retention to 90 days or more',
            profileLevel: 'L2',
            scored: true,
            platform: 'azure',
            section: 'Networking',
            cisControlsV8: ['8.2'],
            nistCsf: ['DE.CM-1'],
          },
          {
            id: '6.1',
            title:
              'Ensure that RDP access from the Internet is evaluated and restricted',
            description:
              'Network security groups should not allow RDP from any source.',
            rationale: 'Open RDP access exposes VMs to brute force attacks.',
            impact: 'Must use VPN or bastion for RDP access.',
            auditProcedure: 'Review NSG rules for port 3389 from 0.0.0.0/0',
            remediation:
              'Restrict RDP access to specific IP ranges or use Azure Bastion',
            profileLevel: 'L1',
            scored: true,
            platform: 'azure',
            section: 'Networking',
            cisControlsV8: ['12.1'],
            nistCsf: ['PR.AC-5'],
          },
        ],
      },
    };
  }

  /**
   * Ingest Microsoft Security documentation
   */
  async ingestMicrosoftSecurityDocs(
    category: MicrosoftSecurityCategory,
    source: 'builtin' | 'url' | 'file' = 'builtin',
    pathOrUrl?: string,
  ): Promise<number> {
    await this.ensureInitialized();

    if (source === 'builtin') {
      const chunks = this.getBuiltinMicrosoftSecurityChunks(category);
      await this.vectorStore.addChunks(chunks);
      await this.vectorStore.saveToDisk();
      return chunks.length;
    }

    if (source === 'file' && pathOrUrl) {
      return this.ingestFile(pathOrUrl, {
        source: 'microsoft_security',
        category,
      });
    }

    throw new Error(`Unsupported source: ${source}`);
  }

  /**
   * Get built-in Microsoft Security chunks
   */
  private getBuiltinMicrosoftSecurityChunks(
    category: MicrosoftSecurityCategory,
  ): ReturnType<DocumentProcessor['processFile']> extends Promise<infer T>
    ? T
    : never {
    const docs = this.getBuiltinMicrosoftDocs();
    const doc = docs[category];

    if (!doc) {
      throw new Error(
        `No built-in documentation available for category: ${category}`,
      );
    }

    return this.documentProcessor.createMicrosoftSecurityChunks(doc);
  }

  /**
   * Built-in Microsoft security documentation
   */
  private getBuiltinMicrosoftDocs(): Record<
    string,
    Parameters<DocumentProcessor['createMicrosoftSecurityChunks']>[0]
  > {
    return {
      defender_endpoint: {
        title: 'Microsoft Defender for Endpoint Configuration',
        category: 'defender_endpoint',
        version: '1.0',
        recommendations: [
          {
            id: 'mde-001',
            title: 'Enable Real-time Protection',
            description:
              'Real-time protection monitors your computer for malware and blocks threats as they occur.',
            category: 'defender_endpoint',
            severity: 'high',
            implementationGuide:
              'Enable real-time protection through Group Policy or Microsoft Intune to ensure continuous protection against malware.',
            commands: [
              'Set-MpPreference -DisableRealtimeMonitoring $false',
              'Set-MpPreference -DisableBehaviorMonitoring $false',
            ],
            policyReference:
              'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection',
            complianceMappings: [
              {
                framework: 'NIST CSF',
                controlId: 'DE.CM-4',
                controlTitle: 'Malicious code is detected',
              },
            ],
          },
          {
            id: 'mde-002',
            title: 'Enable Cloud-delivered Protection',
            description:
              'Cloud-delivered protection provides near-instant detection of new malware threats.',
            category: 'defender_endpoint',
            severity: 'high',
            implementationGuide:
              'Enable cloud protection to receive the latest threat intelligence from Microsoft.',
            commands: [
              'Set-MpPreference -MAPSReporting Advanced',
              'Set-MpPreference -SubmitSamplesConsent SendAllSamples',
            ],
            policyReference:
              'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > MAPS',
            complianceMappings: [
              {
                framework: 'CIS Controls v8',
                controlId: '10.1',
                controlTitle: 'Deploy and Maintain Anti-Malware Software',
              },
            ],
          },
          {
            id: 'mde-003',
            title: 'Configure Attack Surface Reduction Rules',
            description:
              'ASR rules help prevent malware infection by blocking suspicious behaviors.',
            category: 'defender_endpoint',
            severity: 'high',
            implementationGuide:
              'Enable ASR rules to block common attack vectors such as Office macro abuse and script-based attacks.',
            commands: [
              'Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled',
              'Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled',
            ],
            complianceMappings: [
              {
                framework: 'MITRE ATT&CK',
                controlId: 'T1059',
                controlTitle: 'Command and Scripting Interpreter',
              },
            ],
          },
          {
            id: 'mde-004',
            title: 'Enable Controlled Folder Access',
            description:
              'Controlled folder access helps protect valuable data from malicious apps and ransomware.',
            category: 'defender_endpoint',
            severity: 'medium',
            implementationGuide:
              'Enable controlled folder access to protect documents, pictures, and other important folders from unauthorized changes.',
            commands: [
              'Set-MpPreference -EnableControlledFolderAccess Enabled',
            ],
            policyReference:
              'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Windows Defender Exploit Guard > Controlled Folder Access',
            complianceMappings: [
              {
                framework: 'NIST CSF',
                controlId: 'PR.DS-1',
                controlTitle: 'Data-at-rest is protected',
              },
            ],
          },
          {
            id: 'mde-005',
            title: 'Configure Network Protection',
            description:
              'Network protection helps prevent employees from using applications to access dangerous domains.',
            category: 'defender_endpoint',
            severity: 'high',
            implementationGuide:
              'Enable network protection to block connections to known malicious websites and IP addresses.',
            commands: ['Set-MpPreference -EnableNetworkProtection Enabled'],
            policyReference:
              'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Windows Defender Exploit Guard > Network Protection',
            complianceMappings: [
              {
                framework: 'CIS Controls v8',
                controlId: '9.2',
                controlTitle: 'Use DNS Filtering Services',
              },
            ],
          },
        ],
      },
      intune: {
        title: 'Microsoft Intune Security Configuration',
        category: 'intune',
        version: '1.0',
        recommendations: [
          {
            id: 'intune-001',
            title: 'Require Device Encryption',
            description:
              'Device encryption protects data if a device is lost or stolen.',
            category: 'intune',
            severity: 'high',
            implementationGuide:
              'Configure a device compliance policy requiring BitLocker encryption on Windows devices and FileVault on macOS.',
            policyReference:
              'Devices > Compliance policies > Policies > Create Policy > Windows 10 and later > Device Health > Require BitLocker',
            complianceMappings: [
              {
                framework: 'NIST CSF',
                controlId: 'PR.DS-1',
                controlTitle: 'Data-at-rest is protected',
              },
              {
                framework: 'PCI DSS',
                controlId: '3.4',
                controlTitle: 'Render PAN unreadable anywhere it is stored',
              },
            ],
          },
          {
            id: 'intune-002',
            title: 'Configure Conditional Access',
            description:
              'Conditional Access policies ensure only compliant devices can access corporate resources.',
            category: 'intune',
            severity: 'high',
            implementationGuide:
              'Create conditional access policies requiring device compliance and MFA for accessing corporate applications.',
            policyReference:
              'Security > Conditional Access > Policies > New Policy',
            complianceMappings: [
              {
                framework: 'NIST CSF',
                controlId: 'PR.AC-1',
                controlTitle: 'Identities and credentials are issued',
              },
            ],
          },
          {
            id: 'intune-003',
            title: 'Enable Mobile Threat Defense',
            description:
              'MTD integration provides threat protection for mobile devices.',
            category: 'intune',
            severity: 'medium',
            implementationGuide:
              'Integrate a Mobile Threat Defense partner with Intune and configure compliance policies based on threat level.',
            policyReference:
              'Tenant administration > Connectors and tokens > Mobile Threat Defense',
            complianceMappings: [
              {
                framework: 'CIS Controls v8',
                controlId: '10.1',
                controlTitle: 'Deploy and Maintain Anti-Malware Software',
              },
            ],
          },
          {
            id: 'intune-004',
            title: 'Configure App Protection Policies',
            description:
              'App protection policies protect corporate data within managed applications.',
            category: 'intune',
            severity: 'high',
            implementationGuide:
              'Create app protection policies to prevent data leakage from corporate apps to personal apps.',
            policyReference: 'Apps > App protection policies > Create policy',
            complianceMappings: [
              {
                framework: 'NIST CSF',
                controlId: 'PR.DS-5',
                controlTitle: 'Protections against data leaks are implemented',
              },
            ],
          },
        ],
      },
      azure_security_center: {
        title: 'Microsoft Defender for Cloud Configuration',
        category: 'azure_security_center',
        version: '1.0',
        recommendations: [
          {
            id: 'mdc-001',
            title: 'Enable Enhanced Security Features',
            description:
              'Enhanced security features provide advanced threat protection for your Azure resources.',
            category: 'azure_security_center',
            severity: 'high',
            implementationGuide:
              'Enable Microsoft Defender plans for Servers, SQL, Storage, and other workloads in your subscription.',
            policyReference:
              'Microsoft Defender for Cloud > Environment settings > Defender plans',
            complianceMappings: [
              {
                framework: 'CIS Azure',
                controlId: '2.1.1',
                controlTitle:
                  'Ensure Microsoft Defender for Cloud is set to On',
              },
            ],
          },
          {
            id: 'mdc-002',
            title: 'Configure Security Contacts',
            description:
              'Security contacts receive notifications about security alerts.',
            category: 'azure_security_center',
            severity: 'medium',
            implementationGuide:
              'Configure email notifications for security alerts to ensure timely response.',
            policyReference:
              'Microsoft Defender for Cloud > Environment settings > Email notifications',
            complianceMappings: [
              {
                framework: 'CIS Azure',
                controlId: '2.1.19',
                controlTitle: 'Ensure Security Contact emails are configured',
              },
            ],
          },
          {
            id: 'mdc-003',
            title: 'Enable Just-In-Time VM Access',
            description:
              'JIT VM access reduces exposure to attacks by locking down inbound traffic to VMs.',
            category: 'azure_security_center',
            severity: 'high',
            implementationGuide:
              'Enable JIT access for management ports on virtual machines to reduce attack surface.',
            policyReference:
              'Microsoft Defender for Cloud > Workload protections > Just-in-time VM access',
            complianceMappings: [
              {
                framework: 'NIST CSF',
                controlId: 'PR.AC-4',
                controlTitle:
                  'Access permissions and authorizations are managed',
              },
            ],
          },
          {
            id: 'mdc-004',
            title: 'Enable Adaptive Application Controls',
            description:
              'Adaptive application controls help protect machines from malware by allowing only approved applications.',
            category: 'azure_security_center',
            severity: 'medium',
            implementationGuide:
              'Configure adaptive application controls to whitelist known good applications.',
            policyReference:
              'Microsoft Defender for Cloud > Workload protections > Adaptive application controls',
            complianceMappings: [
              {
                framework: 'CIS Controls v8',
                controlId: '2.5',
                controlTitle: 'Allowlist Authorized Software',
              },
            ],
          },
        ],
      },
    };
  }

  /**
   * Search the RAG index
   */
  async search(query: SecurityRAGQuery): Promise<SecurityRAGResponse> {
    await this.ensureInitialized();

    const startTime = Date.now();
    const results = await this.vectorStore.search(query);
    const processingTimeMs = Date.now() - startTime;

    const stats = this.vectorStore.getStats();

    return {
      query,
      results,
      totalDocuments: stats.totalDocuments,
      processingTimeMs,
    };
  }

  /**
   * Get hardening recommendations for a platform
   */
  async getHardeningRecommendations(
    platform: CISPlatform,
    profileLevel: CISProfileLevel = 'L1',
  ): Promise<SecurityRAGResponse> {
    return this.search({
      query: `hardening security configuration best practices remediation ${platform}`,
      sources: ['cis_benchmark'],
      platforms: [platform],
      profileLevel,
      maxResults: 20,
    });
  }

  /**
   * Get compliance guidance for a framework
   */
  async getComplianceGuidance(
    framework: string,
    topic?: string,
  ): Promise<SecurityRAGResponse> {
    const query = topic
      ? `${framework} compliance ${topic}`
      : `${framework} compliance requirements controls`;

    return this.search({
      query,
      complianceFramework: framework,
      maxResults: 15,
    });
  }

  /**
   * Get Microsoft security recommendations for a category
   */
  async getMicrosoftSecurityGuidance(
    category: MicrosoftSecurityCategory,
    topic?: string,
  ): Promise<SecurityRAGResponse> {
    const query = topic
      ? `${category} ${topic} configuration`
      : `${category} security best practices configuration`;

    return this.search({
      query,
      sources: ['microsoft_security'],
      categories: [category],
      maxResults: 15,
    });
  }

  /**
   * Get index statistics
   */
  getStats(): IndexStats {
    return this.vectorStore.getStats();
  }

  /**
   * Clear the index
   */
  async clearIndex(): Promise<void> {
    await this.ensureInitialized();
    this.vectorStore.clear();
    await this.vectorStore.saveToDisk();
  }

  /**
   * Delete documents by source
   */
  async deleteBySource(source: SecurityDocumentSource): Promise<number> {
    await this.ensureInitialized();
    const count = this.vectorStore.deleteBySource(source);
    await this.vectorStore.saveToDisk();
    return count;
  }
}
