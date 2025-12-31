/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Document Processor for Security RAG Pipeline
 *
 * Handles parsing and chunking of security documents:
 * - CIS Benchmark PDFs/JSON
 * - Microsoft Security documentation
 * - Compliance framework documents
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import type {
  CISControl,
  CISPlatform,
  CISProfileLevel,
  ComplianceMapping,
  DocumentChunk,
  IngestionOptions,
  MicrosoftSecurityCategory,
  MicrosoftSecurityRecommendation,
  SecurityDocumentSource,
  SecurityRAGConfig,
} from './types.js';

/**
 * Parsed CIS Benchmark document structure
 */
interface ParsedCISBenchmark {
  title: string;
  version: string;
  platform: CISPlatform;
  releaseDate: string;
  controls: CISControl[];
}

/**
 * Parsed Microsoft Security document
 */
interface ParsedMicrosoftDoc {
  title: string;
  category: MicrosoftSecurityCategory;
  version?: string;
  recommendations: MicrosoftSecurityRecommendation[];
}

/**
 * Document processor for security documents
 */
export class DocumentProcessor {
  private config: SecurityRAGConfig;

  constructor(config: SecurityRAGConfig) {
    this.config = config;
  }

  /**
   * Process a document file and return chunks
   */
  async processFile(
    filePath: string,
    options: IngestionOptions,
  ): Promise<DocumentChunk[]> {
    const content = await fs.readFile(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();

    switch (ext) {
      case '.json':
        return this.processJsonDocument(content, options);
      case '.md':
      case '.markdown':
        return this.processMarkdownDocument(content, options, filePath);
      case '.txt':
        return this.processTextDocument(content, options, filePath);
      default:
        throw new Error(`Unsupported file format: ${ext}`);
    }
  }

  /**
   * Process markdown content directly (not from file)
   * Used for web-fetched content
   */
  processMarkdownContent(
    content: string,
    metadata: Record<string, unknown> = {},
  ): DocumentChunk[] {
    const options: IngestionOptions = {
      source: (metadata['source'] as SecurityDocumentSource) || 'custom',
      platform: metadata['platform'] as CISPlatform | undefined,
      category: metadata['category'] as MicrosoftSecurityCategory | undefined,
      tags: metadata['tags'] as string[] | undefined,
    };

    // Use a virtual file path based on the source
    const virtualPath =
      (metadata['fetchedFromUrl'] as string) || 'fetched-content.md';

    return this.processMarkdownDocument(content, options, virtualPath);
  }

  /**
   * Process JSON document (CIS Benchmark export format)
   */
  private async processJsonDocument(
    content: string,
    options: IngestionOptions,
  ): Promise<DocumentChunk[]> {
    const data = JSON.parse(content);

    // Detect document type
    if (this.isCISBenchmarkJson(data)) {
      return this.processCISBenchmarkJson(data, options);
    }

    if (this.isMicrosoftSecurityJson(data)) {
      return this.processMicrosoftSecurityJson(data, options);
    }

    // Generic JSON processing
    return this.processGenericJson(data, options);
  }

  /**
   * Check if JSON is CIS Benchmark format
   */
  private isCISBenchmarkJson(data: unknown): boolean {
    if (typeof data !== 'object' || data === null) return false;
    const obj = data as Record<string, unknown>;
    return (
      'controls' in obj ||
      'benchmarkTitle' in obj ||
      ('recommendations' in obj && 'platform' in obj)
    );
  }

  /**
   * Check if JSON is Microsoft Security format
   */
  private isMicrosoftSecurityJson(data: unknown): boolean {
    if (typeof data !== 'object' || data === null) return false;
    const obj = data as Record<string, unknown>;
    return (
      'category' in obj &&
      ('recommendations' in obj || 'settings' in obj || 'policies' in obj)
    );
  }

  /**
   * Process CIS Benchmark JSON
   */
  private processCISBenchmarkJson(
    data: Record<string, unknown>,
    options: IngestionOptions,
  ): DocumentChunk[] {
    const chunks: DocumentChunk[] = [];
    const documentId = randomUUID();
    const platform = (options.platform ||
      data['platform'] ||
      'unknown') as CISPlatform;
    const version = options.version || (data['version'] as string) || '1.0';

    // Extract controls/recommendations
    const controls = (data['controls'] ||
      data['recommendations'] ||
      []) as Array<Record<string, unknown>>;

    for (const control of controls) {
      const controlId = (control['id'] || control['controlId'] || '') as string;
      const title = (control['title'] || control['name'] || '') as string;
      const description = (control['description'] || '') as string;
      const rationale = (control['rationale'] || '') as string;
      const audit = (control['audit'] ||
        control['auditProcedure'] ||
        '') as string;
      const remediation = (control['remediation'] ||
        control['fix'] ||
        '') as string;
      const profileLevel = (control['profileLevel'] ||
        control['level'] ||
        'L1') as CISProfileLevel;
      const section = (control['section'] ||
        control['category'] ||
        '') as string;

      // Build comprehensive content for this control
      const content = this.buildCISControlContent({
        id: controlId,
        title,
        description,
        rationale,
        audit,
        remediation,
        profileLevel,
        section,
        platform,
      });

      // Extract compliance mappings
      const complianceMappings = this.extractComplianceMappings(control);

      chunks.push({
        id: `cis_${platform}_${controlId}_${randomUUID().slice(0, 8)}`,
        documentId,
        source: 'cis_benchmark',
        platform,
        content,
        metadata: {
          sectionId: controlId,
          sectionTitle: title,
          profileLevel,
          complianceMappings,
          tags: [
            platform,
            `cis-${profileLevel.toLowerCase()}`,
            section,
            ...(options.tags || []),
          ].filter(Boolean),
          version,
          lastUpdated: new Date().toISOString(),
        },
      });
    }

    return chunks;
  }

  /**
   * Build content string for CIS control
   */
  private buildCISControlContent(control: {
    id: string;
    title: string;
    description: string;
    rationale: string;
    audit: string;
    remediation: string;
    profileLevel: CISProfileLevel;
    section: string;
    platform: CISPlatform;
  }): string {
    const parts = [
      `# CIS Control ${control.id}: ${control.title}`,
      `Platform: ${control.platform}`,
      `Profile Level: ${control.profileLevel}`,
      `Section: ${control.section}`,
      '',
      '## Description',
      control.description,
      '',
      '## Rationale',
      control.rationale,
      '',
      '## Audit Procedure',
      control.audit,
      '',
      '## Remediation',
      control.remediation,
    ];

    return parts.filter(Boolean).join('\n');
  }

  /**
   * Extract compliance mappings from control
   */
  private extractComplianceMappings(
    control: Record<string, unknown>,
  ): ComplianceMapping[] {
    const mappings: ComplianceMapping[] = [];

    // CIS Controls v8 mapping
    const cisV8 = control['cisControlsV8'] || control['cis_controls'];
    if (Array.isArray(cisV8)) {
      for (const item of cisV8) {
        mappings.push({
          framework: 'CIS Controls v8',
          controlId: String(item),
          controlTitle: '',
        });
      }
    }

    // NIST CSF mapping
    const nist = control['nistCsf'] || control['nist'];
    if (Array.isArray(nist)) {
      for (const item of nist) {
        mappings.push({
          framework: 'NIST CSF',
          controlId: String(item),
          controlTitle: '',
        });
      }
    }

    // PCI DSS mapping
    const pci = control['pciDss'] || control['pci'];
    if (Array.isArray(pci)) {
      for (const item of pci) {
        mappings.push({
          framework: 'PCI DSS',
          controlId: String(item),
          controlTitle: '',
        });
      }
    }

    return mappings;
  }

  /**
   * Process Microsoft Security JSON
   */
  private processMicrosoftSecurityJson(
    data: Record<string, unknown>,
    options: IngestionOptions,
  ): DocumentChunk[] {
    const chunks: DocumentChunk[] = [];
    const documentId = randomUUID();
    const category = (options.category ||
      data['category'] ||
      'security_baselines') as MicrosoftSecurityCategory;
    const version = options.version || (data['version'] as string) || '1.0';

    // Extract recommendations/settings
    const items = (data['recommendations'] ||
      data['settings'] ||
      data['policies'] ||
      []) as Array<Record<string, unknown>>;

    for (const item of items) {
      const id = (item['id'] || item['settingId'] || randomUUID()) as string;
      const title = (item['title'] ||
        item['name'] ||
        item['displayName'] ||
        '') as string;
      const description = (item['description'] || '') as string;
      const guidance = (item['implementationGuide'] ||
        item['guidance'] ||
        '') as string;
      const severity = (item['severity'] || 'medium') as string;

      const content = this.buildMicrosoftSecurityContent({
        id,
        title,
        description,
        guidance,
        severity,
        category,
        commands: item['commands'] as string[] | undefined,
        policyReference: item['policyReference'] as string | undefined,
      });

      chunks.push({
        id: `ms_${category}_${id}_${randomUUID().slice(0, 8)}`,
        documentId,
        source: 'microsoft_security',
        category,
        content,
        metadata: {
          sectionId: id,
          sectionTitle: title,
          severity,
          tags: [
            'microsoft',
            category,
            severity,
            ...(options.tags || []),
          ].filter(Boolean),
          version,
          lastUpdated: new Date().toISOString(),
        },
      });
    }

    return chunks;
  }

  /**
   * Build content string for Microsoft security recommendation
   */
  private buildMicrosoftSecurityContent(item: {
    id: string;
    title: string;
    description: string;
    guidance: string;
    severity: string;
    category: MicrosoftSecurityCategory;
    commands?: string[];
    policyReference?: string;
  }): string {
    const parts = [
      `# Microsoft Security: ${item.title}`,
      `Category: ${item.category}`,
      `Severity: ${item.severity}`,
      '',
      '## Description',
      item.description,
      '',
      '## Implementation Guide',
      item.guidance,
    ];

    if (item.commands && item.commands.length > 0) {
      parts.push('', '## Commands', '```powershell');
      parts.push(...item.commands);
      parts.push('```');
    }

    if (item.policyReference) {
      parts.push('', '## Policy Reference', item.policyReference);
    }

    return parts.filter(Boolean).join('\n');
  }

  /**
   * Process generic JSON document
   */
  private processGenericJson(
    data: Record<string, unknown>,
    options: IngestionOptions,
  ): DocumentChunk[] {
    const documentId = randomUUID();
    const content = JSON.stringify(data, null, 2);

    return this.chunkText(content, {
      documentId,
      source: options.source,
      platform: options.platform,
      category: options.category,
      tags: options.tags,
      version: options.version,
    });
  }

  /**
   * Process Markdown document
   */
  private processMarkdownDocument(
    content: string,
    options: IngestionOptions,
    filePath: string,
  ): DocumentChunk[] {
    const documentId = randomUUID();
    const fileName = path.basename(filePath, path.extname(filePath));

    // Split by headers
    const sections = this.splitByHeaders(content);

    const chunks: DocumentChunk[] = [];

    for (const section of sections) {
      if (section.content.trim().length < 50) continue; // Skip very short sections

      chunks.push({
        id: `md_${fileName}_${section.level}_${randomUUID().slice(0, 8)}`,
        documentId,
        source: options.source,
        platform: options.platform,
        category: options.category,
        content: section.content,
        metadata: {
          sectionId: section.id,
          sectionTitle: section.title,
          tags: [fileName, ...(options.tags || [])].filter(Boolean),
          version: options.version,
          lastUpdated: new Date().toISOString(),
        },
      });
    }

    return chunks;
  }

  /**
   * Split markdown content by headers
   */
  private splitByHeaders(
    content: string,
  ): Array<{ id: string; title: string; level: number; content: string }> {
    const lines = content.split('\n');
    const sections: Array<{
      id: string;
      title: string;
      level: number;
      content: string;
    }> = [];

    let currentSection: {
      id: string;
      title: string;
      level: number;
      lines: string[];
    } | null = null;

    for (const line of lines) {
      const headerMatch = line.match(/^(#{1,6})\s+(.+)$/);

      if (headerMatch) {
        // Save previous section
        if (currentSection) {
          sections.push({
            id: currentSection.id,
            title: currentSection.title,
            level: currentSection.level,
            content: currentSection.lines.join('\n'),
          });
        }

        // Start new section
        const level = headerMatch[1]!.length;
        const title = headerMatch[2]!;
        currentSection = {
          id: this.slugify(title),
          title,
          level,
          lines: [line],
        };
      } else if (currentSection) {
        currentSection.lines.push(line);
      }
    }

    // Save last section
    if (currentSection) {
      sections.push({
        id: currentSection.id,
        title: currentSection.title,
        level: currentSection.level,
        content: currentSection.lines.join('\n'),
      });
    }

    return sections;
  }

  /**
   * Process plain text document
   */
  private processTextDocument(
    content: string,
    options: IngestionOptions,
    filePath: string,
  ): DocumentChunk[] {
    const documentId = randomUUID();
    const fileName = path.basename(filePath, path.extname(filePath));

    return this.chunkText(content, {
      documentId,
      source: options.source,
      platform: options.platform,
      category: options.category,
      tags: [fileName, ...(options.tags || [])],
      version: options.version,
    });
  }

  /**
   * Chunk text into smaller pieces with overlap
   */
  private chunkText(
    text: string,
    options: {
      documentId: string;
      source: SecurityDocumentSource;
      platform?: CISPlatform;
      category?: MicrosoftSecurityCategory;
      tags?: string[];
      version?: string;
    },
  ): DocumentChunk[] {
    const chunks: DocumentChunk[] = [];
    const { chunkSize, chunkOverlap } = this.config;

    // Simple word-based chunking
    const words = text.split(/\s+/);
    const wordsPerChunk = Math.floor(chunkSize / 4); // Approximate 4 chars per word
    const overlapWords = Math.floor(chunkOverlap / 4);

    let i = 0;
    let chunkIndex = 0;

    while (i < words.length) {
      const chunkWords = words.slice(i, i + wordsPerChunk);
      const content = chunkWords.join(' ');

      chunks.push({
        id: `chunk_${options.documentId}_${chunkIndex}_${randomUUID().slice(0, 8)}`,
        documentId: options.documentId,
        source: options.source,
        platform: options.platform,
        category: options.category,
        content,
        metadata: {
          tags: options.tags,
          version: options.version,
          lastUpdated: new Date().toISOString(),
        },
      });

      i += wordsPerChunk - overlapWords;
      chunkIndex++;
    }

    return chunks;
  }

  /**
   * Convert string to URL-friendly slug
   */
  private slugify(text: string): string {
    return text
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  /**
   * Create CIS Benchmark chunks from structured data
   */
  createCISBenchmarkChunks(benchmark: ParsedCISBenchmark): DocumentChunk[] {
    const documentId = randomUUID();
    const chunks: DocumentChunk[] = [];

    for (const control of benchmark.controls) {
      const content = this.buildCISControlContent({
        id: control.id,
        title: control.title,
        description: control.description,
        rationale: control.rationale,
        audit: control.auditProcedure,
        remediation: control.remediation,
        profileLevel: control.profileLevel,
        section: control.section,
        platform: control.platform,
      });

      chunks.push({
        id: `cis_${control.platform}_${control.id}_${randomUUID().slice(0, 8)}`,
        documentId,
        source: 'cis_benchmark',
        platform: control.platform,
        content,
        metadata: {
          sectionId: control.id,
          sectionTitle: control.title,
          profileLevel: control.profileLevel,
          complianceMappings: control.cisControlsV8?.map((c) => ({
            framework: 'CIS Controls v8',
            controlId: c,
            controlTitle: '',
          })),
          tags: [
            control.platform,
            `cis-${control.profileLevel.toLowerCase()}`,
            control.section,
          ].filter(Boolean),
          version: benchmark.version,
          lastUpdated: benchmark.releaseDate,
        },
      });
    }

    return chunks;
  }

  /**
   * Create Microsoft Security chunks from structured data
   */
  createMicrosoftSecurityChunks(doc: ParsedMicrosoftDoc): DocumentChunk[] {
    const documentId = randomUUID();
    const chunks: DocumentChunk[] = [];

    for (const rec of doc.recommendations) {
      const content = this.buildMicrosoftSecurityContent({
        id: rec.id,
        title: rec.title,
        description: rec.description,
        guidance: rec.implementationGuide,
        severity: rec.severity,
        category: rec.category,
        commands: rec.commands,
        policyReference: rec.policyReference,
      });

      chunks.push({
        id: `ms_${doc.category}_${rec.id}_${randomUUID().slice(0, 8)}`,
        documentId,
        source: 'microsoft_security',
        category: doc.category,
        content,
        metadata: {
          sectionId: rec.id,
          sectionTitle: rec.title,
          severity: rec.severity,
          complianceMappings: rec.complianceMappings,
          tags: ['microsoft', doc.category, rec.severity].filter(Boolean),
          version: doc.version,
          lastUpdated: new Date().toISOString(),
        },
      });
    }

    return chunks;
  }
}
