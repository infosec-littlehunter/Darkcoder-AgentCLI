/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Web Fetcher for Security RAG Pipeline
 *
 * Fetches security documentation from external sources:
 * - CIS Benchmarks website
 * - Microsoft Learn / Security documentation
 * - NIST publications
 * - Other security documentation sources
 */

import { randomUUID } from 'node:crypto';
import type {
  CISPlatform,
  DocumentChunk,
  MicrosoftSecurityCategory,
  SecurityDocumentSource,
} from './types.js';

const FETCH_TIMEOUT_MS = 30000;

/**
 * Fetch response with parsed content
 */
interface FetchedDocument {
  url: string;
  title: string;
  content: string;
  contentType: 'html' | 'json' | 'markdown' | 'text';
  fetchedAt: string;
}

/**
 * Microsoft Learn article structure
 */
interface MicrosoftLearnArticle {
  title: string;
  description: string;
  content: string;
  url: string;
  category: MicrosoftSecurityCategory;
}

/**
 * CIS Benchmark info from website
 */
interface CISBenchmarkInfo {
  title: string;
  platform: CISPlatform;
  version: string;
  description: string;
  downloadUrl?: string;
}

/**
 * Web Fetcher class for retrieving security documentation
 */
export class WebFetcher {
  private userAgent =
    'DarkCoder-SecurityRAG/1.0 (Security Documentation Fetcher)';

  /**
   * Fetch content from a URL with timeout
   */
  private async fetchWithTimeout(
    url: string,
    options: RequestInit = {},
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'User-Agent': this.userAgent,
          Accept:
            'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,text/plain;q=0.8',
          ...options.headers,
        },
      });
      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Fetch and parse HTML content
   */
  async fetchHtml(url: string): Promise<FetchedDocument> {
    const response = await this.fetchWithTimeout(url);

    if (!response.ok) {
      throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }

    const html = await response.text();
    const content = this.extractTextFromHtml(html);
    const title = this.extractTitleFromHtml(html);

    return {
      url,
      title,
      content,
      contentType: 'html',
      fetchedAt: new Date().toISOString(),
    };
  }

  /**
   * Extract text content from HTML
   */
  private extractTextFromHtml(html: string): string {
    // Remove script and style tags
    let text = html.replace(
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      '',
    );
    text = text.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');

    // Remove HTML comments
    text = text.replace(/<!--[\s\S]*?-->/g, '');

    // Extract main content areas (common patterns)
    const mainContentPatterns = [
      /<main[^>]*>([\s\S]*?)<\/main>/gi,
      /<article[^>]*>([\s\S]*?)<\/article>/gi,
      /<div[^>]*class="[^"]*content[^"]*"[^>]*>([\s\S]*?)<\/div>/gi,
      /<div[^>]*id="[^"]*content[^"]*"[^>]*>([\s\S]*?)<\/div>/gi,
    ];

    let mainContent = '';
    for (const pattern of mainContentPatterns) {
      const matches = text.matchAll(pattern);
      for (const match of matches) {
        if (match[1]) {
          mainContent += match[1] + '\n';
        }
      }
    }

    // If no main content found, use body
    if (!mainContent) {
      const bodyMatch = text.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
      mainContent = bodyMatch ? bodyMatch[1] || text : text;
    }

    // Convert HTML entities
    mainContent = mainContent
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");

    // Remove remaining HTML tags
    mainContent = mainContent.replace(/<[^>]+>/g, ' ');

    // Clean up whitespace
    mainContent = mainContent
      .replace(/\s+/g, ' ')
      .replace(/\n\s*\n/g, '\n\n')
      .trim();

    return mainContent;
  }

  /**
   * Extract title from HTML
   */
  private extractTitleFromHtml(html: string): string {
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    if (titleMatch && titleMatch[1]) {
      return titleMatch[1].trim();
    }

    const h1Match = html.match(/<h1[^>]*>([^<]+)<\/h1>/i);
    if (h1Match && h1Match[1]) {
      return h1Match[1].trim();
    }

    return 'Untitled';
  }

  /**
   * Fetch Microsoft Learn documentation
   */
  async fetchMicrosoftLearn(
    url: string,
    category: MicrosoftSecurityCategory,
  ): Promise<MicrosoftLearnArticle> {
    const doc = await this.fetchHtml(url);

    return {
      title: doc.title,
      description: doc.content.slice(0, 500),
      content: doc.content,
      url,
      category,
    };
  }

  /**
   * Fetch multiple Microsoft Learn articles
   */
  async fetchMicrosoftLearnArticles(
    urls: string[],
    category: MicrosoftSecurityCategory,
  ): Promise<MicrosoftLearnArticle[]> {
    const articles: MicrosoftLearnArticle[] = [];

    for (const url of urls) {
      try {
        const article = await this.fetchMicrosoftLearn(url, category);
        articles.push(article);
      } catch (error) {
        console.error(`Failed to fetch ${url}:`, error);
      }
    }

    return articles;
  }

  /**
   * Convert fetched Microsoft Learn articles to document chunks
   */
  createMicrosoftLearnChunks(
    articles: MicrosoftLearnArticle[],
  ): DocumentChunk[] {
    const chunks: DocumentChunk[] = [];
    const documentId = randomUUID();

    for (const article of articles) {
      // Split content into sections
      const sections = this.splitContentIntoSections(article.content);

      for (let i = 0; i < sections.length; i++) {
        const section = sections[i]!;
        if (section.content.length < 100) continue;

        chunks.push({
          id: `mslearn_${article.category}_${randomUUID().slice(0, 8)}`,
          documentId,
          source: 'microsoft_security',
          category: article.category,
          content: `# ${article.title}\n\n${section.title ? `## ${section.title}\n\n` : ''}${section.content}`,
          metadata: {
            sectionId: `section_${i}`,
            sectionTitle: section.title || article.title,
            tags: ['microsoft', 'learn', article.category],
            lastUpdated: new Date().toISOString(),
          },
        });
      }
    }

    return chunks;
  }

  /**
   * Split content into logical sections
   */
  private splitContentIntoSections(
    content: string,
  ): Array<{ title?: string; content: string }> {
    const sections: Array<{ title?: string; content: string }> = [];

    // Split by common header patterns
    const parts = content.split(/(?=\n(?:#+|[A-Z][^a-z]*:)\s)/);

    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.length < 50) continue;

      // Try to extract title
      const headerMatch = trimmed.match(/^(#+\s*)?([^\n]+)\n([\s\S]*)/);
      if (headerMatch) {
        sections.push({
          title: headerMatch[2]?.trim(),
          content: headerMatch[3]?.trim() || trimmed,
        });
      } else {
        sections.push({ content: trimmed });
      }
    }

    return sections.length > 0 ? sections : [{ content }];
  }

  /**
   * Get known Microsoft Learn security documentation URLs
   */
  getMicrosoftLearnSecurityUrls(): Record<MicrosoftSecurityCategory, string[]> {
    return {
      defender_endpoint: [
        'https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint',
        'https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints',
        'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction',
        'https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders',
        'https://learn.microsoft.com/en-us/defender-endpoint/network-protection',
        'https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection',
        'https://learn.microsoft.com/en-us/defender-endpoint/web-protection-overview',
      ],
      defender_cloud: [
        'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction',
        'https://learn.microsoft.com/en-us/azure/defender-for-cloud/security-policy-concept',
        'https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference',
      ],
      defender_identity: [
        'https://learn.microsoft.com/en-us/defender-for-identity/what-is',
        'https://learn.microsoft.com/en-us/defender-for-identity/configure-sensor-settings',
      ],
      azure_security_center: [
        'https://learn.microsoft.com/en-us/azure/security-center/security-center-introduction',
        'https://learn.microsoft.com/en-us/azure/security/fundamentals/overview',
        'https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns',
      ],
      intune: [
        'https://learn.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune',
        'https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines',
        'https://learn.microsoft.com/en-us/mem/intune/protect/endpoint-security-policy',
        'https://learn.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows',
      ],
      entra_id: [
        'https://learn.microsoft.com/en-us/entra/fundamentals/whatis',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview',
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks',
      ],
      sentinel: [
        'https://learn.microsoft.com/en-us/azure/sentinel/overview',
        'https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in',
        'https://learn.microsoft.com/en-us/azure/sentinel/hunting',
      ],
      purview: [
        'https://learn.microsoft.com/en-us/purview/purview',
        'https://learn.microsoft.com/en-us/purview/data-loss-prevention-policies',
      ],
      security_baselines: [
        'https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines',
        'https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines',
      ],
      windows_security: [
        'https://learn.microsoft.com/en-us/windows/security/',
        'https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/',
      ],
      office_365_security: [
        'https://learn.microsoft.com/en-us/defender-office-365/defender-for-office-365',
        'https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about',
        'https://learn.microsoft.com/en-us/defender-office-365/safe-links-about',
      ],
    };
  }

  /**
   * Get CIS Benchmark documentation URLs (info pages, not downloads)
   */
  getCISBenchmarkInfoUrls(): Record<string, CISBenchmarkInfo> {
    return {
      ubuntu_22_04: {
        title: 'CIS Ubuntu Linux 22.04 LTS Benchmark',
        platform: 'ubuntu_22.04',
        version: 'v2.0.0',
        description:
          'Security configuration recommendations for Ubuntu Linux 22.04 LTS systems.',
      },
      ubuntu_20_04: {
        title: 'CIS Ubuntu Linux 20.04 LTS Benchmark',
        platform: 'ubuntu_20.04',
        version: 'v2.0.1',
        description:
          'Security configuration recommendations for Ubuntu Linux 20.04 LTS systems.',
      },
      rhel_9: {
        title: 'CIS Red Hat Enterprise Linux 9 Benchmark',
        platform: 'rhel_9',
        version: 'v1.0.0',
        description:
          'Security configuration recommendations for RHEL 9 systems.',
      },
      rhel_8: {
        title: 'CIS Red Hat Enterprise Linux 8 Benchmark',
        platform: 'rhel_8',
        version: 'v3.0.0',
        description:
          'Security configuration recommendations for RHEL 8 systems.',
      },
      windows_server_2022: {
        title: 'CIS Microsoft Windows Server 2022 Benchmark',
        platform: 'windows_server_2022',
        version: 'v2.0.0',
        description:
          'Security configuration recommendations for Windows Server 2022.',
      },
      windows_server_2019: {
        title: 'CIS Microsoft Windows Server 2019 Benchmark',
        platform: 'windows_server_2019',
        version: 'v2.0.0',
        description:
          'Security configuration recommendations for Windows Server 2019.',
      },
      kubernetes: {
        title: 'CIS Kubernetes Benchmark',
        platform: 'kubernetes',
        version: 'v1.8.0',
        description:
          'Security configuration recommendations for Kubernetes clusters.',
      },
      docker: {
        title: 'CIS Docker Benchmark',
        platform: 'docker',
        version: 'v1.6.0',
        description:
          'Security configuration recommendations for Docker containers and hosts.',
      },
      aws: {
        title: 'CIS Amazon Web Services Foundations Benchmark',
        platform: 'aws',
        version: 'v2.0.0',
        description:
          'Security configuration recommendations for AWS cloud environments.',
      },
      azure: {
        title: 'CIS Microsoft Azure Foundations Benchmark',
        platform: 'azure',
        version: 'v2.0.0',
        description:
          'Security configuration recommendations for Azure cloud environments.',
      },
      gcp: {
        title: 'CIS Google Cloud Platform Foundation Benchmark',
        platform: 'gcp',
        version: 'v2.0.0',
        description:
          'Security configuration recommendations for GCP cloud environments.',
      },
    };
  }

  /**
   * Fetch generic documentation from URL
   */
  async fetchGenericDocumentation(url: string): Promise<FetchedDocument> {
    return this.fetchHtml(url);
  }

  /**
   * Convert generic fetched document to chunks
   */
  createGenericDocumentChunks(
    doc: FetchedDocument,
    source: SecurityDocumentSource,
    tags: string[] = [],
  ): DocumentChunk[] {
    const chunks: DocumentChunk[] = [];
    const documentId = randomUUID();
    const sections = this.splitContentIntoSections(doc.content);

    for (let i = 0; i < sections.length; i++) {
      const section = sections[i]!;
      if (section.content.length < 100) continue;

      chunks.push({
        id: `doc_${source}_${randomUUID().slice(0, 8)}`,
        documentId,
        source,
        content: section.title
          ? `# ${section.title}\n\n${section.content}`
          : section.content,
        metadata: {
          sectionId: `section_${i}`,
          sectionTitle: section.title || doc.title,
          tags: [...tags, source],
          lastUpdated: doc.fetchedAt,
        },
      });
    }

    return chunks;
  }
}
