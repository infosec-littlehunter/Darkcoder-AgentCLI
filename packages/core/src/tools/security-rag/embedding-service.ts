/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Embedding Service for Security RAG Pipeline
 *
 * Provides vector embeddings for document chunks using various providers:
 * - OpenAI embeddings
 * - DashScope/Qwen embeddings
 * - Local embeddings (e.g., sentence-transformers)
 */

import type { SecurityRAGConfig } from './types.js';

/**
 * Embedding provider interface
 */
export interface EmbeddingProvider {
  /** Provider name */
  name: string;
  /** Embedding dimension */
  dimension: number;
  /** Generate embedding for a single text */
  embed(text: string): Promise<number[]>;
  /** Generate embeddings for multiple texts (batched) */
  embedBatch(texts: string[]): Promise<number[][]>;
}

/**
 * OpenAI-compatible embedding provider
 */
export class OpenAIEmbeddingProvider implements EmbeddingProvider {
  readonly name = 'openai';
  readonly dimension = 1536; // text-embedding-3-small

  constructor(
    private readonly apiKey: string,
    private readonly model: string = 'text-embedding-3-small',
    private readonly baseUrl: string = 'https://api.openai.com/v1',
  ) {}

  async embed(text: string): Promise<number[]> {
    const embeddings = await this.embedBatch([text]);
    return embeddings[0] ?? [];
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    const response = await fetch(`${this.baseUrl}/embeddings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        input: texts,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI embedding failed: ${error}`);
    }

    const data = (await response.json()) as {
      data: Array<{ embedding: number[]; index: number }>;
    };

    // Sort by index to maintain order
    return data.data.sort((a, b) => a.index - b.index).map((d) => d.embedding);
  }
}

/**
 * DashScope/Qwen embedding provider
 */
export class DashScopeEmbeddingProvider implements EmbeddingProvider {
  readonly name = 'dashscope';
  readonly dimension = 1536; // text-embedding-v2

  constructor(
    private readonly apiKey: string,
    private readonly model: string = 'text-embedding-v2',
    private readonly baseUrl: string = 'https://dashscope.aliyuncs.com/api/v1',
  ) {}

  async embed(text: string): Promise<number[]> {
    const embeddings = await this.embedBatch([text]);
    return embeddings[0] ?? [];
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    const response = await fetch(
      `${this.baseUrl}/services/embeddings/text-embedding/text-embedding`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: this.model,
          input: {
            texts,
          },
          parameters: {
            text_type: 'document',
          },
        }),
      },
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`DashScope embedding failed: ${error}`);
    }

    const data = (await response.json()) as {
      output: {
        embeddings: Array<{ text_index: number; embedding: number[] }>;
      };
    };

    // Sort by text_index to maintain order
    return data.output.embeddings
      .sort((a, b) => a.text_index - b.text_index)
      .map((d) => d.embedding);
  }
}

/**
 * Local embedding provider using simple TF-IDF-like approach
 * Fallback when no API is available
 */
export class LocalEmbeddingProvider implements EmbeddingProvider {
  readonly name = 'local';
  readonly dimension = 384;

  private vocabulary: Map<string, number> = new Map();
  private idf: Map<string, number> = new Map();

  constructor() {
    // Initialize with common security terms for better embeddings
    this.initializeSecurityVocabulary();
  }

  private initializeSecurityVocabulary(): void {
    const securityTerms = [
      'security',
      'vulnerability',
      'exploit',
      'cve',
      'patch',
      'update',
      'firewall',
      'antivirus',
      'malware',
      'ransomware',
      'phishing',
      'authentication',
      'authorization',
      'encryption',
      'decryption',
      'password',
      'credential',
      'token',
      'certificate',
      'ssl',
      'tls',
      'audit',
      'log',
      'monitor',
      'alert',
      'incident',
      'response',
      'compliance',
      'policy',
      'procedure',
      'control',
      'baseline',
      'hardening',
      'configuration',
      'registry',
      'service',
      'process',
      'network',
      'port',
      'protocol',
      'tcp',
      'udp',
      'http',
      'https',
      'user',
      'group',
      'permission',
      'privilege',
      'admin',
      'root',
      'windows',
      'linux',
      'ubuntu',
      'rhel',
      'centos',
      'debian',
      'azure',
      'aws',
      'gcp',
      'cloud',
      'container',
      'kubernetes',
      'docker',
      'defender',
      'sentinel',
      'intune',
      'entra',
      'active',
      'directory',
      'cis',
      'nist',
      'stig',
      'pci',
      'hipaa',
      'soc',
      'iso',
      'gdpr',
      'remediation',
      'mitigation',
      'risk',
      'threat',
      'attack',
      'defense',
    ];

    securityTerms.forEach((term, index) => {
      this.vocabulary.set(term, index);
      this.idf.set(term, Math.log(100 / (index + 1))); // Simple IDF approximation
    });
  }

  async embed(text: string): Promise<number[]> {
    return this.computeEmbedding(text);
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    return texts.map((text) => this.computeEmbedding(text));
  }

  private computeEmbedding(text: string): number[] {
    const embedding = new Array<number>(this.dimension).fill(0);
    const words = text.toLowerCase().split(/\W+/);
    const wordCounts = new Map<string, number>();

    // Count word frequencies
    for (const word of words) {
      wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
    }

    // Compute TF-IDF weighted embedding
    for (const [word, count] of wordCounts) {
      const vocabIndex = this.vocabulary.get(word);
      if (vocabIndex !== undefined && vocabIndex < this.dimension) {
        const tf = count / words.length;
        const idfValue = this.idf.get(word) || 1;
        embedding[vocabIndex] = tf * idfValue;
      }

      // Also use character n-grams for unknown words
      if (vocabIndex === undefined) {
        const hash = this.hashString(word);
        const index = Math.abs(hash) % this.dimension;
        embedding[index] += 0.1;
      }
    }

    // Normalize the embedding
    const norm = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
    if (norm > 0) {
      for (let i = 0; i < embedding.length; i++) {
        embedding[i] = embedding[i]! / norm;
      }
    }

    return embedding;
  }

  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return hash;
  }
}

/**
 * Embedding service that manages multiple providers
 */
export class EmbeddingService {
  private provider: EmbeddingProvider;

  constructor(config: SecurityRAGConfig) {
    this.provider = this.createProvider(config);
  }

  private createProvider(config: SecurityRAGConfig): EmbeddingProvider {
    const model = config.embeddingModel;

    // Check for OpenAI API key
    const openaiKey = process.env['OPENAI_API_KEY'];
    if (openaiKey && model.includes('openai')) {
      return new OpenAIEmbeddingProvider(openaiKey, 'text-embedding-3-small');
    }

    // Check for DashScope API key
    const dashscopeKey = process.env['DASHSCOPE_API_KEY'];
    if (dashscopeKey && model.includes('dashscope')) {
      return new DashScopeEmbeddingProvider(dashscopeKey, 'text-embedding-v2');
    }

    // Fallback to local embeddings
    return new LocalEmbeddingProvider();
  }

  /**
   * Get the current provider name
   */
  getProviderName(): string {
    return this.provider.name;
  }

  /**
   * Get the embedding dimension
   */
  getDimension(): number {
    return this.provider.dimension;
  }

  /**
   * Generate embedding for a single text
   */
  async embed(text: string): Promise<number[]> {
    return this.provider.embed(text);
  }

  /**
   * Generate embeddings for multiple texts
   */
  async embedBatch(
    texts: string[],
    batchSize: number = 100,
  ): Promise<number[][]> {
    const results: number[][] = [];

    for (let i = 0; i < texts.length; i += batchSize) {
      const batch = texts.slice(i, i + batchSize);
      const embeddings = await this.provider.embedBatch(batch);
      results.push(...embeddings);
    }

    return results;
  }

  /**
   * Compute cosine similarity between two embeddings
   */
  cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) {
      throw new Error('Embeddings must have the same dimension');
    }

    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i]! * b[i]!;
      normA += a[i]! * a[i]!;
      normB += b[i]! * b[i]!;
    }

    const denominator = Math.sqrt(normA) * Math.sqrt(normB);
    return denominator === 0 ? 0 : dotProduct / denominator;
  }
}
