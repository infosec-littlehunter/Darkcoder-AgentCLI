/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Vector Store for Security RAG Pipeline
 *
 * In-memory vector store with persistence support for storing
 * and searching document embeddings efficiently.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type {
  DocumentChunk,
  IndexStats,
  SecurityDocumentSource,
  SecurityRAGConfig,
  SecurityRAGQuery,
  SecurityRAGResult,
} from './types.js';
import { EmbeddingService } from './embedding-service.js';

/**
 * Simple in-memory vector index entry
 */
interface VectorIndexEntry {
  id: string;
  embedding: number[];
  chunkId: string;
}

/**
 * Persisted index format
 */
interface PersistedIndex {
  version: string;
  createdAt: string;
  updatedAt: string;
  dimension: number;
  entries: VectorIndexEntry[];
  chunks: DocumentChunk[];
}

/**
 * Vector Store implementation using HNSW-like approach
 * with persistence support
 */
export class VectorStore {
  private chunks: Map<string, DocumentChunk> = new Map();
  private index: VectorIndexEntry[] = [];
  private embeddingService: EmbeddingService;
  private config: SecurityRAGConfig;
  private isDirty: boolean = false;

  constructor(config: SecurityRAGConfig) {
    this.config = config;
    this.embeddingService = new EmbeddingService(config);
  }

  /**
   * Initialize the vector store, loading from disk if available
   */
  async initialize(): Promise<void> {
    const indexPath = this.getIndexPath();

    try {
      await fs.access(indexPath);
      await this.loadFromDisk();
    } catch {
      // Index doesn't exist, start fresh
      console.log('No existing index found, starting fresh');
    }
  }

  /**
   * Get the path to the index file
   */
  private getIndexPath(): string {
    return path.join(this.config.dataDirectory, 'security-rag-index.json');
  }

  /**
   * Load index from disk
   */
  private async loadFromDisk(): Promise<void> {
    const indexPath = this.getIndexPath();
    const data = await fs.readFile(indexPath, 'utf-8');
    const persisted = JSON.parse(data) as PersistedIndex;

    this.index = persisted.entries;

    for (const chunk of persisted.chunks) {
      this.chunks.set(chunk.id, chunk);
    }

    console.log(`Loaded ${this.chunks.size} chunks from index`);
  }

  /**
   * Save index to disk
   */
  async saveToDisk(): Promise<void> {
    if (!this.isDirty) {
      return;
    }

    const indexPath = this.getIndexPath();

    // Ensure directory exists
    await fs.mkdir(path.dirname(indexPath), { recursive: true });

    const persisted: PersistedIndex = {
      version: '1.0',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      dimension: this.embeddingService.getDimension(),
      entries: this.index,
      chunks: Array.from(this.chunks.values()),
    };

    await fs.writeFile(indexPath, JSON.stringify(persisted, null, 2));
    this.isDirty = false;

    console.log(`Saved ${this.chunks.size} chunks to index`);
  }

  /**
   * Add a document chunk to the store
   */
  async addChunk(chunk: DocumentChunk): Promise<void> {
    // Check if chunk already exists
    if (this.chunks.has(chunk.id)) {
      return;
    }

    // Generate embedding if not provided
    if (!chunk.embedding) {
      chunk.embedding = await this.embeddingService.embed(chunk.content);
    }

    // Store chunk
    this.chunks.set(chunk.id, chunk);

    // Add to index
    this.index.push({
      id: `idx_${this.index.length}`,
      embedding: chunk.embedding,
      chunkId: chunk.id,
    });

    this.isDirty = true;
  }

  /**
   * Add multiple chunks in batch
   */
  async addChunks(chunks: DocumentChunk[]): Promise<void> {
    // Filter out existing chunks
    const newChunks = chunks.filter((c) => !this.chunks.has(c.id));

    if (newChunks.length === 0) {
      return;
    }

    // Generate embeddings for chunks without them
    const chunksNeedingEmbeddings = newChunks.filter((c) => !c.embedding);
    if (chunksNeedingEmbeddings.length > 0) {
      const texts = chunksNeedingEmbeddings.map((c) => c.content);
      const embeddings = await this.embeddingService.embedBatch(texts);

      chunksNeedingEmbeddings.forEach((chunk, i) => {
        chunk.embedding = embeddings[i];
      });
    }

    // Add all chunks
    for (const chunk of newChunks) {
      this.chunks.set(chunk.id, chunk);

      this.index.push({
        id: `idx_${this.index.length}`,
        embedding: chunk.embedding!,
        chunkId: chunk.id,
      });
    }

    this.isDirty = true;
  }

  /**
   * Search for similar chunks
   */
  async search(query: SecurityRAGQuery): Promise<SecurityRAGResult[]> {
    // Generate query embedding
    const queryEmbedding = await this.embeddingService.embed(query.query);

    // Score all chunks
    const scored: Array<{ chunkId: string; score: number }> = [];

    for (const entry of this.index) {
      const chunk = this.chunks.get(entry.chunkId);
      if (!chunk) continue;

      // Apply filters
      if (!this.matchesFilters(chunk, query)) {
        continue;
      }

      const score = this.embeddingService.cosineSimilarity(
        queryEmbedding,
        entry.embedding,
      );

      // Apply threshold
      if (
        score >= (query.similarityThreshold ?? this.config.similarityThreshold)
      ) {
        scored.push({ chunkId: entry.chunkId, score });
      }
    }

    // Sort by score descending
    scored.sort((a, b) => b.score - a.score);

    // Take top results
    const maxResults = query.maxResults ?? this.config.maxResults;
    const topResults = scored.slice(0, maxResults);

    // Build results
    return topResults.map(({ chunkId, score }) => ({
      chunk: this.chunks.get(chunkId)!,
      score,
      highlights: this.extractHighlights(
        this.chunks.get(chunkId)!,
        query.query,
      ),
    }));
  }

  /**
   * Check if a chunk matches the query filters
   */
  private matchesFilters(
    chunk: DocumentChunk,
    query: SecurityRAGQuery,
  ): boolean {
    // Source filter
    if (query.sources && query.sources.length > 0) {
      if (!query.sources.includes(chunk.source)) {
        return false;
      }
    }

    // Platform filter
    if (query.platforms && query.platforms.length > 0) {
      if (!chunk.platform || !query.platforms.includes(chunk.platform)) {
        return false;
      }
    }

    // Category filter
    if (query.categories && query.categories.length > 0) {
      if (!chunk.category || !query.categories.includes(chunk.category)) {
        return false;
      }
    }

    // Profile level filter
    if (query.profileLevel) {
      if (chunk.metadata.profileLevel !== query.profileLevel) {
        return false;
      }
    }

    // Compliance framework filter
    if (query.complianceFramework) {
      const hasFramework = chunk.metadata.complianceMappings?.some(
        (m) =>
          m.framework.toLowerCase() ===
          query.complianceFramework?.toLowerCase(),
      );
      if (!hasFramework) {
        return false;
      }
    }

    // Tags filter
    if (query.tags && query.tags.length > 0) {
      const chunkTags = chunk.metadata.tags || [];
      const hasMatchingTag = query.tags.some((t) =>
        chunkTags.some((ct) => ct.toLowerCase().includes(t.toLowerCase())),
      );
      if (!hasMatchingTag) {
        return false;
      }
    }

    return true;
  }

  /**
   * Extract highlights from content matching the query
   */
  private extractHighlights(chunk: DocumentChunk, query: string): string[] {
    const highlights: string[] = [];
    const queryTerms = query.toLowerCase().split(/\s+/);
    const sentences = chunk.content.split(/[.!?]+/);

    for (const sentence of sentences) {
      const lowerSentence = sentence.toLowerCase();
      const matchCount = queryTerms.filter((term) =>
        lowerSentence.includes(term),
      ).length;

      if (matchCount >= Math.ceil(queryTerms.length / 2)) {
        highlights.push(sentence.trim());
        if (highlights.length >= 3) break;
      }
    }

    return highlights;
  }

  /**
   * Get a chunk by ID
   */
  getChunk(id: string): DocumentChunk | undefined {
    return this.chunks.get(id);
  }

  /**
   * Delete a chunk by ID
   */
  deleteChunk(id: string): boolean {
    if (!this.chunks.has(id)) {
      return false;
    }

    this.chunks.delete(id);
    this.index = this.index.filter((e) => e.chunkId !== id);
    this.isDirty = true;

    return true;
  }

  /**
   * Delete all chunks from a specific source
   */
  deleteBySource(source: SecurityDocumentSource): number {
    const toDelete: string[] = [];

    for (const [id, chunk] of this.chunks) {
      if (chunk.source === source) {
        toDelete.push(id);
      }
    }

    for (const id of toDelete) {
      this.deleteChunk(id);
    }

    return toDelete.length;
  }

  /**
   * Get index statistics
   */
  getStats(): IndexStats {
    const bySource: Record<SecurityDocumentSource, number> = {} as Record<
      SecurityDocumentSource,
      number
    >;
    const byPlatform: Record<string, number> = {};

    for (const chunk of this.chunks.values()) {
      // Count by source
      bySource[chunk.source] = (bySource[chunk.source] || 0) + 1;

      // Count by platform
      if (chunk.platform) {
        byPlatform[chunk.platform] = (byPlatform[chunk.platform] || 0) + 1;
      }
    }

    // Estimate index size
    const indexSizeBytes =
      this.index.length * (this.embeddingService.getDimension() * 4 + 100); // 4 bytes per float + overhead

    return {
      totalDocuments: new Set(
        Array.from(this.chunks.values()).map((c) => c.documentId),
      ).size,
      totalChunks: this.chunks.size,
      bySource,
      byPlatform,
      lastUpdated: new Date().toISOString(),
      indexSizeBytes,
    };
  }

  /**
   * Clear all data from the store
   */
  clear(): void {
    this.chunks.clear();
    this.index = [];
    this.isDirty = true;
  }
}
