/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Security RAG Module
 *
 * Provides RAG (Retrieval-Augmented Generation) capabilities for security documentation:
 * - CIS Benchmarks
 * - Microsoft Security documentation
 * - Compliance frameworks (NIST, PCI-DSS, HIPAA, etc.)
 */

// Types
export type {
  CISControl,
  CISPlatform,
  CISProfileLevel,
  ComplianceMapping,
  ComplianceReport,
  ControlStatus,
  DocumentChunk,
  DocumentChunkMetadata,
  HardeningChecklistItem,
  IndexStats,
  IngestionOptions,
  MicrosoftSecurityCategory,
  MicrosoftSecurityRecommendation,
  SecurityDocumentSource,
  SecurityRAGConfig,
  SecurityRAGQuery,
  SecurityRAGResponse,
  SecurityRAGResult,
} from './types.js';

// Services
export { EmbeddingService } from './embedding-service.js';
export { VectorStore } from './vector-store.js';
export { DocumentProcessor } from './document-processor.js';
export { WebFetcher } from './web-fetcher.js';

// Pipeline
export { SecurityRAGPipeline, DEFAULT_RAG_CONFIG } from './rag-pipeline.js';

// Tool
export { CISBenchmarkTool } from './cis-benchmark-tool.js';
export type {
  CISBenchmarkToolParams,
  CISBenchmarkSearchMode,
} from './cis-benchmark-tool.js';
