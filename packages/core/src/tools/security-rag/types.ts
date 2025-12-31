/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Security RAG Types
 *
 * Type definitions for the Security Documentation RAG Pipeline
 * supporting CIS Benchmarks, Microsoft Security Docs, and compliance frameworks.
 */

/**
 * Document source types for security documentation
 */
export type SecurityDocumentSource =
  | 'cis_benchmark'
  | 'microsoft_security'
  | 'nist'
  | 'disa_stig'
  | 'pci_dss'
  | 'hipaa'
  | 'soc2'
  | 'iso27001'
  | 'custom';

/**
 * Operating system/platform types for CIS Benchmarks
 */
export type CISPlatform =
  | 'windows_server_2022'
  | 'windows_server_2019'
  | 'windows_11'
  | 'windows_10'
  | 'ubuntu_22.04'
  | 'ubuntu_20.04'
  | 'rhel_9'
  | 'rhel_8'
  | 'centos_stream_9'
  | 'debian_12'
  | 'debian_11'
  | 'aws'
  | 'azure'
  | 'gcp'
  | 'kubernetes'
  | 'docker'
  | 'nginx'
  | 'apache'
  | 'postgresql'
  | 'mysql'
  | 'mongodb'
  | 'oracle_database'
  | 'microsoft_365'
  | 'cisco_ios';

/**
 * Microsoft security document categories
 */
export type MicrosoftSecurityCategory =
  | 'defender_endpoint'
  | 'defender_cloud'
  | 'defender_identity'
  | 'azure_security_center'
  | 'intune'
  | 'entra_id'
  | 'sentinel'
  | 'purview'
  | 'security_baselines'
  | 'windows_security'
  | 'office_365_security';

/**
 * CIS Benchmark profile levels
 */
export type CISProfileLevel = 'L1' | 'L2';

/**
 * Control/recommendation status
 */
export type ControlStatus =
  | 'pass'
  | 'fail'
  | 'not_applicable'
  | 'manual'
  | 'unknown';

/**
 * Represents a single CIS Benchmark control/recommendation
 */
export interface CISControl {
  /** Control ID (e.g., "1.1.1") */
  id: string;
  /** Control title */
  title: string;
  /** Detailed description */
  description: string;
  /** Rationale for the control */
  rationale: string;
  /** Impact of implementing the control */
  impact: string;
  /** Audit procedure to check compliance */
  auditProcedure: string;
  /** Remediation steps */
  remediation: string;
  /** Profile level (L1 or L2) */
  profileLevel: CISProfileLevel;
  /** Whether this is scored or not */
  scored: boolean;
  /** Platform this control applies to */
  platform: CISPlatform;
  /** Section/category within the benchmark */
  section: string;
  /** Related CIS Controls v8 mappings */
  cisControlsV8?: string[];
  /** Related NIST CSF mappings */
  nistCsf?: string[];
  /** Default value if not configured */
  defaultValue?: string;
  /** Additional references */
  references?: string[];
  /** Tags for categorization */
  tags?: string[];
}

/**
 * Represents a Microsoft security recommendation
 */
export interface MicrosoftSecurityRecommendation {
  /** Unique identifier */
  id: string;
  /** Title of the recommendation */
  title: string;
  /** Detailed description */
  description: string;
  /** Category of the recommendation */
  category: MicrosoftSecurityCategory;
  /** Severity level */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Implementation guidance */
  implementationGuide: string;
  /** PowerShell/CLI commands if applicable */
  commands?: string[];
  /** Azure Policy or Intune profile if applicable */
  policyReference?: string;
  /** Related compliance frameworks */
  complianceMappings?: ComplianceMapping[];
  /** Prerequisites */
  prerequisites?: string[];
  /** Estimated implementation effort */
  effort?: 'low' | 'medium' | 'high';
  /** Product version applicability */
  applicableVersions?: string[];
  /** References and documentation links */
  references?: string[];
}

/**
 * Compliance framework mapping
 */
export interface ComplianceMapping {
  framework: string;
  controlId: string;
  controlTitle: string;
  requirement?: string;
}

/**
 * A document chunk for RAG indexing
 */
export interface DocumentChunk {
  /** Unique chunk identifier */
  id: string;
  /** Source document identifier */
  documentId: string;
  /** Document source type */
  source: SecurityDocumentSource;
  /** Platform if applicable */
  platform?: CISPlatform;
  /** Category if applicable */
  category?: MicrosoftSecurityCategory;
  /** Chunk content text */
  content: string;
  /** Embedding vector (will be populated during indexing) */
  embedding?: number[];
  /** Metadata for filtering */
  metadata: DocumentChunkMetadata;
  /** Token count for the chunk */
  tokenCount?: number;
}

/**
 * Metadata for document chunks
 */
export interface DocumentChunkMetadata {
  /** Section or control ID */
  sectionId?: string;
  /** Section title */
  sectionTitle?: string;
  /** Profile level for CIS */
  profileLevel?: CISProfileLevel;
  /** Severity level */
  severity?: string;
  /** Compliance mappings */
  complianceMappings?: ComplianceMapping[];
  /** Tags for filtering */
  tags?: string[];
  /** Document version */
  version?: string;
  /** Last updated date */
  lastUpdated?: string;
}

/**
 * Search query for the RAG system
 */
export interface SecurityRAGQuery {
  /** Natural language query */
  query: string;
  /** Filter by document source */
  sources?: SecurityDocumentSource[];
  /** Filter by platform */
  platforms?: CISPlatform[];
  /** Filter by Microsoft category */
  categories?: MicrosoftSecurityCategory[];
  /** Filter by profile level */
  profileLevel?: CISProfileLevel;
  /** Filter by compliance framework */
  complianceFramework?: string;
  /** Filter by tags */
  tags?: string[];
  /** Maximum number of results */
  maxResults?: number;
  /** Minimum similarity threshold (0-1) */
  similarityThreshold?: number;
}

/**
 * Search result from RAG query
 */
export interface SecurityRAGResult {
  /** Retrieved chunk */
  chunk: DocumentChunk;
  /** Similarity score (0-1) */
  score: number;
  /** Highlighted/matched content */
  highlights?: string[];
}

/**
 * Aggregated response from RAG system
 */
export interface SecurityRAGResponse {
  /** Original query */
  query: SecurityRAGQuery;
  /** Retrieved results */
  results: SecurityRAGResult[];
  /** Total documents searched */
  totalDocuments: number;
  /** Processing time in ms */
  processingTimeMs: number;
  /** Generated summary/answer if applicable */
  summary?: string;
}

/**
 * Index statistics
 */
export interface IndexStats {
  /** Total number of documents */
  totalDocuments: number;
  /** Total number of chunks */
  totalChunks: number;
  /** Documents by source */
  bySource: Record<SecurityDocumentSource, number>;
  /** Documents by platform */
  byPlatform: Record<string, number>;
  /** Last index update time */
  lastUpdated: string;
  /** Index size in bytes */
  indexSizeBytes: number;
}

/**
 * Configuration for the RAG pipeline
 */
export interface SecurityRAGConfig {
  /** Directory for storing index and documents */
  dataDirectory: string;
  /** Embedding model to use */
  embeddingModel: string;
  /** Chunk size in tokens */
  chunkSize: number;
  /** Chunk overlap in tokens */
  chunkOverlap: number;
  /** Maximum results per query */
  maxResults: number;
  /** Default similarity threshold */
  similarityThreshold: number;
  /** Enable caching */
  enableCache: boolean;
  /** Cache TTL in seconds */
  cacheTtlSeconds: number;
}

/**
 * Document ingestion options
 */
export interface IngestionOptions {
  /** Source type */
  source: SecurityDocumentSource;
  /** Platform for CIS benchmarks */
  platform?: CISPlatform;
  /** Category for Microsoft docs */
  category?: MicrosoftSecurityCategory;
  /** Document version */
  version?: string;
  /** Additional tags */
  tags?: string[];
  /** Force re-indexing even if document exists */
  forceReindex?: boolean;
}

/**
 * Hardening checklist item
 */
export interface HardeningChecklistItem {
  /** Control reference */
  controlId: string;
  /** Check description */
  description: string;
  /** Current status */
  status: ControlStatus;
  /** Remediation if failed */
  remediation?: string;
  /** Priority (1-5, 1 being highest) */
  priority: number;
  /** Automation available */
  automatable: boolean;
  /** Related script/command if automatable */
  automationScript?: string;
}

/**
 * Compliance report
 */
export interface ComplianceReport {
  /** Report title */
  title: string;
  /** Target system/platform */
  platform: CISPlatform | string;
  /** Framework assessed against */
  framework: string;
  /** Assessment date */
  assessmentDate: string;
  /** Overall compliance percentage */
  compliancePercentage: number;
  /** Total controls */
  totalControls: number;
  /** Passed controls */
  passedControls: number;
  /** Failed controls */
  failedControls: number;
  /** Not applicable controls */
  notApplicableControls: number;
  /** Detailed findings */
  findings: HardeningChecklistItem[];
  /** Executive summary */
  executiveSummary: string;
  /** Recommendations */
  recommendations: string[];
}
