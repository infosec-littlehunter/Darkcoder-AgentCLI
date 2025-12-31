/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { SecurityRAGPipeline, DEFAULT_RAG_CONFIG } from './rag-pipeline.js';
import type { CISPlatform, MicrosoftSecurityCategory } from './types.js';
import * as path from 'node:path';
import * as os from 'node:os';

describe('SecurityRAGPipeline', () => {
  let pipeline: SecurityRAGPipeline;

  beforeAll(async () => {
    // Use a temp directory for testing
    const testDataDir = path.join(os.tmpdir(), 'darkcoder-security-rag-test');
    pipeline = new SecurityRAGPipeline({
      ...DEFAULT_RAG_CONFIG,
      dataDirectory: testDataDir,
    });
    await pipeline.initialize();
  });

  describe('built-in data ingestion', () => {
    it('should ingest Ubuntu 22.04 CIS Benchmark', async () => {
      const platform: CISPlatform = 'ubuntu_22.04';
      const chunks = await pipeline.ingestCISBenchmark(platform, 'builtin');
      expect(chunks).toBeGreaterThan(0);
    });

    it('should ingest Windows Server 2022 CIS Benchmark', async () => {
      const platform: CISPlatform = 'windows_server_2022';
      const chunks = await pipeline.ingestCISBenchmark(platform, 'builtin');
      expect(chunks).toBeGreaterThan(0);
    });

    it('should ingest Microsoft Defender for Endpoint docs', async () => {
      const category: MicrosoftSecurityCategory = 'defender_endpoint';
      const chunks = await pipeline.ingestMicrosoftSecurityDocs(
        category,
        'builtin',
      );
      expect(chunks).toBeGreaterThan(0);
    });

    it('should ingest Microsoft Intune docs', async () => {
      const category: MicrosoftSecurityCategory = 'intune';
      const chunks = await pipeline.ingestMicrosoftSecurityDocs(
        category,
        'builtin',
      );
      expect(chunks).toBeGreaterThan(0);
    });
  });

  describe('search functionality', () => {
    it('should search for SSH hardening', async () => {
      const response = await pipeline.search({
        query: 'SSH hardening configuration',
        maxResults: 5,
      });
      expect(response.results).toBeDefined();
      expect(response.processingTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should search for password policy', async () => {
      const response = await pipeline.search({
        query: 'password policy minimum length',
        maxResults: 5,
      });
      expect(response.results).toBeDefined();
    });

    it('should filter by platform', async () => {
      const response = await pipeline.search({
        query: 'firewall configuration',
        platforms: ['ubuntu_22.04'],
        maxResults: 5,
      });
      expect(response.results).toBeDefined();
      for (const result of response.results) {
        expect(result.chunk.platform).toBe('ubuntu_22.04');
      }
    });

    it('should filter by source', async () => {
      const response = await pipeline.search({
        query: 'security configuration',
        sources: ['microsoft_security'],
        maxResults: 5,
      });
      expect(response.results).toBeDefined();
      for (const result of response.results) {
        expect(result.chunk.source).toBe('microsoft_security');
      }
    });
  });

  describe('hardening recommendations', () => {
    it('should get Ubuntu hardening recommendations', async () => {
      const response = await pipeline.getHardeningRecommendations(
        'ubuntu_22.04',
        'L1',
      );
      expect(response.results).toBeDefined();
      expect(response.results.length).toBeGreaterThan(0);
    });

    it('should get Windows Server hardening recommendations', async () => {
      const response = await pipeline.getHardeningRecommendations(
        'windows_server_2022',
        'L1',
      );
      expect(response.results).toBeDefined();
      expect(response.results.length).toBeGreaterThan(0);
    });
  });

  describe('compliance guidance', () => {
    it('should get NIST CSF guidance', async () => {
      const response = await pipeline.getComplianceGuidance('NIST CSF');
      expect(response.results).toBeDefined();
    });

    it('should get CIS Controls v8 guidance', async () => {
      const response = await pipeline.getComplianceGuidance('CIS Controls v8');
      expect(response.results).toBeDefined();
    });
  });

  describe('Microsoft security guidance', () => {
    it('should get Defender for Endpoint guidance', async () => {
      const response =
        await pipeline.getMicrosoftSecurityGuidance('defender_endpoint');
      expect(response.results).toBeDefined();
      expect(response.results.length).toBeGreaterThan(0);
    });

    it('should get Intune guidance', async () => {
      const response = await pipeline.getMicrosoftSecurityGuidance('intune');
      expect(response.results).toBeDefined();
      expect(response.results.length).toBeGreaterThan(0);
    });
  });

  describe('index statistics', () => {
    it('should return index stats', () => {
      const stats = pipeline.getStats();
      expect(stats.totalChunks).toBeGreaterThan(0);
      expect(stats.bySource).toBeDefined();
      expect(stats.byPlatform).toBeDefined();
    });
  });
});
