/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * RE State Manager - Persistent state for large binary analysis
 *
 * Solves the problem of LLM context limits when analyzing large binaries
 * by maintaining persistent state across analysis sessions.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { createHash } from 'node:crypto';

interface FunctionInfo {
  address: string;
  name?: string;
  score: number;
  reason: string;
  analyzed: boolean;
  decompiled?: string;
  notes?: string;
  tags?: string[];
}

interface ComparisonPoint {
  address: string;
  instruction: string;
  constant?: string;
  notes?: string;
}

interface DecodedString {
  address: string;
  original: string;
  decoded: string;
  encoding: 'xor' | 'base64' | 'custom' | 'none';
  key?: string;
}

interface AttackSurface {
  inputPoints: Array<{
    type: 'stdin' | 'file' | 'network' | 'args' | 'env';
    address: string;
    function: string;
  }>;
  validators: Array<{
    address: string;
    type: 'comparison' | 'checksum' | 'crypto' | 'custom';
    notes: string;
  }>;
  outputPoints: Array<{
    type: 'stdout' | 'file' | 'network';
    address: string;
  }>;
}

export interface REAnalysisState {
  binaryPath: string;
  binaryHash: string;
  sessionName: string;
  created: string;
  lastUpdated: string;

  // Binary metadata
  metadata: {
    arch?: string;
    os?: string;
    size?: number;
    stripped?: boolean;
    packer?: string;
    compiler?: string;
  };

  // Analysis progress
  criticalFunctions: FunctionInfo[];
  comparisonPoints: ComparisonPoint[];
  decodedStrings: DecodedString[];
  attackSurface?: AttackSurface;

  // Custom notes and findings
  notes: string[];
  tags: string[];

  // Progress tracking
  analysisPhase:
    | 'initial'
    | 'triage'
    | 'discovery'
    | 'deep_dive'
    | 'exploitation'
    | 'complete';
  completedSteps: string[];
}

export class REStateManager {
  private stateDir: string;
  private state: REAnalysisState | null = null;

  constructor(workspaceRoot: string = process.cwd()) {
    this.stateDir = path.join(workspaceRoot, '.darkcoder', 're_analysis');
  }

  /**
   * Initialize or load existing analysis state
   */
  async initState(
    binaryPath: string,
    sessionName?: string,
  ): Promise<REAnalysisState> {
    const binaryHash = await this.hashFile(binaryPath);
    const name =
      sessionName || path.basename(binaryPath, path.extname(binaryPath));
    const stateFile = path.join(this.stateDir, `${name}_state.json`);

    // Try to load existing state
    try {
      const data = await fs.readFile(stateFile, 'utf-8');
      this.state = JSON.parse(data);

      // Verify hash matches (binary hasn't changed)
      if (this.state!.binaryHash !== binaryHash) {
        console.warn(
          `Warning: Binary hash mismatch. Binary may have been modified.`,
        );
      }

      this.state!.lastUpdated = new Date().toISOString();
      return this.state!;
    } catch (_error) {
      // Create new state
      await fs.mkdir(this.stateDir, { recursive: true });

      this.state = {
        binaryPath,
        binaryHash,
        sessionName: name,
        created: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
        metadata: {},
        criticalFunctions: [],
        comparisonPoints: [],
        decodedStrings: [],
        notes: [],
        tags: [],
        analysisPhase: 'initial',
        completedSteps: [],
      };

      await this.save();
      return this.state;
    }
  }

  /**
   * Save current state to disk
   */
  async save(): Promise<void> {
    if (!this.state) {
      throw new Error('No state to save. Call initState() first.');
    }

    this.state.lastUpdated = new Date().toISOString();
    const stateFile = path.join(
      this.stateDir,
      `${this.state.sessionName}_state.json`,
    );

    await fs.writeFile(stateFile, JSON.stringify(this.state, null, 2));
  }

  /**
   * Add a critical function to track
   */
  async addCriticalFunction(info: FunctionInfo): Promise<void> {
    if (!this.state) throw new Error('State not initialized');

    // Check if already exists
    const existing = this.state.criticalFunctions.findIndex(
      (f) => f.address === info.address,
    );

    if (existing >= 0) {
      this.state.criticalFunctions[existing] = info;
    } else {
      this.state.criticalFunctions.push(info);
    }

    // Sort by score descending
    this.state.criticalFunctions.sort((a, b) => b.score - a.score);

    await this.save();
  }

  /**
   * Add comparison point
   */
  async addComparisonPoint(point: ComparisonPoint): Promise<void> {
    if (!this.state) throw new Error('State not initialized');

    const existing = this.state.comparisonPoints.findIndex(
      (p) => p.address === point.address,
    );

    if (existing >= 0) {
      this.state.comparisonPoints[existing] = point;
    } else {
      this.state.comparisonPoints.push(point);
    }

    await this.save();
  }

  /**
   * Add decoded string
   */
  async addDecodedString(str: DecodedString): Promise<void> {
    if (!this.state) throw new Error('State not initialized');

    const existing = this.state.decodedStrings.findIndex(
      (s) => s.address === str.address,
    );

    if (existing >= 0) {
      this.state.decodedStrings[existing] = str;
    } else {
      this.state.decodedStrings.push(str);
    }

    await this.save();
  }

  /**
   * Update attack surface
   */
  async updateAttackSurface(surface: AttackSurface): Promise<void> {
    if (!this.state) throw new Error('State not initialized');
    this.state.attackSurface = surface;
    await this.save();
  }

  /**
   * Add note
   */
  async addNote(note: string): Promise<void> {
    if (!this.state) throw new Error('State not initialized');
    this.state.notes.push(`[${new Date().toISOString()}] ${note}`);
    await this.save();
  }

  /**
   * Add tag
   */
  async addTag(tag: string): Promise<void> {
    if (!this.state) throw new Error('State not initialized');
    if (!this.state.tags.includes(tag)) {
      this.state.tags.push(tag);
      await this.save();
    }
  }

  /**
   * Mark step as complete
   */
  async markStepComplete(step: string): Promise<void> {
    if (!this.state) throw new Error('State not initialized');
    if (!this.state.completedSteps.includes(step)) {
      this.state.completedSteps.push(step);
      await this.save();
    }
  }

  /**
   * Update analysis phase
   */
  async setPhase(phase: REAnalysisState['analysisPhase']): Promise<void> {
    if (!this.state) throw new Error('State not initialized');
    this.state.analysisPhase = phase;
    await this.save();
  }

  /**
   * Get summary for LLM context
   */
  getSummary(maxLength: number = 2000): string {
    if (!this.state) return 'No analysis state loaded.';

    const summary = [
      `Analysis: ${this.state.sessionName}`,
      `Phase: ${this.state.analysisPhase}`,
      `Binary: ${path.basename(this.state.binaryPath)}`,
      '',
      `Progress:`,
      `- Critical functions identified: ${this.state.criticalFunctions.length}`,
      `- Comparison points found: ${this.state.comparisonPoints.length}`,
      `- Strings decoded: ${this.state.decodedStrings.length}`,
      `- Completed steps: ${this.state.completedSteps.join(', ')}`,
      '',
    ];

    if (this.state.metadata.packer) {
      summary.push(`Packer detected: ${this.state.metadata.packer}`);
    }

    if (this.state.criticalFunctions.length > 0) {
      summary.push('', 'Top Critical Functions:');
      this.state.criticalFunctions.slice(0, 5).forEach((f) => {
        summary.push(
          `  ${f.address} (score: ${f.score}): ${f.reason}${f.analyzed ? ' ✓' : ''}`,
        );
      });
    }

    if (this.state.comparisonPoints.length > 0) {
      summary.push('', 'Key Comparison Points:');
      this.state.comparisonPoints.slice(0, 5).forEach((c) => {
        summary.push(`  ${c.address}: ${c.instruction}`);
      });
    }

    if (this.state.notes.length > 0) {
      summary.push('', 'Recent Notes:');
      this.state.notes.slice(-3).forEach((n) => {
        summary.push(`  ${n}`);
      });
    }

    const fullSummary = summary.join('\n');
    return fullSummary.length > maxLength
      ? fullSummary.substring(0, maxLength) + '...'
      : fullSummary;
  }

  /**
   * Export state for LLM memory system
   */
  async exportForMemory(): Promise<string> {
    if (!this.state) return '';

    const memoryContent = [
      `# Reverse Engineering State: ${this.state.sessionName}`,
      '',
      `Binary: ${this.state.binaryPath}`,
      `Phase: ${this.state.analysisPhase}`,
      `Last Updated: ${this.state.lastUpdated}`,
      '',
    ];

    if (this.state.metadata.packer) {
      memoryContent.push(`## Packer Information`);
      memoryContent.push(`- Type: ${this.state.metadata.packer}`);
      memoryContent.push('');
    }

    if (this.state.criticalFunctions.length > 0) {
      memoryContent.push(
        `## Critical Functions (${this.state.criticalFunctions.length})`,
      );
      this.state.criticalFunctions.forEach((f) => {
        memoryContent.push(
          `- ${f.address} (${f.score}/100): ${f.reason}${f.analyzed ? ' [ANALYZED]' : ''}`,
        );
        if (f.notes) {
          memoryContent.push(`  Notes: ${f.notes}`);
        }
      });
      memoryContent.push('');
    }

    if (this.state.comparisonPoints.length > 0) {
      memoryContent.push(
        `## Comparison Points (${this.state.comparisonPoints.length})`,
      );
      this.state.comparisonPoints.forEach((c) => {
        memoryContent.push(`- ${c.address}: ${c.instruction}`);
        if (c.notes) {
          memoryContent.push(`  ${c.notes}`);
        }
      });
      memoryContent.push('');
    }

    if (this.state.decodedStrings.length > 0) {
      memoryContent.push(
        `## Decoded Strings (${this.state.decodedStrings.length})`,
      );
      this.state.decodedStrings.forEach((s) => {
        memoryContent.push(`- ${s.address}: "${s.decoded}" (${s.encoding})`);
      });
      memoryContent.push('');
    }

    if (this.state.attackSurface) {
      memoryContent.push(`## Attack Surface`);
      memoryContent.push(
        `- Input points: ${this.state.attackSurface.inputPoints.length}`,
      );
      memoryContent.push(
        `- Validators: ${this.state.attackSurface.validators.length}`,
      );
      memoryContent.push('');
    }

    memoryContent.push(`## Notes`);
    this.state.notes.forEach((n) => {
      memoryContent.push(`- ${n}`);
    });

    return memoryContent.join('\n');
  }

  /**
   * Get current state
   */
  getState(): REAnalysisState | null {
    return this.state;
  }

  /**
   * Calculate file hash
   */
  private async hashFile(filePath: string): Promise<string> {
    const data = await fs.readFile(filePath);
    return createHash('sha256').update(data).digest('hex');
  }
}
