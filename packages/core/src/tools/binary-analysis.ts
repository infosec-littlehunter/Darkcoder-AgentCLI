/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Binary Analysis Tool - Essential binary file analysis utilities
 *
 * Integrates common Unix binary analysis tools:
 * - file: Identify file types
 * - strings: Extract readable strings
 * - checksec: Check security properties
 * - readelf/objdump: ELF binary analysis
 * - nm: Symbol table viewing
 * - ldd: Library dependencies
 * - hexdump: Hex viewer
 *
 * Enhanced with LLM-focused features:
 * - Automated vulnerability indicators
 * - Security assessment summaries
 * - Actionable recommendations
 * - Pattern detection for common vulnerabilities
 */

import { BaseDeclarativeTool, Kind, type ToolResult } from './tools.js';
import { BaseToolInvocation } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const execAsync = promisify(exec);

/**
 * Escape a string for safe use in shell commands
 * Prevents command injection by escaping special characters
 */
function escapeShellArg(arg: string): string {
  // Use single quotes and escape any existing single quotes
  // This is the safest approach for shell argument escaping
  return "'" + arg.replace(/'/g, "'\"'\"'") + "'";
}

/**
 * Security assessment result (used in quickSecurityAnalysis return type documentation)
 */
interface _SecurityAssessment {
  score: number; // 0-100
  level: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  findings: SecurityFinding[];
  recommendations: string[];
}

// Export type alias for external use
export type SecurityAssessment = _SecurityAssessment;

interface SecurityFinding {
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  impact?: string;
}

/**
 * Interesting strings categories for security analysis
 */
interface CategorizedStrings {
  urls: string[];
  ips: string[];
  paths: string[];
  credentials: string[];
  commands: string[];
  crypto: string[];
  debug: string[];
  interesting: string[];
}

/**
 * Binary analysis operations
 */
interface BinaryAnalysisParams {
  /** Operation to perform */
  operation:
    | 'file' // Identify file type and format
    | 'strings' // Extract readable strings
    | 'checksec' // Check binary security features
    | 'readelf' // Analyze ELF headers and sections
    | 'symbols' // List symbols (nm)
    | 'dependencies' // Show library dependencies (ldd)
    | 'hexdump' // Hex dump of binary
    | 'disassemble' // Quick disassembly (objdump)
    | 'sections' // Show binary sections
    | 'headers' // Show all headers
    | 'quick_analysis' // NEW: Quick security assessment with recommendations
    | 'find_vulnerabilities' // NEW: Search for vulnerability patterns
    | 'analyze_strings'; // NEW: Categorize and analyze strings for security

  /** Path to binary file to analyze */
  binaryPath: string;

  /** Maximum number of strings to extract (default: 100) */
  maxStrings?: number;

  /** Minimum string length for extraction (default: 4) */
  minStringLength?: number;

  /** Hex dump offset (bytes to skip) */
  offset?: number;

  /** Hex dump length (bytes to display) */
  length?: number;

  /** Symbol filter pattern (regex) */
  symbolFilter?: string;

  /** Include section name for strings extraction */
  includeSection?: boolean;

  /** Disassembly function/symbol name */
  function?: string;

  /** Vulnerability patterns to search for (default: common dangerous functions) */
  vulnPatterns?: string[];
}

/**
 * Binary analysis tool invocation
 */
class BinaryAnalysisToolInvocation extends BaseToolInvocation<
  BinaryAnalysisParams,
  ToolResult
> {
  constructor(params: BinaryAnalysisParams) {
    super(params);
  }

  override getDescription(): string {
    return `Performing ${this.params.operation} on ${path.basename(this.params.binaryPath)}`;
  }

  async execute(signal: AbortSignal): Promise<ToolResult> {
    // Validate binary file exists
    try {
      await fs.access(this.params.binaryPath);
    } catch (e) {
      return {
        llmContent: `Error: Binary file not found: ${this.params.binaryPath}`,
        returnDisplay: `File not found: ${this.params.binaryPath}`,
        error: {
          message: `Binary file not found: ${this.params.binaryPath}`,
          type: 'ExecutionError' as any,
        },
      };
    }

    console.debug(
      `[BinaryAnalysis] Running ${this.params.operation} on ${this.params.binaryPath}`,
    );

    try {
      switch (this.params.operation) {
        case 'file':
          return await this.analyzeFileType();
        case 'strings':
          return await this.extractStrings();
        case 'checksec':
          return await this.checkSecurity();
        case 'readelf':
          return await this.analyzeELF();
        case 'symbols':
          return await this.listSymbols();
        case 'dependencies':
          return await this.showDependencies();
        case 'hexdump':
          return await this.hexDump();
        case 'disassemble':
          return await this.disassemble();
        case 'sections':
          return await this.showSections();
        case 'headers':
          return await this.showHeaders();
        case 'quick_analysis':
          return await this.quickSecurityAnalysis();
        case 'find_vulnerabilities':
          return await this.findVulnerabilityPatterns();
        case 'analyze_strings':
          return await this.analyzeStringsForSecurity();
        default:
          throw new Error(`Unknown operation: ${this.params.operation}`);
      }
    } catch (e) {
      const error = e as Error;
      console.error(`[BinaryAnalysis] Error: ${error.message}`);
      return {
        llmContent: `Error during ${this.params.operation}: ${error.message}`,
        returnDisplay: `Error: ${error.message}`,
        error: {
          message: error.message,
          type: 'ExecutionError' as any,
        },
      };
    }
  }

  /**
   * Identify file type using 'file' command
   */
  private async analyzeFileType(): Promise<ToolResult> {
    const { stdout } = await execAsync(
      `file -b ${escapeShellArg(this.params.binaryPath)}`,
    );
    const fileType = stdout.trim();

    return {
      llmContent: `File type analysis:\n${fileType}`,
      returnDisplay: `File type: ${fileType.substring(0, 100)}`,
    };
  }

  /**
   * Extract readable strings from binary
   */
  private async extractStrings(): Promise<ToolResult> {
    const minLen = this.params.minStringLength || 4;
    const maxStrings = this.params.maxStrings || 100;

    // Use strings command with options
    const escapedPath = escapeShellArg(this.params.binaryPath);
    const cmd = this.params.includeSection
      ? `strings -a -t x -n ${minLen} ${escapedPath}`
      : `strings -a -n ${minLen} ${escapedPath}`;

    const { stdout } = await execAsync(cmd, {
      maxBuffer: 10 * 1024 * 1024, // 10MB
    });

    const lines = stdout.trim().split('\n');
    const totalStrings = lines.length;
    const displayStrings = lines.slice(0, maxStrings);

    const formattedOutput = displayStrings.join('\n');
    const truncated = totalStrings > maxStrings;

    return {
      llmContent: `Extracted strings (${totalStrings} total, showing ${displayStrings.length}):\n\`\`\`\n${formattedOutput}\n\`\`\`${truncated ? `\n\n[Truncated ${totalStrings - maxStrings} strings]` : ''}`,
      returnDisplay: `Extracted ${totalStrings} strings (showing ${displayStrings.length})`,
    };
  }

  /**
   * Check binary security properties using checksec.sh or manual checks
   */
  private async checkSecurity(): Promise<ToolResult> {
    // Try checksec.sh first
    try {
      const { stdout } = await execAsync(
        `checksec --file=${escapeShellArg(this.params.binaryPath)} --output=json`,
      );
      const data = JSON.parse(stdout);
      return this.formatChecksecOutput(data);
    } catch (e) {
      // Fallback to manual checks using readelf
      return await this.manualSecurityCheck();
    }
  }

  /**
   * Format checksec JSON output
   */
  private formatChecksecOutput(data: any): ToolResult {
    const file = data[this.params.binaryPath] || data;
    const features = [];

    if (file.relro) features.push(`RELRO: ${file.relro}`);
    if (file.canary) features.push(`Stack Canary: ${file.canary}`);
    if (file.nx) features.push(`NX: ${file.nx}`);
    if (file.pie) features.push(`PIE: ${file.pie}`);
    if (file.rpath) features.push(`RPATH: ${file.rpath}`);
    if (file.runpath) features.push(`RUNPATH: ${file.runpath}`);
    if (file.fortify_source)
      features.push(`FORTIFY_SOURCE: ${file.fortify_source}`);

    const summary = features.join('\n');

    return {
      llmContent: `Security features:\n\`\`\`\n${summary}\n\`\`\``,
      returnDisplay: `Security check completed`,
    };
  }

  /**
   * Manual security check using readelf (fallback)
   */
  private async manualSecurityCheck(): Promise<ToolResult> {
    const checks: string[] = [];
    const escapedPath = escapeShellArg(this.params.binaryPath);

    try {
      // Check for NX (GNU_STACK)
      const { stdout: stack } = await execAsync(
        `readelf -l ${escapedPath} | grep GNU_STACK`,
      );
      const nx = stack.includes('RWE') ? 'disabled' : 'enabled';
      checks.push(`NX: ${nx}`);
    } catch (e) {
      // Binary might not be ELF
    }

    try {
      // Check for PIE
      const { stdout: type } = await execAsync(
        `readelf -h ${escapedPath} | grep Type:`,
      );
      const pie = type.includes('DYN') ? 'enabled' : 'disabled';
      checks.push(`PIE: ${pie}`);
    } catch (e) {
      // Ignore
    }

    try {
      // Check for stack canary
      const { stdout: symbols } = await execAsync(
        `nm -D ${escapedPath} | grep stack_chk_fail`,
      );
      const canary = symbols.trim() ? 'found' : 'not found';
      checks.push(`Stack Canary: ${canary}`);
    } catch (e) {
      checks.push(`Stack Canary: not found`);
    }

    const summary =
      checks.join('\n') || 'Unable to determine security features';

    return {
      llmContent: `Security features (manual check):\n\`\`\`\n${summary}\n\`\`\``,
      returnDisplay: `Security check completed (manual)`,
    };
  }

  /**
   * Analyze ELF binary using readelf
   */
  private async analyzeELF(): Promise<ToolResult> {
    const { stdout } = await execAsync(
      `readelf -h -S -l ${escapeShellArg(this.params.binaryPath)}`,
      { maxBuffer: 5 * 1024 * 1024 },
    );

    return {
      llmContent: `ELF analysis:\n\`\`\`\n${stdout.trim()}\n\`\`\``,
      returnDisplay: `ELF analysis completed`,
    };
  }

  /**
   * List symbols using nm
   */
  private async listSymbols(): Promise<ToolResult> {
    const cmd = `nm -C ${escapeShellArg(this.params.binaryPath)}`;

    const { stdout } = await execAsync(cmd, {
      maxBuffer: 10 * 1024 * 1024,
    });

    let symbols = stdout.trim().split('\n');

    // Apply filter if specified
    if (this.params.symbolFilter) {
      const regex = new RegExp(this.params.symbolFilter, 'i');
      symbols = symbols.filter((line) => regex.test(line));
    }

    const total = symbols.length;
    const maxDisplay = 200;
    const displaySymbols = symbols.slice(0, maxDisplay);
    const truncated = total > maxDisplay;

    return {
      llmContent: `Symbols (${total} total, showing ${displaySymbols.length}):\n\`\`\`\n${displaySymbols.join('\n')}\n\`\`\`${truncated ? `\n\n[Truncated ${total - maxDisplay} symbols]` : ''}`,
      returnDisplay: `Found ${total} symbols`,
    };
  }

  /**
   * Show library dependencies using ldd
   */
  private async showDependencies(): Promise<ToolResult> {
    try {
      const { stdout } = await execAsync(
        `ldd ${escapeShellArg(this.params.binaryPath)}`,
      );

      return {
        llmContent: `Library dependencies:\n\`\`\`\n${stdout.trim()}\n\`\`\``,
        returnDisplay: `Library dependencies listed`,
      };
    } catch (e) {
      const error = e as any;
      // ldd might fail for static binaries
      if (error.stdout && error.stdout.includes('not a dynamic executable')) {
        return {
          llmContent: `Binary is statically linked (no dynamic dependencies)`,
          returnDisplay: `Static binary - no dependencies`,
        };
      }
      throw e;
    }
  }

  /**
   * Hex dump of binary
   */
  private async hexDump(): Promise<ToolResult> {
    const offset = this.params.offset || 0;
    const length = this.params.length || 256;

    const { stdout } = await execAsync(
      `xxd -s ${offset} -l ${length} ${escapeShellArg(this.params.binaryPath)}`,
    );

    return {
      llmContent: `Hex dump (offset: ${offset}, length: ${length}):\n\`\`\`\n${stdout.trim()}\n\`\`\``,
      returnDisplay: `Hex dump: ${length} bytes from offset ${offset}`,
    };
  }

  /**
   * Quick disassembly using objdump
   */
  private async disassemble(): Promise<ToolResult> {
    const escapedPath = escapeShellArg(this.params.binaryPath);
    let cmd = `objdump -d -M intel ${escapedPath}`;

    // If specific function requested, escape it too
    if (this.params.function) {
      // Function names should be alphanumeric with underscores, validate first
      const funcName = this.params.function.replace(/[^a-zA-Z0-9_]/g, '');
      cmd = `objdump -d -M intel --disassemble=${funcName} ${escapedPath}`;
    }

    const { stdout } = await execAsync(cmd, {
      maxBuffer: 10 * 1024 * 1024,
    });

    const lines = stdout.trim().split('\n');
    const maxLines = 500;
    const displayLines = lines.slice(0, maxLines);
    const truncated = lines.length > maxLines;

    return {
      llmContent: `Disassembly${this.params.function ? ` of ${this.params.function}` : ''} (${lines.length} lines, showing ${displayLines.length}):\n\`\`\`asm\n${displayLines.join('\n')}\n\`\`\`${truncated ? `\n\n[Truncated ${lines.length - maxLines} lines]` : ''}`,
      returnDisplay: `Disassembled ${this.params.function || 'binary'}`,
    };
  }

  /**
   * Show binary sections
   */
  private async showSections(): Promise<ToolResult> {
    const { stdout } = await execAsync(
      `readelf -S ${escapeShellArg(this.params.binaryPath)}`,
    );

    return {
      llmContent: `Binary sections:\n\`\`\`\n${stdout.trim()}\n\`\`\``,
      returnDisplay: `Sections listed`,
    };
  }

  /**
   * Show all headers
   */
  private async showHeaders(): Promise<ToolResult> {
    const { stdout } = await execAsync(
      `readelf -a ${escapeShellArg(this.params.binaryPath)}`,
      { maxBuffer: 10 * 1024 * 1024 },
    );

    const lines = stdout.trim().split('\n');
    const maxLines = 1000;
    const displayLines = lines.slice(0, maxLines);
    const truncated = lines.length > maxLines;

    return {
      llmContent: `All headers (${lines.length} lines, showing ${displayLines.length}):\n\`\`\`\n${displayLines.join('\n')}\n\`\`\`${truncated ? `\n\n[Truncated ${lines.length - maxLines} lines]` : ''}`,
      returnDisplay: `All headers displayed`,
    };
  }

  // ==================== LLM-Enhanced Analysis Methods ====================

  /**
   * Quick security analysis with automated assessment and recommendations
   * This provides a comprehensive overview suitable for LLM decision-making
   */
  private async quickSecurityAnalysis(): Promise<ToolResult> {
    const findings: SecurityFinding[] = [];
    const recommendations: string[] = [];
    let score = 100;
    const escapedPath = escapeShellArg(this.params.binaryPath);

    // 1. Get file type
    const { stdout: fileType } = await execAsync(`file -b ${escapedPath}`);
    const isELF = fileType.includes('ELF');
    const isPE = fileType.includes('PE32') || fileType.includes('PE64');
    const isStripped = fileType.includes('stripped');

    // Note PE binary type for potential future Windows-specific checks
    if (isPE) {
      findings.push({
        category: 'Binary Properties',
        severity: 'info',
        description:
          'PE (Windows) binary detected - limited analysis available on Linux',
      });
    }

    if (isStripped) {
      findings.push({
        category: 'Binary Properties',
        severity: 'info',
        description: 'Binary is stripped (no debug symbols)',
        impact: 'Makes reverse engineering harder but not impossible',
      });
    }

    // 2. Check security features (if ELF)
    if (isELF) {
      const securityResult = await this.performSecurityChecks();
      findings.push(...securityResult.findings);
      score -= securityResult.deduction;
      recommendations.push(...securityResult.recommendations);
    }

    // 3. Check for dangerous functions
    const dangerousResult = await this.checkDangerousFunctions();
    findings.push(...dangerousResult.findings);
    score -= dangerousResult.deduction;
    recommendations.push(...dangerousResult.recommendations);

    // 4. Quick strings analysis for sensitive data
    const stringsResult = await this.quickStringsCheck();
    findings.push(...stringsResult.findings);
    recommendations.push(...stringsResult.recommendations);

    // Determine security level
    const level = this.calculateSecurityLevel(Math.max(0, score));

    // Build comprehensive output for LLM
    let output = `# Binary Security Assessment: ${path.basename(this.params.binaryPath)}\n\n`;
    output += `## Overview\n`;
    output += `- **File Type**: ${fileType.trim()}\n`;
    output += `- **Security Score**: ${Math.max(0, score)}/100 (${level.toUpperCase()})\n\n`;

    output += `## Security Findings\n\n`;
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const sortedFindings = findings.sort(
      (a, b) =>
        severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
    );

    for (const finding of sortedFindings) {
      const emoji = this.getSeverityEmoji(finding.severity);
      output += `### ${emoji} [${finding.severity.toUpperCase()}] ${finding.category}\n`;
      output += `${finding.description}\n`;
      if (finding.impact) {
        output += `**Impact**: ${finding.impact}\n`;
      }
      output += '\n';
    }

    if (recommendations.length > 0) {
      output += `## Recommended Next Steps\n\n`;
      recommendations.forEach((rec, i) => {
        output += `${i + 1}. ${rec}\n`;
      });
    }

    output += `\n## Suggested Follow-up Analysis\n`;
    output += `Based on the findings, consider these operations:\n`;
    if (dangerousResult.hasDangerousFunctions) {
      output += `- \`operation=disassemble, function=<vulnerable_func>\` - Examine dangerous function usage\n`;
    }
    if (stringsResult.hasHardcodedSecrets) {
      output += `- \`operation=analyze_strings\` - Deep dive into embedded strings\n`;
    }
    if (!isStripped) {
      output += `- \`operation=symbols, symbolFilter="password|secret|key|crypt"\` - Search for sensitive symbol names\n`;
    }

    return {
      llmContent: output,
      returnDisplay: `Security assessment: ${level.toUpperCase()} (${Math.max(0, score)}/100)`,
    };
  }

  /**
   * Perform detailed security checks
   */
  private async performSecurityChecks(): Promise<{
    findings: SecurityFinding[];
    deduction: number;
    recommendations: string[];
  }> {
    const findings: SecurityFinding[] = [];
    const recommendations: string[] = [];
    let deduction = 0;
    const escapedPath = escapeShellArg(this.params.binaryPath);

    try {
      // Check NX
      const { stdout: stack } = await execAsync(
        `readelf -l ${escapedPath} 2>/dev/null | grep GNU_STACK || true`,
      );
      if (stack.includes('RWE')) {
        findings.push({
          category: 'NX (No-Execute)',
          severity: 'critical',
          description: 'NX is DISABLED - Stack is executable',
          impact: 'Allows direct shellcode execution on the stack',
        });
        deduction += 25;
        recommendations.push(
          'Recompile with -z noexecstack to enable NX protection',
        );
      } else if (stack.includes('RW')) {
        findings.push({
          category: 'NX (No-Execute)',
          severity: 'info',
          description: 'NX is enabled - Stack is non-executable',
        });
      }

      // Check PIE
      const { stdout: elfType } = await execAsync(
        `readelf -h ${escapedPath} 2>/dev/null | grep Type: || true`,
      );
      if (!elfType.includes('DYN')) {
        findings.push({
          category: 'PIE (Position Independent)',
          severity: 'high',
          description: 'PIE is DISABLED - Binary loads at fixed address',
          impact:
            'Makes ROP/ret2libc attacks easier due to predictable addresses',
        });
        deduction += 15;
        recommendations.push('Recompile with -fPIE -pie to enable ASLR');
      } else {
        findings.push({
          category: 'PIE (Position Independent)',
          severity: 'info',
          description: 'PIE is enabled - Supports ASLR',
        });
      }

      // Check Stack Canary
      const { stdout: canary } = await execAsync(
        `nm -D ${escapedPath} 2>/dev/null | grep stack_chk_fail || true`,
      );
      if (!canary.trim()) {
        findings.push({
          category: 'Stack Canary',
          severity: 'high',
          description: 'Stack canary NOT FOUND',
          impact: 'Buffer overflows can directly overwrite return addresses',
        });
        deduction += 20;
        recommendations.push(
          'Recompile with -fstack-protector-strong for stack protection',
        );
      } else {
        findings.push({
          category: 'Stack Canary',
          severity: 'info',
          description: 'Stack canary is present',
        });
      }

      // Check RELRO
      const { stdout: relro } = await execAsync(
        `readelf -l ${escapedPath} 2>/dev/null | grep GNU_RELRO || true`,
      );
      const { stdout: bindNow } = await execAsync(
        `readelf -d ${escapedPath} 2>/dev/null | grep BIND_NOW || true`,
      );

      if (!relro.trim()) {
        findings.push({
          category: 'RELRO',
          severity: 'medium',
          description: 'No RELRO - GOT is fully writable',
          impact: 'GOT overwrite attacks possible',
        });
        deduction += 10;
        recommendations.push('Compile with -Wl,-z,relro,-z,now for full RELRO');
      } else if (!bindNow.trim()) {
        findings.push({
          category: 'RELRO',
          severity: 'low',
          description: 'Partial RELRO - GOT.PLT still writable',
          impact: 'Limited GOT overwrite attacks possible',
        });
        deduction += 5;
      } else {
        findings.push({
          category: 'RELRO',
          severity: 'info',
          description: 'Full RELRO enabled',
        });
      }
    } catch (e) {
      // Binary might not be ELF
    }

    return { findings, deduction, recommendations };
  }

  /**
   * Check for dangerous function usage
   */
  private async checkDangerousFunctions(): Promise<{
    findings: SecurityFinding[];
    deduction: number;
    recommendations: string[];
    hasDangerousFunctions: boolean;
  }> {
    const findings: SecurityFinding[] = [];
    const recommendations: string[] = [];
    let deduction = 0;
    let hasDangerousFunctions = false;

    // Dangerous functions categorized by severity
    // Note: strncpy/snprintf etc are SAFE alternatives and should NOT be flagged
    const dangerousFunctions = {
      critical: ['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf'],
      high: ['scanf', 'fscanf', 'sscanf', 'realpath', 'getwd'],
      medium: ['mktemp', 'tmpnam', 'tempnam'], // Unsafe temp file creation
      low: [] as string[], // Removed safe functions from flagging
    };

    try {
      const escapedPath = escapeShellArg(this.params.binaryPath);
      const { stdout: symbols } = await execAsync(
        `nm -D ${escapedPath} 2>/dev/null || objdump -T ${escapedPath} 2>/dev/null || true`,
        { maxBuffer: 5 * 1024 * 1024 },
      );

      const foundDangerous = {
        critical: [] as string[],
        high: [] as string[],
        medium: [] as string[],
      };

      for (const [severity, funcs] of Object.entries(dangerousFunctions)) {
        if (severity === 'low') continue; // Skip low severity for cleaner output
        for (const func of funcs) {
          const regex = new RegExp(`\\b${func}(@|\\s|$)`, 'gm');
          if (regex.test(symbols)) {
            if (severity in foundDangerous) {
              (foundDangerous as Record<string, string[]>)[severity].push(func);
            }
            hasDangerousFunctions = true;
          }
        }
      }

      if (foundDangerous.critical.length > 0) {
        findings.push({
          category: 'Dangerous Functions',
          severity: 'critical',
          description: `CRITICAL unsafe functions: ${foundDangerous.critical.join(', ')}`,
          impact: 'Direct buffer overflow vulnerabilities likely exploitable',
        });
        deduction += 15;
        recommendations.push(
          `Replace dangerous functions: ${foundDangerous.critical.map((f) => `${f}→${this.getSafeAlternative(f)}`).join(', ')}`,
        );
      }

      if (foundDangerous.high.length > 0) {
        findings.push({
          category: 'Risky Functions',
          severity: 'high',
          description: `High-risk functions found: ${foundDangerous.high.join(', ')}`,
          impact:
            'Potential for format string or buffer overflow vulnerabilities',
        });
        deduction += 10;
      }

      if (foundDangerous.medium.length > 0) {
        findings.push({
          category: 'Potentially Unsafe Functions',
          severity: 'medium',
          description: `Medium-risk functions: ${foundDangerous.medium.join(', ')}`,
          impact: 'May be safe if used correctly, verify size calculations',
        });
      }

      // Check for format string sinks
      const formatFuncs = ['printf', 'fprintf', 'syslog', 'err', 'warn'];
      const foundFormat = formatFuncs.filter((f) =>
        new RegExp(`\\b${f}(@|\\s|$)`).test(symbols),
      );
      if (foundFormat.length > 0) {
        findings.push({
          category: 'Format String Functions',
          severity: 'info',
          description: `Format functions present: ${foundFormat.join(', ')} - verify format string usage`,
        });
        recommendations.push(
          'Audit printf-family calls for user-controlled format strings',
        );
      }
    } catch (e) {
      // Symbol extraction failed
    }

    return { findings, deduction, recommendations, hasDangerousFunctions };
  }

  /**
   * Quick strings analysis for security indicators
   */
  private async quickStringsCheck(): Promise<{
    findings: SecurityFinding[];
    recommendations: string[];
    hasHardcodedSecrets: boolean;
  }> {
    const findings: SecurityFinding[] = [];
    const recommendations: string[] = [];
    let hasHardcodedSecrets = false;

    try {
      const escapedPath = escapeShellArg(this.params.binaryPath);
      const { stdout } = await execAsync(
        `strings -n 6 ${escapedPath} 2>/dev/null | head -5000`,
        { maxBuffer: 2 * 1024 * 1024 },
      );

      const strings = stdout.split('\n');

      // Check for hardcoded credentials patterns
      const credPatterns = [
        /password\s*[=:]\s*["']?[^"'\s]+/i,
        /api[_-]?key\s*[=:]\s*["']?[A-Za-z0-9]+/i,
        /secret\s*[=:]\s*["']?[^"'\s]+/i,
        /token\s*[=:]\s*["']?[A-Za-z0-9]+/i,
        /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/,
        /aws_access_key_id/i,
        /aws_secret_access_key/i,
      ];

      const foundCredentials: string[] = [];
      for (const str of strings) {
        for (const pattern of credPatterns) {
          if (pattern.test(str)) {
            foundCredentials.push(
              str.substring(0, 60) + (str.length > 60 ? '...' : ''),
            );
            hasHardcodedSecrets = true;
            break;
          }
        }
      }

      if (foundCredentials.length > 0) {
        findings.push({
          category: 'Hardcoded Credentials',
          severity: 'critical',
          description: `Found ${foundCredentials.length} potential hardcoded secret(s):\n${foundCredentials
            .slice(0, 5)
            .map((s) => `  - "${s}"`)
            .join('\n')}`,
          impact: 'Credentials may be extracted and abused',
        });
        recommendations.push(
          'Remove hardcoded credentials, use environment variables or secure vaults',
        );
      }

      // Check for debugging/development strings
      const debugPatterns = [/DEBUG/i, /TODO:/i, /FIXME:/i, /test.*password/i];
      const debugStrings = strings.filter((s) =>
        debugPatterns.some((p) => p.test(s)),
      );

      if (debugStrings.length > 5) {
        findings.push({
          category: 'Debug Information',
          severity: 'low',
          description: `Found ${debugStrings.length} debug/development strings`,
          impact: 'May reveal internal logic or development practices',
        });
      }

      // Check for suspicious commands
      const cmdPatterns = [
        /\/bin\/sh/,
        /\/bin\/bash/,
        /system\(/,
        /exec\(/,
        /popen\(/,
        /rm -rf/,
        /wget\s/,
        /curl\s/,
      ];
      const cmdStrings = strings.filter((s) =>
        cmdPatterns.some((p) => p.test(s)),
      );

      if (cmdStrings.length > 0) {
        findings.push({
          category: 'Shell Commands',
          severity: 'medium',
          description: `Found ${cmdStrings.length} shell command reference(s)`,
          impact:
            'Potential command injection vectors if user input reaches these',
        });
        recommendations.push(
          'Audit shell command usage for injection vulnerabilities',
        );
      }
    } catch (e) {
      // Strings extraction failed
    }

    return { findings, recommendations, hasHardcodedSecrets };
  }

  /**
   * Find vulnerability patterns in binary
   */
  private async findVulnerabilityPatterns(): Promise<ToolResult> {
    const patterns = this.params.vulnPatterns || [
      'gets',
      'strcpy',
      'strcat',
      'sprintf',
      'scanf',
      'system',
      'popen',
      'exec',
    ];

    let output = `# Vulnerability Pattern Search\n\n`;
    output += `Searching for: ${patterns.join(', ')}\n\n`;

    const results: { pattern: string; matches: string[] }[] = [];

    try {
      const escapedPath = escapeShellArg(this.params.binaryPath);
      // Search in symbols
      const { stdout: symbols } = await execAsync(
        `nm -D ${escapedPath} 2>/dev/null || true`,
        { maxBuffer: 5 * 1024 * 1024 },
      );

      // Search in disassembly references
      const { stdout: objdump } = await execAsync(
        `objdump -d ${escapedPath} 2>/dev/null | grep -E "(call|jmp).*<" | head -500 || true`,
        { maxBuffer: 5 * 1024 * 1024 },
      );

      for (const pattern of patterns) {
        const symbolMatches = symbols
          .split('\n')
          .filter((l) => l.toLowerCase().includes(pattern.toLowerCase()));
        const callMatches = objdump
          .split('\n')
          .filter((l) => l.toLowerCase().includes(pattern.toLowerCase()));

        if (symbolMatches.length > 0 || callMatches.length > 0) {
          results.push({
            pattern,
            matches: [...symbolMatches.slice(0, 5), ...callMatches.slice(0, 5)],
          });
        }
      }

      if (results.length === 0) {
        output += `✅ No vulnerable patterns found in symbols/calls\n`;
      } else {
        output += `## Found Patterns\n\n`;
        for (const { pattern, matches } of results) {
          const severity = this.getPatternSeverity(pattern);
          output += `### ${this.getSeverityEmoji(severity)} ${pattern} (${severity})\n`;
          output += `\`\`\`\n${matches.join('\n')}\n\`\`\`\n\n`;
        }

        output += `## Exploitation Guidance\n\n`;
        for (const { pattern } of results) {
          output += this.getExploitationGuidance(pattern);
        }
      }
    } catch (e) {
      output += `Error during search: ${(e as Error).message}\n`;
    }

    return {
      llmContent: output,
      returnDisplay: `Found ${results.length} vulnerability patterns`,
    };
  }

  /**
   * Deep string analysis with categorization
   */
  private async analyzeStringsForSecurity(): Promise<ToolResult> {
    let stdout: string;
    try {
      const result = await execAsync(
        `strings -n 6 ${escapeShellArg(this.params.binaryPath)}`,
        { maxBuffer: 10 * 1024 * 1024 },
      );
      stdout = result.stdout;
    } catch (e) {
      return {
        llmContent: `Error extracting strings: ${(e as Error).message}`,
        returnDisplay: 'String extraction failed',
        error: {
          message: (e as Error).message,
          type: 'ExecutionError' as any,
        },
      };
    }

    const allStrings = stdout.trim().split('\n');
    const categories: CategorizedStrings = {
      urls: [],
      ips: [],
      paths: [],
      credentials: [],
      commands: [],
      crypto: [],
      debug: [],
      interesting: [],
    };

    // Categorization patterns
    const patterns = {
      urls: /https?:\/\/[^\s"'<>]+/i,
      // Proper IP validation: each octet 0-255
      ips: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
      paths: /^(\/[a-zA-Z0-9._-]+)+\/?$/,
      credentials: /(password|passwd|secret|api.?key|token|auth|credential)/i,
      // More specific command patterns - require context
      commands:
        /(sh\s+-c|bash\s+-c|cmd\.exe|powershell|wget\s+|curl\s+|nc\s+-|system\(|exec\(|popen\()/i,
      crypto: /(AES|RSA|DES|SHA|MD5|HMAC|ENCRYPT|DECRYPT|PRIVATE.?KEY)/i,
      debug: /(DEBUG|TRACE|TODO|FIXME|ERROR|WARNING|ASSERT)/i,
      interesting:
        /(admin|root|login|config|database|mysql|postgres|redis|mongodb)/i,
    };

    for (const str of allStrings) {
      for (const [category, pattern] of Object.entries(patterns)) {
        if (pattern.test(str) && (categories as any)[category].length < 50) {
          (categories as any)[category].push(str);
          break; // Only categorize once
        }
      }
    }

    let output = `# String Analysis Report\n\n`;
    output += `Total strings found: ${allStrings.length}\n\n`;

    const categoryInfo: Record<string, { title: string; severity: string }> = {
      credentials: { title: '🔴 Potential Credentials', severity: 'critical' },
      urls: { title: '🌐 URLs/Endpoints', severity: 'medium' },
      ips: { title: '📍 IP Addresses', severity: 'medium' },
      commands: { title: '⚡ Shell Commands', severity: 'high' },
      crypto: { title: '🔐 Cryptographic References', severity: 'info' },
      paths: { title: '📁 File Paths', severity: 'low' },
      debug: { title: '🐛 Debug Strings', severity: 'low' },
      interesting: { title: '🔍 Interesting Strings', severity: 'info' },
    };

    for (const [category, info] of Object.entries(categoryInfo)) {
      const items = (categories as any)[category];
      if (items.length > 0) {
        output += `## ${info.title} (${items.length})\n`;
        output += `\`\`\`\n${items.slice(0, 20).join('\n')}\n\`\`\`\n`;
        if (items.length > 20) {
          output += `[+${items.length - 20} more]\n`;
        }
        output += '\n';
      }
    }

    output += `## Analysis Summary\n\n`;
    if (categories.credentials.length > 0) {
      output += `⚠️ **ACTION REQUIRED**: Found ${categories.credentials.length} potential credential strings\n`;
    }
    if (categories.urls.length > 0) {
      output += `🌐 Found ${categories.urls.length} URLs - consider testing for SSRF or data exfiltration\n`;
    }
    if (categories.commands.length > 0) {
      output += `⚡ Found ${categories.commands.length} command strings - audit for command injection\n`;
    }

    return {
      llmContent: output,
      returnDisplay: `Analyzed ${allStrings.length} strings, categorized into ${Object.values(categories).filter((c) => c.length > 0).length} categories`,
    };
  }

  // ==================== Helper Methods ====================

  private calculateSecurityLevel(score: number): string {
    if (score >= 90) return 'secure';
    if (score >= 70) return 'low';
    if (score >= 50) return 'medium';
    if (score >= 30) return 'high';
    return 'critical';
  }

  private getSeverityEmoji(severity: string): string {
    const emojis: Record<string, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: 'ℹ️',
    };
    return emojis[severity] || '❓';
  }

  private getSafeAlternative(func: string): string {
    const alternatives: Record<string, string> = {
      gets: 'fgets',
      strcpy: 'strncpy/strlcpy',
      strcat: 'strncat/strlcat',
      sprintf: 'snprintf',
      vsprintf: 'vsnprintf',
      scanf: 'fgets+sscanf with limits',
    };
    return alternatives[func] || 'bounds-checked alternative';
  }

  private getPatternSeverity(pattern: string): string {
    const critical = ['gets', 'strcpy', 'strcat', 'sprintf'];
    const high = ['scanf', 'system', 'popen', 'exec'];
    if (critical.includes(pattern)) return 'critical';
    if (high.includes(pattern)) return 'high';
    return 'medium';
  }

  private getExploitationGuidance(pattern: string): string {
    const guidance: Record<string, string> = {
      gets: `- **gets**: Classic buffer overflow. Find buffer size, craft payload with shellcode/ROP.\n`,
      strcpy: `- **strcpy**: Overflow if source > dest. Check dest buffer allocation.\n`,
      sprintf: `- **sprintf**: Format string + overflow. Look for %n writes.\n`,
      system: `- **system**: Command injection. Trace input to function argument.\n`,
      scanf: `- **scanf**: Overflow with %s. Check buffer sizes.\n`,
    };
    return (
      guidance[pattern] ||
      `- **${pattern}**: Review usage for security issues.\n`
    );
  }
}

/**
 * Binary Analysis Tool
 */
export class BinaryAnalysisTool extends BaseDeclarativeTool<
  BinaryAnalysisParams,
  ToolResult
> {
  static readonly Name: string = ToolNames.BINARY_ANALYSIS;

  constructor() {
    super(
      BinaryAnalysisTool.Name,
      ToolDisplayNames.BINARY_ANALYSIS,
      `Essential binary analysis utilities for reverse engineering and security assessment

This tool integrates common Unix binary analysis commands with LLM-optimized output.

**Core Operations:**
- **file**: Identify file type and format (ELF, PE, Mach-O, etc.)
- **strings**: Extract readable ASCII/Unicode strings from binary
- **checksec**: Check security features (NX, PIE, RELRO, Stack Canary, FORTIFY)
- **readelf**: Analyze ELF headers, sections, segments, symbols
- **symbols**: List all symbols with demangling (nm -C)
- **dependencies**: Show dynamic library dependencies (ldd)
- **hexdump**: Display hex dump of binary data
- **disassemble**: Quick disassembly using objdump (Intel syntax)
- **sections**: Show all binary sections with sizes and attributes
- **headers**: Display all ELF headers and metadata

**LLM-Optimized Operations (Recommended for initial analysis):**
- **quick_analysis**: Automated security assessment with score, findings, and recommendations
  - Performs comprehensive security check (NX, PIE, RELRO, canaries)
  - Detects dangerous functions (gets, strcpy, sprintf, etc.)
  - Finds hardcoded credentials and suspicious strings
  - Returns security score (0-100) with actionable recommendations
  
- **find_vulnerabilities**: Search for known vulnerability patterns
  - Detects unsafe function usage in symbols and calls
  - Provides exploitation guidance for each finding
  - Custom pattern support via vulnPatterns parameter
  
- **analyze_strings**: Deep string analysis with security categorization
  - Categorizes strings: URLs, IPs, paths, credentials, commands, crypto
  - Highlights security-relevant findings
  - Useful for finding hardcoded secrets and attack surface

**Usage Examples:**
- Quick security audit: operation=quick_analysis
- Find vulnerable functions: operation=find_vulnerabilities
- Deep string analysis: operation=analyze_strings
- Identify unknown file: operation=file
- Find interesting strings: operation=strings, minStringLength=10
- Check exploit mitigations: operation=checksec
- List imported functions: operation=symbols, symbolFilter="@plt"
- Disassemble function: operation=disassemble, function=main
- Examine binary at offset: operation=hexdump, offset=0x1000, length=512

**Requirements:**
- Linux/WSL/macOS environment
- Standard binutils (readelf, objdump, nm)
- Optional: checksec.sh for enhanced security checking

**Supported Formats:**
- ELF (Linux/Unix binaries)
- PE (Windows executables via WSL)
- Mach-O (macOS binaries)
- Raw binary data`,
      Kind.BinaryAnalysis,
      {
        properties: {
          operation: {
            type: 'string',
            enum: [
              'file',
              'strings',
              'checksec',
              'readelf',
              'symbols',
              'dependencies',
              'hexdump',
              'disassemble',
              'sections',
              'headers',
              'quick_analysis',
              'find_vulnerabilities',
              'analyze_strings',
            ],
            description:
              'Analysis operation to perform. For initial analysis, use quick_analysis for automated security assessment.',
          },
          binaryPath: {
            type: 'string',
            description: 'Path to binary file to analyze',
          },
          maxStrings: {
            type: 'number',
            description: 'Maximum number of strings to extract (default: 100)',
          },
          minStringLength: {
            type: 'number',
            description: 'Minimum string length for extraction (default: 4)',
          },
          offset: {
            type: 'number',
            description: 'Hex dump starting offset in bytes',
          },
          length: {
            type: 'number',
            description: 'Hex dump length in bytes (default: 256)',
          },
          symbolFilter: {
            type: 'string',
            description:
              'Regex pattern to filter symbols (e.g., "main|printf")',
          },
          includeSection: {
            type: 'boolean',
            description:
              'Include section information for strings (shows offset)',
          },
          function: {
            type: 'string',
            description:
              'Function name to disassemble (e.g., "main", "vulnerable_func")',
          },
          vulnPatterns: {
            type: 'array',
            items: { type: 'string' },
            description:
              'Custom vulnerability patterns to search for (default: gets, strcpy, strcat, sprintf, scanf, system, popen, exec)',
          },
        },
        required: ['operation', 'binaryPath'],
        type: 'object',
      },
    );
  }

  protected override validateToolParamValues(
    params: BinaryAnalysisParams,
  ): string | null {
    if (!params.binaryPath || params.binaryPath.trim() === '') {
      return "The 'binaryPath' parameter cannot be empty";
    }

    if (params.minStringLength !== undefined && params.minStringLength < 1) {
      return "The 'minStringLength' must be at least 1";
    }

    if (params.maxStrings !== undefined && params.maxStrings < 1) {
      return "The 'maxStrings' must be at least 1";
    }

    if (params.offset !== undefined && params.offset < 0) {
      return "The 'offset' cannot be negative";
    }

    if (params.length !== undefined && params.length < 1) {
      return "The 'length' must be at least 1";
    }

    return null;
  }

  protected createInvocation(params: BinaryAnalysisParams) {
    return new BinaryAnalysisToolInvocation(params);
  }
}
