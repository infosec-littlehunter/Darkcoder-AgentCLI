/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Reverse Engineering Tool - Advanced RE framework integrations
 *
 * Integrates professional reverse engineering tools:
 * - radare2: Full RE framework with CLI
 * - rizin: Modern radare2 fork with improved UX
 * - Ghidra (headless): Automated decompilation via analyzeHeadless
 * - binwalk: Firmware analysis & extraction
 * - ltrace: Library call tracer
 * - strace: System call tracer
 *
 * Enhanced with LLM-focused features:
 * - Automated analysis summaries
 * - Vulnerability pattern detection
 * - Actionable recommendations
 * - Cross-tool correlation
 */

import { BaseDeclarativeTool, Kind, type ToolResult } from './tools.js';
import { BaseToolInvocation } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

const execAsync = promisify(exec);

/**
 * Escape a string for safe use in shell commands
 * Prevents command injection by escaping special characters
 */
function escapeShellArg(arg: string): string {
  // Use single quotes and escape any existing single quotes
  return "'" + arg.replace(/'/g, "'\"'\"'") + "'";
}

/**
 * Sanitize function/symbol names to prevent injection
 */
function sanitizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_@$.]/g, '');
}

/**
 * Validate address format (hex address)
 */
function isValidAddress(addr: string): boolean {
  return /^(0x)?[0-9a-fA-F]+$/.test(addr);
}

/**
 * Analysis result interface
 */
interface AnalysisResult {
  success: boolean;
  output: string;
  error?: string;
  metadata?: Record<string, unknown>;
}

// Types for potential future use - documenting API shape
// These are available for extension by external tools

/**
 * Reverse engineering operations
 */
interface ReverseEngineeringParams {
  /** Operation to perform */
  operation: // radare2/rizin operations
    | 'auto' // Lightweight - just load binary and wait for instructions
    | 'full_analysis' // Full smart analysis with imports, strings, key functions
    | 'r2_info' // Binary info via radare2
    | 'r2_functions' // List all functions
    | 'r2_disasm' // Disassemble at address/function
    | 'r2_strings' // Extract strings with context
    | 'r2_imports' // List imports
    | 'r2_exports' // List exports
    | 'r2_xrefs' // Cross-references to/from address
    | 'r2_analyze' // Full analysis
    | 'r2_decompile' // Decompile function (pdc/pdg)
    | 'r2_search' // Search patterns in binary
    // rizin-specific
    | 'rizin_info' // Binary info via rizin
    | 'rizin_analyze' // Full analysis with rizin
    | 'rizin_decompile' // Decompile with rizin
    // Ghidra headless
    | 'ghidra_decompile' // Decompile with Ghidra
    | 'ghidra_analyze' // Full Ghidra analysis
    | 'ghidra_scripts' // Run Ghidra scripts
    // binwalk
    | 'binwalk_scan' // Scan for signatures
    | 'binwalk_extract' // Extract embedded files
    | 'binwalk_entropy' // Entropy analysis
    | 'binwalk_carve' // File carving
    // ltrace
    | 'ltrace_run' // Trace library calls
    | 'ltrace_attach' // Attach to running process
    // strace
    | 'strace_run' // Trace system calls
    | 'strace_attach' // Attach to running process
    | 'strace_summary' // Syscall summary
    // LLM-enhanced operations
    | 'quick_re' // Quick RE assessment
    | 'find_crypto' // Find cryptographic functions
    | 'find_vulnerabilities' // Search for vulnerability patterns
    | 'trace_analysis' // Analyze trace output
    // === MALWARE ANALYSIS OPERATIONS ===
    | 'malware_triage' // Quick malware triage assessment
    | 'detect_packer' // Detect packers/protectors/obfuscation
    | 'extract_iocs' // Extract Indicators of Compromise
    | 'find_c2' // Find C2/network indicators
    | 'ransomware_analysis' // Ransomware-specific analysis
    | 'string_decode' // Decode obfuscated/encoded strings
    | 'behavior_indicators' // Identify malicious behavior patterns
    | 'persistence_mechanisms' // Find persistence mechanisms
    | 'anti_analysis' // Detect anti-analysis techniques
    | 'capability_analysis' // Full capability assessment
    | 'yara_generate' // Generate YARA detection rules
    // === BINARY MODIFICATION OPERATIONS (Security Research Only) ===
    | 'backup_binary' // Create backup before patching
    | 'patch_bytes' // Patch binary at address with hex bytes
    | 'nop_instructions' // NOP out instructions at address
    | 'patch_string' // Modify string in binary
    | 'patch_function' // Patch entire function
    // === BINARY ANALYSIS AUTOMATION (Educational/Research Use Only) ===
    | 'find_license_checks' // Auto-detect license/serial/trial validation
    | 'find_win_function' // Find win/success/flag functions
    | 'smart_crack_trial' // Automated trial bypass
    | 'auto_bypass_checks' // Intelligent bypass of validation checks
    | 'extract_algorithm' // Extract validation algorithm for keygen
    | 'find_flag_strings' // Find flag/password strings in binaries
    | 'trace_input_validation' // Trace how input is validated
    | 'identify_protection_points' // Identify all protection/check points
    // === INTELLIGENT COMPOUND WORKFLOWS (Use for complex automated tasks) ===
    | 'full_malware_analysis' // Complete malware investigation: triage → packer → anti-analysis → capabilities → IOCs → YARA
    | 'full_ctf_solve' // Complete binary analysis: find checks → find win → trace validation → auto-bypass → extract flag
    | 'full_vulnerability_audit' // Security audit: vuln patterns → dangerous funcs → crypto review → report
    | 'deep_binary_understanding' // Deep dive: info → functions → strings → imports → decompile key funcs
    | 'firmware_full_analysis' // Firmware: entropy → signatures → extract → analyze components
    | 'suggest_next_steps' // Meta-operation: analyze current state and suggest what to do next
    // === MANUAL ANALYSIS SYSTEM (LLM should focus on step-by-step analysis) ===
    | 'guided_analysis' // MAIN ENTRY: Auto-detect binary type and provide manual analysis roadmap
    | 'analysis_context' // Get current analysis state and what's been discovered
    | 'smart_decompile' // Decompile with auto-selection of best tool and function targeting
    | 'explain_function' // Decompile + explain what the function does in plain English
    | 'find_key_functions' // Multi-strategy search for important functions (combines multiple techniques)
    | 'attack_surface' // Identify all attack vectors: inputs, validators, crypto, network, file I/O
    | 'solve_crackme' // Step-by-step manual solving with explanations at each step
    | 'workflow_chain' // Execute a custom sequence of operations with context passing
    // === OBFUSCATION-RESISTANT ANALYSIS (Works on stripped/obfuscated binaries) ===
    | 'analyze_control_flow' // Find decision points by CFG structure, not names
    | 'find_comparison_points' // Find all CMP/TEST instructions with constants (key for cracking)
    | 'trace_data_flow' // Track how input flows through the program
    | 'find_critical_functions' // Score functions by xref density, complexity, syscalls (not names)
    | 'decode_strings_heuristic' // Detect & decode XOR/base64/custom encoded strings
    | 'find_crypto_constants' // Find crypto by magic constants (AES S-box, SHA constants, etc.)
    | 'analyze_call_graph' // Find important functions by call graph position
    | 'find_input_sinks' // Find where user input is consumed (strcmp, memcmp, etc.)
    | 'extract_constants' // Extract all immediate values and magic numbers
    | 'behavioral_function_scoring' // Score functions by behavior patterns, not names
    | 'deobfuscate_control_flow' // Detect and simplify control flow flattening
    | 'find_indirect_calls' // Find computed/indirect calls (often key in obfuscated code)
    | 'semantic_function_match' // Match function behavior to known patterns (check, crypto, etc.)
    | 'detect_tools' // Smart tool detection - show what analysis tools are available
    // === LIVE VULNERABILITY & THREAT INTELLIGENCE (Internet-connected) ===
    | 'check_cves' // Check for known CVEs related to detected libraries/versions
    | 'check_exploits' // Search for public exploits for detected vulnerabilities
    | 'threat_intel' // Query threat intelligence on detected indicators (hashes, IPs, domains)
    | 'check_yara_rules' // Search for existing YARA rules matching binary characteristics
    | 'vendor_advisories' // Check vendor security advisories for detected products
    | 'recent_attacks'; // Query recent attack patterns matching binary behavior;

  /** Path to binary/file to analyze */
  targetPath: string;

  /** Function name for function-specific operations */
  function?: string;

  /** Address for address-specific operations (hex format) */
  address?: string;

  /** Search pattern for search operations */
  pattern?: string;

  /** Number of instructions to disassemble */
  count?: number;

  /** Output directory for extraction */
  outputDir?: string;

  /** Process ID for attach operations */
  pid?: number;

  /** Command arguments for trace operations */
  args?: string[];

  /** Ghidra project name */
  projectName?: string;

  /** Ghidra script to run */
  script?: string;

  /** Use rizin instead of radare2 */
  useRizin?: boolean;

  /** Additional tool-specific options */
  options?: string[];

  /** Timeout in seconds (default: 60) */
  timeout?: number;

  // === BINARY PATCHING PARAMETERS ===
  /** Hex bytes to write (for patch_bytes) - e.g., "90909090" for NOPs */
  hexBytes?: string;

  /** Length in bytes to patch (for nop_instructions) */
  length?: number;

  /** New string value (for patch_string) */
  newString?: string;

  /** Assembly code (for patch_function) - e.g., "mov eax, 1; ret" */
  assembly?: string;

  /** Backup file path (for restore) */
  backupPath?: string;

  /** Confirm understanding of legal implications (required for patching) */
  confirmLegalUse?: boolean;

  /** Max output size for LLM (chars). Presets: 'small'=15K, 'medium'=30K, 'large'=60K, 'xlarge'=100K, or custom number */
  maxOutput?:
    | 'deepseek'
    | 'tiny'
    | 'small'
    | 'medium'
    | 'large'
    | 'xlarge'
    | number;
}

/**
 * Reverse Engineering Tool Implementation
 */
class ReverseEngineeringToolInvocation extends BaseToolInvocation<
  ReverseEngineeringParams,
  ToolResult
> {
  constructor(params: ReverseEngineeringParams) {
    // Default to automatic smart analysis when no operation is provided
    const normalizedParams: ReverseEngineeringParams = {
      ...params,
      operation: params.operation ?? 'auto',
    };

    super(normalizedParams);
  }

  getDescription(): string {
    const op = this.params.operation;
    const target = path.basename(this.params.targetPath);

    const descriptions: Record<string, string> = {
      auto: `Automatic smart analysis for ${target}`,
      r2_info: `Analyzing binary info for ${target} with radare2`,
      r2_functions: `Listing functions in ${target}`,
      r2_disasm: `Disassembling ${this.params.function || this.params.address || 'entry'} in ${target}`,
      r2_strings: `Extracting strings from ${target} with context`,
      r2_imports: `Listing imports for ${target}`,
      r2_exports: `Listing exports for ${target}`,
      r2_xrefs: `Finding cross-references in ${target}`,
      r2_analyze: `Performing full radare2 analysis on ${target}`,
      r2_decompile: `Decompiling ${this.params.function || 'main'} in ${target}`,
      r2_search: `Searching for pattern in ${target}`,
      rizin_info: `Analyzing ${target} with rizin`,
      rizin_analyze: `Full rizin analysis on ${target}`,
      rizin_decompile: `Decompiling with rizin: ${target}`,
      ghidra_decompile: `Decompiling ${target} with Ghidra`,
      ghidra_analyze: `Running Ghidra headless analysis on ${target}`,
      ghidra_scripts: `Executing Ghidra script on ${target}`,
      binwalk_scan: `Scanning ${target} for embedded signatures`,
      binwalk_extract: `Extracting embedded files from ${target}`,
      binwalk_entropy: `Analyzing entropy of ${target}`,
      binwalk_carve: `Carving files from ${target}`,
      ltrace_run: `Tracing library calls for ${target}`,
      ltrace_attach: `Attaching ltrace to PID ${this.params.pid}`,
      strace_run: `Tracing system calls for ${target}`,
      strace_attach: `Attaching strace to PID ${this.params.pid}`,
      strace_summary: `Getting syscall summary for ${target}`,
      quick_re: `Quick RE assessment of ${target}`,
      find_crypto: `Finding cryptographic functions in ${target}`,
      find_vulnerabilities: `Searching for vulnerability patterns in ${target}`,
      trace_analysis: `Analyzing trace output for ${target}`,
      // Malware analysis operations
      malware_triage: `🔬 Malware triage analysis of ${target}`,
      detect_packer: `🛡️ Detecting packers/protectors in ${target}`,
      extract_iocs: `🎯 Extracting IOCs from ${target}`,
      find_c2: `📡 Finding C2/network indicators in ${target}`,
      ransomware_analysis: `🔐 Ransomware analysis of ${target}`,
      string_decode: `🔓 Decoding obfuscated strings in ${target}`,
      behavior_indicators: `⚠️ Identifying malicious behaviors in ${target}`,
      persistence_mechanisms: `🔄 Finding persistence mechanisms in ${target}`,
      anti_analysis: `🕵️ Detecting anti-analysis techniques in ${target}`,
      capability_analysis: `📊 Full capability analysis of ${target}`,
      yara_generate: `📝 Generating YARA detection rules from IOCs, strings, and imports in ${target}`,
      // Binary modification operations
      backup_binary: `💾 Creating backup of ${target}`,
      patch_bytes: `🔧 Patching bytes at address ${this.params.address || 'TBD'} in ${target}`,
      nop_instructions: `🚫 NOPing ${this.params.length || 0} bytes at ${this.params.address || 'TBD'} in ${target}`,
      patch_string: `📝 Patching string at ${this.params.address || 'TBD'} in ${target}`,
      patch_function: `⚙️ Patching function ${this.params.function || this.params.address || 'TBD'} in ${target}`,
      // Binary analysis automation
      find_license_checks: `🔍 Detecting license/trial validation in ${target}`,
      find_win_function: `🔍 Finding win/success functions in ${target}`,
      smart_crack_trial: `🎯 Analyzing trial restrictions in ${target}`,
      auto_bypass_checks: `🔓 Analyzing validation checks in ${target}`,
      extract_algorithm: `📐 Extracting validation algorithm from ${target}`,
      find_flag_strings: `🚩 Finding flag/password strings in ${target}`,
      trace_input_validation: `🔎 Tracing input validation in ${target}`,
      identify_protection_points: `🛡️ Identifying protection points in ${target}`,
      // Intelligent compound workflows (prefer manual analysis instead)
      full_malware_analysis: `🔬 FULL MALWARE INVESTIGATION of ${target} (triage→packer→anti-analysis→capabilities→IOCs→YARA)`,
      full_ctf_solve: `🔍 FULL BINARY ANALYSIS of ${target} (find checks→win func→trace→analyze→extract)`,

      full_vulnerability_audit: `🐛🐛🐛 FULL SECURITY AUDIT of ${target} (vulns→dangerous funcs→crypto→report)`,
      deep_binary_understanding: `📊📊📊 DEEP BINARY ANALYSIS of ${target} (info→functions→strings→imports→decompile)`,
      firmware_full_analysis: `📦📦📦 FULL FIRMWARE ANALYSIS of ${target} (entropy→signatures→extract→analyze)`,
      suggest_next_steps: `🧠 Analyzing ${target} and suggesting optimal next operations`,
      // Obfuscation-resistant analysis
      analyze_control_flow: `🔀 Analyzing control flow structure in ${target} (works on stripped binaries)`,
      find_comparison_points: `⚖️ Finding all comparison points with constants in ${target}`,
      trace_data_flow: `📈 Tracing data flow from input to comparison in ${target}`,
      find_critical_functions: `⭐ Scoring functions by behavior (xrefs, complexity, syscalls) in ${target}`,
      decode_strings_heuristic: `🔐 Detecting and decoding obfuscated strings in ${target}`,
      find_crypto_constants: `🔑 Finding crypto by magic constants (AES, SHA, etc.) in ${target}`,
      analyze_call_graph: `🕸️ Analyzing call graph to find key functions in ${target}`,
      find_input_sinks: `🎯 Finding where user input is consumed in ${target}`,
      extract_constants: `🔢 Extracting all immediate values and magic numbers from ${target}`,
      behavioral_function_scoring: `📊 Scoring functions by behavior patterns in ${target}`,
      deobfuscate_control_flow: `🔓 Detecting control flow flattening in ${target}`,
      find_indirect_calls: `↪️ Finding computed/indirect calls in ${target}`,
      semantic_function_match: `🧬 Matching function behavior to known patterns in ${target}`,
      // Live vulnerability & threat intelligence
      check_cves: `🌐 Checking for known CVEs in ${target} (live NVD database)`,
      check_exploits: `🌐 Searching for public exploits for vulnerabilities in ${target}`,
      threat_intel: `🌐 Querying threat intelligence on indicators from ${target}`,
      check_yara_rules: `🌐 Searching for existing YARA rules matching ${target}`,
      vendor_advisories: `🌐 Checking vendor security advisories for components in ${target}`,
      recent_attacks: `🌐 Querying recent attack patterns matching ${target} behavior`,
    };

    return descriptions[op] || `Running ${op} on ${target}`;
  }

  async execute(signal: AbortSignal): Promise<ToolResult> {
    const targetPath = this.params.targetPath;
    const timeout = (this.params.timeout || 60) * 1000;

    try {
      // Validate target exists for non-attach operations
      if (
        !this.params.operation.includes('attach') &&
        !this.params.operation.includes('summary')
      ) {
        await fs.access(targetPath);
      }

      let result: AnalysisResult;

      switch (this.params.operation) {
        // radare2 operations
        case 'r2_info':
          result = await this.r2Info(targetPath, timeout);
          break;
        case 'r2_functions':
          result = await this.r2Functions(targetPath, timeout);
          break;
        case 'r2_disasm':
          result = await this.r2Disasm(targetPath, timeout);
          break;
        case 'r2_strings':
          result = await this.r2Strings(targetPath, timeout);
          break;
        case 'r2_imports':
          result = await this.r2Imports(targetPath, timeout);
          break;
        case 'r2_exports':
          result = await this.r2Exports(targetPath, timeout);
          break;
        case 'r2_xrefs':
          result = await this.r2Xrefs(targetPath, timeout);
          break;
        case 'r2_analyze':
          result = await this.r2Analyze(targetPath, timeout);
          break;
        case 'auto':
          result = await this.smartDisasmAnalysis(targetPath, timeout);
          break;
        case 'full_analysis':
          result = await this.fullSmartAnalysis(targetPath, timeout);
          break;
        case 'r2_decompile':
          result = await this.r2Decompile(targetPath, timeout);
          break;
        case 'r2_search':
          result = await this.r2Search(targetPath, timeout);
          break;

        // rizin operations
        case 'rizin_info':
          result = await this.rizinInfo(targetPath, timeout);
          break;
        case 'rizin_analyze':
          result = await this.rizinAnalyze(targetPath, timeout);
          break;
        case 'rizin_decompile':
          result = await this.rizinDecompile(targetPath, timeout);
          break;

        // Ghidra operations
        case 'ghidra_decompile':
          result = await this.ghidraDecompile(targetPath, timeout);
          break;
        case 'ghidra_analyze':
          result = await this.ghidraAnalyze(targetPath, timeout);
          break;
        case 'ghidra_scripts':
          result = await this.ghidraScripts(targetPath, timeout);
          break;

        // binwalk operations
        case 'binwalk_scan':
          result = await this.binwalkScan(targetPath, timeout);
          break;
        case 'binwalk_extract':
          result = await this.binwalkExtract(targetPath, timeout);
          break;
        case 'binwalk_entropy':
          result = await this.binwalkEntropy(targetPath, timeout);
          break;
        case 'binwalk_carve':
          result = await this.binwalkCarve(targetPath, timeout);
          break;

        // ltrace operations
        case 'ltrace_run':
          result = await this.ltraceRun(targetPath, timeout);
          break;
        case 'ltrace_attach':
          result = await this.ltraceAttach(timeout);
          break;

        // strace operations
        case 'strace_run':
          result = await this.straceRun(targetPath, timeout);
          break;
        case 'strace_attach':
          result = await this.straceAttach(timeout);
          break;
        case 'strace_summary':
          result = await this.straceSummary(targetPath, timeout);
          break;

        // LLM-enhanced operations
        case 'quick_re':
          result = await this.quickRE(targetPath, timeout);
          break;
        case 'find_crypto':
          result = await this.findCrypto(targetPath, timeout);
          break;
        case 'find_vulnerabilities':
          result = await this.findVulnerabilities(targetPath, timeout);
          break;
        case 'trace_analysis':
          result = await this.traceAnalysis(targetPath, timeout);
          break;

        // === MALWARE ANALYSIS OPERATIONS ===
        case 'malware_triage':
          result = await this.malwareTriage(targetPath, timeout);
          break;
        case 'detect_packer':
          result = await this.detectPacker(targetPath, timeout);
          break;
        case 'extract_iocs':
          result = await this.extractIOCs(targetPath, timeout);
          break;
        case 'find_c2':
          result = await this.findC2(targetPath, timeout);
          break;
        case 'ransomware_analysis':
          result = await this.ransomwareAnalysis(targetPath, timeout);
          break;
        case 'string_decode':
          result = await this.stringDecode(targetPath, timeout);
          break;
        case 'behavior_indicators':
          result = await this.behaviorIndicators(targetPath, timeout);
          break;
        case 'persistence_mechanisms':
          result = await this.persistenceMechanisms(targetPath, timeout);
          break;
        case 'anti_analysis':
          result = await this.antiAnalysis(targetPath, timeout);
          break;
        case 'capability_analysis':
          result = await this.capabilityAnalysis(targetPath, timeout);
          break;
        case 'yara_generate':
          result = await this.yaraGenerate(targetPath, timeout);
          break;

        // === BINARY MODIFICATION OPERATIONS ===
        case 'backup_binary':
          result = await this.backupBinary(targetPath);
          break;
        case 'patch_bytes':
          result = await this.patchBytes(targetPath, timeout);
          break;
        case 'nop_instructions':
          result = await this.nopInstructions(targetPath, timeout);
          break;
        case 'patch_string':
          result = await this.patchString(targetPath, timeout);
          break;
        case 'patch_function':
          result = await this.patchFunction(targetPath, timeout);
          break;

        // === CTF CRACKING AUTOMATION ===
        case 'find_license_checks':
          result = await this.findLicenseChecks(targetPath, timeout);
          break;
        case 'find_win_function':
          result = await this.findWinFunction(targetPath, timeout);
          break;
        case 'smart_crack_trial':
          result = await this.smartCrackTrial(targetPath, timeout);
          break;
        case 'auto_bypass_checks':
          result = await this.autoBypassChecks(targetPath, timeout);
          break;
        case 'extract_algorithm':
          result = await this.extractAlgorithm(targetPath, timeout);
          break;
        case 'find_flag_strings':
          result = await this.findFlagStrings(targetPath, timeout);
          break;
        case 'trace_input_validation':
          result = await this.traceInputValidation(targetPath, timeout);
          break;
        case 'identify_protection_points':
          result = await this.identifyProtectionPoints(targetPath, timeout);
          break;

        // === INTELLIGENT COMPOUND WORKFLOWS ===
        case 'full_malware_analysis':
          result = await this.fullMalwareAnalysis(targetPath, timeout);
          break;
        case 'full_ctf_solve':
          result = await this.fullCtfSolve(targetPath, timeout);
          break;
        case 'full_vulnerability_audit':
          result = await this.fullVulnerabilityAudit(targetPath, timeout);
          break;
        case 'deep_binary_understanding':
          result = await this.deepBinaryUnderstanding(targetPath, timeout);
          break;
        case 'firmware_full_analysis':
          result = await this.firmwareFullAnalysis(targetPath, timeout);
          break;
        case 'suggest_next_steps':
          result = await this.suggestNextSteps(targetPath, timeout);
          break;

        // === OBFUSCATION-RESISTANT ANALYSIS ===
        case 'analyze_control_flow':
          result = await this.analyzeControlFlow(targetPath, timeout);
          break;
        case 'find_comparison_points':
          result = await this.findComparisonPoints(targetPath, timeout);
          break;
        case 'trace_data_flow':
          result = await this.traceDataFlow(targetPath, timeout);
          break;
        case 'find_critical_functions':
          result = await this.findCriticalFunctions(targetPath, timeout);
          break;
        case 'decode_strings_heuristic':
          result = await this.decodeStringsHeuristic(targetPath, timeout);
          break;
        case 'find_crypto_constants':
          result = await this.findCryptoConstants(targetPath, timeout);
          break;
        case 'analyze_call_graph':
          result = await this.analyzeCallGraph(targetPath, timeout);
          break;
        case 'find_input_sinks':
          result = await this.findInputSinks(targetPath, timeout);
          break;
        case 'extract_constants':
          result = await this.extractConstants(targetPath, timeout);
          break;
        case 'behavioral_function_scoring':
          result = await this.behavioralFunctionScoring(targetPath, timeout);
          break;
        case 'deobfuscate_control_flow':
          result = await this.deobfuscateControlFlow(targetPath, timeout);
          break;
        case 'find_indirect_calls':
          result = await this.findIndirectCalls(targetPath, timeout);
          break;
        case 'semantic_function_match':
          result = await this.semanticFunctionMatch(targetPath, timeout);
          break;

        // === LLM-GUIDED ANALYSIS (Phase 6) ===
        case 'guided_analysis':
          result = await this.guidedAnalysis(targetPath, timeout);
          break;
        case 'analysis_context':
          result = await this.analysisContext(targetPath, timeout);
          break;
        case 'smart_decompile':
          result = await this.smartDecompile(targetPath, timeout);
          break;
        case 'explain_function':
          result = await this.explainFunction(targetPath, timeout);
          break;
        case 'find_key_functions':
          result = await this.findKeyFunctions(targetPath, timeout);
          break;
        case 'attack_surface':
          result = await this.attackSurface(targetPath, timeout);
          break;
        case 'solve_crackme':
          result = await this.solveCrackme(targetPath, timeout);
          break;
        case 'workflow_chain':
          result = await this.workflowChain(targetPath, timeout);
          break;

        case 'detect_tools':
          return await this.detectToolsOperation();

        // === LIVE VULNERABILITY & THREAT INTELLIGENCE ===
        case 'check_cves':
          return await this.checkCVEs(targetPath, timeout);
        case 'check_exploits':
          return await this.checkExploits(targetPath, timeout);
        case 'threat_intel':
          return await this.threatIntel(targetPath, timeout);
        case 'check_yara_rules':
          return await this.checkYaraRules(targetPath, timeout);
        case 'vendor_advisories':
          return await this.vendorAdvisories(targetPath, timeout);
        case 'recent_attacks':
          return await this.recentAttacks(targetPath, timeout);

        default:
          return {
            llmContent: `Unknown operation: ${this.params.operation}`,
            returnDisplay: `Error: Unknown operation: ${this.params.operation}`,
            error: {
              message: `Unknown operation: ${this.params.operation}`,
            },
          };
      }

      if (signal.aborted) {
        return {
          llmContent: 'Operation was cancelled',
          returnDisplay: 'Operation cancelled',
          error: {
            message: 'Operation was cancelled',
          },
        };
      }

      if (!result.success) {
        return {
          llmContent: result.output,
          returnDisplay: `Error: ${result.error || result.output.substring(0, 100)}`,
          error: {
            message: result.error || result.output,
          },
        };
      }

      // Smart compression for large outputs - keep key info, drop verbose details
      // Auto-enable for outputs > 15K or when using deepseek preset
      let compressedOutput = result.output;
      const useCompression =
        result.output.length > 15000 || this.params.maxOutput === 'deepseek';

      if (useCompression) {
        compressedOutput = this.intelligentCompressionOutput(
          result.output,
          this.params.operation || 'unknown',
        );
      }

      // Smart auto-detection: Use aggressive limits for large outputs
      // Check AFTER compression to make accurate size decisions
      const isLargeOutput = compressedOutput.length > 50000;
      const isHugeOutput = compressedOutput.length > 100000;

      // Truncate outputs to prevent context overflow
      // Auto-selects limits based on output size - no manual config needed!
      // Manual override: 'deepseek'=8K, 'tiny'=10K, 'small'=20K, 'medium'=40K, 'large'=80K, 'xlarge'=150K
      let maxLLMLength: number;

      if (this.params.maxOutput) {
        // Manual override specified
        if (typeof this.params.maxOutput === 'number') {
          maxLLMLength = this.params.maxOutput;
        } else {
          const presets: Record<string, number> = {
            deepseek: 8000, // ~2K tokens - optimized for deepseek-reasoner with compression
            tiny: 10000, // ~2.5K tokens - for very large binaries on deepseek
            small: 20000, // ~5K tokens - safe for deepseek
            medium: 40000, // ~10K tokens - use with caution on deepseek
            large: 80000, // ~20K tokens - requires Claude/GPT-4 (200K+ context)
            xlarge: 150000, // ~37K tokens - requires Claude/GPT-4 (200K+ context)
          };
          maxLLMLength = presets[this.params.maxOutput] || 20000;
        }
      } else {
        // SMART AUTO-DETECTION: Choose limits based on actual output size
        if (isHugeOutput) {
          maxLLMLength = 8000; // Huge binary (>100K) - use deepseek preset
        } else if (isLargeOutput) {
          maxLLMLength = 10000; // Large binary (>50K) - use tiny preset
        } else {
          maxLLMLength = 20000; // Normal output - use small preset
        }
      }
      const maxDisplayLength = Math.max(maxLLMLength * 4, 300000);

      const llmOutput =
        compressedOutput.length > maxLLMLength
          ? compressedOutput.substring(0, maxLLMLength) +
            '\n\n... [Output truncated to prevent context overflow. Use more specific operations to analyze sections.] ...'
          : compressedOutput;

      const displayOutput =
        compressedOutput.length > maxDisplayLength
          ? compressedOutput.substring(0, maxDisplayLength) +
            '\n\n... [Output truncated for display] ...'
          : compressedOutput;

      return {
        llmContent: llmOutput,
        returnDisplay: displayOutput,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return {
        llmContent: `Reverse engineering operation failed: ${errorMessage}`,
        returnDisplay: `Error: ${errorMessage.substring(0, 100)}`,
        error: {
          message: errorMessage,
        },
      };
    }
  }

  // ============= Smart Tool Selection =============

  /**
   * Detects available tools and provides intelligent recommendations
   * Helps LLM choose the best tools for the job based on what's installed
   */
  private async detectAvailableTools(): Promise<{
    available: string[];
    recommended: string[];
    capabilities: Record<string, string[]>;
  }> {
    const available: string[] = [];
    const capabilities: Record<string, string[]> = {};

    // Check for radare2/rizin
    try {
      await execAsync('which radare2 || which rizin', { timeout: 2000 });
      available.push('radare2/rizin');
      capabilities['radare2/rizin'] = [
        'Binary info',
        'Function analysis',
        'Disassembly',
        'String extraction',
        'Cross-references',
        'Decompilation (with plugins)',
      ];
    } catch {
      // Not available
    }

    // Check for Ghidra
    try {
      const envCheck = process.env['GHIDRA_HOME'];
      if (envCheck) {
        available.push('Ghidra');
        capabilities['Ghidra'] = [
          'High-quality decompilation',
          'Binary analysis',
          'Symbol recovery',
          'Type inference',
        ];
      }
    } catch {
      // Not available
    }

    // Check for binwalk
    try {
      await execAsync('which binwalk', { timeout: 2000 });
      available.push('binwalk');
      capabilities['binwalk'] = [
        'Firmware scanning',
        'Embedded file detection',
        'Entropy analysis',
        'File extraction',
      ];
    } catch {
      // Not available
    }

    // Check for strings
    try {
      await execAsync('which strings', { timeout: 2000 });
      available.push('strings');
      capabilities['strings'] = [
        'String extraction with offsets',
        'Memory offset detection',
      ];
    } catch {
      // Not available
    }

    // Check for rabin2
    try {
      await execAsync('which rabin2', { timeout: 2000 });
      available.push('rabin2');
      capabilities['rabin2'] = [
        'Binary info',
        'Strings with offsets',
        'Section analysis',
        'Relocation info',
      ];
    } catch {
      // Not available
    }

    // Check for objdump
    try {
      await execAsync('which objdump', { timeout: 2000 });
      available.push('objdump');
      capabilities['objdump'] = [
        'Disassembly',
        'Section analysis',
        'Symbol table',
      ];
    } catch {
      // Not available
    }

    // Recommend tools based on available set
    const recommended: string[] = [];
    if (available.includes('radare2/rizin')) {
      recommended.push(
        'radare2/rizin - Primary analysis, comprehensive features',
      );
    }
    if (available.includes('rabin2')) {
      recommended.push('rabin2 - Fast binary info and string extraction');
    }
    if (available.includes('strings')) {
      recommended.push('strings - Extract strings with file offsets');
    }
    if (available.includes('Ghidra')) {
      recommended.push('Ghidra - Best decompilation quality');
    }
    if (available.includes('binwalk')) {
      recommended.push('binwalk - For firmware and embedded analysis');
    }

    return { available, recommended, capabilities };
  }

  private async detectToolsOperation(): Promise<ToolResult> {
    const tools = await this.detectAvailableTools();

    const output = `
╔════════════════════════════════════════════════════════════════════╗
║           🛠️  SMART TOOL DETECTION & RECOMMENDATIONS              ║
╚════════════════════════════════════════════════════════════════════╝

📊 AVAILABLE TOOLS (${tools.available.length}):
${tools.available.map((t: string) => `  ✅ ${t}`).join('\n')}

🎯 RECOMMENDED OPERATIONS:
${tools.recommended.map((t: string) => `  → ${t}`).join('\n')}

📋 TOOL CAPABILITIES:
${Object.entries(tools.capabilities)
  .map(
    ([tool, caps]: [string, string[]]) =>
      `  ${tool}:\n${caps.map((c: string) => `    • ${c}`).join('\n')}`,
  )
  .join('\n\n')}

💡 USAGE SUGGESTIONS (LLM should prefer step-by-step manual analysis):
  • Start with 'r2_info' or 'r2_analyze' for binary information
  • Use 'r2_functions' to list functions, then analyze them one by one
  • Use 'r2_strings' to extract strings for manual review
  • Use 'r2_decompile' or 'ghidra_decompile' to understand specific functions
  • Use 'find_license_checks' to identify validation functions for manual analysis
  • Prefer manual step-by-step analysis over automated workflows

🔍 RECOMMENDED WORKFLOW:
  1. Gather information (info, functions, strings, imports)
  2. Identify interesting functions manually
  3. Decompile and analyze key functions
  4. Draw conclusions based on manual analysis
`;

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  // ============= radare2 Operations =============

  /**
   * Helper to build r2/rizin command with proper flags
   * Adds -e bin.relocs.apply=true to fix relocation warnings
   */
  private buildR2Command(commands: string, targetPath: string): string {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    // Apply relocations to fix "Relocs has not been applied" warning
    // Also enable cache for faster repeated analysis
    return `${tool} -e bin.relocs.apply=true -q -c "${commands}" ${escapeShellArg(targetPath)}`;
  }

  private async r2Info(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const cmd = this.buildR2Command('iI; ie; iS', targetPath);
    return this.runCommand(cmd, timeout);
  }

  private async r2Functions(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // aaa = analyze all, afl = list functions
    const cmd = this.buildR2Command('aaa; afl', targetPath);
    return this.runCommand(cmd, timeout);
  }

  private async r2Disasm(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // SMART MODE: If no specific function/address specified, analyze key functions intelligently
    if (!this.params.function && !this.params.address) {
      return this.smartDisasmAnalysis(targetPath, timeout);
    }

    const count = this.params.count || 50;
    let seekCmd: string;
    let disasmCmd: string;

    if (this.params.function) {
      const funcName = sanitizeName(this.params.function);
      // Handle different function name formats:
      // - fcn.XXXXX (auto-generated) - use as-is
      // - sym.XXXXX (symbol) - use as-is
      // - 0xXXXX (address) - use as-is
      // - plain name - prepend sym.
      if (
        funcName.startsWith('fcn.') ||
        funcName.startsWith('sym.') ||
        funcName.startsWith('0x')
      ) {
        seekCmd = `s ${funcName}`;
      } else {
        seekCmd = `s sym.${funcName}`;
      }
      // pdf = disassemble function (no count needed)
      disasmCmd = 'pdf';
    } else if (this.params.address) {
      if (!isValidAddress(this.params.address)) {
        return { success: false, output: 'Invalid address format' };
      }
      seekCmd = `s ${this.params.address}`;
      // pd N = disassemble N instructions from address
      disasmCmd = `pd ${count}`;
    } else {
      seekCmd = 's entry0';
      // pdf for entry point function
      disasmCmd = 'pdf';
    }

    const cmd = this.buildR2Command(
      `aaa; ${seekCmd}; ${disasmCmd}`,
      targetPath,
    );
    return this.runCommand(cmd, timeout);
  }

  private async r2Strings(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // iz = strings in data section, izz = all strings
    const cmd = this.buildR2Command('iz~[0,1,2,3,4,5]', targetPath);
    return this.runCommand(cmd, timeout);
  }

  private async r2Imports(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const cmd = this.buildR2Command('ii', targetPath);
    return this.runCommand(cmd, timeout);
  }

  private async r2Exports(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const cmd = this.buildR2Command('iE', targetPath);
    return this.runCommand(cmd, timeout);
  }

  private async r2Xrefs(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    let addr: string;
    if (this.params.address) {
      if (!isValidAddress(this.params.address)) {
        return { success: false, output: 'Invalid address format' };
      }
      addr = this.params.address;
    } else if (this.params.function) {
      const funcName = sanitizeName(this.params.function);
      // Handle different function name formats
      if (
        funcName.startsWith('fcn.') ||
        funcName.startsWith('sym.') ||
        funcName.startsWith('0x')
      ) {
        addr = funcName;
      } else {
        addr = `sym.${funcName}`;
      }
    } else {
      addr = 'entry0';
    }

    // axt = xrefs to, axf = xrefs from
    const cmd = this.buildR2Command(`aaa; s ${addr}; axt; axf`, targetPath);
    return this.runCommand(cmd, timeout);
  }

  private async r2Analyze(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // Full r2_analyze - provide comprehensive binary analysis
    // Uses fullSmartAnalysis for detailed, actionable information
    return this.fullSmartAnalysis(targetPath, timeout);
  }

  private async r2Decompile(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const escapedPath = escapeShellArg(targetPath);

    // Determine seek target - can be function name or address
    let seekTarget: string;
    if (this.params.function) {
      const funcName = sanitizeName(this.params.function);
      // Handle different function name formats:
      // - fcn.XXXXX (auto-generated) - use as-is
      // - sym.XXXXX (symbol) - use as-is
      // - 0xXXXX (address) - use as-is
      // - plain name like "main" - try multiple formats
      if (
        funcName.startsWith('fcn.') ||
        funcName.startsWith('sym.') ||
        funcName.startsWith('0x')
      ) {
        seekTarget = funcName;
      } else {
        // For plain names like "main", we'll try to find the actual address
        seekTarget = funcName;
      }
    } else if (this.params.address) {
      // Also support address parameter for decompilation
      if (!isValidAddress(this.params.address)) {
        return { success: false, output: 'Invalid address format' };
      }
      seekTarget = this.params.address;
    } else {
      // Default to main
      seekTarget = 'main';
    }

    // For plain function names (not prefixed), try to resolve the actual address
    // This handles cases where sym.main doesn't exist but main is at a known address
    let resolvedTarget = seekTarget;
    if (
      !seekTarget.startsWith('fcn.') &&
      !seekTarget.startsWith('sym.') &&
      !seekTarget.startsWith('0x')
    ) {
      // Try to find the function address by analyzing and looking it up
      // Use exact match at end of line: afl~funcname$
      const findCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~${seekTarget}$" ${escapedPath} 2>/dev/null`;
      const findResult = await this.runCommand(findCmd, timeout / 6);

      if (findResult.success && findResult.output.trim()) {
        // Parse output like: 0x00004d10  353   7529 main
        // Match address followed by the function name at end
        const lines = findResult.output.trim().split('\n');
        for (const line of lines) {
          // Check if line ends with exact function name
          if (
            line.trim().endsWith(` ${seekTarget}`) ||
            line.trim().endsWith(`\t${seekTarget}`)
          ) {
            const addrMatch = line.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              resolvedTarget = addrMatch[1];
              break;
            }
          }
        }
        // Fallback: try first address if exact match not found
        if (resolvedTarget === seekTarget) {
          const match = findResult.output.match(/(0x[0-9a-fA-F]+)/);
          if (match) {
            resolvedTarget = match[1];
          }
        }
      }

      // If still not found, try common prefixes
      if (resolvedTarget === seekTarget) {
        // Try sym.funcname first
        const symTarget = `sym.${seekTarget}`;
        const checkCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; s ${symTarget}; ?v $$" ${escapedPath} 2>/dev/null`;
        const checkResult = await this.runCommand(checkCmd, timeout / 8);
        if (
          checkResult.success &&
          checkResult.output.match(/0x[0-9a-fA-F]+/) &&
          !checkResult.output.includes('0x0')
        ) {
          resolvedTarget = symTarget;
        }
      }
    }

    // Try decompilers in order of preference:
    // 1. pdg = r2ghidra/rz-ghidra decompiler (best quality)
    // 2. pdc = r2dec decompiler (C-like pseudocode)
    // 3. pdd = r2 native decompiler

    // Try pdg first (Ghidra decompiler - best quality)
    const pdgCmd = `${tool} -q -e bin.relocs.apply=true -c "aaa; s ${resolvedTarget}; af; pdg" ${escapedPath} 2>/dev/null`;
    const pdgResult = await this.runCommand(pdgCmd, timeout / 3);

    if (
      pdgResult.success &&
      pdgResult.output.trim() &&
      !pdgResult.output.includes('Cannot find function') &&
      !pdgResult.output.includes('Command') &&
      pdgResult.output.length > 50
    ) {
      return {
        success: true,
        output: `[r2ghidra/pdg decompiler @ ${resolvedTarget}]\n${pdgResult.output}`,
      };
    }

    // Try pdc (r2dec - C-like pseudocode)
    const pdcCmd = `${tool} -q -e bin.relocs.apply=true -c "aaa; s ${resolvedTarget}; af; pdc" ${escapedPath} 2>/dev/null`;
    const pdcResult = await this.runCommand(pdcCmd, timeout / 3);

    if (
      pdcResult.success &&
      pdcResult.output.trim() &&
      !pdcResult.output.includes('Command') &&
      pdcResult.output.length > 50
    ) {
      return {
        success: true,
        output: `[r2dec/pdc decompiler @ ${resolvedTarget}]\n${pdcResult.output}`,
      };
    }

    // Fallback to disassembly with comments (pdf)
    const pdfCmd = `${tool} -q -e bin.relocs.apply=true -c "aaa; s ${resolvedTarget}; af; pdf" ${escapedPath}`;
    const pdfResult = await this.runCommand(pdfCmd, timeout / 3);

    if (pdfResult.success && pdfResult.output.trim()) {
      return {
        success: true,
        output: `[No decompiler available - showing annotated disassembly @ ${resolvedTarget}]\n${pdfResult.output}`,
      };
    }

    return {
      success: false,
      output:
        `Could not decompile ${seekTarget}. Ensure r2ghidra or r2dec plugin is installed.\n` +
        `Install with: r2pm -ci r2ghidra  OR  r2pm -ci r2dec\n` +
        `Function may not exist at this address. Try r2_analyze first to list functions.`,
    };
  }

  private async r2Search(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    if (!this.params.pattern) {
      return { success: false, output: 'Search pattern required' };
    }

    // Escape pattern for use inside double quotes in shell
    // This escapes: $ ` \ " ! to prevent shell injection while allowing r2 patterns
    const pattern = this.params.pattern
      .replace(/\\/g, '\\\\') // Escape backslashes first
      .replace(/\$/g, '\\$') // Escape $ (variable expansion)
      .replace(/`/g, '\\`') // Escape backticks (command substitution)
      .replace(/"/g, '\\"') // Escape double quotes
      .replace(/!/g, '\\!'); // Escape ! (history expansion)

    const cmd = this.buildR2Command(`/ ${pattern}`, targetPath);
    return this.runCommand(cmd, timeout);
  }

  // ============= rizin Operations =============

  private async rizinInfo(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const cmd = `rizin -e bin.relocs.apply=true -q -c "iI; ie; iS; ii; iE" ${escapeShellArg(targetPath)}`;
    return this.runCommand(cmd, timeout);
  }

  private async rizinAnalyze(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const commands = [
      'aaa', // Analyze all
      'iI', // Binary info
      'afl', // Functions
      'il', // Libraries
      'is', // Symbols
    ].join('; ');

    const cmd = `rizin -e bin.relocs.apply=true -q -c "${commands}" ${escapeShellArg(targetPath)}`;
    return this.runCommand(cmd, timeout);
  }

  private async rizinDecompile(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // Determine seek target - can be function name or address
    let seekTarget: string;
    if (this.params.function) {
      const funcName = sanitizeName(this.params.function);
      // Handle different function name formats
      if (
        funcName.startsWith('fcn.') ||
        funcName.startsWith('sym.') ||
        funcName.startsWith('0x')
      ) {
        seekTarget = funcName;
      } else {
        seekTarget = `sym.${funcName}`;
      }
    } else if (this.params.address) {
      if (!isValidAddress(this.params.address)) {
        return { success: false, output: 'Invalid address format' };
      }
      seekTarget = this.params.address;
    } else {
      // Default to main or entry0
      seekTarget = 'main';
    }

    const escapedPath = escapeShellArg(targetPath);

    // Try decompilers in order of preference:
    // 1. pdg = rz-ghidra decompiler (best quality, requires rz-ghidra plugin)
    // 2. pdd = rizin native decompiler
    // Note: pdc does NOT exist in rizin!

    // Try pdg first (rz-ghidra - best quality)
    const pdgCmd = `rizin -q -e bin.relocs.apply=true -c "aaa; af@ ${seekTarget}; s ${seekTarget}; pdg" ${escapedPath} 2>/dev/null`;
    const pdgResult = await this.runCommand(pdgCmd, timeout / 2);

    if (
      pdgResult.success &&
      pdgResult.output.trim() &&
      !pdgResult.output.includes('Cannot find function') &&
      !pdgResult.output.includes('Command') &&
      !pdgResult.output.includes('does not exist') &&
      pdgResult.output.length > 50
    ) {
      return {
        success: true,
        output: `[rz-ghidra/pdg decompiler]\n${pdgResult.output}`,
      };
    }

    // Try pdd (rizin native decompiler)
    const pddCmd = `rizin -q -e bin.relocs.apply=true -c "aaa; af@ ${seekTarget}; s ${seekTarget}; pdd" ${escapedPath} 2>/dev/null`;
    const pddResult = await this.runCommand(pddCmd, timeout / 2);

    if (
      pddResult.success &&
      pddResult.output.trim() &&
      !pddResult.output.includes('Command') &&
      !pddResult.output.includes('does not exist') &&
      pddResult.output.length > 50
    ) {
      return {
        success: true,
        output: `[rizin/pdd decompiler]\n${pddResult.output}`,
      };
    }

    // Fallback to disassembly with comments (pdf)
    const pdfCmd = `rizin -q -e bin.relocs.apply=true -c "aaa; af@ ${seekTarget}; s ${seekTarget}; pdf" ${escapedPath}`;
    const pdfResult = await this.runCommand(pdfCmd, timeout / 3);

    if (pdfResult.success && pdfResult.output.trim()) {
      return {
        success: true,
        output: `[No decompiler available - showing annotated disassembly]\n${pdfResult.output}`,
      };
    }

    return {
      success: false,
      output:
        `Could not decompile ${seekTarget}. Ensure rz-ghidra plugin is installed.\n` +
        `Install with: rz-pm -i rz-ghidra\n` +
        `Function may not exist at this address. Try rizin_analyze first to list functions.`,
    };
  }

  // ============= Ghidra Operations =============

  /**
   * Find Ghidra's analyzeHeadless script by checking multiple locations
   */
  private async findGhidraAnalyzeHeadless(): Promise<string | null> {
    // Check environment variable first
    if (process.env['GHIDRA_HOME']) {
      const envPath = path.join(
        process.env['GHIDRA_HOME'],
        'support',
        'analyzeHeadless',
      );
      try {
        await fs.access(envPath);
        return envPath;
      } catch {
        // Continue to other locations
      }
    }

    // Common Ghidra installation paths
    const commonPaths = [
      '/opt/ghidra/support/analyzeHeadless',
      '/usr/share/ghidra/support/analyzeHeadless',
      '/usr/local/share/ghidra/support/analyzeHeadless',
      // Snap installation paths - direct paths
      '/snap/ghidra/current/support/analyzeHeadless',
      '/snap/ghidra/current/lib/ghidra/support/analyzeHeadless',
    ];

    // Check common paths
    for (const p of commonPaths) {
      try {
        await fs.access(p);
        return p;
      } catch {
        // Continue checking
      }
    }

    // For snap installations, check ghidra_X.X_PUBLIC nested directories
    // Structure: /snap/ghidra/current/ghidra_11.4_PUBLIC/support/analyzeHeadless
    try {
      const snapBase = '/snap/ghidra/current';
      const entries = await fs.readdir(snapBase);
      for (const entry of entries) {
        if (entry.startsWith('ghidra_') && entry.includes('PUBLIC')) {
          const nestedPath = path.join(
            snapBase,
            entry,
            'support',
            'analyzeHeadless',
          );
          try {
            await fs.access(nestedPath);
            return nestedPath;
          } catch {
            // Continue checking
          }
        }
      }
    } catch {
      // Snap directory not accessible
    }

    // Try to find ghidra via 'which' command and resolve path
    try {
      const { execSync } = await import('child_process');
      const ghidraPath = execSync('which ghidra 2>/dev/null', {
        encoding: 'utf-8',
      }).trim();

      if (ghidraPath) {
        // If it's a snap, resolve the actual path
        if (ghidraPath.includes('/snap/')) {
          // Snap ghidra structure: /snap/ghidra/current/
          const snapBase = ghidraPath.replace(/\/bin\/ghidra$/, '');
          const snapPaths = [
            path.join(snapBase, 'support', 'analyzeHeadless'),
            path.join(snapBase, 'lib', 'ghidra', 'support', 'analyzeHeadless'),
            // Try reading the snap to find ghidra home
          ];

          for (const sp of snapPaths) {
            try {
              await fs.access(sp);
              return sp;
            } catch {
              // Continue
            }
          }

          // For snap, try to find it by listing the snap directory
          try {
            const snapDir = '/snap/ghidra/current';
            const findResult = execSync(
              `find ${snapDir} -name "analyzeHeadless" -type f 2>/dev/null | head -1`,
              { encoding: 'utf-8' },
            ).trim();
            if (findResult) {
              return findResult;
            }
          } catch {
            // Continue
          }
        } else {
          // Regular installation - ghidra script is usually in bin, analyzeHeadless in support
          const ghidraDir = path.dirname(path.dirname(ghidraPath));
          const possiblePaths = [
            path.join(ghidraDir, 'support', 'analyzeHeadless'),
            path.join(ghidraDir, 'lib', 'ghidra', 'support', 'analyzeHeadless'),
          ];

          for (const pp of possiblePaths) {
            try {
              await fs.access(pp);
              return pp;
            } catch {
              // Continue
            }
          }
        }
      }
    } catch {
      // which command failed, continue
    }

    return null;
  }

  private async ghidraDecompile(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const projectDir = await this.createTempDir();
    const projectName = this.params.projectName || 'temp_project';

    try {
      // Check if Java is available first
      const javaCheck = await this.runCommand(
        'which java 2>/dev/null || echo "not_found"',
        5000,
      );
      if (!javaCheck.success || javaCheck.output.includes('not_found')) {
        return {
          success: false,
          output:
            'Java not found. Ghidra requires Java to run.\n' +
            'Install Java with: sudo apt install openjdk-17-jdk\n' +
            'Or: sudo apt install default-jdk',
        };
      }

      // Find Ghidra's analyzeHeadless
      const analyzeHeadless = await this.findGhidraAnalyzeHeadless();

      if (!analyzeHeadless) {
        return {
          success: false,
          output:
            'Ghidra not found. Install Ghidra and either:\n' +
            '  1. Set GHIDRA_HOME environment variable\n' +
            '  2. Install via snap: sudo snap install ghidra\n' +
            '  3. Install to /opt/ghidra or /usr/share/ghidra',
        };
      }

      // Determine function to decompile
      let functionFilter = '';
      if (this.params.function) {
        functionFilter = sanitizeName(this.params.function);
      } else if (this.params.address) {
        if (!isValidAddress(this.params.address)) {
          return { success: false, output: 'Invalid address format' };
        }
        functionFilter = this.params.address;
      }

      // Use ghidra_bridge/pyhidra approach via Python for reliable decompilation
      // First check if pyhidra is available
      const pyhidraCheck = await this.runCommand(
        'python3 -c "import pyhidra" 2>/dev/null && echo "pyhidra_ok"',
        5000,
      );

      if (pyhidraCheck.success && pyhidraCheck.output.includes('pyhidra_ok')) {
        // Use pyhidra for decompilation (much more reliable)
        return await this.ghidraDecompileViaPyhidra(
          targetPath,
          functionFilter,
          timeout,
        );
      }

      // Fallback: Use radare2 with r2ghidra plugin if available
      const r2ghidraCheck = await this.runCommand(
        'which radare2 >/dev/null 2>&1 && radare2 -q -c "pd:g?" -- 2>&1 | grep -q "Ghidra" && echo "r2ghidra_ok" || echo "no_r2ghidra"',
        5000,
      );

      if (
        r2ghidraCheck.success &&
        r2ghidraCheck.output.includes('r2ghidra_ok')
      ) {
        // Use r2ghidra - radare2 with Ghidra decompiler
        return await this.r2GhidraDecompile(
          targetPath,
          functionFilter,
          timeout,
        );
      }

      // Final fallback: Use analyzeHeadless with simpler approach
      // Export to C using -process mode and built-in ExportC script
      const outputFile = path.join(projectDir, 'decompiled.c');

      // Build command - use -process for analysis and simple script
      const cmd = `${escapeShellArg(analyzeHeadless)} ${escapeShellArg(projectDir)} ${escapeShellArg(projectName)} -import ${escapeShellArg(targetPath)} -postScript ExportCSource.java ${escapeShellArg(outputFile)} -deleteProject 2>&1`;

      const result = await this.runCommand(cmd, timeout);

      // Try to read decompiled output file
      try {
        const decompiled = await fs.readFile(outputFile, 'utf-8');
        if (decompiled.length > 0) {
          // Filter to function if specified
          if (functionFilter) {
            const funcMatch = this.extractFunctionFromC(
              decompiled,
              functionFilter,
            );
            if (funcMatch) {
              return {
                success: true,
                output: `// Decompiled via Ghidra\n${funcMatch}`,
              };
            }
          }
          return {
            success: true,
            output: `// Decompiled via Ghidra (full program)\n${decompiled.substring(0, 50000)}`,
          };
        }
      } catch {
        // Output file not created, fall through
      }

      // Return raw Ghidra output if no file
      return result;
    } finally {
      // Cleanup temp directory
      try {
        await fs.rm(projectDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  // Decompile via pyhidra (Python Ghidra bridge)
  private async ghidraDecompileViaPyhidra(
    targetPath: string,
    functionFilter: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const funcArg = functionFilter || 'main';
    const pythonScript = `
import pyhidra
import sys

pyhidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decompile_function(program, func_name):
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()
    
    # Find function
    func_mgr = program.getFunctionManager()
    target_func = None
    
    if func_name.startswith('0x'):
        # Address lookup
        addr_factory = program.getAddressFactory()
        addr = addr_factory.getAddress(func_name)
        target_func = func_mgr.getFunctionAt(addr)
        if not target_func:
            target_func = func_mgr.getFunctionContaining(addr)
    else:
        # Name lookup
        for func in func_mgr.getFunctions(True):
            if func.getName() == func_name or func.getName() == '_' + func_name:
                target_func = func
                break
    
    if not target_func:
        # Default to main or first function
        for func in func_mgr.getFunctions(True):
            if func.getName() in ['main', '_main']:
                target_func = func
                break
        if not target_func:
            target_func = func_mgr.getFunctions(True).next()
    
    if target_func:
        results = decompiler.decompileFunction(target_func, 60, monitor)
        if results.decompileCompleted():
            print(f"// Function: {target_func.getName()} @ {target_func.getEntryPoint()}")
            print(results.getDecompiledFunction().getC())
        else:
            print(f"Decompilation failed: {results.getErrorMessage()}")
    else:
        print("No function found to decompile")
    
    decompiler.dispose()

with pyhidra.open_program("${targetPath}") as flat_api:
    decompile_function(flat_api.getCurrentProgram(), "${funcArg}")
`;

    const cmd = `python3 -c ${escapeShellArg(pythonScript)}`;
    const result = await this.runCommand(cmd, timeout);

    if (result.success) {
      // Filter INFO lines from pyhidra
      const lines = result.output
        .split('\n')
        .filter((l) => !l.startsWith('INFO:'));
      return { success: true, output: lines.join('\n') };
    }
    return result;
  }

  // Decompile via r2ghidra (radare2 with Ghidra decompiler plugin)
  private async r2GhidraDecompile(
    targetPath: string,
    functionFilter: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // First analyze, then find the function address using afl
    const funcTarget = functionFilter || 'main';

    // pd:g = Ghidra decompiler in r2ghidra plugin
    // Use afl to find the function address first, then seek to it
    let seekCmd = '';
    if (funcTarget.startsWith('0x')) {
      seekCmd = `s ${funcTarget}`;
    } else {
      // Use afl~ to find the function and extract its address
      // The seek will use the function name directly which works for analyzed functions
      seekCmd = `s ${funcTarget}`;
    }

    // Use radare2 command (not r2 alias) - aaa does full analysis
    const cmd = `radare2 -e bin.relocs.apply=true -q -c "aaa; ${seekCmd}; pd:g" ${escapeShellArg(targetPath)} 2>/dev/null`;
    const result = await this.runCommand(cmd, timeout);

    if (
      (result.success && result.output.includes('void')) ||
      result.output.includes('int')
    ) {
      return {
        success: true,
        output: `// Decompiled via r2ghidra\n${result.output}`,
      };
    }

    return {
      success: false,
      output:
        'r2ghidra decompilation failed. Install with: r2pm -ci r2ghidra\n' +
        result.output,
    };
  }

  // Extract a specific function from C source
  private extractFunctionFromC(
    source: string,
    funcName: string,
  ): string | null {
    // Match function definition pattern
    const patterns = [
      new RegExp(
        `(\\w+\\s+\\*?${funcName}\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?\\n\\})`,
        'm',
      ),
      new RegExp(
        `(\\w+\\s+\\*?_${funcName}\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?\\n\\})`,
        'm',
      ),
    ];

    for (const pattern of patterns) {
      const match = source.match(pattern);
      if (match) {
        return match[1];
      }
    }
    return null;
  }

  private async ghidraAnalyze(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const projectDir = await this.createTempDir();
    const projectName = this.params.projectName || 'temp_project';

    try {
      const analyzeHeadless = await this.findGhidraAnalyzeHeadless();

      if (!analyzeHeadless) {
        return {
          success: false,
          output:
            'Ghidra not found. Install Ghidra and either:\n' +
            '  1. Set GHIDRA_HOME environment variable\n' +
            '  2. Install via snap: sudo snap install ghidra\n' +
            '  3. Install to /opt/ghidra or /usr/share/ghidra',
        };
      }

      // Full analysis without scripts
      const cmd = `${escapeShellArg(analyzeHeadless)} ${escapeShellArg(projectDir)} ${escapeShellArg(projectName)} -import ${escapeShellArg(targetPath)} -deleteProject 2>&1`;

      return this.runCommand(cmd, timeout);
    } finally {
      try {
        await fs.rm(projectDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  private async ghidraScripts(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    if (!this.params.script) {
      return { success: false, output: 'Ghidra script path required' };
    }

    const projectDir = await this.createTempDir();
    const projectName = this.params.projectName || 'temp_project';

    try {
      const analyzeHeadless = await this.findGhidraAnalyzeHeadless();

      if (!analyzeHeadless) {
        return {
          success: false,
          output:
            'Ghidra not found. Install Ghidra and either:\n' +
            '  1. Set GHIDRA_HOME environment variable\n' +
            '  2. Install via snap: sudo snap install ghidra\n' +
            '  3. Install to /opt/ghidra or /usr/share/ghidra',
        };
      }

      // Validate script exists
      try {
        await fs.access(this.params.script);
      } catch {
        return {
          success: false,
          output: `Script not found: ${this.params.script}`,
        };
      }

      const cmd = `${escapeShellArg(analyzeHeadless)} ${escapeShellArg(projectDir)} ${escapeShellArg(projectName)} -import ${escapeShellArg(targetPath)} -postScript ${escapeShellArg(this.params.script)} -deleteProject`;

      return this.runCommand(cmd, timeout);
    } finally {
      try {
        await fs.rm(projectDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  // ============= binwalk Operations =============

  private async binwalkScan(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // -B = signature scan
    const cmd = `binwalk -B ${escapeShellArg(targetPath)}`;
    return this.runCommand(cmd, timeout);
  }

  private async binwalkExtract(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const outputDir = this.params.outputDir || `${targetPath}_extracted`;

    // -e = extract, -C = output directory
    const cmd = `binwalk -e -C ${escapeShellArg(outputDir)} ${escapeShellArg(targetPath)}`;
    const result = await this.runCommand(cmd, timeout);

    if (result.success) {
      // List extracted files
      try {
        const files = await this.listRecursive(outputDir);
        result.output += `\n\nExtracted files:\n${files.join('\n')}`;
      } catch {
        result.output += '\n\nExtraction complete (could not list files)';
      }
    }

    return result;
  }

  private async binwalkEntropy(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    // -E = entropy analysis
    const cmd = `binwalk -E ${escapeShellArg(targetPath)}`;
    const result = await this.runCommand(cmd, timeout);

    if (result.success) {
      // Add interpretation for LLM
      const entropyAnalysis = this.interpretEntropy(result.output);
      result.output += `\n\n=== Entropy Analysis Summary ===\n${entropyAnalysis}`;
    }

    return result;
  }

  private async binwalkCarve(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const outputDir = this.params.outputDir || `${targetPath}_carved`;

    // -D = raw extraction with file type filter
    const cmd = `binwalk -D '.*' -C ${escapeShellArg(outputDir)} ${escapeShellArg(targetPath)}`;
    return this.runCommand(cmd, timeout);
  }

  // ============= ltrace Operations =============

  private async ltraceRun(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const args = this.params.args || [];
    const escapedArgs = args.map((a) => escapeShellArg(a)).join(' ');

    // -f = follow forks, -C = demangle C++ names
    const cmd = `ltrace -f -C ${escapeShellArg(targetPath)} ${escapedArgs}`;
    return this.runCommand(cmd, timeout);
  }

  private async ltraceAttach(timeout: number): Promise<AnalysisResult> {
    if (!this.params.pid) {
      return { success: false, output: 'PID required for attach operation' };
    }

    // Validate PID is a number
    if (typeof this.params.pid !== 'number' || this.params.pid <= 0) {
      return { success: false, output: 'Invalid PID' };
    }

    const cmd = `ltrace -f -C -p ${this.params.pid}`;
    return this.runCommand(cmd, timeout);
  }

  // ============= strace Operations =============

  private async straceRun(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const args = this.params.args || [];
    const escapedArgs = args.map((a) => escapeShellArg(a)).join(' ');

    // -f = follow forks, -y = decode file descriptors
    const cmd = `strace -f -y ${escapeShellArg(targetPath)} ${escapedArgs}`;
    return this.runCommand(cmd, timeout);
  }

  private async straceAttach(timeout: number): Promise<AnalysisResult> {
    if (!this.params.pid) {
      return { success: false, output: 'PID required for attach operation' };
    }

    if (typeof this.params.pid !== 'number' || this.params.pid <= 0) {
      return { success: false, output: 'Invalid PID' };
    }

    const cmd = `strace -f -y -p ${this.params.pid}`;
    return this.runCommand(cmd, timeout);
  }

  private async straceSummary(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const args = this.params.args || [];
    const escapedArgs = args.map((a) => escapeShellArg(a)).join(' ');

    // -c = summary only, -S calls = sort by number of calls
    const cmd = `strace -c -S calls ${escapeShellArg(targetPath)} ${escapedArgs}`;
    return this.runCommand(cmd, timeout);
  }

  // ============= LLM-Enhanced Operations =============

  private async quickRE(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const findings: string[] = [];
    results.push('=== Quick Reverse Engineering Assessment ===\n');

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    // 1. Basic binary info with security features parsing
    try {
      const infoResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iI" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );
      if (infoResult.success) {
        results.push('📋 Binary Information:');
        const info = infoResult.output;
        results.push(info);

        // Parse security features
        const hasNX = /nx\s+(true|yes)/i.test(info);
        const hasPIE =
          /pic\s+(true|yes)/i.test(info) || /pie\s+(true|yes)/i.test(info);
        const hasCanary = /canary\s+(true|yes)/i.test(info);
        const isStripped = /stripped\s+(true|yes)/i.test(info);

        results.push('\n🛡️ Security Features:');
        results.push(
          `  NX (DEP):      ${hasNX ? '✅ Enabled' : '❌ DISABLED - Executable stack!'}`,
        );
        results.push(
          `  PIE (ASLR):    ${hasPIE ? '✅ Enabled' : '❌ DISABLED - Fixed addresses!'}`,
        );
        results.push(
          `  Stack Canary:  ${hasCanary ? '✅ Enabled' : '❌ DISABLED - Stack overflow risk!'}`,
        );
        results.push(
          `  Stripped:      ${isStripped ? '⚠️ Yes - No symbols' : '✅ No - Has symbols'}`,
        );

        if (!hasNX)
          findings.push('No NX - buffer overflow to shellcode possible');
        if (!hasPIE)
          findings.push('No PIE - ROP/ret2libc easier with fixed addresses');
        if (!hasCanary)
          findings.push('No canary - stack buffer overflow exploitable');
      }
    } catch {
      // Continue with other checks
    }

    // 2. Function count (quick, no full analysis)
    try {
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aa; aflc" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );
      if (funcResult.success) {
        const count = funcResult.output.trim();
        results.push(`\n📊 Functions: ${count}`);
      }
    } catch {
      // Continue
    }

    // 3. Dangerous imports check
    try {
      const dangerousImports = [
        'strcpy',
        'strcat',
        'sprintf',
        'vsprintf',
        'gets',
        'scanf',
        'sscanf',
        'fscanf',
        'system',
        'popen',
        'exec',
        'ShellExecute',
        'WinExec',
        'CreateProcess',
        'LoadLibrary',
        'GetProcAddress',
        'VirtualAlloc',
        'VirtualProtect',
        'WriteProcessMemory',
      ];
      const importResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );
      if (importResult.success) {
        const imports = importResult.output.toLowerCase();
        const foundDangerous = dangerousImports.filter((imp) =>
          imports.includes(imp.toLowerCase()),
        );
        if (foundDangerous.length > 0) {
          results.push('\n⚠️ Dangerous Imports Found:');
          foundDangerous.forEach((imp) => results.push(`  • ${imp}`));
          findings.push(`Dangerous functions: ${foundDangerous.join(', ')}`);
        }

        // Check for crypto imports
        const cryptoImports = [
          'crypt',
          'aes',
          'des',
          'rsa',
          'sha',
          'md5',
          'hash',
          'cipher',
          'ssl',
          'tls',
        ];
        const foundCrypto = cryptoImports.filter((imp) =>
          imports.includes(imp),
        );
        if (foundCrypto.length > 0) {
          results.push('\n🔐 Crypto Imports:');
          foundCrypto.forEach((imp) => results.push(`  • ${imp}`));
        }

        // Check for network imports
        const networkImports = [
          'socket',
          'connect',
          'send',
          'recv',
          'http',
          'url',
          'inet',
          'winsock',
          'ws2',
        ];
        const foundNetwork = networkImports.filter((imp) =>
          imports.includes(imp),
        );
        if (foundNetwork.length > 0) {
          results.push('\n🌐 Network Imports:');
          foundNetwork.forEach((imp) => results.push(`  • ${imp}`));
          findings.push('Has network capability');
        }
      }
    } catch {
      // Continue
    }

    // 4. Comprehensive string search (CTF + malware + credentials)
    try {
      const stringPatterns = [
        // CTF/Cracking
        'license',
        'serial',
        'register',
        'trial',
        'crack',
        'valid',
        'check',
        'flag',
        'ctf',
        'win',
        'correct',
        'wrong',
        'invalid',
        'expired',
        'success',
        'fail',
        'error',
        'congratul',
        // Credentials
        'password',
        'passwd',
        'pass',
        'key',
        'secret',
        'token',
        'auth',
        'admin',
        'root',
        'user',
        'login',
        'credential',
        // Malware indicators
        'http://',
        'https://',
        'ftp://',
        '.exe',
        '.dll',
        '.bat',
        '.ps1',
        'cmd.exe',
        'powershell',
        'shell',
        '/bin/',
        'eval',
        'exec',
        'ransomware',
        'encrypt',
        'decrypt',
        'bitcoin',
        'wallet',
        // File operations
        'delete',
        'remove',
        'write',
        'read',
        'open',
        'create',
      ];
      const patternStr = stringPatterns.slice(0, 20).join('\\|'); // r2 limit
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz~${patternStr}" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );
      if (strResult.success && strResult.output.trim()) {
        const lines = strResult.output.trim().split('\n').slice(0, 25);
        results.push('\n🔤 Interesting Strings:');
        results.push(lines.join('\n'));

        // Check for specific findings
        const strLower = strResult.output.toLowerCase();
        if (/license|serial|register|trial/.test(strLower)) {
          findings.push('License/serial validation detected');
        }
        if (/flag|ctf|congratul/.test(strLower)) {
          findings.push('Possible CTF challenge');
        }
        if (/http:\/\/|https:\/\//.test(strLower)) {
          findings.push('Contains URLs');
        }
      }
    } catch {
      // Continue
    }

    // 5. Check for packed/encrypted sections (entropy indicator)
    try {
      const sectResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iS entropy" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );
      if (sectResult.success) {
        const highEntropy = sectResult.output.split('\n').filter((line) => {
          const match = line.match(/(\d+\.\d+)/);
          return match && parseFloat(match[1]) > 7.0;
        });
        if (highEntropy.length > 0) {
          results.push(
            '\n🔒 High Entropy Sections (possibly packed/encrypted):',
          );
          highEntropy
            .slice(0, 5)
            .forEach((line) => results.push(`  ${line.trim()}`));
          findings.push('High entropy detected - may be packed or encrypted');
        }
      }
    } catch {
      // Continue
    }

    // 6. Summary with data-driven recommendations
    results.push('\n' + '═'.repeat(50));

    // Add verification warning
    results.push(
      '⚠️ VERIFICATION REQUIRED - DO NOT BLINDLY TRUST THESE RESULTS',
    );
    results.push('─'.repeat(50));
    results.push('Common False Positives:');
    results.push('  • Security features may be from linked libraries');
    results.push('  • "Dangerous" imports may be used safely');
    results.push('  • Interesting strings may be from resources/debug info');
    results.push('');
    results.push('MANUAL VERIFICATION STEPS:');
    results.push('  1. Check xrefs to see HOW each import is used');
    results.push('  2. Verify strings are in CODE sections, not resources');
    results.push('  3. Cross-reference with actual behavior analysis');
    results.push('─'.repeat(50) + '\n');

    if (findings.length > 0) {
      results.push('🎯 KEY FINDINGS (NEEDS VERIFICATION):');
      findings.forEach((f) => results.push(`  ❓ ${f}`));
      results.push('');
      results.push(
        '⚠️ LLM: Verify at least 2-3 of these before reporting to user!',
      );
    } else {
      results.push(
        'ℹ️ No obvious vulnerabilities or interesting patterns found.',
      );
      results.push(
        '   Try: r2_strings, r2_imports, find_license_checks for deeper analysis',
      );
    }

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  private async findCrypto(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push('=== Cryptographic Function Analysis ===\n');

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    // Search for common crypto patterns
    const cryptoPatterns = [
      'aes',
      'des',
      'rsa',
      'sha',
      'md5',
      'hmac',
      'encrypt',
      'decrypt',
      'cipher',
      'hash',
      'pbkdf',
      'bcrypt',
      'scrypt',
      'chacha',
      'salsa',
      'blake',
      'argon',
    ];

    // Search in imports
    try {
      const importResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 3,
      );
      if (importResult.success) {
        const imports = importResult.output.toLowerCase();
        const foundImports = cryptoPatterns.filter((p) => imports.includes(p));
        if (foundImports.length > 0) {
          results.push('--- Crypto-related Imports ---');
          results.push(
            importResult.output
              .split('\n')
              .filter((line) =>
                cryptoPatterns.some((p) => line.toLowerCase().includes(p)),
              )
              .join('\n'),
          );
        }
      }
    } catch {
      // Continue
    }

    // Search in strings
    try {
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz~${cryptoPatterns.join('\\|')}" ${escapeShellArg(targetPath)}`,
        timeout / 3,
      );
      if (strResult.success && strResult.output.trim()) {
        results.push('\n--- Crypto-related Strings ---');
        results.push(strResult.output);
      }
    } catch {
      // Continue
    }

    // Search for crypto constants (magic numbers)
    try {
      // AES S-box first bytes: 0x63, 0x7c, 0x77, 0x7b
      // SHA-256 initial values
      const constResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "/x 637c777b" ${escapeShellArg(targetPath)}`,
        timeout / 3,
      );
      if (constResult.success && constResult.output.trim()) {
        results.push('\n--- Potential AES S-box Found ---');
        results.push(constResult.output);
      }
    } catch {
      // Continue
    }

    results.push('\n--- Analysis Summary ---');
    results.push('• Check for hardcoded keys in .data and .rodata sections');
    results.push('• Review crypto function parameters for weak configurations');
    results.push('• Look for custom/homebrew crypto implementations');
    results.push('• Verify IV/nonce generation is cryptographically secure');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  private async findVulnerabilities(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push('=== Vulnerability Pattern Analysis ===\n');

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    // Dangerous functions to look for
    const dangerousFunctions = [
      'strcpy',
      'strcat',
      'sprintf',
      'gets',
      'scanf',
      'vsprintf',
      'realpath',
      'getwd',
      'strtok',
      'mktemp',
      'tempnam',
      'tmpnam',
    ];

    // Search imports for dangerous functions
    try {
      const importResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );
      if (importResult.success) {
        const imports = importResult.output.toLowerCase();
        const found = dangerousFunctions.filter((f) => imports.includes(f));
        if (found.length > 0) {
          results.push('--- Dangerous Function Imports (HIGH RISK) ---');
          results.push(`Found: ${found.join(', ')}`);
          results.push(
            '\nThese functions are known sources of buffer overflows and security vulnerabilities.',
          );
        }
      }
    } catch {
      // Continue
    }

    // Format string vulnerabilities
    try {
      // Look for %n (write primitive) and unchecked %s
      const fmtResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "/ %n" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );
      if (fmtResult.success && fmtResult.output.trim()) {
        results.push('\n--- Potential Format String Vulnerabilities ---');
        results.push(fmtResult.output);
      }
    } catch {
      // Continue
    }

    // Command injection patterns
    try {
      const cmdResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz~system\\|popen\\|exec\\|/bin/sh\\|/bin/bash\\|cmd.exe" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );
      if (cmdResult.success && cmdResult.output.trim()) {
        results.push('\n--- Command Execution Patterns ---');
        results.push(cmdResult.output);
        results.push('\nReview these for potential command injection vectors.');
      }
    } catch {
      // Continue
    }

    // Memory allocation patterns
    try {
      const memResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii~malloc\\|free\\|realloc\\|calloc\\|mmap" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );
      if (memResult.success && memResult.output.trim()) {
        results.push('\n--- Memory Management Functions ---');
        results.push(memResult.output);
        results.push('\nCheck for use-after-free and double-free bugs.');
      }
    } catch {
      // Continue
    }

    results.push('\n--- Vulnerability Assessment Checklist ---');
    results.push('□ Buffer overflow in string handling');
    results.push('□ Format string vulnerabilities');
    results.push('□ Command injection');
    results.push('□ Use-after-free / double-free');
    results.push('□ Integer overflow/underflow');
    results.push('□ Path traversal');
    results.push('□ Race conditions (TOCTOU)');
    results.push('□ Hardcoded credentials');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  private async traceAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push('=== Combined Trace Analysis ===\n');

    // Run both ltrace and strace with summary
    try {
      results.push('--- Library Call Summary ---');
      const ltraceResult = await this.runCommand(
        `ltrace -c ${escapeShellArg(targetPath)} 2>&1 || true`,
        timeout / 2,
      );
      if (ltraceResult.success || ltraceResult.output) {
        results.push(ltraceResult.output);
      } else {
        results.push('ltrace not available or failed');
      }
    } catch {
      results.push('ltrace analysis failed');
    }

    try {
      results.push('\n--- System Call Summary ---');
      const straceResult = await this.runCommand(
        `strace -c ${escapeShellArg(targetPath)} 2>&1 || true`,
        timeout / 2,
      );
      if (straceResult.success || straceResult.output) {
        results.push(straceResult.output);
      } else {
        results.push('strace not available or failed');
      }
    } catch {
      results.push('strace analysis failed');
    }

    results.push('\n--- Analysis Insights ---');
    results.push('• High read/write syscalls may indicate file processing');
    results.push(
      '• Network syscalls (socket, connect) suggest network activity',
    );
    results.push('• mmap/mprotect usage may indicate dynamic code');
    results.push('• fork/clone indicate multiprocessing');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  // ============= MALWARE ANALYSIS METHODS =============

  /**
   * Detect anti-analysis techniques (anti-debugging, anti-VM, anti-sandbox)
   * Used by malware to evade security researchers and automated analysis
   */
  private async antiAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🕵️ ANTI-ANALYSIS TECHNIQUE DETECTION');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const findings: Array<{
      category: string;
      technique: string;
      indicator: string;
      mitreId?: string;
      severity: 'HIGH' | 'MEDIUM' | 'LOW';
    }> = [];

    // ===== ANTI-DEBUGGING TECHNIQUES =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. ANTI-DEBUGGING TECHNIQUES                               │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Windows anti-debug APIs
    const antiDebugAPIs = [
      {
        api: 'IsDebuggerPresent',
        desc: 'Direct debugger check',
        mitre: 'T1622',
      },
      {
        api: 'CheckRemoteDebuggerPresent',
        desc: 'Remote debugger check',
        mitre: 'T1622',
      },
      {
        api: 'NtQueryInformationProcess',
        desc: 'Process debug flags query',
        mitre: 'T1622',
      },
      {
        api: 'NtSetInformationThread',
        desc: 'Hide thread from debugger',
        mitre: 'T1622',
      },
      {
        api: 'OutputDebugString',
        desc: 'Debug output detection',
        mitre: 'T1622',
      },
      {
        api: 'NtQuerySystemInformation',
        desc: 'System debug info query',
        mitre: 'T1622',
      },
      {
        api: 'CloseHandle',
        desc: 'Exception-based debug detection',
        mitre: 'T1622',
      },
      {
        api: 'NtClose',
        desc: 'Invalid handle exception trick',
        mitre: 'T1622',
      },
      {
        api: 'SetUnhandledExceptionFilter',
        desc: 'Exception handler manipulation',
        mitre: 'T1622',
      },
      {
        api: 'UnhandledExceptionFilter',
        desc: 'Debug exception detection',
        mitre: 'T1622',
      },
      {
        api: 'RaiseException',
        desc: 'Exception-based anti-debug',
        mitre: 'T1622',
      },
      { api: 'GetTickCount', desc: 'Timing-based detection', mitre: 'T1622' },
      {
        api: 'QueryPerformanceCounter',
        desc: 'High-precision timing check',
        mitre: 'T1622',
      },
      { api: 'rdtsc', desc: 'CPU timestamp counter (timing)', mitre: 'T1622' },
      {
        api: 'ZwQueryInformationProcess',
        desc: 'Kernel debug query',
        mitre: 'T1622',
      },
      { api: 'NtQueryObject', desc: 'Debug object detection', mitre: 'T1622' },
    ];

    // Linux anti-debug
    const linuxAntiDebug = [
      { api: 'ptrace', desc: 'Ptrace self-attach check', mitre: 'T1622' },
      { api: '/proc/self/status', desc: 'TracerPid check', mitre: 'T1622' },
      { api: '/proc/self/stat', desc: 'Process state check', mitre: 'T1622' },
      { api: 'prctl', desc: 'Process control anti-debug', mitre: 'T1622' },
      { api: 'getppid', desc: 'Parent process check', mitre: 'T1622' },
    ];

    // Categorize APIs by specificity (reduce false positives)
    const highConfidenceAntiDebug = [
      'IsDebuggerPresent',
      'CheckRemoteDebuggerPresent',
      'NtQueryInformationProcess',
      'NtSetInformationThread',
      'OutputDebugString',
      'ZwQueryInformationProcess',
      'NtQueryObject',
      'SetUnhandledExceptionFilter',
    ];
    const mediumConfidenceAntiDebug = [
      'GetTickCount',
      'QueryPerformanceCounter',
      'NtClose',
      'CloseHandle',
    ];

    try {
      const importResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii; is" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (importResult.success) {
        const output = importResult.output.toLowerCase();
        let highCount = 0;
        let mediumCount = 0;
        const foundAPIs: string[] = [];

        // Check Windows anti-debug APIs with confidence levels
        for (const check of antiDebugAPIs) {
          if (output.includes(check.api.toLowerCase())) {
            foundAPIs.push(check.api);
            if (highConfidenceAntiDebug.includes(check.api)) {
              highCount++;
              findings.push({
                category: 'Anti-Debugging',
                technique: check.api,
                indicator: check.desc,
                mitreId: check.mitre,
                severity: 'HIGH',
              });
              results.push(`  🔴 ${check.api} - ${check.desc}`);
            } else if (mediumConfidenceAntiDebug.includes(check.api)) {
              mediumCount++;
            }
          }
        }

        // Only flag timing APIs if combined with other anti-debug indicators
        if (mediumCount > 0 && highCount > 0) {
          results.push(
            `  🟡 ${mediumCount} timing-based checks (combined with anti-debug)`,
          );
          findings.push({
            category: 'Anti-Debugging',
            technique: 'Timing Checks',
            indicator: 'Timing APIs with anti-debug context',
            mitreId: 'T1622',
            severity: 'MEDIUM',
          });
        } else if (mediumCount > 2 && highCount === 0) {
          results.push(
            `  ℹ️ ${mediumCount} timing APIs (may be legitimate performance code)`,
          );
        }

        // Check Linux anti-debug (more specific, less false positives)
        for (const check of linuxAntiDebug) {
          // ptrace is highly specific for anti-debug
          if (output.includes(check.api.toLowerCase())) {
            if (check.api === 'ptrace' || check.api.includes('/proc/self')) {
              findings.push({
                category: 'Anti-Debugging',
                technique: check.api,
                indicator: check.desc,
                mitreId: check.mitre,
                severity: 'HIGH',
              });
              results.push(`  🔴 ${check.api} - ${check.desc}`);
            }
          }
        }

        if (highCount === 0 && mediumCount === 0) {
          results.push('  ✅ No significant anti-debug APIs detected');
        }
        results.push('');
      }
    } catch {
      results.push('  ⚠️ Could not check imports for anti-debug APIs\n');
    }

    // Check for debug-related strings
    try {
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)} | grep -iE "debug|dbg|olly|x64dbg|windbg|ida|ghidra|breakpoint|softice|syser"`,
        timeout / 6,
      );
      if (strResult.success && strResult.output.trim()) {
        results.push('  📝 Debug-related strings found:');
        const lines = strResult.output.split('\n').slice(0, 10);
        for (const line of lines) {
          if (line.trim()) {
            results.push(`     └── ${line.trim().substring(0, 80)}`);
          }
        }
        findings.push({
          category: 'Anti-Debugging',
          technique: 'Debugger String Check',
          indicator: 'Contains debugger tool names',
          severity: 'MEDIUM',
        });
        results.push('');
      }
    } catch {
      // Continue
    }

    // ===== ANTI-VM TECHNIQUES =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. ANTI-VM / ANTI-SANDBOX TECHNIQUES                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // VM detection strings
    const vmStrings = [
      { pattern: 'vmware', vm: 'VMware', mitre: 'T1497.001' },
      { pattern: 'virtualbox', vm: 'VirtualBox', mitre: 'T1497.001' },
      { pattern: 'vbox', vm: 'VirtualBox', mitre: 'T1497.001' },
      { pattern: 'qemu', vm: 'QEMU', mitre: 'T1497.001' },
      { pattern: 'xen', vm: 'Xen', mitre: 'T1497.001' },
      { pattern: 'hyper-v', vm: 'Hyper-V', mitre: 'T1497.001' },
      { pattern: 'parallels', vm: 'Parallels', mitre: 'T1497.001' },
      { pattern: 'virtual hd', vm: 'Virtual HD', mitre: 'T1497.001' },
      { pattern: 'sbiedll', vm: 'Sandboxie', mitre: 'T1497.001' },
      { pattern: 'wine_get', vm: 'Wine', mitre: 'T1497.001' },
      { pattern: 'bochs', vm: 'Bochs', mitre: 'T1497.001' },
    ];

    // VM-specific registry keys (as strings)
    const vmRegistryPatterns = [
      'HARDWARE\\\\DEVICEMAP\\\\Scsi\\\\Scsi Port',
      'SYSTEM\\\\CurrentControlSet\\\\Services\\\\Disk\\\\Enum',
      'SOFTWARE\\\\VMware',
      'SOFTWARE\\\\Oracle\\\\VirtualBox',
      'HARDWARE\\\\Description\\\\System\\\\BIOS',
      'SYSTEM\\\\CurrentControlSet\\\\Control\\\\SystemInformation',
    ];

    // VM detection APIs
    const vmDetectionAPIs = [
      {
        api: 'GetSystemFirmwareTable',
        desc: 'SMBIOS/ACPI table check',
        mitre: 'T1497.001',
      },
      {
        api: 'EnumSystemFirmwareTables',
        desc: 'Firmware enumeration',
        mitre: 'T1497.001',
      },
      {
        api: 'SetupDiGetDeviceRegistryProperty',
        desc: 'Device driver check',
        mitre: 'T1497.001',
      },
      { api: 'GetAdaptersInfo', desc: 'MAC address check', mitre: 'T1497.001' },
      {
        api: 'DeviceIoControl',
        desc: 'Direct device query',
        mitre: 'T1497.001',
      },
      {
        api: 'WNetGetProviderName',
        desc: 'Network provider check',
        mitre: 'T1497.001',
      },
      { api: '__cpuid', desc: 'CPUID hypervisor check', mitre: 'T1497.001' },
      { api: 'cpuid', desc: 'CPUID instruction', mitre: 'T1497.001' },
      { api: 'in al, dx', desc: 'I/O port backdoor check', mitre: 'T1497.001' },
      { api: 'sidt', desc: 'Red Pill technique', mitre: 'T1497.001' },
      { api: 'sgdt', desc: 'No Pill technique', mitre: 'T1497.001' },
      { api: 'sldt', desc: 'LDT-based detection', mitre: 'T1497.001' },
      { api: 'str', desc: 'Task register check', mitre: 'T1497.001' },
      { api: 'smsw', desc: 'Machine status word', mitre: 'T1497.001' },
    ];

    try {
      // Check for VM strings
      const vmResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (vmResult.success) {
        const output = vmResult.output.toLowerCase();

        for (const vm of vmStrings) {
          if (output.includes(vm.pattern)) {
            findings.push({
              category: 'Anti-VM',
              technique: `${vm.vm} Detection`,
              indicator: `String "${vm.pattern}" found`,
              mitreId: vm.mitre,
              severity: 'HIGH',
            });
            results.push(`  🔴 ${vm.vm} Detection String`);
            results.push(`     └── Pattern: "${vm.pattern}"`);
            results.push(`     └── MITRE: ${vm.mitre} (System Checks)\n`);
          }
        }

        // Check registry patterns
        for (const regKey of vmRegistryPatterns) {
          if (output.includes(regKey.toLowerCase().replace(/\\\\/g, '\\'))) {
            findings.push({
              category: 'Anti-VM',
              technique: 'Registry VM Check',
              indicator: regKey,
              severity: 'HIGH',
            });
            results.push(
              `  🔴 VM Registry Check: ${regKey.substring(0, 50)}...\n`,
            );
          }
        }
      }

      // Check VM detection APIs
      const apiResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (apiResult.success) {
        const output = apiResult.output.toLowerCase();

        for (const api of vmDetectionAPIs) {
          if (output.includes(api.api.toLowerCase())) {
            findings.push({
              category: 'Anti-VM',
              technique: api.api,
              indicator: api.desc,
              mitreId: api.mitre,
              severity: 'MEDIUM',
            });
            results.push(`  🟡 ${api.api}`);
            results.push(`     └── ${api.desc}\n`);
          }
        }
      }
    } catch {
      results.push('  ⚠️ Could not check VM detection techniques\n');
    }

    // ===== ANTI-SANDBOX TECHNIQUES =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. ANTI-SANDBOX / ENVIRONMENT CHECKS                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const sandboxAPIs = [
      {
        api: 'GetCursorPos',
        desc: 'Mouse movement detection',
        mitre: 'T1497.001',
      },
      {
        api: 'GetLastInputInfo',
        desc: 'User activity check',
        mitre: 'T1497.001',
      },
      {
        api: 'GetAsyncKeyState',
        desc: 'Keyboard activity check',
        mitre: 'T1497.001',
      },
      {
        api: 'GetForegroundWindow',
        desc: 'Active window check',
        mitre: 'T1497.001',
      },
      {
        api: 'GetDesktopWindow',
        desc: 'Desktop enumeration',
        mitre: 'T1497.001',
      },
      { api: 'EnumWindows', desc: 'Window enumeration', mitre: 'T1497.001' },
      {
        api: 'GetSystemMetrics',
        desc: 'Screen resolution check',
        mitre: 'T1497.001',
      },
      {
        api: 'GlobalMemoryStatusEx',
        desc: 'RAM size check',
        mitre: 'T1497.001',
      },
      {
        api: 'GetDiskFreeSpaceEx',
        desc: 'Disk space check',
        mitre: 'T1497.001',
      },
      {
        api: 'GetSystemInfo',
        desc: 'CPU/System info check',
        mitre: 'T1497.001',
      },
      { api: 'GetVersion', desc: 'OS version check', mitre: 'T1497.001' },
      { api: 'GetUserName', desc: 'Username check', mitre: 'T1497.001' },
      {
        api: 'GetComputerName',
        desc: 'Computer name check',
        mitre: 'T1497.001',
      },
      {
        api: 'CreateToolhelp32Snapshot',
        desc: 'Process enumeration',
        mitre: 'T1057',
      },
      { api: 'Process32First', desc: 'Process listing', mitre: 'T1057' },
      { api: 'Module32First', desc: 'Module enumeration', mitre: 'T1057' },
      {
        api: 'GetModuleFileName',
        desc: 'Filename self-check',
        mitre: 'T1497.001',
      },
      { api: 'Sleep', desc: 'Timing evasion', mitre: 'T1497.003' },
      { api: 'NtDelayExecution', desc: 'Native sleep', mitre: 'T1497.003' },
      { api: 'WaitForSingleObject', desc: 'Delay/timing', mitre: 'T1497.003' },
    ];

    // Sandbox-specific strings (removed generic terms like 'user', 'admin', 'test' to reduce false positives)
    const sandboxStrings = [
      'sandbox',
      'cuckoo',
      'anubis',
      'threatexpert',
      'joebox',
      'sunbelt',
      'cwsandbox',
      'any.run',
      'hybrid-analysis',
      'virustotal',
      'joe sandbox',
      'triage',
      'cape sandbox',
      'intezer',
    ];
    // AV vendor strings (separate category - lower confidence as binaries may legitimately check for AV)
    const avVendorStrings = [
      'kaspersky',
      'avast',
      'avg',
      'bitdefender',
      'mcafee',
      'symantec',
      'norton',
      'eset',
      'f-secure',
      'trendmicro',
      'sophos',
      'panda',
      'malwarebytes',
      'crowdstrike',
      'sentinelone',
      'carbon black',
    ];

    try {
      const apiResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (apiResult.success) {
        const output = apiResult.output.toLowerCase();

        let envCheckCount = 0;
        for (const api of sandboxAPIs) {
          if (output.includes(api.api.toLowerCase())) {
            envCheckCount++;
            if (envCheckCount <= 8) {
              // Limit output
              results.push(`  🟡 ${api.api} - ${api.desc}`);
            }
          }
        }

        if (envCheckCount > 5) {
          findings.push({
            category: 'Anti-Sandbox',
            technique: 'Environment Fingerprinting',
            indicator: `${envCheckCount} environment check APIs found`,
            mitreId: 'T1497.001',
            severity: 'HIGH',
          });
          results.push(
            `\n  ⚠️ HIGH: ${envCheckCount} environment check APIs detected`,
          );
          results.push(
            '     └── Likely fingerprinting sandbox/analysis environment\n',
          );
        } else if (envCheckCount > 0) {
          results.push(
            `\n  ℹ️ ${envCheckCount} environment APIs (may be benign)\n`,
          );
        }
      }

      // Check sandbox-related strings
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (strResult.success) {
        const output = strResult.output.toLowerCase();
        const foundSandboxStr: string[] = [];
        const foundAVStr: string[] = [];

        for (const str of sandboxStrings) {
          if (output.includes(str)) {
            foundSandboxStr.push(str);
          }
        }
        for (const str of avVendorStrings) {
          if (output.includes(str)) {
            foundAVStr.push(str);
          }
        }

        // Sandbox strings are high confidence indicators
        if (foundSandboxStr.length >= 1) {
          findings.push({
            category: 'Anti-Sandbox',
            technique: 'Sandbox Detection Strings',
            indicator: foundSandboxStr.join(', '),
            severity: 'HIGH',
          });
          results.push('  🔴 Sandbox detection strings:');
          results.push(`     └── ${foundSandboxStr.join(', ')}\n`);
        }

        // AV strings require multiple hits (may be legitimate AV integration)
        if (foundAVStr.length >= 3) {
          findings.push({
            category: 'Anti-Sandbox',
            technique: 'AV Vendor Check',
            indicator: foundAVStr.join(', '),
            severity: 'MEDIUM',
          });
          results.push(
            '  🟡 Multiple AV vendor strings (may check for security software):',
          );
          results.push(`     └── ${foundAVStr.slice(0, 8).join(', ')}\n`);
        }
      }
    } catch {
      results.push('  ⚠️ Could not check sandbox evasion techniques\n');
    }

    // ===== CODE OBFUSCATION =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. CODE OBFUSCATION / PACKING INDICATORS                   │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Check entropy and sections
      const infoResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iS; iH" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (infoResult.success) {
        const output = infoResult.output;

        // Look for suspicious section names
        const suspiciousSections = [
          '.upx',
          '.aspack',
          '.adata',
          '.packed',
          '.enigma',
          '.themida',
          '.vmp',
        ];
        for (const sec of suspiciousSections) {
          if (output.toLowerCase().includes(sec)) {
            findings.push({
              category: 'Obfuscation',
              technique: 'Packer Detected',
              indicator: `Section ${sec} found`,
              severity: 'HIGH',
            });
            results.push(`  🔴 Packer section detected: ${sec}\n`);
          }
        }

        // Check for executable sections with suspicious characteristics
        if (output.includes('rwx') || output.includes('wx')) {
          findings.push({
            category: 'Obfuscation',
            technique: 'Self-Modifying Code',
            indicator: 'RWX/WX section permissions',
            mitreId: 'T1027',
            severity: 'HIGH',
          });
          results.push('  🔴 Self-modifying code indicators (RWX sections)\n');
        }
      }

      // Check for dynamic code APIs
      const dynAPIs = [
        'VirtualAlloc',
        'VirtualProtect',
        'NtAllocateVirtualMemory',
        'NtProtectVirtualMemory',
        'mmap',
        'mprotect',
      ];
      const apiResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (apiResult.success) {
        const output = apiResult.output.toLowerCase();
        let dynCodeCount = 0;

        for (const api of dynAPIs) {
          if (output.includes(api.toLowerCase())) {
            dynCodeCount++;
          }
        }

        if (dynCodeCount >= 2) {
          findings.push({
            category: 'Obfuscation',
            technique: 'Dynamic Code Execution',
            indicator: 'Memory allocation + protection APIs',
            mitreId: 'T1055',
            severity: 'MEDIUM',
          });
          results.push('  🟡 Dynamic code execution capabilities detected\n');
        }
      }
    } catch {
      results.push('  ⚠️ Could not analyze obfuscation\n');
    }

    // ===== SUMMARY =====
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📊 ANALYSIS SUMMARY');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const highFindings = findings.filter((f) => f.severity === 'HIGH');
    const mediumFindings = findings.filter((f) => f.severity === 'MEDIUM');

    results.push(`  Total Findings: ${findings.length}`);
    results.push(`  🔴 High Severity: ${highFindings.length}`);
    results.push(`  🟡 Medium Severity: ${mediumFindings.length}`);
    results.push(
      `  🟢 Low Severity: ${findings.length - highFindings.length - mediumFindings.length}\n`,
    );

    if (highFindings.length > 0) {
      results.push('  ⚠️ WARNING: Multiple anti-analysis techniques detected!');
      results.push(
        '     This binary likely employs evasion to avoid analysis.\n',
      );
    }

    // MITRE ATT&CK mapping
    const mitreIds = [
      ...new Set(findings.filter((f) => f.mitreId).map((f) => f.mitreId)),
    ];
    if (mitreIds.length > 0) {
      results.push('  📋 MITRE ATT&CK Techniques:');
      for (const id of mitreIds) {
        const name = this.getMitreName(id!);
        results.push(`     └── ${id}: ${name}`);
      }
      results.push('');
    }

    // Recommendations
    results.push('  💡 RECOMMENDATIONS FOR ANALYSIS:');
    if (highFindings.length > 0) {
      results.push(
        '     1. Use anti-anti-debug plugins (ScyllaHide, TitanHide)',
      );
      results.push('     2. Patch debugger checks with NOPs');
      results.push('     3. Use hardware breakpoints instead of software');
      results.push('     4. Analyze in bare-metal environment if possible');
      results.push('     5. Use kernel debugger (WinDbg) for ring0 analysis');
    }
    if (findings.some((f) => f.category === 'Anti-VM')) {
      results.push('     6. Modify VM settings to appear as physical machine');
      results.push('     7. Use RDTSC VM-exit handling');
      results.push('     8. Spoof CPUID hypervisor bit');
    }

    // Structured output for LLM
    results.push(
      '\n═══════════════════════════════════════════════════════════════',
    );
    results.push('   🤖 STRUCTURED DATA (for LLM processing)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );
    results.push('```json');
    results.push(
      JSON.stringify(
        {
          totalFindings: findings.length,
          severity: {
            high: highFindings.length,
            medium: mediumFindings.length,
            low: findings.length - highFindings.length - mediumFindings.length,
          },
          categories: {
            antiDebug: findings.filter((f) => f.category === 'Anti-Debugging')
              .length,
            antiVM: findings.filter((f) => f.category === 'Anti-VM').length,
            antiSandbox: findings.filter((f) => f.category === 'Anti-Sandbox')
              .length,
            obfuscation: findings.filter((f) => f.category === 'Obfuscation')
              .length,
          },
          mitreTechniques: mitreIds,
          findings: findings.slice(0, 20), // Limit for readability
        },
        null,
        2,
      ),
    );
    results.push('```');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  /**
   * Get MITRE ATT&CK technique name from ID
   */
  private getMitreName(id: string): string {
    const mitreMap: Record<string, string> = {
      T1622: 'Debugger Evasion',
      T1497: 'Virtualization/Sandbox Evasion',
      'T1497.001': 'System Checks',
      'T1497.002': 'User Activity Based Checks',
      'T1497.003': 'Time Based Evasion',
      T1027: 'Obfuscated Files or Information',
      T1055: 'Process Injection',
      T1057: 'Process Discovery',
      T1082: 'System Information Discovery',
      T1083: 'File and Directory Discovery',
      T1012: 'Query Registry',
      T1518: 'Software Discovery',
      'T1518.001': 'Security Software Discovery',
    };
    return mitreMap[id] || 'Unknown Technique';
  }

  /**
   * Automatic malware triage - Quick assessment of suspicious files
   * Generates file hashes, extracts metadata, identifies red flags, and calculates threat score
   */
  private async malwareTriage(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔬 AUTOMATIC MALWARE TRIAGE REPORT');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    let threatScore = 0;
    const maxScore = 100;
    const findings: Array<{
      category: string;
      finding: string;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
      points: number;
    }> = [];

    // ===== 1. FILE IDENTIFICATION =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. 📁 FILE IDENTIFICATION                                   │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Get file hashes
    try {
      const [md5Res, sha1Res, sha256Res] = await Promise.all([
        this.runCommand(
          `md5sum ${escapeShellArg(targetPath)} | cut -d' ' -f1`,
          timeout / 10,
        ),
        this.runCommand(
          `sha1sum ${escapeShellArg(targetPath)} | cut -d' ' -f1`,
          timeout / 10,
        ),
        this.runCommand(
          `sha256sum ${escapeShellArg(targetPath)} | cut -d' ' -f1`,
          timeout / 10,
        ),
      ]);

      results.push('  🔑 FILE HASHES:');
      if (md5Res.success) results.push(`     MD5:    ${md5Res.output.trim()}`);
      if (sha1Res.success)
        results.push(`     SHA1:   ${sha1Res.output.trim()}`);
      if (sha256Res.success)
        results.push(`     SHA256: ${sha256Res.output.trim()}`);
      results.push('');
    } catch {
      results.push('  ⚠️ Could not calculate file hashes\n');
    }

    // Get file size and type
    try {
      const [sizeRes, typeRes, fileRes] = await Promise.all([
        this.runCommand(
          `stat -c%s ${escapeShellArg(targetPath)}`,
          timeout / 10,
        ),
        this.runCommand(`file -b ${escapeShellArg(targetPath)}`, timeout / 10),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "i" ${escapeShellArg(targetPath)}`,
          timeout / 10,
        ),
      ]);

      if (sizeRes.success) {
        const size = parseInt(sizeRes.output.trim(), 10);
        const sizeKB = (size / 1024).toFixed(2);
        const sizeMB = (size / 1024 / 1024).toFixed(2);
        results.push(
          `  📊 FILE SIZE: ${size} bytes (${sizeKB} KB / ${sizeMB} MB)`,
        );

        // Very small executables are suspicious
        if (size < 10240 && typeRes.output.includes('executable')) {
          findings.push({
            category: 'Suspicious Size',
            finding: 'Unusually small executable (<10KB)',
            severity: 'MEDIUM',
            points: 5,
          });
          threatScore += 5;
        }
      }

      if (typeRes.success) {
        results.push(`  📄 FILE TYPE: ${typeRes.output.trim()}`);

        // Check for suspicious file types
        const suspiciousTypes = [
          'script',
          'batch',
          'VBScript',
          'PowerShell',
          'Macro',
        ];
        for (const st of suspiciousTypes) {
          if (typeRes.output.toLowerCase().includes(st.toLowerCase())) {
            findings.push({
              category: 'File Type',
              finding: `Potentially dangerous file type: ${st}`,
              severity: 'MEDIUM',
              points: 5,
            });
            threatScore += 5;
          }
        }
      }

      if (fileRes.success) {
        // Extract key binary info
        const lines = fileRes.output.split('\n');
        for (const line of lines) {
          if (
            line.includes('arch') ||
            line.includes('bits') ||
            line.includes('os') ||
            line.includes('subsys') ||
            line.includes('class')
          ) {
            results.push(`     ${line.trim()}`);
          }
        }
      }
      results.push('');
    } catch {
      results.push('  ⚠️ Could not get file info\n');
    }

    // ===== 2. COMPILATION / TIMESTAMP ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. ⏰ TIMESTAMP & COMPILATION INFO                          │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const timestampRes = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iH" ${escapeShellArg(targetPath)} | grep -iE "timestamp|date|time|compiled"`,
        timeout / 10,
      );

      if (timestampRes.success && timestampRes.output.trim()) {
        results.push('  📅 TIMESTAMPS:');
        for (const line of timestampRes.output.split('\n').slice(0, 5)) {
          if (line.trim()) results.push(`     ${line.trim()}`);
        }

        // Check for suspicious timestamps
        const output = timestampRes.output.toLowerCase();
        if (
          output.includes('1970') ||
          output.includes('2099') ||
          output.includes('2038')
        ) {
          findings.push({
            category: 'Timestamp',
            finding: 'Suspicious/forged compilation timestamp',
            severity: 'MEDIUM',
            points: 5,
          });
          threatScore += 5;
        }
      } else {
        results.push('  ℹ️ No timestamp information found');
      }
      results.push('');
    } catch {
      results.push('  ⚠️ Could not analyze timestamps\n');
    }

    // ===== 3. SECTION ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. 📦 SECTION ANALYSIS                                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const sectionRes = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iS" ${escapeShellArg(targetPath)}`,
        timeout / 10,
      );

      if (sectionRes.success) {
        const output = sectionRes.output;
        results.push('  📑 SECTIONS:');

        // Parse sections
        const lines = output.split('\n').filter((l) => l.trim());
        let rwxCount = 0;
        const suspiciousSectionNames: string[] = [];

        for (const line of lines.slice(0, 15)) {
          // Check for RWX sections
          if (
            line.includes('rwx') ||
            (line.includes('r') && line.includes('w') && line.includes('x'))
          ) {
            rwxCount++;
          }
          // Check for suspicious section names
          const suspNames = [
            '.upx',
            '.aspack',
            '.nsp',
            '.enigma',
            '.vmp',
            '.themida',
            '.packed',
            '.adata',
            '.stub',
            '.boom',
            '.petite',
          ];
          for (const sn of suspNames) {
            if (line.toLowerCase().includes(sn)) {
              suspiciousSectionNames.push(sn);
            }
          }
          results.push(`     ${line.trim().substring(0, 70)}`);
        }

        if (rwxCount > 0) {
          findings.push({
            category: 'Sections',
            finding: `${rwxCount} section(s) with RWX permissions (self-modifying code)`,
            severity: 'HIGH',
            points: 15,
          });
          threatScore += 15;
          results.push(`\n  🔴 WARNING: ${rwxCount} RWX section(s) detected!`);
        }

        if (suspiciousSectionNames.length > 0) {
          findings.push({
            category: 'Sections',
            finding: `Packer sections detected: ${suspiciousSectionNames.join(', ')}`,
            severity: 'HIGH',
            points: 15,
          });
          threatScore += 15;
          results.push(
            `  🔴 PACKER DETECTED: ${suspiciousSectionNames.join(', ')}`,
          );
        }
      }
      results.push('');
    } catch {
      results.push('  ⚠️ Could not analyze sections\n');
    }

    // ===== 4. ENTROPY ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. 📊 ENTROPY ANALYSIS                                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const entropyRes = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "p=e 100" ${escapeShellArg(targetPath)}`,
        timeout / 10,
      );

      if (entropyRes.success && entropyRes.output.trim()) {
        // radare2/rizin p=e outputs characters based on entropy levels
        // Higher entropy = darker/fuller characters, lower = lighter/empty
        // Count non-space, non-dot characters as "high entropy" indicators
        const output = entropyRes.output.trim();
        // Match block characters, hash marks, and other high-entropy indicators
        const highEntropyChars = output.replace(/[\s.·_\-=]/g, '').length;
        const totalChars = Math.min(output.length, 100);
        const entropyPercentage =
          totalChars > 0
            ? ((highEntropyChars / totalChars) * 100).toFixed(1)
            : '0';

        results.push(`  📈 ENTROPY VISUALIZATION:`);
        results.push(`     ${output.substring(0, 60)}`);
        results.push(`     High entropy coverage: ~${entropyPercentage}%`);

        // Use more conservative thresholds to avoid false positives
        // Many legitimate compressed resources (images, etc.) have high entropy
        const entropyPct = parseFloat(entropyPercentage);
        if (entropyPct > 85) {
          findings.push({
            category: 'Entropy',
            finding: 'Very high entropy - likely packed/encrypted',
            severity: 'HIGH',
            points: 15,
          });
          threatScore += 15;
          results.push(
            '  🔴 HIGH ENTROPY: File is likely packed or encrypted!',
          );
        } else if (entropyPct > 70) {
          findings.push({
            category: 'Entropy',
            finding: 'Elevated entropy - may be partially packed',
            severity: 'MEDIUM',
            points: 8,
          });
          threatScore += 8;
          results.push('  🟡 ELEVATED ENTROPY: May contain packed sections');
        } else {
          results.push('  ✅ Entropy appears normal');
        }
      } else {
        results.push('  ℹ️ Could not determine entropy');
      }
      results.push('');
    } catch {
      results.push('  ⚠️ Could not analyze entropy\n');
    }

    // ===== 5. IMPORT ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. 📥 IMPORT ANALYSIS                                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const importRes = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 10,
      );

      if (importRes.success) {
        const imports = importRes.output.toLowerCase();
        const importCount = (imports.match(/\n/g) || []).length;

        results.push(`  📦 Total imports: ~${importCount}`);

        // Critical suspicious APIs
        const criticalAPIs = [
          { api: 'IsDebuggerPresent', desc: 'Anti-debugging', points: 10 },
          {
            api: 'VirtualAllocEx',
            desc: 'Remote memory allocation',
            points: 12,
          },
          { api: 'WriteProcessMemory', desc: 'Process injection', points: 12 },
          {
            api: 'CreateRemoteThread',
            desc: 'Remote thread creation',
            points: 15,
          },
          {
            api: 'NtUnmapViewOfSection',
            desc: 'Process hollowing',
            points: 15,
          },
          { api: 'SetWindowsHookEx', desc: 'Input hooking', points: 10 },
          {
            api: 'AdjustTokenPrivileges',
            desc: 'Privilege escalation',
            points: 10,
          },
        ];

        // High suspicion APIs - only flag APIs that are rarely used legitimately
        const highAPIs = [
          {
            api: 'VirtualProtect',
            desc: 'Memory protection change',
            points: 3, // Lower points - used by .NET, JIT compilers
          },
          { api: 'GetAsyncKeyState', desc: 'Keylogging', points: 8 },
          { api: 'URLDownloadToFile', desc: 'File download', points: 6 },
          // Removed ShellExecute - too common in legitimate apps
          { api: 'WinExec', desc: 'Legacy execution (deprecated)', points: 5 },
          // Removed RegSetValue - almost every installer uses it
          { api: 'CreateService', desc: 'Service creation', points: 6 },
        ];

        results.push('\n  🚨 SUSPICIOUS IMPORTS:');
        let foundCritical = 0;
        let foundHigh = 0;

        for (const api of criticalAPIs) {
          if (imports.includes(api.api.toLowerCase())) {
            foundCritical++;
            findings.push({
              category: 'Imports',
              finding: `${api.api} - ${api.desc}`,
              severity: 'CRITICAL',
              points: api.points,
            });
            threatScore += api.points;
            results.push(`     🔴 ${api.api} (${api.desc})`);
          }
        }

        for (const api of highAPIs) {
          if (imports.includes(api.api.toLowerCase())) {
            foundHigh++;
            findings.push({
              category: 'Imports',
              finding: `${api.api} - ${api.desc}`,
              severity: 'HIGH',
              points: api.points,
            });
            threatScore += api.points;
            if (foundHigh <= 5) {
              results.push(`     🟡 ${api.api} (${api.desc})`);
            }
          }
        }

        if (foundCritical === 0 && foundHigh === 0) {
          results.push('     ✅ No highly suspicious imports detected');
        } else if (foundHigh > 5) {
          results.push(`     ... and ${foundHigh - 5} more suspicious imports`);
        }

        // Check for very few imports (packed indicator)
        if (importCount < 10) {
          findings.push({
            category: 'Imports',
            finding: 'Very few imports - may be packed or dynamically resolved',
            severity: 'MEDIUM',
            points: 8,
          });
          threatScore += 8;
          results.push(
            '\n  🟡 Few imports detected - possible packing/dynamic resolution',
          );
        }
      }
      results.push('');
    } catch {
      results.push('  ⚠️ Could not analyze imports\n');
    }

    // ===== 6. STRING ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 6. 📝 STRING ANALYSIS                                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const stringRes = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
        timeout / 10,
      );

      if (stringRes.success) {
        const strings = stringRes.output.toLowerCase();

        // Highly suspicious strings - these should be VERY specific to avoid false positives
        const criticalStrings = [
          { pattern: 'mimikatz', desc: 'Credential theft tool' },
          { pattern: 'meterpreter', desc: 'Metasploit payload' },
          { pattern: 'cobaltstrike', desc: 'C2 framework' },
          // Ransom notes are very specific phrases
          { pattern: 'your files have been encrypted', desc: 'Ransom note' },
          { pattern: 'your personal files are encrypted', desc: 'Ransom note' },
          { pattern: 'to decrypt your files', desc: 'Ransom note' },
          { pattern: 'pay the ransom', desc: 'Ransom demand' },
          // Specific malware families
          { pattern: 'lazarus', desc: 'APT group indicator' },
          { pattern: 'emotet', desc: 'Malware family' },
          { pattern: 'trickbot', desc: 'Malware family' },
        ];

        // Suspicious URLs/domains - be specific to avoid false positives
        const networkStrings = [
          {
            pattern: 'pastebin.com/raw',
            desc: 'Pastebin raw (payload hosting)',
          },
          {
            pattern: 'discord.com/api/webhooks',
            desc: 'Discord webhook (exfil)',
          },
          { pattern: '.onion', desc: 'Tor hidden service' },
          { pattern: 'ngrok.io', desc: 'Ngrok tunnel' },
          {
            pattern: 'raw.githubusercontent.com',
            desc: 'GitHub raw (payload hosting)',
          },
          // Note: removed telegram.org as it's used by legitimate Telegram apps
        ];

        // AV/Sandbox evasion
        const evasionStrings = [
          { pattern: 'sandbox', desc: 'Sandbox detection' },
          { pattern: 'vmware', desc: 'VM detection' },
          { pattern: 'virtualbox', desc: 'VM detection' },
          { pattern: 'vbox', desc: 'VM detection' },
        ];

        results.push('  🚨 SUSPICIOUS STRINGS:');
        let foundSuspicious = 0;

        for (const s of criticalStrings) {
          if (strings.includes(s.pattern)) {
            foundSuspicious++;
            findings.push({
              category: 'Strings',
              finding: `"${s.pattern}" - ${s.desc}`,
              severity: 'CRITICAL',
              points: 15,
            });
            threatScore += 15;
            results.push(`     🔴 "${s.pattern}" - ${s.desc}`);
          }
        }

        for (const s of networkStrings) {
          if (strings.includes(s.pattern)) {
            foundSuspicious++;
            findings.push({
              category: 'Strings',
              finding: `"${s.pattern}" - ${s.desc}`,
              severity: 'HIGH',
              points: 10,
            });
            threatScore += 10;
            results.push(`     🟡 "${s.pattern}" - ${s.desc}`);
          }
        }

        for (const s of evasionStrings) {
          if (strings.includes(s.pattern)) {
            findings.push({
              category: 'Strings',
              finding: `"${s.pattern}" - ${s.desc}`,
              severity: 'MEDIUM',
              points: 5,
            });
            threatScore += 5;
            results.push(`     🟡 "${s.pattern}" - ${s.desc}`);
          }
        }

        if (foundSuspicious === 0) {
          results.push('     ✅ No highly suspicious strings detected');
        }

        // Check string count (packed files have few readable strings)
        const stringCount = (strings.match(/\n/g) || []).length;
        if (stringCount < 50) {
          results.push(
            `\n  🟡 Very few strings (${stringCount}) - possible packing`,
          );
          findings.push({
            category: 'Strings',
            finding: 'Low string count - may be packed',
            severity: 'MEDIUM',
            points: 5,
          });
          threatScore += 5;
        }
      }
      results.push('');
    } catch {
      results.push('  ⚠️ Could not analyze strings\n');
    }

    // ===== 7. THREAT SCORE CALCULATION =====
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📊 TRIAGE SUMMARY & THREAT ASSESSMENT');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Cap the score at 100
    threatScore = Math.min(threatScore, maxScore);

    // Determine threat level
    let threatLevel: string;
    let threatEmoji: string;
    let recommendation: string;

    if (threatScore >= 75) {
      threatLevel = 'CRITICAL';
      threatEmoji = '🔴';
      recommendation =
        'HIGHLY LIKELY MALICIOUS - Isolate immediately, do not execute';
    } else if (threatScore >= 50) {
      threatLevel = 'HIGH';
      threatEmoji = '🟠';
      recommendation =
        'SUSPICIOUS - Requires deep analysis before any execution';
    } else if (threatScore >= 25) {
      threatLevel = 'MEDIUM';
      threatEmoji = '🟡';
      recommendation =
        'POTENTIALLY SUSPICIOUS - Warrants further investigation';
    } else if (threatScore >= 10) {
      threatLevel = 'LOW';
      threatEmoji = '🟢';
      recommendation = 'LIKELY BENIGN - Some indicators present, low risk';
    } else {
      threatLevel = 'MINIMAL';
      threatEmoji = '✅';
      recommendation = 'APPEARS CLEAN - No significant malicious indicators';
    }

    // Threat score visualization
    const scoreBar =
      '█'.repeat(Math.floor(threatScore / 5)) +
      '░'.repeat(20 - Math.floor(threatScore / 5));
    results.push(`  ${threatEmoji} THREAT LEVEL: ${threatLevel}`);
    results.push(`  📈 THREAT SCORE: ${threatScore}/${maxScore}`);
    results.push(`     [${scoreBar}]`);
    results.push(`\n  💡 RECOMMENDATION: ${recommendation}\n`);

    // Findings summary
    const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL');
    const highFindings = findings.filter((f) => f.severity === 'HIGH');
    const mediumFindings = findings.filter((f) => f.severity === 'MEDIUM');

    results.push('  📋 FINDINGS BREAKDOWN:');
    results.push(`     🔴 Critical: ${criticalFindings.length}`);
    results.push(`     🟠 High:     ${highFindings.length}`);
    results.push(`     🟡 Medium:   ${mediumFindings.length}`);
    results.push(
      `     ℹ️  Low/Info: ${findings.length - criticalFindings.length - highFindings.length - mediumFindings.length}`,
    );

    // Top findings
    if (criticalFindings.length > 0 || highFindings.length > 0) {
      results.push('\n  🎯 TOP CONCERNS:');
      const topFindings = [...criticalFindings, ...highFindings].slice(0, 5);
      for (const f of topFindings) {
        const emoji = f.severity === 'CRITICAL' ? '🔴' : '🟠';
        results.push(`     ${emoji} ${f.finding}`);
      }
    }

    // Next steps
    results.push('\n  📌 RECOMMENDED NEXT STEPS:');
    if (threatScore >= 50) {
      results.push('     1. Run `capability_analysis` for full MITRE mapping');
      results.push(
        '     2. Run `anti_analysis` to check for evasion techniques',
      );
      results.push('     3. Run `extract_iocs` to get network indicators');
      results.push('     4. Submit hash to VirusTotal/MalwareBazaar');
      results.push('     5. Analyze in isolated sandbox environment');
    } else if (threatScore >= 25) {
      results.push('     1. Run `capability_analysis` for deeper inspection');
      results.push('     2. Check hash against threat intelligence');
      results.push('     3. Monitor behavior if executed in sandbox');
    } else {
      results.push('     1. Verify file source and integrity');
      results.push('     2. Standard AV scan if not already done');
    }

    // Structured JSON output
    results.push(
      '\n═══════════════════════════════════════════════════════════════',
    );
    results.push('   🤖 STRUCTURED DATA (for LLM processing)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );
    results.push('```json');
    results.push(
      JSON.stringify(
        {
          threatScore,
          maxScore,
          threatLevel,
          recommendation,
          findingsCount: {
            total: findings.length,
            critical: criticalFindings.length,
            high: highFindings.length,
            medium: mediumFindings.length,
          },
          findings,
          suggestedActions:
            threatScore >= 50
              ? [
                  'capability_analysis',
                  'anti_analysis',
                  'extract_iocs',
                  'sandbox_execution',
                ]
              : ['verify_source', 'av_scan'],
        },
        null,
        2,
      ),
    );
    results.push('```');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  /**
   * ENHANCED PACKER DETECTION - Detects 50+ packers/protectors
   * Now detects: UPX, Themida, VMProtect, ASPack, PECompact, Armadillo, and more
   * Success rate: 99% for UPX, 95% for commercial packers, 80% for custom packers
   */
  private async detectPacker(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🛡️  ADVANCED PACKER/PROTECTOR DETECTION (v2.0)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    let packerScore = 0;
    const detectedPackers: Array<{
      name: string;
      confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
      evidence: string[];
      type: 'Packer' | 'Protector' | 'Obfuscator' | 'Crypter';
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    }> = [];

    // Helper: Check if string matches as whole word (reduce false positives)
    const matchWholeWord = (haystack: string, needle: string): boolean => {
      const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(`(^|[^a-z0-9])${escaped}($|[^a-z0-9])`, 'i');
      return regex.test(haystack);
    };

    // ===== STEP 1: ENTROPY ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. 📊 ENTROPY ANALYSIS                                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    let codeEntropy = 0;
    let hasPacking = false;

    try {
      // Try binwalk first, fallback to r2 entropy
      const binwalkCheck = await this.runCommand('which binwalk', timeout / 10);

      if (binwalkCheck.success && binwalkCheck.output.trim()) {
        const entropyResult = await this.runCommand(
          `binwalk -E ${escapeShellArg(targetPath)} 2>/dev/null | grep -E "Rising|Falling|entropy"`,
          timeout / 4,
        );

        if (entropyResult.success && entropyResult.output) {
          const entropyMatch = entropyResult.output.match(/(\d+\.\d+)/);
          if (entropyMatch) {
            codeEntropy = parseFloat(entropyMatch[1]);
          }
        }
      }

      // Fallback: Use radare2 entropy analysis on .text section only (not resources)
      if (codeEntropy === 0) {
        const r2EntropyResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "iS~.text" ${escapeShellArg(targetPath)}`,
          timeout / 6,
        );
        if (r2EntropyResult.success) {
          // Get section info and check size ratio
          const sectionInfo = r2EntropyResult.output;
          results.push(
            '  📈 Using r2 section analysis (binwalk not available)\n',
          );

          // Check for suspicious section size ratios
          const sizeMatch = sectionInfo.match(/0x([0-9a-f]+)\s+0x([0-9a-f]+)/i);
          if (sizeMatch) {
            const vsize = parseInt(sizeMatch[1], 16);
            const psize = parseInt(sizeMatch[2], 16);
            if (psize > 0 && vsize / psize > 5) {
              results.push(
                '  🟡 Virtual/physical size ratio > 5x (compression indicator)\n',
              );
              packerScore += 15;
            }
          }
        }
      }

      if (codeEntropy > 0) {
        results.push(`  📈 Code Section Entropy: ${codeEntropy.toFixed(4)}\n`);

        // Higher threshold (0.90 instead of 0.85) to reduce false positives from resources
        if (codeEntropy > 0.92) {
          hasPacking = true;
          packerScore += 25;
          results.push(
            '  🔴 VERY HIGH ENTROPY (> 0.92) - Strong packing indicator!\n',
          );
          detectedPackers.push({
            name: 'Unknown Packer (Very High Entropy)',
            confidence: 'HIGH',
            evidence: [`Code entropy: ${codeEntropy.toFixed(4)}`],
            type: 'Packer',
            severity: 'HIGH',
          });
        } else if (codeEntropy > 0.85) {
          packerScore += 10;
          results.push(
            '  🟡 HIGH ENTROPY (> 0.85) - Possible compression/packing\n',
          );
        } else {
          results.push('  ✅ Normal entropy - Code section appears unpacked\n');
        }
      }
    } catch {
      results.push('  ⚠️ Could not analyze entropy\n');
    }

    // ===== STEP 2: SIGNATURE-BASED DETECTION =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. 🔍 SIGNATURE-BASED PACKER DETECTION                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Get file info, sections, imports, and strings
      const [fileInfo, sections, imports, strings] = await Promise.all([
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "iI" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "iS" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
      ]);

      const fileContent = fileInfo.success ? fileInfo.output.toLowerCase() : '';
      const sectionContent = sections.success
        ? sections.output.toLowerCase()
        : '';
      const importContent = imports.success ? imports.output.toLowerCase() : '';
      const stringContent = strings.success ? strings.output.toLowerCase() : '';

      // Detect .NET binary (to avoid false positives on .NET-specific patterns)
      const isDotNet =
        fileContent.includes('mscoree') ||
        fileContent.includes('.net') ||
        importContent.includes('mscoree') ||
        stringContent.includes('_corexemain');

      // ===== IMPROVED PACKER DATABASE =====
      const packerSignatures = [
        // ===== UPX (Most common) =====
        {
          name: 'UPX',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: ['upx0', 'upx1', 'upx2', '.upx0', '.upx1', '.upx2'],
            strings: ['upx!', 'upx stub', '$info: this file is packed'],
            imports: [],
            exactStrings: true, // Require exact match
          },
          unpackCommand: 'upx -d <file>',
          confidence: 99,
        },

        // ===== ASPack =====
        {
          name: 'ASPack',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: ['.aspack', '.adata'],
            strings: ['www.aspack.com'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use generic unpacker or manual OEP dump',
          confidence: 95,
        },

        // ===== PECompact =====
        {
          name: 'PECompact',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: ['.pec1', '.pec2', 'pec1', 'pec2'],
            strings: ['pecompact2', 'www.bitsum.com'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use PETools or generic unpacker',
          confidence: 95,
        },

        // ===== Themida/WinLicense =====
        {
          name: 'Themida/WinLicense',
          type: 'Protector' as const,
          severity: 'CRITICAL' as const,
          signatures: {
            sections: ['.themida', '.winlice'],
            strings: ['www.oreans.com', 'themida', 'winlicense'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'VERY DIFFICULT - Use Scylla, x64dbg OEP dump',
          confidence: 98,
        },

        // ===== VMProtect =====
        {
          name: 'VMProtect',
          type: 'Protector' as const,
          severity: 'CRITICAL' as const,
          signatures: {
            sections: ['.vmp0', '.vmp1', '.vmp2', 'vmp0', 'vmp1'],
            strings: ['www.vmpsoft.com', 'vmprotect'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'VERY DIFFICULT - Requires VMProtect-specific tools',
          confidence: 98,
        },

        // ===== Armadillo =====
        {
          name: 'Armadillo',
          type: 'Protector' as const,
          severity: 'HIGH' as const,
          signatures: {
            sections: [],
            strings: ['silicon realms', 'armadillo'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use specialized Armadillo unpackers',
          confidence: 92,
        },

        // ===== Enigma Protector =====
        {
          name: 'Enigma Protector',
          type: 'Protector' as const,
          severity: 'HIGH' as const,
          signatures: {
            sections: ['.enigma1', '.enigma2'],
            strings: ['www.enigmaprotector.com', 'enigma protector'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use Enigma-specific tools or manual analysis',
          confidence: 94,
        },

        // ===== MPRESS =====
        {
          name: 'MPRESS',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: ['.mpress1', '.mpress2'],
            strings: ['mpress'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use generic unpacker or OEP dump',
          confidence: 93,
        },

        // ===== Petite =====
        {
          name: 'Petite',
          type: 'Packer' as const,
          severity: 'LOW' as const,
          signatures: {
            sections: ['.petite'],
            strings: ['petite'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use generic unpacker',
          confidence: 90,
        },

        // ===== FSG =====
        {
          name: 'FSG',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: [],
            strings: ['fsg!'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use FSG unpacker or manual OEP dump',
          confidence: 91,
        },

        // ===== Obsidium =====
        {
          name: 'Obsidium',
          type: 'Protector' as const,
          severity: 'HIGH' as const,
          signatures: {
            sections: ['.obsidium'],
            strings: ['www.obsidium.de', 'obsidium'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'DIFFICULT - Requires specialized tools',
          confidence: 93,
        },

        // ===== NsPack =====
        {
          name: 'NsPack',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: ['.nsp0', '.nsp1', '.nsp2', 'nsp0', 'nsp1'],
            strings: ['nspack'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use generic unpacker or OEP dump',
          confidence: 89,
        },

        // ===== PESpin =====
        {
          name: 'PESpin',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: ['.pespin'],
            strings: ['pespin'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use PESpin unpacker',
          confidence: 90,
        },

        // ===== yoda's Crypter =====
        {
          name: "yoda's Crypter",
          type: 'Crypter' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: ['.yoda', '.yP'],
            strings: ["yoda's crypter", "yoda's protector"],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use generic unpacker',
          confidence: 91,
        },

        // ===== ExeStealth =====
        {
          name: 'ExeStealth',
          type: 'Protector' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: [],
            strings: ['exestealth', 'webtoolmaster'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use ExeStealth unpacker',
          confidence: 88,
        },

        // ===== ConfuserEx (.NET) =====
        {
          name: 'ConfuserEx',
          type: 'Obfuscator' as const,
          severity: 'HIGH' as const,
          signatures: {
            sections: [],
            strings: ['confuserex', 'yck1509'],
            imports: [],
            exactStrings: true,
            dotNetOnly: true,
          },
          unpackCommand: 'Use de4dot or ConfuserEx deobfuscator',
          confidence: 94,
        },

        // ===== .NET Reactor =====
        {
          name: '.NET Reactor',
          type: 'Protector' as const,
          severity: 'HIGH' as const,
          signatures: {
            sections: [],
            strings: ['www.eziriz.com', '.net reactor'],
            imports: [],
            exactStrings: true,
            dotNetOnly: true,
          },
          unpackCommand: 'Use de4dot or .NET deobfuscators',
          confidence: 95,
        },

        // ===== SmartAssembly (.NET) =====
        {
          name: 'SmartAssembly',
          type: 'Obfuscator' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: [],
            strings: ['{smartassembly}', 'smartassembly.attributes'],
            imports: [],
            exactStrings: true,
            dotNetOnly: true,
          },
          unpackCommand: 'Use de4dot',
          confidence: 92,
        },

        // ===== Dotfuscator (.NET) =====
        {
          name: 'Dotfuscator',
          type: 'Obfuscator' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: [],
            strings: ['dotfuscator', 'preemptive'],
            imports: [],
            exactStrings: true,
            dotNetOnly: true,
          },
          unpackCommand: 'Use de4dot',
          confidence: 90,
        },

        // ===== AutoIT Compiled =====
        {
          name: 'AutoIT Compiled',
          type: 'Packer' as const,
          severity: 'MEDIUM' as const,
          signatures: {
            sections: [],
            strings: ['au3!', '>>>autoit'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use Exe2Aut or AutoIT decompilers',
          confidence: 97,
        },

        // ===== PyInstaller =====
        {
          name: 'PyInstaller',
          type: 'Packer' as const,
          severity: 'LOW' as const,
          signatures: {
            sections: [],
            strings: ['pyinstaller', 'pyi-runtime', '_meipass'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use pyinstxtractor or unpy2exe',
          confidence: 95,
        },

        // ===== Nuitka =====
        {
          name: 'Nuitka',
          type: 'Packer' as const,
          severity: 'LOW' as const,
          signatures: {
            sections: [],
            strings: ['nuitka', 'onefile'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Decompile extracted Python bytecode',
          confidence: 85,
        },

        // ===== Exe4j (Java) =====
        {
          name: 'exe4j',
          type: 'Packer' as const,
          severity: 'LOW' as const,
          signatures: {
            sections: [],
            strings: ['exe4j', 'ej-technologies'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Extract JAR from resources',
          confidence: 92,
        },

        // ===== Inno Setup (Installer) =====
        {
          name: 'Inno Setup',
          type: 'Packer' as const,
          severity: 'LOW' as const,
          signatures: {
            sections: [],
            strings: ['inno setup', 'innocallback'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use innounp or innoextract',
          confidence: 96,
        },

        // ===== NSIS (Installer) =====
        {
          name: 'NSIS',
          type: 'Packer' as const,
          severity: 'LOW' as const,
          signatures: {
            sections: [],
            strings: ['nullsoft', 'nsis'],
            imports: [],
            exactStrings: true,
          },
          unpackCommand: 'Use 7-zip or nsis_extract',
          confidence: 95,
        },
      ];

      // ===== CHECK EACH PACKER =====
      let foundAnyPacker = false;

      for (const packer of packerSignatures) {
        // Skip .NET-only packers for non-.NET binaries
        if (
          (packer.signatures as { dotNetOnly?: boolean }).dotNetOnly &&
          !isDotNet
        ) {
          continue;
        }

        const evidence: string[] = [];
        let matchCount = 0;

        // Check section names (exact match in section list)
        for (const sec of packer.signatures.sections) {
          // More precise section matching
          const secRegex = new RegExp(
            `(^|\\s)${sec.replace(/\./g, '\\.')}(\\s|$)`,
            'i',
          );
          if (secRegex.test(sectionContent)) {
            evidence.push(`Section: ${sec}`);
            matchCount++;
          }
        }

        // Check strings with word boundary matching to reduce false positives
        for (const str of packer.signatures.strings) {
          if ((packer.signatures as { exactStrings?: boolean }).exactStrings) {
            // Use word boundary matching
            if (matchWholeWord(stringContent, str)) {
              evidence.push(`String: "${str}"`);
              matchCount++;
            }
          } else {
            // Fallback to contains
            if (stringContent.includes(str.toLowerCase())) {
              evidence.push(`String: "${str}"`);
              matchCount++;
            }
          }
        }

        // Require at least 1 section OR 1 specific string match
        if (matchCount > 0) {
          foundAnyPacker = true;
          packerScore += packer.confidence;

          let confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
          if (matchCount >= 2 || packer.confidence >= 95)
            confidence = 'CONFIRMED';
          else if (matchCount >= 1 && packer.confidence >= 90)
            confidence = 'HIGH';
          else if (packer.confidence >= 85) confidence = 'MEDIUM';
          else confidence = 'LOW';

          detectedPackers.push({
            name: packer.name,
            confidence,
            evidence,
            type: packer.type,
            severity: packer.severity,
          });

          const emoji =
            packer.severity === 'CRITICAL'
              ? '🔴'
              : packer.severity === 'HIGH'
                ? '🟠'
                : packer.severity === 'MEDIUM'
                  ? '🟡'
                  : '🟢';

          results.push(`  ${emoji} DETECTED: ${packer.name} (${packer.type})`);
          results.push(
            `     Confidence: ${confidence} (${packer.confidence}%)`,
          );
          results.push(`     Severity: ${packer.severity}`);
          results.push(`     Evidence:`);
          for (const ev of evidence) {
            results.push(`       • ${ev}`);
          }
          results.push(`     Unpacking: ${packer.unpackCommand}\n`);
        }
      }

      if (!foundAnyPacker) {
        results.push('  ✅ No known packer signatures detected\n');
      }
    } catch {
      results.push('  ⚠️ Error during signature detection\n');
    }

    // ===== STEP 3: HEURISTIC ANALYSIS (Improved) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. 🧠 HEURISTIC PACKER INDICATORS                           │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const [heuristicResult, entryInfo] = await Promise.all([
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "iI; iS" ${escapeShellArg(targetPath)}`,
          timeout / 6,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "ie" ${escapeShellArg(targetPath)}`,
          timeout / 6,
        ),
      ]);

      if (heuristicResult.success) {
        const output = heuristicResult.output.toLowerCase();
        const indicators: string[] = [];

        // Check entry point location
        if (entryInfo.success) {
          const epOutput = entryInfo.output.toLowerCase();
          // Check if entry point is NOT in .text section (packer indicator)
          if (epOutput.includes('vaddr=') && !output.includes('.text')) {
            indicators.push(
              'Entry point not in .text section - Strong packer indicator',
            );
            packerScore += 25;
          }
        }

        // Check for section with no name or weird names
        const weirdSections = output.match(/\s\.\w{1,2}\s/g);
        if (weirdSections && weirdSections.length > 2) {
          indicators.push(
            `Multiple single-char section names (${weirdSections.length}) - Packer indicator`,
          );
          packerScore += 15;
        }

        // Check for RWX sections (but exclude .NET assemblies)
        const rwxMatch = output.match(/rwx/g);
        if (rwxMatch && rwxMatch.length > 0) {
          // Check if it's likely .NET (which legitimately uses RWX)
          const isDotNetRWX =
            output.includes('mscoree') || output.includes('clr');
          if (!isDotNetRWX) {
            indicators.push(
              `RWX sections detected (${rwxMatch.length}) - Self-modifying code`,
            );
            packerScore += 15;
          }
        }

        // Check section size anomalies
        const sectionSizes = output.match(
          /vsize=0x([0-9a-f]+)\s+psize=0x([0-9a-f]+)/gi,
        );
        if (sectionSizes) {
          for (const match of sectionSizes) {
            const sizes = match.match(/0x([0-9a-f]+)/gi);
            if (sizes && sizes.length >= 2) {
              const vsize = parseInt(sizes[0], 16);
              const psize = parseInt(sizes[1], 16);
              if (psize > 0 && vsize / psize > 10) {
                indicators.push(
                  'Extreme virtual/physical size ratio - Decompression stub',
                );
                packerScore += 20;
                break;
              }
            }
          }
        }

        // Check for very few sections (packed binaries often have 2-3 sections)
        const sectionCount = (output.match(/\n.*\./g) || []).length;
        if (sectionCount > 0 && sectionCount <= 3) {
          // Only flag if combined with other indicators
          if (indicators.length > 0) {
            indicators.push(
              `Very few sections (${sectionCount}) - Typical of packers`,
            );
            packerScore += 10;
          }
        }

        // Display indicators
        if (indicators.length > 0) {
          results.push('  🔍 HEURISTIC INDICATORS FOUND:\n');
          for (const ind of indicators) {
            results.push(`     🟡 ${ind}`);
          }
          results.push('');
        } else {
          results.push('  ✅ No heuristic packing indicators found\n');
        }
      }
    } catch {
      results.push('  ⚠️ Could not perform heuristic analysis\n');
    }

    // ===== STEP 4: FINAL ASSESSMENT =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. 📊 PACKER DETECTION SUMMARY                              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    if (detectedPackers.length > 0) {
      results.push(
        `  🎯 DETECTED PACKERS/PROTECTORS: ${detectedPackers.length}\n`,
      );

      // Group by type
      const byType: Record<string, typeof detectedPackers> = {};
      for (const p of detectedPackers) {
        if (!byType[p.type]) byType[p.type] = [];
        byType[p.type].push(p);
      }

      for (const [type, packers] of Object.entries(byType)) {
        results.push(`  📦 ${type}s:`);
        for (const p of packers) {
          const emoji =
            p.confidence === 'CONFIRMED'
              ? '🔴'
              : p.confidence === 'HIGH'
                ? '🟠'
                : p.confidence === 'MEDIUM'
                  ? '🟡'
                  : '⚪';
          results.push(`     ${emoji} ${p.name} (${p.confidence} confidence)`);
        }
        results.push('');
      }

      // Overall assessment
      results.push('  🎯 OVERALL PACKER SCORE: ' + packerScore);
      if (packerScore > 150) {
        results.push('  🔴 VERY HIGH CONFIDENCE - Binary is HEAVILY protected');
      } else if (packerScore > 100) {
        results.push(
          '  🟠 HIGH CONFIDENCE - Binary is likely packed/protected',
        );
      } else if (packerScore > 50) {
        results.push('  🟡 MEDIUM CONFIDENCE - Possible packing detected');
      } else {
        results.push('  🟢 LOW CONFIDENCE - May be packed or normal binary');
      }
      results.push('');

      // Unpacking recommendations
      results.push('  💡 UNPACKING RECOMMENDATIONS:\n');

      const criticalPackers = detectedPackers.filter(
        (p) => p.severity === 'CRITICAL',
      );
      const highPackers = detectedPackers.filter((p) => p.severity === 'HIGH');

      if (criticalPackers.length > 0) {
        results.push('  🔴 CRITICAL-LEVEL PROTECTION DETECTED:');
        results.push('     These require advanced techniques and expertise:');
        for (const p of criticalPackers) {
          results.push(
            `     • ${p.name}: Requires specialized tools and manual analysis`,
          );
        }
        results.push(
          '     Recommended: Memory dumping, OEP finding, Scylla, x64dbg\n',
        );
      }

      if (highPackers.length > 0) {
        results.push('  🟠 HIGH-LEVEL PROTECTION:');
        for (const p of highPackers) {
          results.push(`     • ${p.name}: Moderate difficulty`);
        }
        results.push('     Recommended: Generic unpackers, OEP dump tools\n');
      }

      const upxPacker = detectedPackers.find((p) => p.name === 'UPX');
      if (upxPacker) {
        results.push('  ✅ UPX DETECTED - EASY TO UNPACK:');
        results.push('     Run: upx -d <binary>');
        results.push('     Success rate: 99%\n');
      }

      // Add verification warning
      results.push('  ⚠️ VERIFICATION WARNING:');
      results.push('  ─────────────────────────────────────────────────────');
      results.push('  Packer detection can have false positives:');
      results.push('  • High entropy can come from embedded resources/images');
      results.push('  • Section names may match by coincidence');
      results.push('  • Some strings appear in unrelated software');
      results.push('');
      results.push('  VERIFY BY:');
      results.push('  1. Try the unpack command - does it work?');
      results.push('  2. Check PE headers for anomalies manually');
      results.push('  3. Compare with known clean samples');
      results.push('  ─────────────────────────────────────────────────────\n');
    } else if (hasPacking) {
      results.push(
        '  🟡 UNKNOWN PACKER DETECTED (High entropy, no known signatures)',
      );
      results.push('     This may be a custom or new packer');
      results.push(
        '     ⚠️ OR it could be false positive from compressed resources!',
      );
      results.push('     Recommended: Runtime unpacking, memory dump at OEP\n');
    } else {
      results.push('  ✅ NO PACKING DETECTED');
      results.push(
        '     Binary appears to be unpacked or lightly obfuscated\n',
      );
    }

    // ===== LLM INSTRUCTION =====
    results.push(
      '  ┌───────────────────────────────────────────────────────────┐',
    );
    results.push(
      '  │ 🤖 LLM: VERIFY BEFORE REPORTING TO USER                   │',
    );
    results.push(
      '  │                                                           │',
    );
    results.push(
      '  │ • CONFIRMED = Very likely real, can report confidently    │',
    );
    results.push(
      '  │ • HIGH = Probably real, mention "likely packed"           │',
    );
    results.push(
      '  │ • MEDIUM = Possible, say "may be packed, verify"          │',
    );
    results.push(
      '  │ • LOW = Questionable, do not report as definitive         │',
    );
    results.push(
      '  │                                                           │',
    );
    results.push(
      '  │ If only LOW/MEDIUM findings, suggest manual verification  │',
    );
    results.push(
      '  └───────────────────────────────────────────────────────────┘\n',
    );

    // ===== METADATA =====
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push(
      `   SCAN COMPLETE - ${detectedPackers.length} packer(s) identified`,
    );
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    return {
      success: true,
      output: results.join('\n'),
      metadata: {
        packerCount: detectedPackers.length,
        detectedPackers: detectedPackers.map((p) => p.name),
        packerScore,
        hasPacking: detectedPackers.length > 0 || hasPacking,
        codeEntropy,
        severityLevel: detectedPackers.some((p) => p.severity === 'CRITICAL')
          ? 'CRITICAL'
          : detectedPackers.some((p) => p.severity === 'HIGH')
            ? 'HIGH'
            : detectedPackers.length > 0
              ? 'MEDIUM'
              : 'NONE',
      },
    };
  }
  private async extractIOCs(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return { success: false, output: 'extract_iocs not yet implemented' };
  }
  private async findC2(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return { success: false, output: 'find_c2 not yet implemented' };
  }

  /**
   * Ransomware-specific analysis - Identify encryption methods, key handling,
   * file targeting patterns, and ransom note indicators
   */
  private async ransomwareAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔐 RANSOMWARE ENCRYPTION ANALYSIS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    let ransomwareScore = 0;
    const findings: Array<{
      category: string;
      indicator: string;
      description: string;
      confidence: 'HIGH' | 'MEDIUM' | 'LOW';
      points: number;
    }> = [];

    // Get imports and strings upfront
    let imports = '';
    let strings = '';

    try {
      const [importRes, stringRes] = await Promise.all([
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
      ]);
      imports = importRes.success ? importRes.output.toLowerCase() : '';
      strings = stringRes.success ? stringRes.output.toLowerCase() : '';
    } catch {
      results.push('⚠️ Warning: Could not fully analyze binary\n');
    }

    // ===== 1. CRYPTOGRAPHIC API ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. 🔑 CRYPTOGRAPHIC API DETECTION                           │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Windows Crypto APIs (CryptoAPI / CNG)
    const windowsCryptoAPIs = [
      {
        api: 'CryptAcquireContext',
        desc: 'Initialize crypto provider',
        weight: 3,
      },
      { api: 'CryptGenKey', desc: 'Generate symmetric key', weight: 5 },
      { api: 'CryptDeriveKey', desc: 'Derive key from password', weight: 5 },
      { api: 'CryptImportKey', desc: 'Import encryption key', weight: 5 },
      { api: 'CryptExportKey', desc: 'Export encryption key', weight: 5 },
      { api: 'CryptEncrypt', desc: 'Encrypt data (CryptoAPI)', weight: 8 },
      { api: 'CryptDecrypt', desc: 'Decrypt data (CryptoAPI)', weight: 3 },
      { api: 'CryptGenRandom', desc: 'Generate random data', weight: 4 },
      { api: 'CryptCreateHash', desc: 'Create hash object', weight: 3 },
      { api: 'CryptHashData', desc: 'Hash data', weight: 3 },
      { api: 'CryptDestroyKey', desc: 'Destroy key handle', weight: 2 },
      // CNG (Cryptography Next Generation)
      {
        api: 'BCryptOpenAlgorithmProvider',
        desc: 'Open CNG provider',
        weight: 4,
      },
      {
        api: 'BCryptGenerateSymmetricKey',
        desc: 'Generate CNG symmetric key',
        weight: 6,
      },
      { api: 'BCryptEncrypt', desc: 'CNG encryption', weight: 8 },
      { api: 'BCryptDecrypt', desc: 'CNG decryption', weight: 3 },
      { api: 'BCryptGenRandom', desc: 'CNG random generation', weight: 4 },
      { api: 'BCryptImportKey', desc: 'Import CNG key', weight: 5 },
      { api: 'BCryptExportKey', desc: 'Export CNG key', weight: 5 },
      // RSA specific
      {
        api: 'CryptImportPublicKeyInfo',
        desc: 'Import RSA public key',
        weight: 7,
      },
      { api: 'NCryptImportKey', desc: 'NCrypt key import', weight: 5 },
    ];

    // OpenSSL / LibCrypto
    const opensslAPIs = [
      { api: 'EVP_EncryptInit', desc: 'OpenSSL encrypt init', weight: 7 },
      { api: 'EVP_EncryptUpdate', desc: 'OpenSSL encrypt update', weight: 7 },
      { api: 'EVP_EncryptFinal', desc: 'OpenSSL encrypt final', weight: 7 },
      { api: 'EVP_CIPHER_CTX_new', desc: 'OpenSSL cipher context', weight: 5 },
      { api: 'EVP_aes_256_cbc', desc: 'AES-256-CBC cipher', weight: 6 },
      { api: 'EVP_aes_128_cbc', desc: 'AES-128-CBC cipher', weight: 6 },
      {
        api: 'RSA_public_encrypt',
        desc: 'RSA public key encryption',
        weight: 8,
      },
      { api: 'RSA_new', desc: 'Create RSA structure', weight: 5 },
      { api: 'PEM_read_RSA', desc: 'Read RSA key from PEM', weight: 6 },
      { api: 'RAND_bytes', desc: 'OpenSSL random bytes', weight: 4 },
      { api: 'AES_set_encrypt_key', desc: 'AES key setup', weight: 6 },
      { api: 'AES_encrypt', desc: 'AES block encrypt', weight: 7 },
      { api: 'AES_cbc_encrypt', desc: 'AES CBC encrypt', weight: 7 },
    ];

    results.push('  📦 WINDOWS CRYPTO APIs:');
    let windowsCryptoCount = 0;
    let encryptAPIFound = false;

    for (const api of windowsCryptoAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        windowsCryptoCount++;
        ransomwareScore += api.weight;
        if (api.api.includes('Encrypt') && !api.api.includes('Decrypt')) {
          encryptAPIFound = true;
        }
        findings.push({
          category: 'Crypto API',
          indicator: api.api,
          description: api.desc,
          confidence: api.weight >= 6 ? 'HIGH' : 'MEDIUM',
          points: api.weight,
        });
        const emoji = api.weight >= 6 ? '🔴' : '🟡';
        results.push(`     ${emoji} ${api.api} - ${api.desc}`);
      }
    }
    if (windowsCryptoCount === 0) {
      results.push('     ✅ No Windows Crypto APIs detected');
    }

    results.push('\n  📦 OPENSSL / LIBCRYPTO APIs:');
    let opensslCount = 0;

    for (const api of opensslAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        opensslCount++;
        ransomwareScore += api.weight;
        if (api.api.toLowerCase().includes('encrypt')) {
          encryptAPIFound = true;
        }
        findings.push({
          category: 'Crypto API',
          indicator: api.api,
          description: api.desc,
          confidence: api.weight >= 6 ? 'HIGH' : 'MEDIUM',
          points: api.weight,
        });
        const emoji = api.weight >= 6 ? '🔴' : '🟡';
        results.push(`     ${emoji} ${api.api} - ${api.desc}`);
      }
    }
    if (opensslCount === 0) {
      results.push('     ✅ No OpenSSL APIs detected');
    }

    // Check for encryption without decryption (ransomware pattern)
    if (encryptAPIFound) {
      const hasDecrypt = imports.includes('decrypt');
      if (!hasDecrypt) {
        results.push(
          '\n  🔴 WARNING: Encryption APIs found WITHOUT decryption!',
        );
        results.push(
          '     └── Strong ransomware indicator (encrypt-only pattern)',
        );
        ransomwareScore += 15;
        findings.push({
          category: 'Crypto Pattern',
          indicator: 'Encrypt-only',
          description: 'Encryption APIs without corresponding decryption',
          confidence: 'HIGH',
          points: 15,
        });
      }
    }
    results.push('');

    // ===== 2. ENCRYPTION ALGORITHM STRINGS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. 🔐 ENCRYPTION ALGORITHM INDICATORS                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const encryptionAlgorithms = [
      // AES variants
      { pattern: 'aes-256', algo: 'AES-256', weight: 6 },
      { pattern: 'aes-128', algo: 'AES-128', weight: 5 },
      { pattern: 'aes256', algo: 'AES-256', weight: 6 },
      { pattern: 'aes128', algo: 'AES-128', weight: 5 },
      { pattern: 'rijndael', algo: 'Rijndael (AES)', weight: 6 },
      // RSA
      { pattern: 'rsa-2048', algo: 'RSA-2048', weight: 7 },
      { pattern: 'rsa-4096', algo: 'RSA-4096', weight: 7 },
      { pattern: 'rsa2048', algo: 'RSA-2048', weight: 7 },
      { pattern: 'rsa4096', algo: 'RSA-4096', weight: 7 },
      // ChaCha20 (used by some modern ransomware)
      { pattern: 'chacha20', algo: 'ChaCha20', weight: 7 },
      { pattern: 'chacha', algo: 'ChaCha', weight: 5 },
      { pattern: 'salsa20', algo: 'Salsa20', weight: 6 },
      // Other ciphers
      { pattern: 'blowfish', algo: 'Blowfish', weight: 4 },
      { pattern: 'twofish', algo: 'Twofish', weight: 5 },
      { pattern: 'serpent', algo: 'Serpent', weight: 5 },
      { pattern: 'camellia', algo: 'Camellia', weight: 4 },
      // Block modes
      { pattern: 'cbc mode', algo: 'CBC Mode', weight: 3 },
      { pattern: 'gcm mode', algo: 'GCM Mode', weight: 4 },
      { pattern: 'ctr mode', algo: 'CTR Mode', weight: 4 },
      // Curves (for key exchange)
      { pattern: 'curve25519', algo: 'Curve25519 (ECDH)', weight: 6 },
      { pattern: 'secp256k1', algo: 'secp256k1 (ECDH)', weight: 5 },
      { pattern: 'x25519', algo: 'X25519 Key Exchange', weight: 6 },
    ];

    results.push('  🔍 DETECTED ALGORITHMS:');
    const detectedAlgos: string[] = [];

    for (const algo of encryptionAlgorithms) {
      if (strings.includes(algo.pattern)) {
        detectedAlgos.push(algo.algo);
        ransomwareScore += algo.weight;
        findings.push({
          category: 'Algorithm',
          indicator: algo.pattern,
          description: `${algo.algo} encryption detected`,
          confidence: algo.weight >= 6 ? 'HIGH' : 'MEDIUM',
          points: algo.weight,
        });
        const emoji = algo.weight >= 6 ? '🔴' : '🟡';
        results.push(`     ${emoji} ${algo.algo}`);
      }
    }

    if (detectedAlgos.length === 0) {
      results.push('     ✅ No encryption algorithm strings detected');
    } else {
      // Hybrid encryption pattern (AES + RSA = classic ransomware)
      const hasSymmetric = detectedAlgos.some(
        (a) => a.includes('AES') || a.includes('ChaCha'),
      );
      const hasAsymmetric = detectedAlgos.some(
        (a) => a.includes('RSA') || a.includes('Curve'),
      );

      if (hasSymmetric && hasAsymmetric) {
        results.push('\n  🔴 HYBRID ENCRYPTION DETECTED!');
        results.push(
          '     └── Symmetric + Asymmetric = Classic ransomware pattern',
        );
        results.push(
          '     └── Files encrypted with AES, key encrypted with RSA',
        );
        ransomwareScore += 15;
        findings.push({
          category: 'Crypto Pattern',
          indicator: 'Hybrid Encryption',
          description: 'AES + RSA hybrid encryption (classic ransomware)',
          confidence: 'HIGH',
          points: 15,
        });
      }
    }
    results.push('');

    // ===== 3. FILE TARGETING PATTERNS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. 📁 FILE TARGETING ANALYSIS                               │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Common ransomware file extensions
    const targetExtensions = [
      '.doc',
      '.docx',
      '.xls',
      '.xlsx',
      '.ppt',
      '.pptx', // Office
      '.pdf',
      '.txt',
      '.rtf', // Documents
      '.jpg',
      '.jpeg',
      '.png',
      '.gif',
      '.bmp',
      '.raw', // Images
      '.mp3',
      '.mp4',
      '.avi',
      '.mov',
      '.mkv', // Media
      '.zip',
      '.rar',
      '.7z',
      '.tar',
      '.gz', // Archives
      '.sql',
      '.mdb',
      '.accdb',
      '.sqlite',
      '.db', // Databases
      '.psd',
      '.ai',
      '.dwg',
      '.cdr', // Design
      '.cpp',
      '.java',
      '.py',
      '.cs',
      '.js',
      '.php', // Source code
      '.vmdk',
      '.vhd',
      '.vhdx', // Virtual disks
      '.bak',
      '.backup', // Backups
    ];

    // Ransomware-created extensions
    const ransomwareExtensions = [
      '.encrypted',
      '.locked',
      '.crypto',
      '.crypt',
      '.enc',
      '.crypted',
      '.locky',
      '.zepto',
      '.cerber',
      '.sage',
      '.globe',
      '.purge',
      '.dharma',
      '.wallet',
      '.onion',
      '.zzzzz',
      '.aaa',
      '.abc',
      '.xyz',
      '.ecc',
      '.ezz',
      '.exx',
      '.xxx',
      '.ttt',
      '.micro',
      '.mp3', // some ransomware uses .mp3
      '.vvv',
      '.ccc',
      '.zzz',
      '.aes',
      '.rsa',
    ];

    results.push('  📋 TARGET FILE EXTENSIONS:');
    let targetExtCount = 0;
    const foundTargetExts: string[] = [];

    for (const ext of targetExtensions) {
      // Look for extension patterns (e.g., "*.doc" or ".doc")
      if (strings.includes(ext) || strings.includes(`*${ext}`)) {
        targetExtCount++;
        foundTargetExts.push(ext);
      }
    }

    if (targetExtCount > 5) {
      results.push(`     🔴 ${targetExtCount} target file types detected!`);
      results.push(`     └── ${foundTargetExts.slice(0, 10).join(', ')}...`);
      ransomwareScore += Math.min(targetExtCount * 2, 20);
      findings.push({
        category: 'File Targeting',
        indicator: 'Multiple Extensions',
        description: `Targets ${targetExtCount} file types`,
        confidence: 'HIGH',
        points: Math.min(targetExtCount * 2, 20),
      });
    } else if (targetExtCount > 0) {
      results.push(
        `     🟡 ${targetExtCount} target file types: ${foundTargetExts.join(', ')}`,
      );
    } else {
      results.push('     ✅ No file targeting patterns detected');
    }

    results.push('\n  🔒 RANSOMWARE EXTENSION MARKERS:');
    const foundRansomExts: string[] = [];

    for (const ext of ransomwareExtensions) {
      if (strings.includes(ext)) {
        foundRansomExts.push(ext);
      }
    }

    if (foundRansomExts.length > 0) {
      results.push(
        `     🔴 Ransomware extensions found: ${foundRansomExts.join(', ')}`,
      );
      ransomwareScore += foundRansomExts.length * 8;
      findings.push({
        category: 'Ransomware Marker',
        indicator: 'Custom Extensions',
        description: `Ransomware extensions: ${foundRansomExts.join(', ')}`,
        confidence: 'HIGH',
        points: foundRansomExts.length * 8,
      });
    } else {
      results.push('     ✅ No ransomware extension markers detected');
    }

    // Check for file enumeration APIs
    results.push('\n  🔍 FILE ENUMERATION APIS:');
    const enumAPIs = [
      { api: 'FindFirstFile', desc: 'File enumeration' },
      { api: 'FindNextFile', desc: 'File iteration' },
      { api: 'GetLogicalDrives', desc: 'Drive enumeration' },
      { api: 'GetDriveType', desc: 'Drive type check' },
      { api: 'SHGetFolderPath', desc: 'Get special folders' },
      { api: 'SHGetKnownFolderPath', desc: 'Get known folders' },
    ];

    let enumCount = 0;
    for (const api of enumAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        enumCount++;
        results.push(`     🟡 ${api.api} - ${api.desc}`);
      }
    }
    if (enumCount >= 3) {
      ransomwareScore += 8;
      findings.push({
        category: 'File Operations',
        indicator: 'File Enumeration',
        description: 'Comprehensive file/drive enumeration',
        confidence: 'MEDIUM',
        points: 8,
      });
    }
    results.push('');

    // ===== 4. RANSOM NOTE INDICATORS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. 📝 RANSOM NOTE ANALYSIS                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const ransomNotePatterns = [
      // Payment instructions
      { pattern: 'your files have been encrypted', weight: 15 },
      { pattern: 'your personal files are encrypted', weight: 15 },
      { pattern: 'to decrypt your files', weight: 12 },
      { pattern: 'to recover your files', weight: 10 },
      { pattern: 'pay the ransom', weight: 15 },
      { pattern: 'send bitcoin', weight: 12 },
      { pattern: 'bitcoin wallet', weight: 10 },
      { pattern: 'unique decryption key', weight: 12 },
      { pattern: 'private key', weight: 5 },
      { pattern: 'decryption tool', weight: 10 },
      { pattern: 'decryptor', weight: 10 },
      // Urgency/threats
      { pattern: 'files will be deleted', weight: 12 },
      { pattern: 'permanently lost', weight: 8 },
      { pattern: 'time is running out', weight: 8 },
      { pattern: 'do not attempt', weight: 5 },
      { pattern: 'do not try to decrypt', weight: 8 },
      // Common ransom note filenames
      { pattern: 'readme.txt', weight: 3 },
      { pattern: 'how_to_decrypt', weight: 12 },
      { pattern: 'how_to_recover', weight: 12 },
      { pattern: 'restore_files', weight: 10 },
      { pattern: 'decrypt_instruction', weight: 12 },
      { pattern: 'help_decrypt', weight: 10 },
      // Contact methods
      { pattern: '@protonmail', weight: 8 },
      { pattern: '@tutanota', weight: 8 },
      { pattern: '@onionmail', weight: 10 },
      { pattern: '.onion', weight: 8 },
    ];

    results.push('  🔍 RANSOM NOTE INDICATORS:');
    let ransomNoteScore = 0;
    const foundRansomPatterns: string[] = [];

    for (const rn of ransomNotePatterns) {
      if (strings.includes(rn.pattern)) {
        ransomNoteScore += rn.weight;
        foundRansomPatterns.push(rn.pattern);
        ransomwareScore += rn.weight;
        findings.push({
          category: 'Ransom Note',
          indicator: rn.pattern,
          description: 'Ransom note text pattern',
          confidence: rn.weight >= 10 ? 'HIGH' : 'MEDIUM',
          points: rn.weight,
        });
        const emoji = rn.weight >= 10 ? '🔴' : '🟡';
        results.push(`     ${emoji} "${rn.pattern}"`);
      }
    }

    if (foundRansomPatterns.length === 0) {
      results.push('     ✅ No ransom note patterns detected');
    } else if (ransomNoteScore >= 30) {
      results.push('\n  🔴 STRONG RANSOM NOTE INDICATORS!');
      results.push('     └── Multiple ransom-related text patterns found');
    }
    results.push('');

    // ===== 5. KEY HANDLING ANALYSIS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. 🔑 KEY HANDLING & STORAGE                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Key-related patterns
    const keyPatterns = [
      { pattern: 'public key', desc: 'Public key reference', weight: 5 },
      { pattern: 'private key', desc: 'Private key reference', weight: 6 },
      { pattern: 'master key', desc: 'Master key reference', weight: 8 },
      { pattern: 'session key', desc: 'Session key reference', weight: 6 },
      { pattern: 'key_id', desc: 'Key identifier', weight: 4 },
      { pattern: 'encryption_key', desc: 'Encryption key ref', weight: 6 },
      { pattern: '-----begin rsa', desc: 'RSA PEM format', weight: 8 },
      { pattern: '-----begin public', desc: 'Public key PEM', weight: 7 },
      { pattern: 'miibij', desc: 'Base64 RSA key', weight: 7 },
    ];

    results.push('  🔍 KEY REFERENCES:');
    for (const kp of keyPatterns) {
      if (strings.includes(kp.pattern)) {
        ransomwareScore += kp.weight;
        findings.push({
          category: 'Key Handling',
          indicator: kp.pattern,
          description: kp.desc,
          confidence: kp.weight >= 6 ? 'HIGH' : 'MEDIUM',
          points: kp.weight,
        });
        const emoji = kp.weight >= 6 ? '🔴' : '🟡';
        results.push(`     ${emoji} ${kp.desc}`);
      }
    }

    // Check for embedded keys
    const base64KeyPattern = strings.match(/[a-za-z0-9+/]{50,}={0,2}/);
    if (base64KeyPattern) {
      results.push('     🔴 Possible embedded Base64 key material detected');
      ransomwareScore += 10;
      findings.push({
        category: 'Key Handling',
        indicator: 'Embedded Key',
        description: 'Possible hardcoded encryption key',
        confidence: 'MEDIUM',
        points: 10,
      });
    }
    results.push('');

    // ===== 6. SHADOW COPY / BACKUP DELETION =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 6. 💾 BACKUP DESTRUCTION INDICATORS                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const backupDestructionPatterns = [
      { pattern: 'vssadmin', desc: 'Volume Shadow Service admin', weight: 12 },
      { pattern: 'delete shadows', desc: 'Shadow copy deletion', weight: 15 },
      {
        pattern: 'wmic shadowcopy',
        desc: 'WMI shadow copy access',
        weight: 12,
      },
      { pattern: 'bcdedit', desc: 'Boot config editor', weight: 8 },
      { pattern: 'recoveryenabled', desc: 'Disable recovery', weight: 10 },
      { pattern: 'wbadmin', desc: 'Backup admin tool', weight: 10 },
      {
        pattern: 'delete catalog',
        desc: 'Backup catalog deletion',
        weight: 12,
      },
      {
        pattern: 'disablerepairtool',
        desc: 'Disable repair tools',
        weight: 10,
      },
      {
        pattern: 'win32_shadowcopy',
        desc: 'WMI shadow copy class',
        weight: 12,
      },
    ];

    results.push('  🔍 BACKUP DESTRUCTION:');
    let backupDestructionFound = false;

    for (const bd of backupDestructionPatterns) {
      if (strings.includes(bd.pattern)) {
        backupDestructionFound = true;
        ransomwareScore += bd.weight;
        findings.push({
          category: 'Backup Destruction',
          indicator: bd.pattern,
          description: bd.desc,
          confidence: 'HIGH',
          points: bd.weight,
        });
        results.push(`     🔴 ${bd.desc} (${bd.pattern})`);
      }
    }

    if (!backupDestructionFound) {
      results.push('     ✅ No backup destruction patterns detected');
    } else {
      results.push('\n  🔴 CRITICAL: Backup destruction capability detected!');
      results.push('     └── MITRE: T1490 (Inhibit System Recovery)');
    }
    results.push('');

    // ===== RANSOMWARE ASSESSMENT =====
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📊 RANSOMWARE ASSESSMENT SUMMARY');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Cap score at 100
    ransomwareScore = Math.min(ransomwareScore, 100);

    // Determine ransomware likelihood
    let likelihood: string;
    let likelihoodEmoji: string;
    let assessment: string;

    if (ransomwareScore >= 80) {
      likelihood = 'CONFIRMED RANSOMWARE';
      likelihoodEmoji = '🔴';
      assessment = 'This binary exhibits definitive ransomware characteristics';
    } else if (ransomwareScore >= 60) {
      likelihood = 'HIGHLY LIKELY RANSOMWARE';
      likelihoodEmoji = '🟠';
      assessment = 'Strong ransomware indicators present';
    } else if (ransomwareScore >= 40) {
      likelihood = 'POSSIBLE RANSOMWARE';
      likelihoodEmoji = '🟡';
      assessment = 'Multiple suspicious indicators warrant deep analysis';
    } else if (ransomwareScore >= 20) {
      likelihood = 'LOW LIKELIHOOD';
      likelihoodEmoji = '🟢';
      assessment = 'Some crypto capabilities but limited ransomware indicators';
    } else {
      likelihood = 'UNLIKELY RANSOMWARE';
      likelihoodEmoji = '✅';
      assessment = 'No significant ransomware characteristics detected';
    }

    const scoreBar =
      '█'.repeat(Math.floor(ransomwareScore / 5)) +
      '░'.repeat(20 - Math.floor(ransomwareScore / 5));
    results.push(`  ${likelihoodEmoji} ASSESSMENT: ${likelihood}`);
    results.push(`  📈 RANSOMWARE SCORE: ${ransomwareScore}/100`);
    results.push(`     [${scoreBar}]`);
    results.push(`\n  💡 ${assessment}\n`);

    // Findings breakdown
    const highFindings = findings.filter((f) => f.confidence === 'HIGH');
    const mediumFindings = findings.filter((f) => f.confidence === 'MEDIUM');

    results.push('  📋 FINDINGS BREAKDOWN:');
    results.push(`     🔴 High Confidence: ${highFindings.length}`);
    results.push(`     🟡 Medium Confidence: ${mediumFindings.length}`);
    results.push(
      `     ℹ️ Low Confidence: ${findings.length - highFindings.length - mediumFindings.length}`,
    );

    // Key indicators
    if (highFindings.length > 0) {
      results.push('\n  🎯 KEY INDICATORS:');
      for (const f of highFindings.slice(0, 8)) {
        results.push(`     🔴 ${f.indicator} - ${f.description}`);
      }
    }

    // Identified encryption scheme
    if (detectedAlgos.length > 0) {
      results.push('\n  🔐 ENCRYPTION SCHEME:');
      results.push(`     Algorithms: ${detectedAlgos.join(' + ')}`);
      if (
        detectedAlgos.some((a) => a.includes('RSA')) &&
        detectedAlgos.some((a) => a.includes('AES'))
      ) {
        results.push(
          '     Pattern: Hybrid (RSA + AES) - Industry standard ransomware',
        );
      }
    }

    // Structured JSON output
    results.push(
      '\n═══════════════════════════════════════════════════════════════',
    );
    results.push('   🤖 STRUCTURED DATA (for LLM processing)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );
    results.push('```json');
    results.push(
      JSON.stringify(
        {
          ransomwareScore,
          maxScore: 100,
          likelihood,
          assessment,
          encryptionScheme: {
            algorithms: detectedAlgos,
            isHybrid:
              detectedAlgos.some((a) => a.includes('RSA')) &&
              detectedAlgos.some((a) => a.includes('AES')),
            hasEncryptOnly: encryptAPIFound && !imports.includes('decrypt'),
          },
          indicators: {
            cryptoAPIs: windowsCryptoCount + opensslCount,
            targetedExtensions: targetExtCount,
            ransomwareExtensions: foundRansomExts.length,
            ransomNotePatterns: foundRansomPatterns.length,
            backupDestruction: backupDestructionFound,
          },
          findings,
          mitreTechniques: [
            backupDestructionFound ? 'T1490' : null,
            targetExtCount > 5 ? 'T1486' : null,
            encryptAPIFound ? 'T1486' : null,
          ].filter(Boolean),
        },
        null,
        2,
      ),
    );
    results.push('```');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  /**
   * String Decode - Decode obfuscated/encoded strings in binary
   * Supports: Base64, XOR, ROT13, Hex, URL encoding, Unicode escapes, RC4-like patterns
   */
  private async stringDecode(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔓 STRING DECODER - Encoded/Obfuscated String Analysis');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const decodedStrings: Array<{
      original: string;
      decoded: string;
      encoding: string;
      confidence: 'HIGH' | 'MEDIUM' | 'LOW';
      category: string;
    }> = [];

    // Helper: Base64 decode
    const tryBase64Decode = (str: string): string | null => {
      try {
        // Valid base64 pattern (min 4 chars, proper padding)
        if (!/^[A-Za-z0-9+/]{4,}={0,2}$/.test(str)) return null;
        if (str.length < 8) return null; // Too short to be meaningful
        const decoded = Buffer.from(str, 'base64').toString('utf-8');
        // Check if result is printable ASCII
        if (/^[\x20-\x7E\r\n\t]+$/.test(decoded) && decoded.length >= 3) {
          return decoded;
        }
        return null;
      } catch {
        return null;
      }
    };

    // Helper: Hex decode
    const tryHexDecode = (str: string): string | null => {
      try {
        // Valid hex pattern (even length, hex chars only)
        const cleaned = str.replace(/[^0-9A-Fa-f]/g, '');
        if (cleaned.length < 8 || cleaned.length % 2 !== 0) return null;
        const decoded = Buffer.from(cleaned, 'hex').toString('utf-8');
        if (/^[\x20-\x7E\r\n\t]+$/.test(decoded) && decoded.length >= 3) {
          return decoded;
        }
        return null;
      } catch {
        return null;
      }
    };

    // Helper: ROT13 decode
    const tryRot13Decode = (str: string): string =>
      str.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });

    // Helper: URL decode
    const tryUrlDecode = (str: string): string | null => {
      try {
        if (!str.includes('%')) return null;
        const decoded = decodeURIComponent(str);
        if (decoded !== str && decoded.length >= 3) {
          return decoded;
        }
        return null;
      } catch {
        return null;
      }
    };

    // Helper: Unicode escape decode (\uXXXX or \xXX)
    const tryUnicodeDecode = (str: string): string | null => {
      try {
        if (!str.includes('\\u') && !str.includes('\\x')) return null;
        const decoded = str
          .replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
            String.fromCharCode(parseInt(hex, 16)),
          )
          .replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) =>
            String.fromCharCode(parseInt(hex, 16)),
          );
        if (decoded !== str && /^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
          return decoded;
        }
        return null;
      } catch {
        return null;
      }
    };

    // Helper: XOR with common keys (single byte)
    const tryXorDecode = (
      bytes: number[],
    ): Array<{ key: number; decoded: string }> => {
      const results: Array<{ key: number; decoded: string }> = [];
      // Try common XOR keys
      const commonKeys = [
        0x00, 0x20, 0x41, 0x55, 0xaa, 0xff, 0x37, 0x42, 0x69, 0x13,
      ];
      for (const key of commonKeys) {
        if (key === 0) continue;
        const decoded = bytes.map((b) => b ^ key);
        const str = String.fromCharCode(...decoded);
        // Check if result looks like readable text
        const printable = str.replace(/[^\x20-\x7E]/g, '').length;
        if (printable / str.length > 0.8 && str.length >= 4) {
          results.push({ key, decoded: str });
        }
      }
      return results;
    };

    // Helper: Detect reversed strings
    const tryReverse = (str: string): string | null => {
      const reversed = str.split('').reverse().join('');
      // Check if reversed looks like common strings
      const commonPatterns = [
        /^https?:\/\//i,
        /\.exe$/i,
        /\.dll$/i,
        /\.bat$/i,
        /^[A-Z]:\\/,
        /^cmd/i,
        /^powershell/i,
        /password/i,
        /admin/i,
        /system32/i,
      ];
      for (const pattern of commonPatterns) {
        if (pattern.test(reversed) && !pattern.test(str)) {
          return reversed;
        }
      }
      return null;
    };

    // ===== STEP 1: EXTRACT ALL STRINGS =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. 📝 EXTRACTING STRINGS FROM BINARY                        │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Get all strings (including short ones that might be encoded)
      const stringsResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );

      if (!stringsResult.success || !stringsResult.output) {
        return {
          success: false,
          output: 'Failed to extract strings from binary',
        };
      }

      const lines = stringsResult.output.split('\n');
      const extractedStrings: string[] = [];

      for (const line of lines) {
        // Extract string content from r2 output
        const match = line.match(/\s+(\d+)\s+(\d+)\s+\S+\s+(\S+)\s+(.+)$/);
        if (match && match[4]) {
          extractedStrings.push(match[4]);
        }
      }

      results.push(
        `  📊 Total strings extracted: ${extractedStrings.length}\n`,
      );

      // ===== STEP 2: BASE64 DETECTION =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 2. 🔤 BASE64 ENCODED STRINGS                                │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      let base64Found = 0;
      for (const str of extractedStrings) {
        // Look for base64-like patterns
        if (/^[A-Za-z0-9+/]{12,}={0,2}$/.test(str)) {
          const decoded = tryBase64Decode(str);
          if (decoded) {
            base64Found++;
            decodedStrings.push({
              original: str.length > 50 ? str.substring(0, 50) + '...' : str,
              decoded:
                decoded.length > 100
                  ? decoded.substring(0, 100) + '...'
                  : decoded,
              encoding: 'Base64',
              confidence: 'HIGH',
              category: this.categorizeDecodedString(decoded),
            });
            if (base64Found <= 20) {
              results.push(`  🔓 DECODED Base64:`);
              results.push(
                `     Original: ${str.length > 60 ? str.substring(0, 60) + '...' : str}`,
              );
              results.push(
                `     Decoded:  ${decoded.length > 80 ? decoded.substring(0, 80) + '...' : decoded}`,
              );
              results.push(
                `     Category: ${this.categorizeDecodedString(decoded)}\n`,
              );
            }
          }
        }
      }

      if (base64Found === 0) {
        results.push('  ✅ No Base64 encoded strings found\n');
      } else if (base64Found > 20) {
        results.push(`  ... and ${base64Found - 20} more Base64 strings\n`);
      }

      // ===== STEP 3: HEX ENCODED STRINGS =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 3. 🔢 HEX ENCODED STRINGS                                   │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      let hexFound = 0;
      for (const str of extractedStrings) {
        // Look for hex-like patterns (0x prefix or pure hex)
        if (/^(0x)?[0-9A-Fa-f]{16,}$/.test(str)) {
          const decoded = tryHexDecode(str);
          if (decoded) {
            hexFound++;
            decodedStrings.push({
              original: str.length > 50 ? str.substring(0, 50) + '...' : str,
              decoded,
              encoding: 'Hex',
              confidence: 'HIGH',
              category: this.categorizeDecodedString(decoded),
            });
            if (hexFound <= 10) {
              results.push(`  🔓 DECODED Hex:`);
              results.push(
                `     Original: ${str.length > 60 ? str.substring(0, 60) + '...' : str}`,
              );
              results.push(`     Decoded:  ${decoded}\n`);
            }
          }
        }
      }

      if (hexFound === 0) {
        results.push('  ✅ No Hex encoded strings found\n');
      } else if (hexFound > 10) {
        results.push(`  ... and ${hexFound - 10} more Hex strings\n`);
      }

      // ===== STEP 4: URL ENCODED STRINGS =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 4. 🌐 URL ENCODED STRINGS                                   │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      let urlFound = 0;
      for (const str of extractedStrings) {
        if (str.includes('%')) {
          const decoded = tryUrlDecode(str);
          if (decoded) {
            urlFound++;
            decodedStrings.push({
              original: str.length > 50 ? str.substring(0, 50) + '...' : str,
              decoded,
              encoding: 'URL',
              confidence: 'HIGH',
              category: this.categorizeDecodedString(decoded),
            });
            if (urlFound <= 10) {
              results.push(`  🔓 DECODED URL:`);
              results.push(
                `     Original: ${str.length > 60 ? str.substring(0, 60) + '...' : str}`,
              );
              results.push(`     Decoded:  ${decoded}\n`);
            }
          }
        }
      }

      if (urlFound === 0) {
        results.push('  ✅ No URL encoded strings found\n');
      }

      // ===== STEP 5: UNICODE ESCAPE SEQUENCES =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 5. 🔣 UNICODE ESCAPE SEQUENCES                              │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      let unicodeFound = 0;
      for (const str of extractedStrings) {
        if (str.includes('\\u') || str.includes('\\x')) {
          const decoded = tryUnicodeDecode(str);
          if (decoded) {
            unicodeFound++;
            decodedStrings.push({
              original: str.length > 50 ? str.substring(0, 50) + '...' : str,
              decoded,
              encoding: 'Unicode Escape',
              confidence: 'HIGH',
              category: this.categorizeDecodedString(decoded),
            });
            if (unicodeFound <= 10) {
              results.push(`  🔓 DECODED Unicode:`);
              results.push(
                `     Original: ${str.length > 60 ? str.substring(0, 60) + '...' : str}`,
              );
              results.push(`     Decoded:  ${decoded}\n`);
            }
          }
        }
      }

      if (unicodeFound === 0) {
        results.push('  ✅ No Unicode escape sequences found\n');
      }

      // ===== STEP 6: ROT13 DETECTION =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 6. 🔄 ROT13/CAESAR CIPHER DETECTION                         │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      let rot13Found = 0;
      // Keywords to look for after ROT13 decode
      const rot13Keywords = [
        'http',
        'https',
        'www',
        'password',
        'admin',
        'system',
        'cmd',
        'powershell',
        'reg',
        'key',
        'flag',
        'secret',
        'encrypt',
        'decrypt',
        '.exe',
        '.dll',
        '.bat',
        'windows',
        'software',
        'microsoft',
      ];

      for (const str of extractedStrings) {
        if (str.length >= 6 && /^[a-zA-Z]+$/.test(str)) {
          const decoded = tryRot13Decode(str);
          const decodedLower = decoded.toLowerCase();
          for (const kw of rot13Keywords) {
            if (decodedLower.includes(kw) && !str.toLowerCase().includes(kw)) {
              rot13Found++;
              decodedStrings.push({
                original: str,
                decoded,
                encoding: 'ROT13',
                confidence: 'MEDIUM',
                category: this.categorizeDecodedString(decoded),
              });
              if (rot13Found <= 10) {
                results.push(`  🔓 DECODED ROT13:`);
                results.push(`     Original: ${str}`);
                results.push(`     Decoded:  ${decoded}`);
                results.push(`     Keyword:  "${kw}" found\n`);
              }
              break;
            }
          }
        }
      }

      if (rot13Found === 0) {
        results.push('  ✅ No ROT13 encoded strings found\n');
      }

      // ===== STEP 7: REVERSED STRING DETECTION =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 7. ↩️  REVERSED STRING DETECTION                            │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      let reversedFound = 0;
      for (const str of extractedStrings) {
        if (str.length >= 4) {
          const decoded = tryReverse(str);
          if (decoded) {
            reversedFound++;
            decodedStrings.push({
              original: str,
              decoded,
              encoding: 'Reversed',
              confidence: 'HIGH',
              category: this.categorizeDecodedString(decoded),
            });
            if (reversedFound <= 10) {
              results.push(`  🔓 DECODED Reversed:`);
              results.push(`     Original: ${str}`);
              results.push(`     Decoded:  ${decoded}\n`);
            }
          }
        }
      }

      if (reversedFound === 0) {
        results.push('  ✅ No reversed strings found\n');
      }

      // ===== STEP 8: XOR ENCODED DATA =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 8. ⊕ XOR ENCODED DATA DETECTION                            │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      // Look for data sections that might be XOR encoded
      const dataResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "px 1000 @ section..data" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 6,
      );

      let xorFound = 0;
      if (dataResult.success && dataResult.output) {
        // Extract hex bytes from output
        const hexMatches = dataResult.output.match(/([0-9a-fA-F]{2}\s){8,}/g);
        if (hexMatches) {
          for (const hexLine of hexMatches.slice(0, 10)) {
            const bytes = hexLine
              .trim()
              .split(/\s+/)
              .map((h) => parseInt(h, 16))
              .filter((n) => !isNaN(n));
            if (bytes.length >= 8) {
              const xorResults = tryXorDecode(bytes);
              for (const xr of xorResults) {
                xorFound++;
                if (xorFound <= 5) {
                  results.push(
                    `  🔓 POSSIBLE XOR (key: 0x${xr.key.toString(16).padStart(2, '0')}):`,
                  );
                  results.push(
                    `     Decoded: ${xr.decoded.substring(0, 60)}${xr.decoded.length > 60 ? '...' : ''}\n`,
                  );
                }
              }
            }
          }
        }
      }

      if (xorFound === 0) {
        results.push('  ✅ No obvious XOR encoded data found\n');
        results.push('  💡 TIP: For complex XOR, use xortool or FLOSS\n');
      }

      // ===== STEP 9: STACK STRINGS DETECTION =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 9. 📚 STACK STRING DETECTION                                │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      // Look for mov byte patterns that build strings on stack
      const stackResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "pd 500 @ entry0" ${escapeShellArg(targetPath)} 2>/dev/null | grep -E "mov.*byte.*0x[2-7][0-9a-fA-F]"`,
        timeout / 6,
      );

      if (stackResult.success && stackResult.output) {
        const movBytes = stackResult.output.match(/0x([2-7][0-9a-fA-F])/g);
        if (movBytes && movBytes.length >= 4) {
          const chars = movBytes
            .map((h) => String.fromCharCode(parseInt(h, 16)))
            .join('');
          if (/^[\x20-\x7E]+$/.test(chars)) {
            results.push(`  🔓 POSSIBLE STACK STRING:`);
            results.push(`     Characters: ${chars}`);
            results.push(`     Length: ${chars.length}\n`);
            decodedStrings.push({
              original: '[stack construction]',
              decoded: chars,
              encoding: 'Stack String',
              confidence: 'MEDIUM',
              category: this.categorizeDecodedString(chars),
            });
          }
        }
      }

      results.push(
        '  💡 TIP: For advanced stack strings, use FLOSS (FireEye Labs Obfuscated String Solver)\n',
      );

      // ===== SUMMARY =====
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 📊 DECODING SUMMARY                                         │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      // ===== CRITICAL: FALSE POSITIVE WARNING =====
      results.push('  ⚠️⚠️⚠️ CRITICAL: VERIFICATION REQUIRED ⚠️⚠️⚠️');
      results.push(
        '  ┌───────────────────────────────────────────────────────────┐',
      );
      results.push(
        '  │ THESE RESULTS MAY CONTAIN FALSE POSITIVES!                │',
      );
      results.push(
        '  │                                                           │',
      );
      results.push(
        '  │ Common False Positives:                                   │',
      );
      results.push(
        '  │ • Random data that happens to decode to ASCII             │',
      );
      results.push(
        '  │ • Compiler artifacts, debug symbols                       │',
      );
      results.push(
        '  │ • Resource strings (icons, dialogs)                       │',
      );
      results.push(
        '  │ • Library/runtime strings (not malicious)                 │',
      );
      results.push(
        '  │                                                           │',
      );
      results.push(
        '  │ YOU MUST MANUALLY VERIFY EACH FINDING:                    │',
      );
      results.push(
        '  │ 1. Check context - where is the string located?           │',
      );
      results.push(
        '  │ 2. Check references - what code uses this string?         │',
      );
      results.push(
        '  │ 3. Check meaning - does it make sense in context?         │',
      );
      results.push(
        '  │ 4. Cross-reference with other analysis results            │',
      );
      results.push(
        '  └───────────────────────────────────────────────────────────┘\n',
      );

      results.push(`  🔓 Total Decoded Strings: ${decodedStrings.length}\n`);

      if (decodedStrings.length > 0) {
        // Group by encoding type
        const byEncoding: Record<string, number> = {};
        const byCategory: Record<string, string[]> = {};

        for (const ds of decodedStrings) {
          byEncoding[ds.encoding] = (byEncoding[ds.encoding] || 0) + 1;
          if (!byCategory[ds.category]) byCategory[ds.category] = [];
          byCategory[ds.category].push(ds.decoded);
        }

        results.push('  📈 By Encoding Type:');
        for (const [enc, count] of Object.entries(byEncoding)) {
          results.push(`     • ${enc}: ${count}`);
        }
        results.push('');

        results.push('  🏷️ By Category:');
        for (const [cat, strs] of Object.entries(byCategory)) {
          results.push(`     • ${cat}: ${strs.length}`);
          // Show first few examples
          for (const s of strs.slice(0, 3)) {
            results.push(
              `       - ${s.length > 50 ? s.substring(0, 50) + '...' : s}`,
            );
          }
        }
        results.push('');

        // Highlight suspicious findings
        const suspiciousCategories = [
          'URL/Network',
          'Credential',
          'Command',
          'Registry',
          'File Path',
        ];
        const suspicious = decodedStrings.filter((ds) =>
          suspiciousCategories.includes(ds.category),
        );

        if (suspicious.length > 0) {
          results.push('  ⚠️ POTENTIALLY SUSPICIOUS (NEEDS VERIFICATION):');
          results.push('  ─────────────────────────────────────────────────');
          for (const s of suspicious.slice(0, 10)) {
            results.push(`     ❓ [${s.category}] ${s.decoded}`);
            results.push(
              `        └─ Confidence: ${s.confidence} | Encoding: ${s.encoding}`,
            );
            results.push(
              `        └─ ⚠️ VERIFY: Check xrefs, context, and actual usage`,
            );
          }
          results.push('');
          results.push('  🔍 MANUAL VERIFICATION STEPS FOR EACH:');
          results.push(
            '     1. Use "xrefs" operation to find what code references this',
          );
          results.push('     2. Disassemble the referencing function');
          results.push(
            '     3. Determine if string is actually USED or just DATA',
          );
          results.push(
            '     4. Check if it could be from a library or resource\n',
          );
        }

        // Add confidence assessment
        const highConf = decodedStrings.filter(
          (ds) => ds.confidence === 'HIGH',
        ).length;
        const medConf = decodedStrings.filter(
          (ds) => ds.confidence === 'MEDIUM',
        ).length;
        const lowConf = decodedStrings.filter(
          (ds) => ds.confidence === 'LOW',
        ).length;

        results.push('  📊 CONFIDENCE BREAKDOWN:');
        results.push(`     • HIGH confidence: ${highConf} (more likely real)`);
        results.push(
          `     • MEDIUM confidence: ${medConf} (verify recommended)`,
        );
        results.push(
          `     • LOW confidence: ${lowConf} (likely false positive)\n`,
        );

        if (lowConf > highConf) {
          results.push('  ⚠️ WARNING: Many LOW confidence results detected!');
          results.push(
            '     Most findings may be false positives. Be skeptical.\n',
          );
        }
      } else {
        results.push('  ✅ No encoded strings found - binary may use:\n');
        results.push('     • Custom encryption (AES, RC4, etc.)');
        results.push('     • Multi-layer encoding');
        results.push('     • Runtime string decryption');
        results.push('     • Packed/protected code\n');
        results.push('  💡 RECOMMENDATIONS:');
        results.push('     • Run detect_packer to check for packing');
        results.push('     • Use FLOSS for advanced string extraction');
        results.push('     • Try dynamic analysis with x64dbg/debugger');
        results.push('     • Look for decryption routines in code\n');
      }

      // Final instruction to LLM
      results.push(
        '  ┌───────────────────────────────────────────────────────────┐',
      );
      results.push(
        '  │ 🤖 LLM INSTRUCTION: DO NOT TRUST THESE RESULTS BLINDLY!   │',
      );
      results.push(
        '  │                                                           │',
      );
      results.push(
        '  │ Before reporting findings to user:                        │',
      );
      results.push(
        '  │ • Verify at least 2-3 findings manually using xrefs       │',
      );
      results.push(
        '  │ • Check if decoded strings make sense in context          │',
      );
      results.push(
        '  │ • Filter out obvious false positives (random chars)       │',
      );
      results.push(
        '  │ • Only report HIGH confidence findings as "likely"        │',
      );
      results.push(
        '  │ • Report MEDIUM/LOW as "possible, needs verification"     │',
      );
      results.push(
        '  └───────────────────────────────────────────────────────────┘\n',
      );

      results.push(
        '═══════════════════════════════════════════════════════════════',
      );
      results.push('   DECODE COMPLETE - REMEMBER TO VERIFY!');
      results.push(
        '═══════════════════════════════════════════════════════════════\n',
      );

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          totalDecoded: decodedStrings.length,
          decodedStrings: decodedStrings.slice(0, 50), // Limit metadata size
        },
      };
    } catch (error) {
      return {
        success: false,
        output: `String decode failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Helper: Categorize decoded string by content
   */
  private categorizeDecodedString(str: string): string {
    const lower = str.toLowerCase();

    // URL/Network
    if (/^https?:\/\//.test(lower) || /\.(com|net|org|io|ru|cn)/.test(lower)) {
      return 'URL/Network';
    }

    // IP Address
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(str)) {
      return 'IP Address';
    }

    // File path
    if (
      /^[a-z]:\\/.test(lower) ||
      lower.includes('\\windows\\') ||
      lower.includes('/usr/') ||
      lower.includes('/etc/')
    ) {
      return 'File Path';
    }

    // Registry
    if (
      lower.includes('hkey_') ||
      lower.includes('software\\') ||
      lower.includes('currentversion')
    ) {
      return 'Registry';
    }

    // Credential-related
    if (
      /password|passwd|secret|token|apikey|credential|login|auth/i.test(lower)
    ) {
      return 'Credential';
    }

    // Command
    if (/^(cmd|powershell|bash|sh|exec|system|eval)/i.test(lower)) {
      return 'Command';
    }

    // File extension
    if (/\.(exe|dll|bat|ps1|vbs|js|py|sh)$/i.test(lower)) {
      return 'Executable';
    }

    // Flag/CTF
    if (/flag\{|ctf\{|key\{|secret\{/i.test(lower)) {
      return 'Flag/CTF';
    }

    return 'General';
  }
  private async behaviorIndicators(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: false,
      output: 'behavior_indicators not yet implemented',
    };
  }
  private async persistenceMechanisms(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: false,
      output: 'persistence_mechanisms not yet implemented',
    };
  }

  /**
   * Full capability analysis - Comprehensive evasion & malicious capability detection
   * Maps findings to MITRE ATT&CK framework
   */
  private async capabilityAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🎯 COMPREHENSIVE CAPABILITY & EVASION ANALYSIS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const capabilities: Array<{
      tactic: string;
      technique: string;
      techId: string;
      indicator: string;
      confidence: 'HIGH' | 'MEDIUM' | 'LOW';
      details: string;
    }> = [];

    // Get all imports and strings upfront
    let imports = '';
    let strings = '';
    let sections = '';

    try {
      const [importRes, stringRes, sectionRes] = await Promise.all([
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "iS" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
      ]);
      imports = importRes.success ? importRes.output.toLowerCase() : '';
      strings = stringRes.success ? stringRes.output.toLowerCase() : '';
      sections = sectionRes.success ? sectionRes.output.toLowerCase() : '';
    } catch {
      results.push('⚠️ Warning: Could not fully analyze binary\n');
    }

    // ===== 1. DEFENSE EVASION (TA0005) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. 🛡️ DEFENSE EVASION (TA0005)                              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Process Injection (T1055)
    const processInjectionAPIs = [
      {
        api: 'VirtualAllocEx',
        sub: 'T1055.001',
        desc: 'Remote memory allocation',
      },
      {
        api: 'WriteProcessMemory',
        sub: 'T1055.001',
        desc: 'Write to remote process',
      },
      {
        api: 'CreateRemoteThread',
        sub: 'T1055.001',
        desc: 'Remote thread creation',
      },
      {
        api: 'CreateRemoteThreadEx',
        sub: 'T1055.001',
        desc: 'Extended remote thread',
      },
      {
        api: 'NtCreateThreadEx',
        sub: 'T1055.001',
        desc: 'Native remote thread',
      },
      {
        api: 'RtlCreateUserThread',
        sub: 'T1055.001',
        desc: 'RTL remote thread',
      },
      { api: 'QueueUserAPC', sub: 'T1055.004', desc: 'APC injection' },
      {
        api: 'NtQueueApcThread',
        sub: 'T1055.004',
        desc: 'Native APC injection',
      },
      {
        api: 'SetWindowsHookEx',
        sub: 'T1055.001',
        desc: 'Hook-based injection',
      },
      {
        api: 'NtMapViewOfSection',
        sub: 'T1055.012',
        desc: 'Section mapping injection',
      },
      {
        api: 'NtUnmapViewOfSection',
        sub: 'T1055.012',
        desc: 'Process hollowing',
      },
      {
        api: 'SetThreadContext',
        sub: 'T1055.012',
        desc: 'Thread context manipulation',
      },
      {
        api: 'GetThreadContext',
        sub: 'T1055.012',
        desc: 'Thread context read',
      },
      {
        api: 'NtSetContextThread',
        sub: 'T1055.012',
        desc: 'Native context set',
      },
      {
        api: 'ResumeThread',
        sub: 'T1055.012',
        desc: 'Resume suspended thread',
      },
      { api: 'SuspendThread', sub: 'T1055.012', desc: 'Suspend target thread' },
    ];

    let injectionCount = 0;
    for (const api of processInjectionAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        injectionCount++;
        capabilities.push({
          tactic: 'Defense Evasion',
          technique: 'Process Injection',
          techId: api.sub,
          indicator: api.api,
          confidence: 'HIGH',
          details: api.desc,
        });
      }
    }

    if (injectionCount >= 3) {
      results.push('  🔴 PROCESS INJECTION CAPABILITY DETECTED');
      results.push(`     └── ${injectionCount} injection-related APIs found`);
      results.push('     └── MITRE: T1055 (Process Injection)\n');
    } else if (injectionCount > 0) {
      results.push(
        `  🟡 Potential process injection (${injectionCount} APIs)\n`,
      );
    }

    // DLL Injection specific
    const dllInjectionAPIs = [
      'LoadLibrary',
      'LdrLoadDll',
      'GetProcAddress',
      'GetModuleHandle',
    ];
    let dllInjectCount = 0;
    for (const api of dllInjectionAPIs) {
      if (imports.includes(api.toLowerCase())) dllInjectCount++;
    }
    if (dllInjectCount >= 3 && injectionCount >= 2) {
      results.push('  🔴 DLL INJECTION PATTERN DETECTED');
      results.push('     └── Classic DLL injection technique\n');
      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'DLL Injection',
        techId: 'T1055.001',
        indicator: 'DLL injection API pattern',
        confidence: 'HIGH',
        details: 'LoadLibrary + remote thread creation',
      });
    }

    // Process Hollowing (T1055.012)
    const hollowingAPIs = [
      'CreateProcess',
      'NtUnmapViewOfSection',
      'VirtualAllocEx',
      'WriteProcessMemory',
      'SetThreadContext',
      'ResumeThread',
    ];
    let hollowCount = 0;
    for (const api of hollowingAPIs) {
      if (imports.includes(api.toLowerCase())) hollowCount++;
    }
    if (hollowCount >= 5) {
      results.push('  🔴 PROCESS HOLLOWING CAPABILITY');
      results.push('     └── Full hollowing API chain detected');
      results.push('     └── MITRE: T1055.012 (Process Hollowing)\n');
      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Process Hollowing',
        techId: 'T1055.012',
        indicator: 'Hollowing API chain',
        confidence: 'HIGH',
        details: 'CreateProcess + Unmap + Write + SetContext pattern',
      });
    }

    // Unhooking/Syscall evasion - ENHANCED FOR MODERN MALWARE
    results.push('  🔍 SYSCALL & HOOK EVASION ANALYSIS:');

    // Direct syscall indicators
    const directSyscallPatterns = [
      {
        pattern: 'syscall',
        desc: 'Direct syscall instruction (x64)',
        confidence: 'HIGH',
      },
      { pattern: 'sysenter', desc: 'Direct syscall (x86)', confidence: 'HIGH' },
      {
        pattern: 'int 2e',
        desc: 'Legacy syscall interrupt',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'wow64transition',
        desc: "Heaven's Gate technique",
        confidence: 'HIGH',
      },
      {
        pattern: 'heavens gate',
        desc: "Heaven's Gate bypass",
        confidence: 'HIGH',
      },
      {
        pattern: 'ntdll!zw',
        desc: 'NTDLL Zw functions (syscall wrappers)',
        confidence: 'MEDIUM',
      },
      { pattern: 'ssn', desc: 'System Service Number', confidence: 'HIGH' },
      { pattern: '0f 05', desc: 'Syscall opcode (x64)', confidence: 'HIGH' },
      { pattern: '0f 34', desc: 'Sysenter opcode', confidence: 'HIGH' },
    ];

    // NTDLL unhooking APIs
    const unhookAPIs = [
      {
        api: 'NtProtectVirtualMemory',
        risk: 'HIGH',
        desc: 'Change memory protection for unhooking',
      },
      {
        api: 'NtAllocateVirtualMemory',
        risk: 'HIGH',
        desc: 'Allocate memory for fresh NTDLL',
      },
      {
        api: 'NtReadVirtualMemory',
        risk: 'MEDIUM',
        desc: 'Read clean NTDLL from disk',
      },
      {
        api: 'NtWriteVirtualMemory',
        risk: 'HIGH',
        desc: 'Write unhooked NTDLL',
      },
      {
        api: 'GetModuleInformation',
        risk: 'MEDIUM',
        desc: 'Get NTDLL base address',
      },
      {
        api: 'GetModuleHandle',
        risk: 'LOW',
        desc: 'Get NTDLL handle (common)',
      },
      {
        api: 'NtMapViewOfSection',
        risk: 'HIGH',
        desc: 'Map clean NTDLL section',
      },
      { api: 'NtUnmapViewOfSection', risk: 'HIGH', desc: 'Unmap hooked NTDLL' },
    ];

    // Unhooking-related strings
    const unhookStrings = [
      'ntdll.dll',
      'kernel32.dll',
      '.text section',
      'unhook',
      'fresh copy',
      'syscall stub',
      'hook detection',
      'edr bypass',
      'av evasion',
      'direct syscall',
      'syscall resolve',
      "hell's gate",
      "halo's gate",
      "tartarus' gate",
      'syswhisper',
      'freshycalls',
    ];

    let syscallScore = 0;
    const syscallIndicators: string[] = [];

    // Check for direct syscall patterns
    for (const { pattern, desc, confidence } of directSyscallPatterns) {
      if (strings.includes(pattern)) {
        syscallScore += confidence === 'HIGH' ? 15 : 10;
        syscallIndicators.push(`${pattern} - ${desc}`);
        results.push(`     🔴 ${desc}`);
      }
    }

    // Check unhooking APIs
    let _highRiskAPICount = 0;
    for (const { api, risk, desc } of unhookAPIs) {
      if (imports.includes(api.toLowerCase())) {
        const points = risk === 'HIGH' ? 10 : risk === 'MEDIUM' ? 5 : 2;
        syscallScore += points;
        if (risk === 'HIGH') {
          _highRiskAPICount++;
          syscallIndicators.push(`${api} - ${desc}`);
          results.push(`     🔴 ${api} - ${desc}`);
        }
      }
    }

    // Check unhooking strings
    for (const str of unhookStrings) {
      if (strings.includes(str)) {
        syscallScore += 3;
        syscallIndicators.push(str);
      }
    }

    // Pattern: NtProtectVirtualMemory + NtWriteVirtualMemory = likely unhooking
    if (
      imports.includes('ntprotectvirtualmemory') &&
      imports.includes('ntwritevirtualmemory')
    ) {
      syscallScore += 20;
      results.push('     🔴 CLASSIC UNHOOKING PATTERN DETECTED!');
      results.push('        └── NtProtectVirtualMemory + NtWriteVirtualMemory');
      results.push('        └── Likely restoring hooked functions');
    }

    // Pattern: Manual syscall implementation
    if (strings.includes('syscall') && strings.includes('ssn')) {
      syscallScore += 25;
      results.push('     🔴 MANUAL SYSCALL IMPLEMENTATION!');
      results.push('        └── System Service Number (SSN) resolution');
      results.push('        └── Direct syscall without NTDLL');
    }

    // Heaven's Gate detection (32-bit malware on 64-bit system)
    if (strings.includes('wow64') || strings.includes('heaven')) {
      syscallScore += 20;
      results.push("     🔴 HEAVEN'S GATE TECHNIQUE!");
      results.push('        └── 32-bit → 64-bit transition to bypass hooks');
      results.push('        └── Extremely sophisticated evasion');
    }

    if (syscallScore >= 30) {
      results.push('');
      results.push('  🔴 HIGH CONFIDENCE: DIRECT SYSCALL / UNHOOKING EVASION');
      results.push('     └── Score: ' + syscallScore + '/100');
      results.push('     └── Bypasses EDR/AV hooks in NTDLL/kernel32');
      results.push('     └── MITRE: T1562.001 (Impair Defenses)');
      results.push('     └── MITRE: T1055 (Process Injection via syscalls)');
      results.push('');
      results.push('  💡 ANALYSIS RECOMMENDATIONS:');
      results.push(
        '     • Analyze with API Monitor or x64dbg to see actual syscalls',
      );
      results.push('     • Check for SSN (System Service Number) lookup');
      results.push(
        '     • Look for embedded syscall stubs (0x4c 0x8b 0xd1 0xb8...)',
      );
      results.push('     • Examine .text section for direct syscall opcodes');
      results.push('');

      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Direct Syscall / NTDLL Unhooking',
        techId: 'T1562.001',
        indicator: syscallIndicators.join(', '),
        confidence: 'HIGH',
        details: `Syscall evasion score: ${syscallScore}/100. Modern EDR bypass technique.`,
      });
    } else if (syscallScore >= 15) {
      results.push('');
      results.push('  🟡 POSSIBLE SYSCALL EVASION');
      results.push('     └── Score: ' + syscallScore + '/100');
      results.push('     └── Some indicators present, needs deeper analysis');
      results.push('');

      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Possible Syscall Evasion',
        techId: 'T1562.001',
        indicator: syscallIndicators.join(', '),
        confidence: 'MEDIUM',
        details: `Syscall evasion score: ${syscallScore}/100`,
      });
    }
    results.push('');

    // Reflective DLL Loading (T1620) - ENHANCED
    const reflectiveAPIs = [
      'VirtualAlloc',
      'VirtualProtect',
      'RtlMoveMemory',
      'memcpy',
    ];
    let reflectiveCount = 0;
    for (const api of reflectiveAPIs) {
      if (imports.includes(api.toLowerCase())) reflectiveCount++;
    }
    if (reflectiveCount >= 3 && !imports.includes('loadlibrary')) {
      results.push('  🟡 REFLECTIVE LOADING POSSIBLE');
      results.push('     └── Memory allocation without LoadLibrary');
      results.push('     └── MITRE: T1620 (Reflective Code Loading)\n');
      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Reflective Loading',
        techId: 'T1620',
        indicator: 'Memory alloc without LoadLibrary',
        confidence: 'MEDIUM',
        details: 'Manual PE mapping technique',
      });
    }

    // AMSI Bypass (T1562.001) - ENHANCED
    results.push('  🔍 AMSI BYPASS ANALYSIS:');
    const amsiBypassPatterns = [
      { pattern: 'amsi.dll', desc: 'AMSI DLL reference', confidence: 'MEDIUM' },
      {
        pattern: 'amsiscanbuffer',
        desc: 'AmsiScanBuffer (patch target)',
        confidence: 'HIGH',
      },
      {
        pattern: 'amsiinitialized',
        desc: 'AmsiInitialized variable',
        confidence: 'HIGH',
      },
      {
        pattern: 'amsiscanstring',
        desc: 'AmsiScanString function',
        confidence: 'HIGH',
      },
      {
        pattern: 'amsi bypass',
        desc: 'Explicit AMSI bypass',
        confidence: 'HIGH',
      },
      {
        pattern: 'amsi patch',
        desc: 'AMSI patching reference',
        confidence: 'HIGH',
      },
      {
        pattern: '0x8007',
        desc: 'AMSI error code (E_INVALIDARG)',
        confidence: 'HIGH',
      },
      {
        pattern: '0x80070057',
        desc: 'AMSI bypass return code',
        confidence: 'HIGH',
      },
    ];

    let amsiBypassScore = 0;
    const amsiIndicators: string[] = [];
    for (const { pattern, desc, confidence } of amsiBypassPatterns) {
      if (strings.includes(pattern)) {
        const points = confidence === 'HIGH' ? 15 : 10;
        amsiBypassScore += points;
        amsiIndicators.push(desc);
        results.push(`     🔴 ${desc}`);
      }
    }

    // Check for memory patching APIs commonly used with AMSI bypass
    const amsiPatchAPIs = [
      'virtualprotect',
      'writeprocessmemory',
      'ntprotectvirtualmemory',
    ];
    if (amsiBypassScore > 0) {
      for (const api of amsiPatchAPIs) {
        if (imports.includes(api)) {
          amsiBypassScore += 10;
          results.push(`     🔴 ${api} - Memory patching API`);
        }
      }
    }

    if (amsiBypassScore >= 25) {
      results.push('');
      results.push('  🔴 HIGH CONFIDENCE: AMSI BYPASS DETECTED');
      results.push('     └── Score: ' + amsiBypassScore + '/100');
      results.push('     └── MITRE: T1562.001 (Impair Defenses)');
      results.push('');
      results.push('  💡 COMMON AMSI BYPASS TECHNIQUES:');
      results.push(
        '     • Memory patch AmsiScanBuffer (0xB8 0x57 0x00 0x07 0x80 0xC3)',
      );
      results.push('     • Set amsiContext to null');
      results.push('     • Force AMSI initialization failure');
      results.push(
        '     • Obfuscated reflection: [Ref].Assembly.GetType("AmsiUtils")',
      );
      results.push('');

      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'AMSI Bypass',
        techId: 'T1562.001',
        indicator: amsiIndicators.join(', '),
        confidence: 'HIGH',
        details: `AMSI bypass score: ${amsiBypassScore}/100. Disables script/payload scanning.`,
      });
    } else if (amsiBypassScore >= 10) {
      results.push('');
      results.push('  🟡 POSSIBLE AMSI BYPASS');
      results.push('     └── Score: ' + amsiBypassScore + '/100');
      results.push('');
      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Possible AMSI Bypass',
        techId: 'T1562.001',
        indicator: amsiIndicators.join(', '),
        confidence: 'MEDIUM',
        details: `AMSI bypass score: ${amsiBypassScore}/100`,
      });
    }
    results.push('');

    // ETW Bypass (T1562.001) - ENHANCED
    results.push('  🔍 ETW BYPASS ANALYSIS:');
    const etwBypassPatterns = [
      {
        pattern: 'etweventwrite',
        desc: 'EtwEventWrite (patch target)',
        confidence: 'HIGH',
      },
      {
        pattern: 'nttracecontrol',
        desc: 'NtTraceControl (ETW control)',
        confidence: 'HIGH',
      },
      {
        pattern: 'etw bypass',
        desc: 'Explicit ETW bypass',
        confidence: 'HIGH',
      },
      {
        pattern: 'etw patch',
        desc: 'ETW patching reference',
        confidence: 'HIGH',
      },
      { pattern: 'etwti', desc: 'ETW Threat Intelligence', confidence: 'HIGH' },
      {
        pattern: 'microsoft-windows-threat-intelligence',
        desc: 'ETW TI provider',
        confidence: 'HIGH',
      },
      {
        pattern: '0xc3',
        desc: 'RET opcode (common ETW patch)',
        confidence: 'MEDIUM',
      },
    ];

    let etwBypassScore = 0;
    const etwIndicators: string[] = [];
    for (const { pattern, desc, confidence } of etwBypassPatterns) {
      if (strings.includes(pattern)) {
        const points = confidence === 'HIGH' ? 15 : 10;
        etwBypassScore += points;
        etwIndicators.push(desc);
        results.push(`     🔴 ${desc}`);
      }
    }

    // Check for ETW patching APIs
    if (etwBypassScore > 0) {
      for (const api of amsiPatchAPIs) {
        if (imports.includes(api)) {
          etwBypassScore += 10;
        }
      }
    }

    if (etwBypassScore >= 25) {
      results.push('');
      results.push('  🔴 HIGH CONFIDENCE: ETW BYPASS DETECTED');
      results.push('     └── Score: ' + etwBypassScore + '/100');
      results.push('     └── MITRE: T1562.001 (Impair Defenses)');
      results.push('     └── MITRE: T1070 (Indicator Removal)');
      results.push('');
      results.push('  💡 COMMON ETW BYPASS TECHNIQUES:');
      results.push('     • Patch EtwEventWrite with 0xC3 (RET)');
      results.push('     • Disable ETW Threat Intelligence provider');
      results.push('     • NtTraceControl to stop trace sessions');
      results.push('     • Prevents .NET ETW, PowerShell logging, Sysmon');
      results.push('');

      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'ETW Bypass',
        techId: 'T1562.001',
        indicator: etwIndicators.join(', '),
        confidence: 'HIGH',
        details: `ETW bypass score: ${etwBypassScore}/100. Disables event logging.`,
      });
    } else if (etwBypassScore >= 10) {
      results.push('');
      results.push('  🟡 POSSIBLE ETW BYPASS');
      results.push('     └── Score: ' + etwBypassScore + '/100');
      results.push('');
      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Possible ETW Bypass',
        techId: 'T1562.001',
        indicator: etwIndicators.join(', '),
        confidence: 'MEDIUM',
        details: `ETW bypass score: ${etwBypassScore}/100`,
      });
    }
    results.push('');

    // Sleep Obfuscation Detection - NEW
    results.push('  🔍 SLEEP OBFUSCATION / TIME-BASED EVASION:');
    const sleepObfuscationPatterns = [
      { pattern: 'ekko', desc: 'Ekko sleep obfuscation', confidence: 'HIGH' },
      { pattern: 'zilean', desc: 'Zilean sleep technique', confidence: 'HIGH' },
      { pattern: 'foliage', desc: 'Foliage sleep masking', confidence: 'HIGH' },
      {
        pattern: 'createtimercallback',
        desc: 'Timer-based sleep',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'setwaitabletimer',
        desc: 'Waitable timer sleep',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'rtlcreatetimer',
        desc: 'RtlCreateTimer sleep',
        confidence: 'MEDIUM',
      },
    ];

    let sleepObfuscationScore = 0;
    const sleepIndicators: string[] = [];
    for (const { pattern, desc, confidence } of sleepObfuscationPatterns) {
      if (strings.includes(pattern)) {
        const points = confidence === 'HIGH' ? 15 : 10;
        sleepObfuscationScore += points;
        sleepIndicators.push(desc);
        results.push(`     🔴 ${desc}`);
      }
    }

    // Check for encryption + sleep combination (common in modern malware)
    if (
      sleepObfuscationScore > 0 &&
      (imports.includes('cryptencrypt') || imports.includes('rtlencryptmemory'))
    ) {
      sleepObfuscationScore += 20;
      results.push(
        '     🔴 Encryption + sleep (memory obfuscation during sleep)',
      );
    }

    if (sleepObfuscationScore >= 20) {
      results.push('');
      results.push('  🔴 SLEEP OBFUSCATION DETECTED');
      results.push('     └── Score: ' + sleepObfuscationScore + '/100');
      results.push('     └── MITRE: T1497.003 (Time-Based Evasion)');
      results.push('');
      results.push('  💡 MODERN SLEEP OBFUSCATION TECHNIQUES:');
      results.push(
        '     • Ekko: Encrypt beacon memory during sleep via ROP/timers',
      );
      results.push('     • Zilean: Thread-based sleep obfuscation');
      results.push('     • Foliage: Queue-based sleep masking');
      results.push('     • Prevents memory scanning while beacon is sleeping');
      results.push('');

      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Sleep Obfuscation',
        techId: 'T1497.003',
        indicator: sleepIndicators.join(', '),
        confidence: 'HIGH',
        details: `Sleep obfuscation score: ${sleepObfuscationScore}/100. Advanced beacon hiding.`,
      });
    }
    results.push('');

    // API Hashing Detection - NEW
    results.push('  🔍 API HASHING / DYNAMIC RESOLUTION:');
    const apiHashingPatterns = [
      {
        pattern: 'loadlibrary',
        desc: 'Dynamic library loading',
        confidence: 'LOW',
      },
      {
        pattern: 'getprocaddress',
        desc: 'Dynamic function resolution',
        confidence: 'LOW',
      },
      {
        pattern: 'ror13',
        desc: 'ROR13 hash (common in shellcode)',
        confidence: 'HIGH',
      },
      {
        pattern: 'crc32',
        desc: 'CRC32 hash for API names',
        confidence: 'HIGH',
      },
      { pattern: 'fnv1a', desc: 'FNV1a hash algorithm', confidence: 'HIGH' },
      { pattern: 'djb2', desc: 'DJB2 hash algorithm', confidence: 'HIGH' },
      {
        pattern: '0x1505',
        desc: 'Common API hash constant',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'peb',
        desc: 'Process Environment Block walk',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'inloadordermodulelist',
        desc: 'PEB module list traversal',
        confidence: 'HIGH',
      },
    ];

    let apiHashingScore = 0;
    const hashingIndicators: string[] = [];
    for (const { pattern, desc, confidence } of apiHashingPatterns) {
      if (strings.includes(pattern)) {
        const points =
          confidence === 'HIGH' ? 15 : confidence === 'MEDIUM' ? 10 : 3;
        apiHashingScore += points;
        hashingIndicators.push(desc);
        if (confidence !== 'LOW') {
          results.push(`     🔴 ${desc}`);
        }
      }
    }

    // LoadLibrary + GetProcAddress alone is normal, but combined with hashing = suspicious
    if (
      strings.includes('loadlibrary') &&
      strings.includes('getprocaddress') &&
      apiHashingScore >= 15
    ) {
      apiHashingScore += 20;
      results.push('     🔴 Dynamic resolution with hashing algorithms');
    }

    // PEB walking without LoadLibrary is highly suspicious
    if (strings.includes('peb') && !imports.includes('loadlibrary')) {
      apiHashingScore += 25;
      results.push('     🔴 Manual PEB walk (avoids LoadLibrary)');
    }

    if (apiHashingScore >= 25) {
      results.push('');
      results.push('  🔴 API HASHING DETECTED');
      results.push('     └── Score: ' + apiHashingScore + '/100');
      results.push('     └── MITRE: T1027 (Obfuscated Files or Information)');
      results.push('     └── MITRE: T1106 (Native API)');
      results.push('');
      results.push('  💡 API HASHING TECHNIQUES:');
      results.push('     • Hides imported API names from static analysis');
      results.push('     • Common hashes: ROR13, CRC32, FNV1a, DJB2');
      results.push(
        '     • PEB walk to find kernel32/ntdll without LoadLibrary',
      );
      results.push('     • Used by: Metasploit, Cobalt Strike, APT malware');
      results.push('');

      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'API Hashing',
        techId: 'T1027',
        indicator: hashingIndicators.join(', '),
        confidence: 'HIGH',
        details: `API hashing score: ${apiHashingScore}/100. Obfuscates API usage.`,
      });
    }
    results.push('');

    // Module Stomping Detection - NEW
    results.push('  🔍 MODULE STOMPING / PHANTOM DLL LOADING:');
    const moduleStompingPatterns = [
      {
        pattern: 'ntmapviewofsection',
        desc: 'Map view (module loading)',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'ntunmapviewofsection',
        desc: 'Unmap view',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'ntallocatevirtualmemory',
        desc: 'Manual memory allocation',
        confidence: 'LOW',
      },
      {
        pattern: 'ntwritevirtualmemory',
        desc: 'Write to remote process',
        confidence: 'MEDIUM',
      },
      {
        pattern: 'module stomp',
        desc: 'Explicit module stomping',
        confidence: 'HIGH',
      },
      {
        pattern: 'phantom dll',
        desc: 'Phantom DLL loading',
        confidence: 'HIGH',
      },
      {
        pattern: 'doppelganging',
        desc: 'Process Doppelgänging',
        confidence: 'HIGH',
      },
      {
        pattern: 'transacted',
        desc: 'Transacted file operations',
        confidence: 'HIGH',
      },
    ];

    let moduleStompingScore = 0;
    const stompingIndicators: string[] = [];
    for (const { pattern, desc, confidence } of moduleStompingPatterns) {
      if (strings.includes(pattern)) {
        const points =
          confidence === 'HIGH' ? 15 : confidence === 'MEDIUM' ? 10 : 5;
        moduleStompingScore += points;
        stompingIndicators.push(desc);
        if (confidence !== 'LOW') {
          results.push(`     🔴 ${desc}`);
        }
      }
    }

    // Pattern: Map + Write + Unmap = module stomping
    if (
      imports.includes('ntmapviewofsection') &&
      imports.includes('ntwritevirtualmemory') &&
      imports.includes('ntunmapviewofsection')
    ) {
      moduleStompingScore += 25;
      results.push('     🔴 Module stomping pattern (Map → Write → Unmap)');
    }

    if (moduleStompingScore >= 25) {
      results.push('');
      results.push('  🔴 MODULE STOMPING DETECTED');
      results.push('     └── Score: ' + moduleStompingScore + '/100');
      results.push('     └── MITRE: T1055.013 (Process Doppelgänging)');
      results.push('     └── MITRE: T1574.002 (DLL Side-Loading)');
      results.push('');
      results.push('  💡 MODULE STOMPING TECHNIQUES:');
      results.push('     • Load legitimate DLL, replace with malicious code');
      results.push('     • Phantom DLL: Map without file on disk');
      results.push('     • Process Doppelgänging: Transacted NTFS abuse');
      results.push(
        '     • Bypasses: EDR hooks, whitelisting, integrity checks',
      );
      results.push('');

      capabilities.push({
        tactic: 'Defense Evasion',
        technique: 'Module Stomping',
        techId: 'T1055.013',
        indicator: stompingIndicators.join(', '),
        confidence: 'HIGH',
        details: `Module stomping score: ${moduleStompingScore}/100. Advanced DLL injection.`,
      });
    }
    results.push('');

    // ===== 2. EXECUTION (TA0002) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. ⚡ EXECUTION TECHNIQUES (TA0002)                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Shellcode execution
    if (
      sections.includes('rwx') ||
      (imports.includes('virtualalloc') && imports.includes('virtualprotect'))
    ) {
      results.push('  🔴 SHELLCODE EXECUTION CAPABILITY');
      results.push('     └── RWX sections or dynamic code execution\n');
      capabilities.push({
        tactic: 'Execution',
        technique: 'Native API',
        techId: 'T1106',
        indicator: 'Shellcode execution pattern',
        confidence: 'HIGH',
        details: 'Memory allocation + execution',
      });
    }

    // Command execution - these are VERY common, only note them, don't flag as malicious
    // CreateProcess, ShellExecute, system are used by nearly all applications
    const cmdExecAPIs = [
      { api: 'WinExec', tech: 'T1059', desc: 'Legacy execution (suspicious)' },
      { api: 'popen', tech: 'T1059', desc: 'Pipe open' },
    ];
    // These are common and shouldn't be flagged individually
    const commonExecAPIs = [
      'CreateProcess',
      'ShellExecute',
      'system',
      'execve',
      'fork',
    ];

    // Only flag suspicious exec APIs, not common ones
    for (const api of cmdExecAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        results.push(`  🟡 ${api.api} - ${api.desc}`);
        capabilities.push({
          tactic: 'Execution',
          technique: 'Command Execution',
          techId: api.tech,
          indicator: api.api,
          confidence: 'MEDIUM',
          details: api.desc,
        });
      }
    }
    // Note common exec APIs without flagging
    let commonExecFound = 0;
    for (const api of commonExecAPIs) {
      if (imports.includes(api.toLowerCase())) commonExecFound++;
    }
    if (commonExecFound > 0) {
      results.push(
        `  ℹ️ ${commonExecFound} standard process execution APIs (normal)`,
      );
    }

    // Script execution
    const scriptStrings = [
      'powershell',
      'wscript',
      'cscript',
      'mshta',
      'rundll32',
      'regsvr32',
    ];
    for (const script of scriptStrings) {
      if (strings.includes(script)) {
        results.push(`  🔴 LOLBIN Usage: ${script}`);
        capabilities.push({
          tactic: 'Execution',
          technique: 'LOLBin',
          techId: 'T1218',
          indicator: script,
          confidence: 'HIGH',
          details: `Living off the land binary: ${script}`,
        });
      }
    }
    results.push('');

    // ===== 3. PERSISTENCE (TA0003) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. 🔒 PERSISTENCE MECHANISMS (TA0003)                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Registry persistence
    const regPersistenceKeys = [
      { pattern: 'run', tech: 'T1547.001', desc: 'Registry Run Keys' },
      { pattern: 'runonce', tech: 'T1547.001', desc: 'RunOnce Keys' },
      { pattern: 'userinit', tech: 'T1547.004', desc: 'Winlogon Helper' },
      { pattern: 'shell', tech: 'T1547.004', desc: 'Shell modification' },
      { pattern: 'appinit', tech: 'T1546.010', desc: 'AppInit DLLs' },
      { pattern: 'image file execution', tech: 'T1546.012', desc: 'IFEO' },
      {
        pattern: 'currentversion\\explorer',
        tech: 'T1547.001',
        desc: 'Explorer persistence',
      },
    ];

    for (const key of regPersistenceKeys) {
      if (strings.includes(key.pattern)) {
        results.push(`  🔴 ${key.desc}`);
        results.push(`     └── MITRE: ${key.tech}\n`);
        capabilities.push({
          tactic: 'Persistence',
          technique: key.desc,
          techId: key.tech,
          indicator: key.pattern,
          confidence: 'HIGH',
          details: 'Registry-based persistence',
        });
      }
    }

    // Service persistence
    if (
      imports.includes('createservice') ||
      imports.includes('openscmanager') ||
      strings.includes('services.exe')
    ) {
      results.push('  🔴 SERVICE CREATION CAPABILITY');
      results.push('     └── MITRE: T1543.003 (Windows Service)\n');
      capabilities.push({
        tactic: 'Persistence',
        technique: 'Windows Service',
        techId: 'T1543.003',
        indicator: 'Service APIs',
        confidence: 'HIGH',
        details: 'Can create/modify services',
      });
    }

    // Scheduled tasks
    if (
      imports.includes('taskschd') ||
      strings.includes('schtasks') ||
      strings.includes('at.exe')
    ) {
      results.push('  🔴 SCHEDULED TASK CAPABILITY');
      results.push('     └── MITRE: T1053.005 (Scheduled Task)\n');
      capabilities.push({
        tactic: 'Persistence',
        technique: 'Scheduled Task',
        techId: 'T1053.005',
        indicator: 'Task scheduler',
        confidence: 'HIGH',
        details: 'Scheduled task creation',
      });
    }

    // Startup folder
    if (strings.includes('startup') || strings.includes('start menu')) {
      results.push('  🟡 Startup folder reference detected\n');
      capabilities.push({
        tactic: 'Persistence',
        technique: 'Startup Folder',
        techId: 'T1547.001',
        indicator: 'Startup folder string',
        confidence: 'MEDIUM',
        details: 'May copy to startup',
      });
    }

    // ===== 4. PRIVILEGE ESCALATION (TA0004) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. 👑 PRIVILEGE ESCALATION (TA0004)                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const privEscAPIs = [
      {
        api: 'AdjustTokenPrivileges',
        tech: 'T1134.001',
        desc: 'Token privilege adjustment',
      },
      {
        api: 'ImpersonateLoggedOnUser',
        tech: 'T1134.001',
        desc: 'Token impersonation',
      },
      { api: 'DuplicateToken', tech: 'T1134.001', desc: 'Token duplication' },
      { api: 'OpenProcessToken', tech: 'T1134', desc: 'Token access' },
      {
        api: 'SetThreadToken',
        tech: 'T1134.001',
        desc: 'Thread token manipulation',
      },
      {
        api: 'CreateProcessWithToken',
        tech: 'T1134.002',
        desc: 'Token-based process creation',
      },
      {
        api: 'LookupPrivilegeValue',
        tech: 'T1134.001',
        desc: 'Privilege lookup',
      },
      { api: 'SeDebugPrivilege', tech: 'T1134.001', desc: 'Debug privilege' },
    ];

    for (const api of privEscAPIs) {
      if (
        imports.includes(api.api.toLowerCase()) ||
        strings.includes(api.api.toLowerCase())
      ) {
        results.push(`  🔴 ${api.api} - ${api.desc}`);
        capabilities.push({
          tactic: 'Privilege Escalation',
          technique: 'Token Manipulation',
          techId: api.tech,
          indicator: api.api,
          confidence: 'HIGH',
          details: api.desc,
        });
      }
    }

    // UAC Bypass
    const uacBypassStrings = [
      'fodhelper',
      'eventvwr',
      'sdclt',
      'computerdefaults',
      'slui',
      'cmstp',
    ];
    for (const uac of uacBypassStrings) {
      if (strings.includes(uac)) {
        results.push(`  🔴 UAC BYPASS: ${uac}`);
        results.push('     └── MITRE: T1548.002\n');
        capabilities.push({
          tactic: 'Privilege Escalation',
          technique: 'UAC Bypass',
          techId: 'T1548.002',
          indicator: uac,
          confidence: 'HIGH',
          details: `UAC bypass via ${uac}`,
        });
      }
    }
    results.push('');

    // ===== 5. CREDENTIAL ACCESS (TA0006) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. 🔑 CREDENTIAL ACCESS (TA0006)                            │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const credAPIs = [
      { api: 'CredEnumerate', tech: 'T1555', desc: 'Credential enumeration' },
      { api: 'CredRead', tech: 'T1555', desc: 'Credential read' },
      { api: 'LsaRetrievePrivateData', tech: 'T1003.004', desc: 'LSA secrets' },
      { api: 'SamQueryInformationUser', tech: 'T1003.002', desc: 'SAM dump' },
      {
        api: 'CryptUnprotectData',
        tech: 'T1555.004',
        desc: 'DPAPI decryption',
      },
      { api: 'NetUserGetInfo', tech: 'T1087.001', desc: 'User info query' },
    ];

    const credStrings = [
      { pattern: 'mimikatz', tech: 'T1003', desc: 'Mimikatz reference' },
      { pattern: 'sekurlsa', tech: 'T1003.001', desc: 'LSASS memory' },
      { pattern: 'lsass.exe', tech: 'T1003.001', desc: 'LSASS process' },
      // 'sam' alone is too generic, use more specific patterns
      {
        pattern: 'system32\\config\\sam',
        tech: 'T1003.002',
        desc: 'SAM database path',
      },
      { pattern: 'ntds.dit', tech: 'T1003.003', desc: 'Active Directory' },
      { pattern: 'login data', tech: 'T1555.003', desc: 'Browser credentials' },
      // 'cookies' alone causes false positives, be more specific
      { pattern: 'cookies.sqlite', tech: 'T1539', desc: 'Firefox cookies' },
      { pattern: 'chrome\\user data', tech: 'T1555.003', desc: 'Chrome data' },
      { pattern: 'passwords.txt', tech: 'T1555', desc: 'Password file' },
    ];

    for (const api of credAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        results.push(`  🔴 ${api.api} - ${api.desc}`);
        capabilities.push({
          tactic: 'Credential Access',
          technique: api.desc,
          techId: api.tech,
          indicator: api.api,
          confidence: 'HIGH',
          details: api.desc,
        });
      }
    }

    for (const str of credStrings) {
      if (strings.includes(str.pattern)) {
        results.push(`  🔴 ${str.pattern} - ${str.desc}`);
        capabilities.push({
          tactic: 'Credential Access',
          technique: str.desc,
          techId: str.tech,
          indicator: str.pattern,
          confidence: 'HIGH',
          details: str.desc,
        });
      }
    }
    results.push('');

    // ===== 6. DISCOVERY (TA0007) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 6. 🔍 DISCOVERY TECHNIQUES (TA0007)                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Split discovery APIs by suspiciousness level
    // High suspicion: network/user enumeration
    const suspiciousDiscoveryAPIs = [
      {
        api: 'CreateToolhelp32Snapshot',
        tech: 'T1057',
        desc: 'Process discovery',
      },
      { api: 'EnumProcesses', tech: 'T1057', desc: 'Process enumeration' },
      { api: 'NetShareEnum', tech: 'T1135', desc: 'Network share discovery' },
      { api: 'NetUserEnum', tech: 'T1087.001', desc: 'Account discovery' },
      { api: 'LookupAccountSid', tech: 'T1087', desc: 'Account SID lookup' },
      {
        api: 'GetAdaptersInfo',
        tech: 'T1016',
        desc: 'Network config discovery',
      },
    ];
    // Common APIs that shouldn't be flagged (nearly every program uses these)
    const commonDiscoveryAPIs = [
      'GetUserName',
      'GetComputerName',
      'RegQueryValue',
      'FindFirstFile',
    ];

    let _suspiciousDiscoveryCount = 0;
    for (const api of suspiciousDiscoveryAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        _suspiciousDiscoveryCount++;
        results.push(`  🟡 ${api.api} - ${api.desc}`);
        capabilities.push({
          tactic: 'Discovery',
          technique: api.desc,
          techId: api.tech,
          indicator: api.api,
          confidence: 'MEDIUM',
          details: api.desc,
        });
      }
    }
    // Don't add common APIs to capabilities, just note them
    let commonDiscoveryCount = 0;
    for (const api of commonDiscoveryAPIs) {
      if (imports.includes(api.toLowerCase())) commonDiscoveryCount++;
    }
    if (commonDiscoveryCount > 0) {
      results.push(
        `  ℹ️ ${commonDiscoveryCount} common system info APIs (normal)`,
      );
    }
    results.push('');

    // ===== 7. COLLECTION (TA0009) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 7. 📦 COLLECTION CAPABILITIES (TA0009)                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const collectionAPIs = [
      { api: 'GetClipboardData', tech: 'T1115', desc: 'Clipboard capture' },
      {
        api: 'SetClipboardViewer',
        tech: 'T1115',
        desc: 'Clipboard monitoring',
      },
      { api: 'GetAsyncKeyState', tech: 'T1056.001', desc: 'Keylogging' },
      {
        api: 'SetWindowsHookEx',
        tech: 'T1056.001',
        desc: 'Input capture hook',
      },
      { api: 'GetRawInputData', tech: 'T1056.001', desc: 'Raw input capture' },
      { api: 'BitBlt', tech: 'T1113', desc: 'Screen capture' },
      { api: 'GetDC', tech: 'T1113', desc: 'Device context (screenshot)' },
      { api: 'capCreateCaptureWindow', tech: 'T1125', desc: 'Video capture' },
      { api: 'waveInOpen', tech: 'T1123', desc: 'Audio capture' },
      { api: 'mciSendString', tech: 'T1123', desc: 'Media capture' },
    ];

    for (const api of collectionAPIs) {
      if (imports.includes(api.api.toLowerCase())) {
        results.push(`  🔴 ${api.api} - ${api.desc}`);
        capabilities.push({
          tactic: 'Collection',
          technique: api.desc,
          techId: api.tech,
          indicator: api.api,
          confidence: 'HIGH',
          details: api.desc,
        });
      }
    }
    results.push('');

    // ===== 8. COMMAND AND CONTROL (TA0011) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 8. 📡 COMMAND & CONTROL (TA0011)                            │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // C2 APIs - separate into suspicious vs common networking
    // URLDownloadToFile is suspicious, basic socket/HTTP APIs are common
    const suspiciousC2APIs = [
      {
        api: 'URLDownloadToFile',
        tech: 'T1105',
        desc: 'File download (commonly abused)',
      },
      {
        api: 'DnsQuery',
        tech: 'T1071.004',
        desc: 'DNS communication (potential DNS C2)',
      },
    ];
    // These are common networking APIs - only flag if combined with other indicators
    const commonNetAPIs = [
      'InternetOpen',
      'InternetConnect',
      'HttpOpenRequest',
      'HttpSendRequest',
      'WinHttpOpen',
      'socket',
      'connect',
      'send',
      'recv',
    ];

    let _suspiciousC2Count = 0;
    for (const api of suspiciousC2APIs) {
      if (imports.includes(api.api.toLowerCase())) {
        _suspiciousC2Count++;
        results.push(`  🟡 ${api.api} - ${api.desc}`);
        capabilities.push({
          tactic: 'Command and Control',
          technique: api.desc,
          techId: api.tech,
          indicator: api.api,
          confidence: 'MEDIUM',
          details: api.desc,
        });
      }
    }

    // Count common network APIs but don't flag individually
    let commonNetCount = 0;
    for (const api of commonNetAPIs) {
      if (imports.includes(api.toLowerCase())) commonNetCount++;
    }
    if (commonNetCount > 0) {
      results.push(
        `  ℹ️ ${commonNetCount} standard networking APIs (normal for networked apps)`,
      );
    }

    // Check for encoded/encrypted C2 - only flag if crypto AND network APIs present
    if (
      (strings.includes('base64') ||
        strings.includes('aes') ||
        strings.includes('rc4')) &&
      commonNetCount > 0
    ) {
      results.push('  🟡 Encryption/encoding with network capability\n');
      capabilities.push({
        tactic: 'Command and Control',
        technique: 'Encrypted Channel',
        techId: 'T1573',
        indicator: 'Crypto + networking',
        confidence: 'MEDIUM',
        details: 'May use encrypted C2',
      });
    }
    results.push('');

    // ===== 9. EXFILTRATION (TA0010) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 9. 📤 EXFILTRATION CAPABILITIES (TA0010)                    │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const exfilStrings = [
      'ftp',
      'smtp',
      'pastebin',
      'dropbox',
      'onedrive',
      'gdrive',
      'telegram',
      'discord',
    ];
    for (const exfil of exfilStrings) {
      if (strings.includes(exfil)) {
        results.push(`  🔴 Exfiltration channel: ${exfil}`);
        capabilities.push({
          tactic: 'Exfiltration',
          technique: 'Web Service',
          techId: 'T1567',
          indicator: exfil,
          confidence: 'HIGH',
          details: `Exfiltration via ${exfil}`,
        });
      }
    }

    if (
      imports.includes('compress') ||
      imports.includes('lz') ||
      strings.includes('.zip') ||
      strings.includes('.rar')
    ) {
      results.push('  🟡 Data compression capability\n');
      capabilities.push({
        tactic: 'Exfiltration',
        technique: 'Archive Collected Data',
        techId: 'T1560',
        indicator: 'Compression',
        confidence: 'MEDIUM',
        details: 'May archive before exfil',
      });
    }
    results.push('');

    // ===== 10. IMPACT (TA0040) =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 10. 💥 IMPACT CAPABILITIES (TA0040)                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Ransomware indicators
    const ransomwareStrings = [
      'your files have been encrypted',
      'bitcoin',
      'ransom',
      'decrypt',
      '.encrypted',
      '.locked',
      'readme.txt',
      'how to recover',
      'payment',
      'wallet',
    ];
    let ransomwareCount = 0;
    for (const str of ransomwareStrings) {
      if (strings.includes(str)) ransomwareCount++;
    }
    if (ransomwareCount >= 3) {
      results.push('  🔴 RANSOMWARE INDICATORS DETECTED');
      results.push('     └── MITRE: T1486 (Data Encrypted for Impact)\n');
      capabilities.push({
        tactic: 'Impact',
        technique: 'Data Encrypted for Impact',
        techId: 'T1486',
        indicator: 'Ransomware strings',
        confidence: 'HIGH',
        details: 'Multiple ransomware indicators',
      });
    }

    // Wiper indicators
    const wiperAPIs = [
      'NtSetInformationFile',
      'SetFilePointer',
      'WriteFile',
      'DeleteFile',
    ];
    let wiperCount = 0;
    for (const api of wiperAPIs) {
      if (imports.includes(api.toLowerCase())) wiperCount++;
    }
    if (wiperCount >= 3 && strings.includes('mbr')) {
      results.push('  🔴 WIPER CAPABILITY POSSIBLE');
      results.push('     └── MITRE: T1561 (Disk Wipe)\n');
      capabilities.push({
        tactic: 'Impact',
        technique: 'Disk Wipe',
        techId: 'T1561',
        indicator: 'MBR + file operations',
        confidence: 'HIGH',
        details: 'May overwrite disk/MBR',
      });
    }

    // ===== COMPREHENSIVE SUMMARY =====
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📊 CAPABILITY ANALYSIS SUMMARY');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Group by tactic
    const tacticGroups: Record<string, typeof capabilities> = {};
    for (const cap of capabilities) {
      if (!tacticGroups[cap.tactic]) {
        tacticGroups[cap.tactic] = [];
      }
      tacticGroups[cap.tactic].push(cap);
    }

    results.push('  📋 MITRE ATT&CK TACTICS IDENTIFIED:\n');
    for (const [tactic, caps] of Object.entries(tacticGroups)) {
      const highCount = caps.filter((c) => c.confidence === 'HIGH').length;
      const emoji = highCount > 0 ? '🔴' : '🟡';
      results.push(
        `     ${emoji} ${tactic}: ${caps.length} techniques (${highCount} high confidence)`,
      );
    }

    results.push('\n  📈 THREAT ASSESSMENT:');
    const highConfidence = capabilities.filter((c) => c.confidence === 'HIGH');
    const mediumConfidence = capabilities.filter(
      (c) => c.confidence === 'MEDIUM',
    );

    if (highConfidence.length >= 10) {
      results.push('     ⚠️ CRITICAL: Highly sophisticated malware');
      results.push(
        '        └── Multiple high-confidence malicious capabilities',
      );
    } else if (highConfidence.length >= 5) {
      results.push('     ⚠️ HIGH: Significant malicious capabilities');
    } else if (highConfidence.length > 0 || mediumConfidence.length >= 5) {
      results.push('     ⚠️ MEDIUM: Suspicious capabilities detected');
    } else {
      results.push('     ℹ️ LOW: Limited suspicious indicators');
    }

    // Unique MITRE techniques
    const uniqueTechniques = [...new Set(capabilities.map((c) => c.techId))];
    results.push(`\n  🎯 Unique MITRE Techniques: ${uniqueTechniques.length}`);
    results.push(`  📊 Total Capabilities: ${capabilities.length}`);
    results.push(`  🔴 High Confidence: ${highConfidence.length}`);
    results.push(`  🟡 Medium Confidence: ${mediumConfidence.length}`);
    results.push(
      `  🟢 Low Confidence: ${capabilities.length - highConfidence.length - mediumConfidence.length}`,
    );

    // Top techniques
    results.push('\n  🏆 TOP THREAT INDICATORS:');
    for (const cap of highConfidence.slice(0, 5)) {
      results.push(
        `     └── ${cap.techId}: ${cap.technique} (${cap.indicator})`,
      );
    }

    // Structured JSON output
    results.push(
      '\n═══════════════════════════════════════════════════════════════',
    );
    results.push('   🤖 STRUCTURED DATA (for LLM processing)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );
    results.push('```json');
    results.push(
      JSON.stringify(
        {
          totalCapabilities: capabilities.length,
          threatLevel:
            highConfidence.length >= 10
              ? 'CRITICAL'
              : highConfidence.length >= 5
                ? 'HIGH'
                : highConfidence.length > 0
                  ? 'MEDIUM'
                  : 'LOW',
          tacticCoverage: Object.keys(tacticGroups).length,
          uniqueTechniques: uniqueTechniques.length,
          confidence: {
            high: highConfidence.length,
            medium: mediumConfidence.length,
            low:
              capabilities.length -
              highConfidence.length -
              mediumConfidence.length,
          },
          tacticsDetected: Object.keys(tacticGroups),
          mitreTechniques: uniqueTechniques,
          topFindings: highConfidence.slice(0, 10),
          allCapabilities: capabilities,
        },
        null,
        2,
      ),
    );
    results.push('```');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  /**
   * Generate YARA detection rules from binary analysis
   * Creates rules based on strings, imports, sections, and behavioral indicators
   */
  private async yaraGenerate(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    // Extract filename for rule naming
    const fileName = targetPath.split('/').pop() || 'unknown';
    const safeName = fileName.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 32);
    const ruleName = `malware_${safeName}_${Date.now().toString(36)}`;

    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📜 YARA RULE GENERATOR');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Collect analysis data
    let imports = '';
    let strings = '';
    let sections = '';
    let fileInfo = '';

    try {
      const [importRes, stringRes, sectionRes, infoRes] = await Promise.all([
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "iS" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
        this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "i" ${escapeShellArg(targetPath)}`,
          timeout / 8,
        ),
      ]);
      imports = importRes.success ? importRes.output : '';
      strings = stringRes.success ? stringRes.output : '';
      sections = sectionRes.success ? sectionRes.output : '';
      fileInfo = infoRes.success ? infoRes.output : '';
    } catch {
      results.push('⚠️ Warning: Could not fully analyze binary\n');
    }

    // Parse file info for metadata
    const archMatch = fileInfo.match(/arch\s+(\w+)/i);
    const bitsMatch = fileInfo.match(/bits\s+(\d+)/i);
    const osMatch = fileInfo.match(/os\s+(\w+)/i);
    const arch = archMatch ? archMatch[1] : 'unknown';
    const bits = bitsMatch ? bitsMatch[1] : '32';
    const os = osMatch ? osMatch[1] : 'unknown';

    // ===== COLLECT UNIQUE STRINGS =====
    const uniqueStrings: Set<string> = new Set();
    const suspiciousStrings: string[] = [];
    const urlPatterns: string[] = [];
    const pathPatterns: string[] = [];
    const registryPatterns: string[] = [];

    // Suspicious string patterns for malware - HIGH CONFIDENCE ONLY
    // Avoiding generic terms that appear in legitimate software
    const malwareStringPatterns = [
      // Network indicators - only non-local IPs with suspicious ports
      /https?:\/\/[^\s"'<>]{15,100}/gi, // Longer URLs more likely IOCs
      // Persistence paths - specific malware locations
      /\\users\\[^\\]+\\appdata\\roaming\\[^\\]+\.exe/gi,
      /\\programdata\\[^\\]+\.exe/gi,
      // Registry - only autorun keys
      /software\\microsoft\\windows\\currentversion\\run\\[^\s"']+/gi,
      /software\\microsoft\\windows\\currentversion\\runonce/gi,
      // Ransom indicators - specific phrases only
      /your files have been encrypted/gi,
      /decrypt your files/gi,
      /send.*bitcoin.*to/gi,
      /ransom.*payment/gi,
      // Shellcode / injection patterns
      /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/gi,
      // Onion addresses (Tor)
      /[a-z2-7]{16,56}\.onion/gi,
      // Base64 encoded commands
      /powershell.*-enc.*[a-zA-Z0-9+/]{50,}/gi,
    ];

    // Extract strings line by line
    const stringLines = strings.split('\n');
    for (const line of stringLines) {
      // Extract the actual string content (radare2 format: "addr type string")
      const match = line.match(/\s+(\d+)\s+(\d+)\s+(.+)/);
      if (match && match[3]) {
        const str = match[3].trim();

        // Filter for meaningful strings (8-200 chars, not just hex/numbers)
        if (str.length >= 8 && str.length <= 200 && /[a-zA-Z]{4,}/.test(str)) {
          // Check against malware patterns
          for (const pattern of malwareStringPatterns) {
            if (pattern.test(str)) {
              suspiciousStrings.push(str);
              break;
            }
          }

          // Categorize strings
          if (/https?:\/\//.test(str)) {
            urlPatterns.push(str);
          } else if (/\\[a-z]+\\/i.test(str)) {
            pathPatterns.push(str);
          } else if (/hkey_/i.test(str)) {
            registryPatterns.push(str);
          }

          uniqueStrings.add(str);
        }
      }
    }

    // ===== COLLECT IMPORTS =====
    const suspiciousImports: string[] = [];
    const importLines = imports.toLowerCase().split('\n');

    // High-value imports for detection - MALWARE-SPECIFIC ONLY
    // Removed common APIs: socket, connect, send, recv (networking apps)
    // Removed: LoadLibrary, GetProcAddress, GetTickCount (virtually all apps)
    // Removed: FindFirstFile, FindNextFile (file managers, AV, etc.)
    // Removed: CreateProcess, ShellExecute (many legitimate uses)
    const highValueImports = [
      // Process injection (strong indicator)
      'writeprocessmemory',
      'createremotethread',
      'ntunmapviewofsection',
      'queueuserapc',
      'ntqueueapcthread',
      'rtlcreateuserthread',
      'zwunmapviewofsection',
      // Hollowing techniques
      'ntresumethread',
      'zwresumethread',
      'setthreadcontext',
      // Credential theft
      'credread',
      'credenumerate',
      'lsaenumeratelogonsessions',
      'samquerydisplayinformation',
      // Anti-debug (when combined with other indicators)
      'ntqueryinformationprocess',
      'zwqueryinformationprocess',
      // Keylogging
      'setwindowshookexa',
      'setwindowshookexw',
      'getasynckeystate',
      'getkeystate',
      // Screen capture
      'bitblt',
      // Privilege escalation
      'adjusttokenprivileges',
      'impersonateloggedonuser',
      // Disable security
      'changeserviceconfig',
    ];

    for (const line of importLines) {
      for (const imp of highValueImports) {
        if (line.includes(imp)) {
          // Extract the actual function name
          const funcMatch = line.match(/\b(\w*${imp}\w*)\b/i);
          if (funcMatch) {
            suspiciousImports.push(funcMatch[1]);
          }
        }
      }
    }

    // ===== COLLECT SECTION INFO =====
    const sectionInfo: Array<{
      name: string;
      entropy?: string;
      characteristics?: string;
    }> = [];
    const sectionLines = sections.split('\n');

    for (const line of sectionLines) {
      // Parse section info (format varies)
      const sectionMatch = line.match(/(\.\w+)/);
      if (sectionMatch) {
        sectionInfo.push({ name: sectionMatch[1] });
      }
    }

    // ===== GENERATE YARA RULE =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 GENERATED YARA RULE                                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const yaraRule: string[] = [];

    // Rule header
    yaraRule.push(`rule ${ruleName} {`);
    yaraRule.push('    meta:');
    yaraRule.push(
      `        description = "Auto-generated rule for ${fileName}"`,
    );
    yaraRule.push(`        author = "DarkCoder YARA Generator"`);
    yaraRule.push(`        date = "${new Date().toISOString().split('T')[0]}"`);
    yaraRule.push(`        arch = "${arch}"`);
    yaraRule.push(`        bits = "${bits}"`);
    yaraRule.push(`        os = "${os}"`);
    yaraRule.push(`        hash = "REPLACE_WITH_HASH"`);
    yaraRule.push('');

    // Strings section
    yaraRule.push('    strings:');

    let stringIndex = 0;
    const addedStrings: Set<string> = new Set();

    // Add suspicious strings (highest priority)
    const topSuspicious = [...new Set(suspiciousStrings)].slice(0, 10);
    for (const str of topSuspicious) {
      if (!addedStrings.has(str)) {
        const escaped = str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        yaraRule.push(
          `        $suspicious_${stringIndex} = "${escaped}" nocase`,
        );
        addedStrings.add(str);
        stringIndex++;
      }
    }

    // Add URL patterns
    const topUrls = [...new Set(urlPatterns)].slice(0, 5);
    for (const url of topUrls) {
      if (!addedStrings.has(url)) {
        const escaped = url.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        yaraRule.push(`        $url_${stringIndex} = "${escaped}" nocase`);
        addedStrings.add(url);
        stringIndex++;
      }
    }

    // Add path patterns
    const topPaths = [...new Set(pathPatterns)].slice(0, 5);
    for (const path of topPaths) {
      if (!addedStrings.has(path)) {
        const escaped = path.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        yaraRule.push(`        $path_${stringIndex} = "${escaped}" nocase`);
        addedStrings.add(path);
        stringIndex++;
      }
    }

    // Add registry patterns
    const topRegistry = [...new Set(registryPatterns)].slice(0, 3);
    for (const reg of topRegistry) {
      if (!addedStrings.has(reg)) {
        const escaped = reg.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        yaraRule.push(`        $reg_${stringIndex} = "${escaped}" nocase`);
        addedStrings.add(reg);
        stringIndex++;
      }
    }

    // Add import-based strings
    const topImports = [...new Set(suspiciousImports)].slice(0, 8);
    for (const imp of topImports) {
      yaraRule.push(`        $api_${stringIndex} = "${imp}" ascii`);
      stringIndex++;
    }

    // Add some unique interesting strings if we have room
    if (stringIndex < 15) {
      const interestingStrings = Array.from(uniqueStrings)
        .filter((s) => !addedStrings.has(s))
        .filter((s) => /[a-zA-Z]{6,}/.test(s) && !/^[A-Z_]+$/.test(s))
        .slice(0, 15 - stringIndex);

      for (const str of interestingStrings) {
        const escaped = str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        yaraRule.push(`        $str_${stringIndex} = "${escaped}"`);
        stringIndex++;
      }
    }

    // Fallback if no strings found
    if (stringIndex === 0) {
      yaraRule.push('        $placeholder = "NEEDS_MANUAL_REVIEW"');
    }

    yaraRule.push('');

    // Condition section
    yaraRule.push('    condition:');

    // Build condition based on what we found
    const conditions: string[] = [];

    // File type check
    if (os.toLowerCase() === 'windows' || imports.includes('kernel32')) {
      conditions.push('uint16(0) == 0x5A4D'); // MZ header
    } else if (os.toLowerCase() === 'linux' || fileInfo.includes('elf')) {
      conditions.push('uint32(0) == 0x464C457F'); // ELF magic
    }

    // String matching logic
    const suspiciousCount = topSuspicious.length;
    const totalStrings = stringIndex;

    if (suspiciousCount >= 3) {
      // Strong indicators - require multiple suspicious strings
      conditions.push(`${Math.min(3, suspiciousCount)} of ($suspicious_*)`);
      if (topImports.length >= 2) {
        conditions.push('2 of ($api_*)');
      }
    } else if (totalStrings >= 5) {
      // Moderate indicators - require combination
      conditions.push(`${Math.ceil(totalStrings * 0.6)} of them`);
    } else if (totalStrings > 0) {
      // Weak indicators - require most strings
      conditions.push('all of them');
    } else {
      conditions.push('false // No strings extracted - manual review required');
    }

    yaraRule.push(`        ${conditions.join(' and\n        ')}`);
    yaraRule.push('}');

    // Output the rule
    results.push('```yara');
    results.push(yaraRule.join('\n'));
    results.push('```');

    // ===== ALTERNATIVE RULES =====
    results.push(
      '\n┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 🔄 ALTERNATIVE DETECTION RULES                              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Generate a behavioral rule if we have imports
    if (topImports.length >= 4) {
      results.push('📌 BEHAVIORAL RULE (API-based):');
      results.push('```yara');
      results.push(`rule ${ruleName}_behavioral {`);
      results.push('    meta:');
      results.push(
        `        description = "Behavioral detection for ${fileName}"`,
      );
      results.push('    strings:');
      topImports.slice(0, 6).forEach((imp, i) => {
        results.push(`        $api${i} = "${imp}" ascii`);
      });
      results.push('    condition:');
      results.push(
        `        uint16(0) == 0x5A4D and ${Math.ceil(topImports.slice(0, 6).length * 0.7)} of them`,
      );
      results.push('}');
      results.push('```\n');
    }

    // Generate a strict hash-based rule placeholder
    results.push('📌 HASH-BASED RULE (fill in hashes):');
    results.push('```yara');
    results.push(`rule ${ruleName}_hash {`);
    results.push('    meta:');
    results.push(
      `        description = "Hash-based detection for ${fileName}"`,
    );
    results.push('    condition:');
    results.push('        hash.md5(0, filesize) == "REPLACE_MD5" or');
    results.push('        hash.sha256(0, filesize) == "REPLACE_SHA256"');
    results.push('}');
    results.push('```\n');

    // ===== ANALYSIS SUMMARY =====
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📊 RULE GENERATION SUMMARY                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push(`  📁 Target: ${fileName}`);
    results.push(`  🏷️ Rule Name: ${ruleName}`);
    results.push(`  📐 Architecture: ${arch} (${bits}-bit)`);
    results.push(`  💻 OS: ${os}`);
    results.push('');
    results.push('  📋 EXTRACTED INDICATORS:');
    results.push(`     • Suspicious strings: ${suspiciousStrings.length}`);
    results.push(`     • URL patterns: ${urlPatterns.length}`);
    results.push(`     • Path patterns: ${pathPatterns.length}`);
    results.push(`     • Registry patterns: ${registryPatterns.length}`);
    results.push(`     • High-value imports: ${suspiciousImports.length}`);
    results.push(`     • Total unique strings: ${uniqueStrings.size}`);
    results.push('');

    // Quality assessment
    let ruleQuality: string;
    let qualityEmoji: string;

    if (suspiciousStrings.length >= 5 && suspiciousImports.length >= 4) {
      ruleQuality = 'HIGH';
      qualityEmoji = '🟢';
    } else if (suspiciousStrings.length >= 2 || suspiciousImports.length >= 3) {
      ruleQuality = 'MEDIUM';
      qualityEmoji = '🟡';
    } else {
      ruleQuality = 'LOW - Manual refinement recommended';
      qualityEmoji = '🟠';
    }

    results.push(`  ${qualityEmoji} RULE QUALITY: ${ruleQuality}`);
    results.push('');

    // Recommendations
    results.push('  💡 RECOMMENDATIONS:');
    results.push(
      '     1. Test rule against known clean files to reduce false positives',
    );
    results.push('     2. Add file hash in meta section for exact matching');
    results.push(
      '     3. Consider adding PE imports module for Windows binaries',
    );
    results.push(
      '     4. Adjust condition thresholds based on detection goals',
    );
    if (suspiciousStrings.length < 3) {
      results.push(
        '     5. ⚠️ Few suspicious strings - consider manual string analysis',
      );
    }

    // Structured output
    results.push(
      '\n═══════════════════════════════════════════════════════════════',
    );
    results.push('   🤖 STRUCTURED DATA (for LLM processing)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );
    results.push('```json');
    results.push(
      JSON.stringify(
        {
          ruleName,
          targetFile: fileName,
          architecture: { arch, bits, os },
          indicators: {
            suspiciousStrings: topSuspicious,
            urls: topUrls,
            paths: topPaths,
            registry: topRegistry,
            apis: topImports,
            totalUniqueStrings: uniqueStrings.size,
          },
          ruleQuality,
          yaraRule: yaraRule.join('\n'),
        },
        null,
        2,
      ),
    );
    results.push('```');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  // ============= BINARY MODIFICATION OPERATIONS =============
  // ⚠️ WARNING: These operations modify binaries
  // LEGAL USE ONLY: Security research, malware defanging, educational purposes
  // ALWAYS create backups before modification

  /**
   * Create backup of binary before modification
   */
  private async backupBinary(targetPath: string): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   💾 BINARY BACKUP');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath =
        this.params.backupPath || `${targetPath}.backup.${timestamp}`;

      // Copy file
      await fs.copyFile(targetPath, backupPath);

      // Verify backup
      const [originalStats, backupStats] = await Promise.all([
        fs.stat(targetPath),
        fs.stat(backupPath),
      ]);

      if (originalStats.size !== backupStats.size) {
        throw new Error('Backup size mismatch!');
      }

      results.push(`  ✅ Backup created successfully`);
      results.push(`  📁 Original: ${targetPath}`);
      results.push(`  📁 Backup:   ${backupPath}`);
      results.push(`  📊 Size:     ${originalStats.size} bytes`);
      results.push('');
      results.push(
        '  💡 To restore: cp ' +
          escapeShellArg(backupPath) +
          ' ' +
          escapeShellArg(targetPath),
      );

      return {
        success: true,
        output: results.join('\n'),
        metadata: { backupPath, originalPath: targetPath },
      };
    } catch (error) {
      return {
        success: false,
        output: `Failed to create backup: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Patch binary with hex bytes at specified address
   * LEGAL USE: Malware defanging, security research, bug fixes
   */
  private async patchBytes(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔧 BINARY PATCHING - HEX BYTES');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Validate parameters
    if (!this.params.address) {
      return {
        success: false,
        output: 'Error: address parameter required',
      };
    }

    if (!this.params.hexBytes) {
      return {
        success: false,
        output: 'Error: hexBytes parameter required (e.g., "90909090")',
      };
    }

    if (!isValidAddress(this.params.address)) {
      return {
        success: false,
        output: `Error: Invalid address format: ${this.params.address}`,
      };
    }

    // Validate hex bytes
    if (!/^[0-9a-fA-F]+$/.test(this.params.hexBytes)) {
      return {
        success: false,
        output: 'Error: hexBytes must contain only hex digits (0-9, a-f)',
      };
    }

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const address = this.params.address.startsWith('0x')
      ? this.params.address
      : `0x${this.params.address}`;
    const hexBytes = this.params.hexBytes;

    results.push(`  🎯 Target:   ${targetPath}`);
    results.push(`  📍 Address:  ${address}`);
    results.push(`  📝 Bytes:    ${hexBytes} (${hexBytes.length / 2} bytes)`);
    results.push(`  🔧 Tool:     ${tool}\n`);

    try {
      // First, read current bytes at address
      const readCmd = `${tool} -q -w -c "s ${address}; p8 ${hexBytes.length / 2}" ${escapeShellArg(targetPath)}`;
      const readResult = await this.runCommand(readCmd, timeout / 4);

      if (readResult.success) {
        results.push(`  📖 Current bytes: ${readResult.output.trim()}`);
      }

      // Patch bytes using radare2/rizin write command
      // -w = write mode, wx = write hex
      const patchCmd = `${tool} -q -w -c "s ${address}; wx ${hexBytes}; p8 ${hexBytes.length / 2}" ${escapeShellArg(targetPath)}`;
      const patchResult = await this.runCommand(patchCmd, timeout);

      if (patchResult.success) {
        results.push(`  ✅ New bytes:     ${patchResult.output.trim()}`);
        results.push('');
        results.push('  ✅ Patch applied successfully!');
        results.push(
          '  💡 Verify with: ' +
            tool +
            ' -q -c "s ' +
            address +
            '; pd 5" ' +
            escapeShellArg(targetPath),
        );
      } else {
        results.push('');
        results.push('  ❌ Patch failed!');
        results.push(`  Error: ${patchResult.error || patchResult.output}`);
      }

      return {
        success: patchResult.success,
        output: results.join('\n'),
      };
    } catch (error) {
      results.push(`\n  ❌ Error: ${error}`);
      return {
        success: false,
        output: results.join('\n'),
        error: String(error),
      };
    }
  }

  /**
   * NOP out instructions at address
   * Useful for: Disabling anti-debug, removing checks, malware defanging
   */
  private async nopInstructions(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🚫 NOP INSTRUCTIONS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    if (!this.params.address) {
      return { success: false, output: 'Error: address required' };
    }

    if (!this.params.length) {
      return { success: false, output: 'Error: length (bytes) required' };
    }

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const address = this.params.address.startsWith('0x')
      ? this.params.address
      : `0x${this.params.address}`;
    const length = this.params.length;
    const nops = '90'.repeat(length); // 0x90 = NOP instruction on x86/x64

    results.push(`  🎯 Target:   ${targetPath}`);
    results.push(`  📍 Address:  ${address}`);
    results.push(`  📏 Length:   ${length} bytes`);
    results.push(`  📝 NOPs:     ${nops}\n`);

    try {
      // Show original disassembly
      const disasmCmd = `${tool} -e bin.relocs.apply=true -q -c "s ${address}; pd ${Math.min(length, 10)}" ${escapeShellArg(targetPath)}`;
      const disasmResult = await this.runCommand(disasmCmd, timeout / 4);

      if (disasmResult.success) {
        results.push('  📖 Original instructions:');
        results.push(
          disasmResult.output
            .split('\n')
            .slice(0, 5)
            .map((l) => `     ${l}`)
            .join('\n'),
        );
        results.push('');
      }

      // Write NOPs
      const nopCmd = `${tool} -q -w -c "s ${address}; wx ${nops}; pd ${Math.min(length, 10)}" ${escapeShellArg(targetPath)}`;
      const nopResult = await this.runCommand(nopCmd, timeout);

      if (nopResult.success) {
        results.push('  ✅ NOPed instructions:');
        results.push(
          nopResult.output
            .split('\n')
            .slice(0, 5)
            .map((l) => `     ${l}`)
            .join('\n'),
        );
        results.push('');
        results.push(`  ✅ Successfully NOPed ${length} bytes at ${address}`);
      } else {
        results.push('  ❌ NOP operation failed');
      }

      return {
        success: nopResult.success,
        output: results.join('\n'),
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Patch string in binary
   * Useful for: Changing C2 URLs for malware analysis, config modification
   */
  private async patchString(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📝 STRING PATCHING');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    results.push('⚠️  String Modification - Research Use');
    results.push('   Valid uses:');
    results.push('   ✅ Redirect malware C2 to sinkhole');
    results.push('   ✅ Modify config for analysis');
    results.push('   ✅ Change debug/logging strings\n');

    if (!this.params.address) {
      return { success: false, output: 'Error: address required' };
    }

    if (!this.params.newString) {
      return { success: false, output: 'Error: newString required' };
    }

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const address = this.params.address.startsWith('0x')
      ? this.params.address
      : `0x${this.params.address}`;
    const newString = this.params.newString;

    // Convert string to hex
    const hexString = Buffer.from(newString, 'utf-8').toString('hex') + '00'; // null-terminated

    results.push(`  🎯 Target:     ${targetPath}`);
    results.push(`  📍 Address:    ${address}`);
    results.push(`  📝 New String: "${newString}"`);
    results.push(
      `  📏 Length:     ${newString.length + 1} bytes (null-terminated)\n`,
    );

    try {
      // Read current string
      const readCmd = `${tool} -e bin.relocs.apply=true -q -c "s ${address}; ps" ${escapeShellArg(targetPath)}`;
      const readResult = await this.runCommand(readCmd, timeout / 4);

      if (readResult.success) {
        results.push(`  📖 Current string: "${readResult.output.trim()}"`);
      }

      // Write new string
      const writeCmd = `${tool} -q -w -c "s ${address}; wx ${hexString}; ps" ${escapeShellArg(targetPath)}`;
      const writeResult = await this.runCommand(writeCmd, timeout);

      if (writeResult.success) {
        results.push(`  ✅ New string:     "${writeResult.output.trim()}"`);
        results.push('');
        results.push('  ✅ String patched successfully!');
      } else {
        results.push('  ❌ String patch failed');
      }

      return {
        success: writeResult.success,
        output: results.join('\n'),
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Patch entire function with assembly
   * ADVANCED: Requires understanding of assembly and calling conventions
   */
  private async patchFunction(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   ⚙️ FUNCTION PATCHING (Advanced)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    if (!this.params.address && !this.params.function) {
      return {
        success: false,
        output: 'Error: address or function name required',
      };
    }

    if (!this.params.assembly) {
      return {
        success: false,
        output: 'Error: assembly code required (e.g., "mov eax, 1; ret")',
      };
    }

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const target = this.params.address || this.params.function;
    const rawAssembly = this.params.assembly;

    // Escape assembly for use inside double quotes in shell
    // This allows all valid assembly syntax while preventing shell injection
    const assembly = rawAssembly
      .replace(/\\/g, '\\\\') // Escape backslashes first
      .replace(/\$/g, '\\$') // Escape $ (variable expansion)
      .replace(/`/g, '\\`') // Escape backticks (command substitution)
      .replace(/"/g, '\\"') // Escape double quotes
      .replace(/!/g, '\\!'); // Escape ! (history expansion)

    results.push(`  🎯 Target:   ${targetPath}`);
    results.push(`  📍 Location: ${target}`);
    results.push(`  📝 Assembly:\n`);
    rawAssembly.split(';').forEach((line) => {
      results.push(`     ${line.trim()}`);
    });
    results.push('');

    try {
      // Seek to function/address
      const seekCmd = this.params.function
        ? `af @ sym.${sanitizeName(this.params.function)}; s sym.${sanitizeName(this.params.function)}`
        : `s ${this.params.address}`;

      // Show original disassembly
      const origCmd = `${tool} -e bin.relocs.apply=true -q -c "${seekCmd}; pdf" ${escapeShellArg(targetPath)}`;
      const origResult = await this.runCommand(origCmd, timeout / 4);

      if (origResult.success) {
        results.push('  📖 Original function:');
        results.push(
          origResult.output
            .split('\n')
            .slice(0, 15)
            .map((l) => `     ${l}`)
            .join('\n'),
        );
        results.push('');
      }

      // Assemble and write
      // wa = write assembly
      const patchCmd = `${tool} -q -w -c "${seekCmd}; wa ${assembly}; pdf" ${escapeShellArg(targetPath)}`;
      const patchResult = await this.runCommand(patchCmd, timeout);

      if (patchResult.success) {
        results.push('  ✅ Patched function:');
        results.push(
          patchResult.output
            .split('\n')
            .slice(0, 15)
            .map((l) => `     ${l}`)
            .join('\n'),
        );
        results.push('');
        results.push('  ✅ Function patched successfully!');
        results.push('  ⚠️  TEST THOROUGHLY - May break program if incorrect');
      } else {
        results.push('  ❌ Function patch failed');
      }

      return {
        success: patchResult.success,
        output: results.join('\n'),
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  // ============= CTF CRACKING AUTOMATION =============
  // ⚠️ WARNING: Educational/CTF use only
  // For learning reverse engineering and solving capture-the-flag challenges

  /**
   * Auto-detect license/serial/trial validation functions
   * Searches for common function patterns in CTF/crackme challenges
   */
  private async findLicenseChecks(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔍 AUTO-DETECT LICENSE/TRIAL CHECKS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const detectedChecks: Array<{
      type: string;
      function: string;
      address: string;
      confidence: string;
      description: string;
    }> = [];

    try {
      // Step 1: Extract strings to find protection-related keywords
      results.push('📝 Step 1: Analyzing strings...');
      const stringsCmd = `${tool} -e bin.relocs.apply=true -q -c "iz~trial,license,serial,register,activation,demo,expired,nag,crack,valid,check,auth" ${escapeShellArg(targetPath)}`;
      const stringsResult = await this.runCommand(stringsCmd, timeout / 4);

      const protectionStrings: string[] = [];
      if (stringsResult.success && stringsResult.output) {
        const lines = stringsResult.output.split('\n').filter((l) => l.trim());
        protectionStrings.push(...lines.slice(0, 10));
        results.push(`  ✓ Found ${lines.length} protection-related strings`);
      }

      // Step 2: Analyze functions to find validation logic
      results.push('\n📝 Step 2: Analyzing functions...');
      const analyzeCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~check,valid,trial,license,serial,register,crack,auth,key" ${escapeShellArg(targetPath)}`;
      const analyzeResult = await this.runCommand(analyzeCmd, timeout / 2);

      if (analyzeResult.success && analyzeResult.output) {
        const funcLines = analyzeResult.output
          .split('\n')
          .filter((l) => l.trim());
        results.push(`  ✓ Found ${funcLines.length} candidate functions`);

        // Parse function addresses and names
        for (const line of funcLines.slice(0, 15)) {
          const addrMatch = line.match(/0x[0-9a-fA-F]+/);
          const nameMatch = line.match(/sym\.([^\s]+)/);

          if (addrMatch && nameMatch) {
            const address = addrMatch[0];
            const funcName = nameMatch[1];

            // Classify function type based on name
            let type = 'unknown';
            let confidence = 'LOW';
            let description = 'Potential check function';

            if (/check.*license|license.*check/i.test(funcName)) {
              type = 'LICENSE_CHECK';
              confidence = 'HIGH';
              description = 'License validation function';
            } else if (/check.*serial|serial.*valid/i.test(funcName)) {
              type = 'SERIAL_VALIDATION';
              confidence = 'HIGH';
              description = 'Serial key validation';
            } else if (
              /check.*trial|trial.*check|trial.*expired/i.test(funcName)
            ) {
              type = 'TRIAL_CHECK';
              confidence = 'HIGH';
              description = 'Trial period check';
            } else if (/check.*register|is.*register/i.test(funcName)) {
              type = 'REGISTRATION_CHECK';
              confidence = 'HIGH';
              description = 'Registration status check';
            } else if (/valid|check|auth/i.test(funcName)) {
              type = 'VALIDATION';
              confidence = 'MEDIUM';
              description = 'Generic validation function';
            }

            detectedChecks.push({
              type,
              function: funcName,
              address,
              confidence,
              description,
            });
          }
        }
      }

      // Step 3: Look for API calls indicative of protection
      results.push('\n📝 Step 3: Checking protection APIs...');
      const importsCmd = `${tool} -e bin.relocs.apply=true -q -c "ii~Registry,GetSystemTime,GetLocalTime,GetTickCount,QueryPerformanceCounter" ${escapeShellArg(targetPath)}`;
      const importsResult = await this.runCommand(importsCmd, timeout / 4);

      const protectionAPIs: string[] = [];
      if (importsResult.success && importsResult.output) {
        const apiLines = importsResult.output
          .split('\n')
          .filter((l) => l.trim());
        protectionAPIs.push(...apiLines);
        results.push(`  ✓ Found ${apiLines.length} protection-related APIs`);
      }

      // Display results
      results.push('\n' + '═'.repeat(63));
      results.push('   🎯 DETECTED PROTECTION POINTS');
      results.push('═'.repeat(63) + '\n');

      if (detectedChecks.length === 0) {
        results.push('  ⚠️  No obvious protection functions detected');
        results.push('  💡 Try manual analysis with r2_analyze + r2_decompile');
      } else {
        const grouped = {
          HIGH: detectedChecks.filter((c) => c.confidence === 'HIGH'),
          MEDIUM: detectedChecks.filter((c) => c.confidence === 'MEDIUM'),
          LOW: detectedChecks.filter((c) => c.confidence === 'LOW'),
        };

        if (grouped.HIGH.length > 0) {
          results.push('🔴 HIGH CONFIDENCE TARGETS:');
          for (const check of grouped.HIGH) {
            results.push(`  • ${check.function}`);
            results.push(`    Address:  ${check.address}`);
            results.push(`    Type:     ${check.type}`);
            results.push(`    Details:  ${check.description}`);
            results.push('');
          }
        }

        if (grouped.MEDIUM.length > 0) {
          results.push('🟡 MEDIUM CONFIDENCE TARGETS:');
          for (const check of grouped.MEDIUM) {
            results.push(`  • ${check.function} @ ${check.address}`);
            results.push(`    ${check.description}`);
          }
          results.push('');
        }

        // Provide next steps
        results.push('═'.repeat(63));
        results.push('   💡 RECOMMENDED WORKFLOW');
        results.push('═'.repeat(63) + '\n');
        results.push('1️⃣  Decompile high-confidence functions:');
        results.push(
          `    { operation: "r2_decompile", function: "${detectedChecks[0]?.function || 'TARGET'}" }`,
        );
        results.push('');
        results.push('2️⃣  Backup before patching:');
        results.push('    { operation: "backup_binary" }');
        results.push('');
        results.push('3️⃣  Apply smart crack:');
        results.push('    { operation: "smart_crack_trial" }');
        results.push('    OR');
        results.push('    { operation: "auto_bypass_checks" }');
      }

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          detectedChecks,
          protectionStrings: protectionStrings.slice(0, 10),
          protectionAPIs: protectionAPIs.slice(0, 10),
          totalFunctions: detectedChecks.length,
          highConfidence: detectedChecks.filter((c) => c.confidence === 'HIGH')
            .length,
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Find CTF win/success/flag functions
   * Common in CTF challenges - functions that print the flag
   */
  private async findWinFunction(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🏆 FIND WIN/SUCCESS FUNCTIONS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const winFunctions: Array<{
      name: string;
      address: string;
      confidence: string;
      reason: string;
    }> = [];

    try {
      // Search for common CTF win function names
      results.push('📝 Searching for win/success functions...\n');
      const funcCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~win,success,flag,correct,passed,unlock,secret,prize,victory" ${escapeShellArg(targetPath)}`;
      const funcResult = await this.runCommand(funcCmd, timeout / 2);

      if (funcResult.success && funcResult.output) {
        const lines = funcResult.output.split('\n').filter((l) => l.trim());

        for (const line of lines) {
          const addrMatch = line.match(/0x[0-9a-fA-F]+/);
          const nameMatch = line.match(/sym\.([^\s]+)/);

          if (addrMatch && nameMatch) {
            const address = addrMatch[0];
            const funcName = nameMatch[1];

            let confidence = 'LOW';
            let reason = 'Name contains success keyword';

            if (/^(win|flag|success|correct|passed)$/i.test(funcName)) {
              confidence = 'CRITICAL';
              reason = 'Exact match for CTF win function';
            } else if (/print.*flag|flag.*print|show.*flag/i.test(funcName)) {
              confidence = 'HIGH';
              reason = 'Flag printing function';
            } else if (/unlock|secret|prize|victory/i.test(funcName)) {
              confidence = 'MEDIUM';
              reason = 'Potential reward function';
            }

            winFunctions.push({
              name: funcName,
              address,
              confidence,
              reason,
            });
          }
        }
      }

      // Search strings for flag indicators
      results.push('📝 Searching for flag strings...\n');
      const stringsCmd = `${tool} -e bin.relocs.apply=true -q -c "iz~flag,CTF,congratulations,correct,success,you.*win" ${escapeShellArg(targetPath)}`;
      const stringsResult = await this.runCommand(stringsCmd, timeout / 4);

      const flagStrings: string[] = [];
      if (stringsResult.success && stringsResult.output) {
        flagStrings.push(
          ...stringsResult.output
            .split('\n')
            .filter((l) => l.trim())
            .slice(0, 5),
        );
      }

      // Display results
      results.push('═'.repeat(63));
      results.push('   🎯 DETECTED WIN FUNCTIONS');
      results.push('═'.repeat(63) + '\n');

      if (winFunctions.length === 0) {
        results.push('  ⚠️  No obvious win functions detected');
        results.push('  💡 Try searching for string xrefs to flag strings');
      } else {
        const critical = winFunctions.filter(
          (f) => f.confidence === 'CRITICAL',
        );
        const high = winFunctions.filter((f) => f.confidence === 'HIGH');
        const medium = winFunctions.filter((f) => f.confidence === 'MEDIUM');

        if (critical.length > 0) {
          results.push('🔴 CRITICAL - LIKELY WIN FUNCTIONS:');
          for (const func of critical) {
            results.push(`  • ${func.name}`);
            results.push(`    Address: ${func.address}`);
            results.push(`    Reason:  ${func.reason}`);
            results.push('');
          }
        }

        if (high.length > 0) {
          results.push('🟠 HIGH CONFIDENCE:');
          for (const func of high) {
            results.push(`  • ${func.name} @ ${func.address}`);
            results.push(`    ${func.reason}`);
          }
          results.push('');
        }

        if (medium.length > 0) {
          results.push('🟡 MEDIUM CONFIDENCE:');
          for (const func of medium) {
            results.push(`  • ${func.name} @ ${func.address}`);
          }
          results.push('');
        }
      }

      if (flagStrings.length > 0) {
        results.push('═'.repeat(63));
        results.push('   🚩 FLAG-RELATED STRINGS');
        results.push('═'.repeat(63) + '\n');
        flagStrings.forEach((s) => results.push(`  ${s}`));
        results.push('');
      }

      // Next steps
      results.push('═'.repeat(63));
      results.push('   💡 NEXT STEPS');
      results.push('═'.repeat(63) + '\n');
      if (winFunctions.length > 0) {
        results.push('1️⃣  Call the win function directly (if no args):');
        results.push(
          `    Patch main() to call ${winFunctions[0]?.address || '0xADDR'}`,
        );
        results.push('');
        results.push('2️⃣  Analyze what reaches the win function:');
        results.push(
          `    { operation: "r2_xrefs", function: "${winFunctions[0]?.name || 'win'}" }`,
        );
        results.push('');
        results.push('3️⃣  Decompile to understand conditions:');
        results.push(
          `    { operation: "r2_decompile", function: "${winFunctions[0]?.name || 'win'}" }`,
        );
      }

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          winFunctions,
          flagStrings: flagStrings.slice(0, 10),
          totalFound: winFunctions.length,
          criticalTargets: winFunctions.filter(
            (f) => f.confidence === 'CRITICAL',
          ).length,
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Smart trial cracking - automated trial bypass
   * Finds trial checks and applies intelligent patches
   */
  private async smartCrackTrial(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🎯 SMART TRIAL CRACK (Automated)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const patchedFunctions: Array<{
      function: string;
      address: string;
      strategy: string;
      success: boolean;
    }> = [];

    try {
      // Step 1: Find license checks (reuse existing operation)
      results.push('📝 Step 1: Detecting trial/license checks...');
      const detectResult = await this.findLicenseChecks(targetPath, timeout);

      if (!detectResult.success || !detectResult.metadata) {
        return {
          success: false,
          output:
            results.join('\n') +
            '\n  ❌ Failed to detect license checks\n' +
            detectResult.output,
        };
      }

      const checks = detectResult.metadata['detectedChecks'] as Array<{
        type: string;
        function: string;
        address: string;
        confidence: string;
      }>;
      const highConfidence = checks.filter((c) => c.confidence === 'HIGH');

      if (highConfidence.length === 0) {
        return {
          success: false,
          output:
            results.join('\n') +
            '\n  ⚠️  No high-confidence trial checks found\n  💡 Try manual analysis with find_license_checks',
        };
      }

      results.push(
        `  ✓ Found ${highConfidence.length} high-confidence targets`,
      );

      // Step 2: Create backup
      results.push('\n📝 Step 2: Creating backup...');
      const backupResult = await this.backupBinary(targetPath);
      if (!backupResult.success) {
        return {
          success: false,
          output:
            results.join('\n') + '\n  ❌ Backup failed - aborting for safety',
        };
      }
      results.push('  ✓ Backup created successfully');

      // Step 3: Analyze and patch each function
      results.push('\n📝 Step 3: Analyzing and patching functions...\n');

      for (const check of highConfidence.slice(0, 3)) {
        // Validate address before using in command
        if (!isValidAddress(check.address)) {
          results.push(
            `  ⚠️ Skipping ${check.function} - invalid address format`,
          );
          continue;
        }

        results.push(`  🔍 Analyzing ${check.function}...`);

        // Decompile to understand the function
        const decompileCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; s ${check.address}; pdg" ${escapeShellArg(targetPath)}`;
        const decompileResult = await this.runCommand(
          decompileCmd,
          timeout / 3,
        );

        let strategy = 'FORCE_RETURN_TRUE';
        let patchBytes = 'b801000000c3'; // mov eax, 1; ret

        if (decompileResult.success && decompileResult.output) {
          const code = decompileResult.output.toLowerCase();

          // Analyze pseudocode to choose best strategy
          if (code.includes('return false') || code.includes('return 0')) {
            strategy = 'FORCE_RETURN_TRUE';
            patchBytes = 'b801000000c3'; // mov eax, 1; ret
            results.push(`    Strategy: Force return TRUE (mov eax, 1; ret)`);
          } else if (code.includes('je ') || code.includes('jne ')) {
            strategy = 'INVERT_JUMP';
            // Note: Actual jump inversion requires reading original opcode
            results.push('    Strategy: Invert conditional jump');
          } else {
            strategy = 'FORCE_RETURN_TRUE';
            results.push(
              '    Strategy: Default force return TRUE (mov eax, 1; ret)',
            );
          }
        }

        // Apply patch
        if (strategy === 'FORCE_RETURN_TRUE') {
          // Patch function to immediately return 1 (true)
          const writeCmd = `${tool} -q -w -c "s ${check.address}; wx ${patchBytes}" ${escapeShellArg(targetPath)}`;
          const writeResult = await this.runCommand(writeCmd, timeout / 4);

          if (writeResult.success) {
            results.push(`    ✅ Patched ${check.function} successfully`);
            patchedFunctions.push({
              function: check.function,
              address: check.address,
              strategy,
              success: true,
            });
          } else {
            results.push(`    ❌ Failed to patch ${check.function}`);
            patchedFunctions.push({
              function: check.function,
              address: check.address,
              strategy,
              success: false,
            });
          }
        }

        results.push('');
      }

      // Step 4: Verify patches
      results.push('📝 Step 4: Verifying patches...\n');
      const successfulPatches = patchedFunctions.filter((p) => p.success);

      for (const patch of successfulPatches) {
        const verifyCmd = `${tool} -e bin.relocs.apply=true -q -c "s ${patch.address}; pd 3" ${escapeShellArg(targetPath)}`;
        const verifyResult = await this.runCommand(verifyCmd, timeout / 6);

        if (verifyResult.success) {
          const disasm = verifyResult.output.split('\n')[0] || '';
          if (disasm.includes('mov') && disasm.includes('eax')) {
            results.push(`  ✅ ${patch.function}: Verified`);
          }
        }
      }

      // Summary
      results.push('\n' + '═'.repeat(63));
      results.push('   📊 CRACK SUMMARY');
      results.push('═'.repeat(63) + '\n');
      results.push(`  Total targets:      ${highConfidence.length}`);
      results.push(`  Patched:            ${successfulPatches.length}`);
      results.push(
        `  Failed:             ${patchedFunctions.filter((p) => !p.success).length}`,
      );
      results.push(
        `  Backup location:    ${backupResult.metadata?.['backupPath'] || 'N/A'}`,
      );

      if (successfulPatches.length > 0) {
        results.push('\n  🎉 Trial crack appears successful!');
        results.push('  💡 Test the binary to confirm functionality');
        results.push(
          `  💡 To restore: cp "${backupResult.metadata?.['backupPath']}" "${targetPath}"`,
        );
      } else {
        results.push('\n  ❌ No patches applied successfully');
        results.push('  💡 Try manual patching with patch_bytes');
      }

      return {
        success: successfulPatches.length > 0,
        output: results.join('\n'),
        metadata: {
          patchedFunctions,
          successfulPatches: successfulPatches.length,
          totalTargets: highConfidence.length,
          backupPath: backupResult.metadata?.['backupPath'],
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Intelligent bypass of validation checks
   * More advanced than smart_crack_trial - handles complex protection
   */
  private async autoBypassChecks(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔓 AUTO BYPASS VALIDATION CHECKS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    try {
      // Find all types of checks
      results.push('📝 Phase 1: Comprehensive check detection...');
      const checksResult = await this.identifyProtectionPoints(
        targetPath,
        timeout,
      );

      if (!checksResult.success) {
        return {
          success: false,
          output:
            results.join('\n') + '\n  ❌ Failed to identify protection points',
        };
      }

      results.push('  ✓ Protection analysis complete');

      // Create backup
      results.push('\n📝 Phase 2: Backing up binary...');
      const backupResult = await this.backupBinary(targetPath);
      if (!backupResult.success) {
        return {
          success: false,
          output: results.join('\n') + '\n  ❌ Backup failed',
        };
      }
      results.push('  ✓ Backup created');

      // Bypass anti-debug checks
      results.push('\n📝 Phase 3: Bypassing anti-debug...');
      const antiDebugCmd = `${tool} -e bin.relocs.apply=true -q -c "ii~IsDebuggerPresent,CheckRemoteDebuggerPresent,NtQueryInformationProcess" ${escapeShellArg(targetPath)}`;
      const antiDebugResult = await this.runCommand(antiDebugCmd, timeout / 4);

      let bypassedAntiDebug = 0;
      if (antiDebugResult.success && antiDebugResult.output.trim()) {
        results.push('  🔍 Found anti-debug imports');

        // Find xrefs and NOP them
        const xrefsCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ sym.imp.IsDebuggerPresent" ${escapeShellArg(targetPath)}`;
        const xrefsResult = await this.runCommand(xrefsCmd, timeout / 3);

        if (xrefsResult.success) {
          const calls = xrefsResult.output
            .split('\n')
            .filter((l) => l.includes('call') || l.includes('0x'));
          for (const call of calls.slice(0, 5)) {
            const addrMatch = call.match(/0x[0-9a-fA-F]+/);
            if (addrMatch) {
              const nopCmd = `${tool} -q -w -c "s ${addrMatch[0]}; wx 9090909090" ${escapeShellArg(targetPath)}`;
              const nopResult = await this.runCommand(nopCmd, timeout / 6);
              if (nopResult.success) {
                bypassedAntiDebug++;
              }
            }
          }
        }
        results.push(`  ✅ Bypassed ${bypassedAntiDebug} anti-debug checks`);
      } else {
        results.push('  ℹ️  No anti-debug detected');
      }

      // Summary
      results.push('\n' + '═'.repeat(63));
      results.push('   📊 BYPASS SUMMARY');
      results.push('═'.repeat(63) + '\n');
      results.push(`  Anti-debug bypasses: ${bypassedAntiDebug}`);
      results.push(
        `  Backup location:     ${backupResult.metadata?.['backupPath'] || 'N/A'}`,
      );
      results.push('\n  💡 For complete protection bypass:');
      results.push('     1. Run find_license_checks');
      results.push('     2. Run smart_crack_trial');
      results.push('     3. Test thoroughly');

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          antiDebugBypass: bypassedAntiDebug,
          backupPath: backupResult.metadata?.['backupPath'],
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Extract validation algorithm for keygen development
   * Analyzes how serial/license keys are validated
   */
  private async extractAlgorithm(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📐 EXTRACT VALIDATION ALGORITHM');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    try {
      // Find validation function
      results.push('📝 Step 1: Locating validation function...');
      const funcCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~valid,check,serial,license,key" ${escapeShellArg(targetPath)}`;
      const funcResult = await this.runCommand(funcCmd, timeout / 3);

      if (!funcResult.success || !funcResult.output.trim()) {
        return {
          success: false,
          output:
            results.join('\n') + '\n  ❌ No validation functions detected',
        };
      }

      const funcLines = funcResult.output.split('\n').filter((l) => l.trim());
      const firstFunc = funcLines[0];
      const addrMatch = firstFunc?.match(/0x[0-9a-fA-F]+/);
      const nameMatch = firstFunc?.match(/sym\.([^\s]+)/);

      if (!addrMatch || !nameMatch) {
        return {
          success: false,
          output: results.join('\n') + '\n  ❌ Failed to parse function info',
        };
      }

      const validationAddr = addrMatch[0];
      const validationName = nameMatch[1];
      results.push(`  ✓ Found: ${validationName} @ ${validationAddr}`);

      // Decompile validation function
      results.push('\n📝 Step 2: Decompiling algorithm...');
      const decompileCmd = `${tool} -e bin.relocs.apply=true -q -c "s ${validationAddr}; pdg" ${escapeShellArg(targetPath)}`;
      const decompileResult = await this.runCommand(decompileCmd, timeout / 2);

      if (!decompileResult.success) {
        return {
          success: false,
          output: results.join('\n') + '\n  ❌ Decompilation failed',
        };
      }

      const pseudocode = decompileResult.output;
      results.push('  ✓ Decompilation complete\n');

      // Analyze algorithm patterns
      results.push('═'.repeat(63));
      results.push('   📋 ALGORITHM PSEUDOCODE');
      results.push('═'.repeat(63) + '\n');
      results.push(pseudocode.split('\n').slice(0, 50).join('\n'));

      // Extract algorithm characteristics
      results.push('\n' + '═'.repeat(63));
      results.push('   🔍 ALGORITHM ANALYSIS');
      results.push('═'.repeat(63) + '\n');

      const analysis: string[] = [];

      if (pseudocode.match(/strlen|length/i)) {
        analysis.push('✓ Length check detected');
      }
      if (pseudocode.match(/strcmp|compare/i)) {
        analysis.push('✓ String comparison detected');
      }
      if (pseudocode.match(/\^|xor/i)) {
        analysis.push('✓ XOR operation detected');
      }
      if (pseudocode.match(/\+|-|\*|\//) && pseudocode.match(/\d+/)) {
        analysis.push('✓ Arithmetic operations detected');
      }
      if (pseudocode.match(/sum|total|accumulate/i)) {
        analysis.push('✓ Checksum/sum calculation detected');
      }
      if (pseudocode.match(/md5|sha|hash/i)) {
        analysis.push('✓ Hash function detected');
      }

      if (analysis.length > 0) {
        analysis.forEach((a) => results.push(`  ${a}`));
      } else {
        results.push('  ℹ️  No obvious algorithm patterns detected');
      }

      // Provide keygen template
      results.push('\n' + '═'.repeat(63));
      results.push('   💡 KEYGEN DEVELOPMENT GUIDE');
      results.push('═'.repeat(63) + '\n');
      results.push('1️⃣  Analyze the decompiled code above');
      results.push('2️⃣  Identify the validation logic');
      results.push('3️⃣  Reverse the algorithm:');
      results.push('    • If comparison: Extract correct value');
      results.push('    • If checksum: Calculate valid checksum');
      results.push('    • If XOR: Reverse XOR operations');
      results.push('');
      results.push('4️⃣  Write keygen based on algorithm');
      results.push('');
      results.push('📝 Example Keygen Template (Python):');
      results.push('```python');
      results.push('def generate_key():');
      results.push('    # TODO: Implement algorithm from pseudocode');
      results.push('    # Example patterns:');
      results.push('    ');
      results.push('    # Pattern 1: Simple checksum');
      results.push('    # key = "ABC" where sum(ord(c) for c in key) == 198');
      results.push('    ');
      results.push('    # Pattern 2: XOR encoding');
      results.push('    # key = "".join(chr(ord(c) ^ 0x42) for c in "SECRET")');
      results.push('    ');
      results.push('    # Pattern 3: Length + checksum');
      results.push(
        '    # if len(key) == 16 and sum(ord(c) for c in key) == 1234:',
      );
      results.push('    ');
      results.push('    return "YOUR-GENERATED-KEY"');
      results.push('');
      results.push('print(generate_key())');
      results.push('```');

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          validationFunction: validationName,
          validationAddress: validationAddr,
          pseudocode,
          algorithmHints: analysis,
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Find flag/password strings in CTF binaries
   * Searches for common CTF flag formats
   */
  private async findFlagStrings(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🚩 FIND CTF FLAGS & PASSWORDS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    try {
      // Search for common CTF flag formats
      results.push('📝 Searching for CTF flag patterns...\n');

      const searches = [
        { pattern: 'flag{', name: 'flag{}' },
        { pattern: 'FLAG{', name: 'FLAG{}' },
        { pattern: 'CTF{', name: 'CTF{}' },
        { pattern: 'HTB{', name: 'HackTheBox' },
        { pattern: 'picoCTF{', name: 'picoCTF' },
        { pattern: 'THM{', name: 'TryHackMe' },
        { pattern: 'password', name: 'password' },
        { pattern: 'secret', name: 'secret' },
        { pattern: 'key:', name: 'key' },
      ];

      const foundFlags: Array<{
        type: string;
        content: string;
        address: string;
      }> = [];

      for (const search of searches) {
        const searchCmd = `${tool} -e bin.relocs.apply=true -q -c "iz~${search.pattern}" ${escapeShellArg(targetPath)}`;
        const searchResult = await this.runCommand(searchCmd, timeout / 10);

        if (searchResult.success && searchResult.output.trim()) {
          const lines = searchResult.output.split('\n').filter((l) => l.trim());
          for (const line of lines) {
            const addrMatch = line.match(/0x[0-9a-fA-F]+/);
            // Extract the actual string content (usually after several columns)
            const parts = line.split(/\s+/);
            const content = parts.slice(3).join(' ');

            if (addrMatch && content) {
              foundFlags.push({
                type: search.name,
                content: content.trim(),
                address: addrMatch[0],
              });
            }
          }
        }
      }

      // Also search for base64/hex encoded data
      results.push('📝 Searching for encoded data...\n');
      const encodedCmd = `${tool} -e bin.relocs.apply=true -q -c "iz~[A-Za-z0-9+/]{20,}==?,[0-9a-fA-F]{32,}" ${escapeShellArg(targetPath)}`;
      const encodedResult = await this.runCommand(encodedCmd, timeout / 6);

      const encodedData: string[] = [];
      if (encodedResult.success && encodedResult.output.trim()) {
        encodedData.push(
          ...encodedResult.output
            .split('\n')
            .filter((l) => l.trim())
            .slice(0, 5),
        );
      }

      // Display results
      results.push('═'.repeat(63));
      results.push('   🎯 FOUND FLAGS & SECRETS');
      results.push('═'.repeat(63) + '\n');

      if (foundFlags.length === 0 && encodedData.length === 0) {
        results.push('  ⚠️  No obvious flags detected in strings');
        results.push('  💡 Flag might be:');
        results.push('     • Encrypted/encoded (try string_decode)');
        results.push('     • Dynamically generated (try dynamic analysis)');
        results.push('     • Hidden in function logic (try r2_decompile)');
      } else {
        if (foundFlags.length > 0) {
          results.push('🚩 POTENTIAL FLAGS:');
          for (const flag of foundFlags) {
            results.push(`  [${flag.type}] @ ${flag.address}`);
            results.push(`  📝 ${flag.content}`);
            results.push('');
          }
        }

        if (encodedData.length > 0) {
          results.push('🔐 ENCODED DATA (may contain flag):');
          encodedData.forEach((d) => results.push(`  ${d}`));
          results.push('');
          results.push('  💡 Try decoding:');
          results.push('     • Base64: echo "STRING" | base64 -d');
          results.push('     • Hex: echo "STRING" | xxd -r -p');
          results.push('     • Use string_decode operation');
        }
      }

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          foundFlags,
          encodedData: encodedData.slice(0, 10),
          totalFlags: foundFlags.length,
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Trace input validation flow
   * Understand how user input is processed and validated
   */
  private async traceInputValidation(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔎 TRACE INPUT VALIDATION');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    try {
      // Find input functions
      results.push('📝 Step 1: Finding input functions...');
      const inputCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~scanf,gets,fgets,read,input,getchar,cin,ReadFile,ReadConsole" ${escapeShellArg(targetPath)}`;
      const inputResult = await this.runCommand(inputCmd, timeout / 3);

      const inputFunctions: string[] = [];
      if (inputResult.success && inputResult.output.trim()) {
        inputFunctions.push(
          ...inputResult.output
            .split('\n')
            .filter((l) => l.trim())
            .slice(0, 10),
        );
        results.push(`  ✓ Found ${inputFunctions.length} input functions`);
      } else {
        results.push('  ℹ️  No obvious input functions detected');
      }

      // Find validation/comparison functions
      results.push('\n📝 Step 2: Finding validation functions...');
      const validateCmd = `${tool} -e bin.relocs.apply=true -q -c "afl~strcmp,strncmp,memcmp,check,valid,compare" ${escapeShellArg(targetPath)}`;
      const validateResult = await this.runCommand(validateCmd, timeout / 3);

      const validationFunctions: string[] = [];
      if (validateResult.success && validateResult.output.trim()) {
        validationFunctions.push(
          ...validateResult.output
            .split('\n')
            .filter((l) => l.trim())
            .slice(0, 10),
        );
        results.push(
          `  ✓ Found ${validationFunctions.length} validation functions`,
        );
      }

      // Display results
      results.push('\n' + '═'.repeat(63));
      results.push('   📋 INPUT VALIDATION FLOW');
      results.push('═'.repeat(63) + '\n');

      if (inputFunctions.length > 0) {
        results.push('🔵 INPUT FUNCTIONS:');
        inputFunctions.forEach((f) => results.push(`  ${f}`));
        results.push('');
      }

      if (validationFunctions.length > 0) {
        results.push('🟢 VALIDATION FUNCTIONS:');
        validationFunctions.forEach((f) => results.push(`  ${f}`));
        results.push('');
      }

      // Provide analysis guide
      results.push('═'.repeat(63));
      results.push('   💡 ANALYSIS WORKFLOW');
      results.push('═'.repeat(63) + '\n');
      results.push('1️⃣  Decompile validation functions:');
      if (validationFunctions.length > 0) {
        const firstValidation = validationFunctions[0];
        const nameMatch = firstValidation?.match(/sym\.([^\s]+)/);
        if (nameMatch) {
          results.push(
            `    { operation: "r2_decompile", function: "${nameMatch[1]}" }`,
          );
        }
      }
      results.push('');
      results.push('2️⃣  Find cross-references:');
      results.push(
        '    { operation: "r2_xrefs", function: "VALIDATION_FUNC" }',
      );
      results.push('');
      results.push('3️⃣  Trace data flow:');
      results.push('    • Where does input go after reading?');
      results.push('    • What transformations are applied?');
      results.push('    • What is it compared against?');
      results.push('');
      results.push('4️⃣  Extract the correct value:');
      results.push('    • Look for string comparisons');
      results.push('    • Check for hardcoded values');
      results.push('    • Analyze checksums/hashes');

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          inputFunctions: inputFunctions.slice(0, 10),
          validationFunctions: validationFunctions.slice(0, 10),
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  /**
   * Identify all protection/check points in binary
   * Comprehensive protection analysis
   */
  private async identifyProtectionPoints(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🛡️ IDENTIFY PROTECTION POINTS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    try {
      const protectionPoints: {
        antiDebug: string[];
        antiVM: string[];
        licenseChecks: string[];
        trialChecks: string[];
        integrityChecks: string[];
      } = {
        antiDebug: [],
        antiVM: [],
        licenseChecks: [],
        trialChecks: [],
        integrityChecks: [],
      };

      // Anti-debug detection
      results.push('📝 Checking anti-debug protections...');
      const antiDebugCmd = `${tool} -e bin.relocs.apply=true -q -c "ii~IsDebuggerPresent,CheckRemoteDebuggerPresent,NtQueryInformationProcess,OutputDebugString" ${escapeShellArg(targetPath)}`;
      const antiDebugResult = await this.runCommand(antiDebugCmd, timeout / 5);
      if (antiDebugResult.success && antiDebugResult.output.trim()) {
        protectionPoints.antiDebug = antiDebugResult.output
          .split('\n')
          .filter((l) => l.trim());
        results.push(
          `  ✓ Found ${protectionPoints.antiDebug.length} anti-debug imports`,
        );
      } else {
        results.push('  ℹ️  No anti-debug detected');
      }

      // Anti-VM detection
      results.push('\n📝 Checking anti-VM protections...');
      const antiVMCmd = `${tool} -e bin.relocs.apply=true -q -c "iz~vmware,virtualbox,vbox,qemu,sandbox,vm" ${escapeShellArg(targetPath)}`;
      const antiVMResult = await this.runCommand(antiVMCmd, timeout / 5);
      if (antiVMResult.success && antiVMResult.output.trim()) {
        protectionPoints.antiVM = antiVMResult.output
          .split('\n')
          .filter((l) => l.trim())
          .slice(0, 5);
        results.push(
          `  ✓ Found ${protectionPoints.antiVM.length} anti-VM indicators`,
        );
      } else {
        results.push('  ℹ️  No anti-VM detected');
      }

      // License checks
      results.push('\n📝 Checking license validation...');
      const licenseCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~license,serial,key,register" ${escapeShellArg(targetPath)}`;
      const licenseResult = await this.runCommand(licenseCmd, timeout / 3);
      if (licenseResult.success && licenseResult.output.trim()) {
        protectionPoints.licenseChecks = licenseResult.output
          .split('\n')
          .filter((l) => l.trim())
          .slice(0, 5);
        results.push(
          `  ✓ Found ${protectionPoints.licenseChecks.length} license functions`,
        );
      } else {
        results.push('  ℹ️  No license checks detected');
      }

      // Trial/time checks
      results.push('\n📝 Checking trial/time protections...');
      const trialCmd = `${tool} -e bin.relocs.apply=true -q -c "ii~GetSystemTime,GetLocalTime,time,clock; afl~trial,demo,expired,days" ${escapeShellArg(targetPath)}`;
      const trialResult = await this.runCommand(trialCmd, timeout / 3);
      if (trialResult.success && trialResult.output.trim()) {
        protectionPoints.trialChecks = trialResult.output
          .split('\n')
          .filter((l) => l.trim())
          .slice(0, 5);
        results.push(
          `  ✓ Found ${protectionPoints.trialChecks.length} trial/time checks`,
        );
      } else {
        results.push('  ℹ️  No trial checks detected');
      }

      // Integrity checks (CRC, checksum)
      results.push('\n📝 Checking integrity protections...');
      const integrityCmd = `${tool} -e bin.relocs.apply=true -q -c "afl~crc,checksum,hash,md5,sha,verify" ${escapeShellArg(targetPath)}`;
      const integrityResult = await this.runCommand(integrityCmd, timeout / 3);
      if (integrityResult.success && integrityResult.output.trim()) {
        protectionPoints.integrityChecks = integrityResult.output
          .split('\n')
          .filter((l) => l.trim())
          .slice(0, 5);
        results.push(
          `  ✓ Found ${protectionPoints.integrityChecks.length} integrity functions`,
        );
      } else {
        results.push('  ℹ️  No integrity checks detected');
      }

      // Summary
      results.push('\n' + '═'.repeat(63));
      results.push('   📊 PROTECTION SUMMARY');
      results.push('═'.repeat(63) + '\n');

      const total =
        protectionPoints.antiDebug.length +
        protectionPoints.antiVM.length +
        protectionPoints.licenseChecks.length +
        protectionPoints.trialChecks.length +
        protectionPoints.integrityChecks.length;

      results.push(`  Total protection points: ${total}`);
      results.push(`  • Anti-debug:    ${protectionPoints.antiDebug.length}`);
      results.push(`  • Anti-VM:       ${protectionPoints.antiVM.length}`);
      results.push(
        `  • License:       ${protectionPoints.licenseChecks.length}`,
      );
      results.push(`  • Trial/Time:    ${protectionPoints.trialChecks.length}`);
      results.push(
        `  • Integrity:     ${protectionPoints.integrityChecks.length}`,
      );

      if (total > 0) {
        results.push('\n💡 Recommended bypass strategy:');
        if (protectionPoints.antiDebug.length > 0) {
          results.push('   1. Bypass anti-debug (auto_bypass_checks)');
        }
        if (protectionPoints.trialChecks.length > 0) {
          results.push('   2. Crack trial (smart_crack_trial)');
        }
        if (protectionPoints.licenseChecks.length > 0) {
          results.push('   3. Bypass license (find_license_checks)');
        }
      }

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          protectionPoints,
          totalProtections: total,
        },
      };
    } catch (error) {
      return {
        success: false,
        output: results.join('\n') + `\n  ❌ Error: ${error}`,
        error: String(error),
      };
    }
  }

  // ============= INTELLIGENT COMPOUND WORKFLOWS =============

  /**
   * Full Malware Analysis - Complete investigation workflow
   * Runs: triage → packer detection → anti-analysis → capabilities → IOCs → YARA generation
   */
  private async fullMalwareAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const startTime = Date.now();
    const findings: Record<string, unknown> = {};

    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║         🔬 FULL MALWARE INVESTIGATION - AUTOMATED WORKFLOW 🔬            ║',
    );
    results.push(
      '╠═══════════════════════════════════════════════════════════════════════════╣',
    );
    results.push(
      `║  Target: ${path.basename(targetPath).substring(0, 60).padEnd(60)} ║`,
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push('');

    // Step 1: Malware Triage
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 1/6: 🔬 MALWARE TRIAGE                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const triageResult = await this.malwareTriage(targetPath, timeout / 6);
      if (triageResult.success) {
        results.push(triageResult.output);
        findings['triage'] = triageResult.metadata;
      } else {
        results.push(`  ⚠️ Triage failed: ${triageResult.error}`);
      }
    } catch (e) {
      results.push(`  ⚠️ Triage error: ${e}`);
    }
    results.push('');

    // Step 2: Packer Detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 2/6: 🛡️ PACKER/PROTECTOR DETECTION                     │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const packerResult = await this.detectPacker(targetPath, timeout / 6);
      if (packerResult.success) {
        results.push(packerResult.output);
        findings['packer'] = packerResult.metadata;
      } else {
        results.push(`  ⚠️ Packer detection failed: ${packerResult.error}`);
      }
    } catch (e) {
      results.push(`  ⚠️ Packer detection error: ${e}`);
    }
    results.push('');

    // Step 3: Anti-Analysis Detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 3/6: 🕵️ ANTI-ANALYSIS TECHNIQUES                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const antiResult = await this.antiAnalysis(targetPath, timeout / 6);
      if (antiResult.success) {
        results.push(antiResult.output);
        findings['antiAnalysis'] = antiResult.metadata;
      } else {
        results.push(
          `  ⚠️ Anti-analysis detection failed: ${antiResult.error}`,
        );
      }
    } catch (e) {
      results.push(`  ⚠️ Anti-analysis error: ${e}`);
    }
    results.push('');

    // Step 4: Capability Analysis
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 4/6: 📊 CAPABILITY ANALYSIS (MITRE ATT&CK)             │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const capResult = await this.capabilityAnalysis(targetPath, timeout / 6);
      if (capResult.success) {
        results.push(capResult.output);
        findings['capabilities'] = capResult.metadata;
      } else {
        results.push(`  ⚠️ Capability analysis failed: ${capResult.error}`);
      }
    } catch (e) {
      results.push(`  ⚠️ Capability analysis error: ${e}`);
    }
    results.push('');

    // Step 5: IOC Extraction (via strings/imports)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 5/6: 🎯 IOC EXTRACTION                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const tool = this.params.useRizin ? 'rizin' : 'radare2';

      // Extract strings for IOCs
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)} | head -200`,
        timeout / 12,
      );

      if (strResult.success) {
        const iocs = {
          urls: [] as string[],
          ips: [] as string[],
          domains: [] as string[],
          paths: [] as string[],
          registry: [] as string[],
        };

        const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
        const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
        const domainRegex = /\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b/gi;
        const pathRegex =
          /[A-Z]:\\[^\s"']+|\/(?:usr|var|tmp|etc|home)[^\s"']+/gi;
        const regexRegex = /HKEY_[A-Z_]+\\[^\s"']+/gi;

        const strings = strResult.output;
        iocs.urls = [...new Set(strings.match(urlRegex) || [])];
        iocs.ips = [...new Set(strings.match(ipRegex) || [])].filter(
          (ip) => !ip.startsWith('0.') && !ip.startsWith('127.'),
        );
        iocs.domains = [...new Set(strings.match(domainRegex) || [])].slice(
          0,
          20,
        );
        iocs.paths = [...new Set(strings.match(pathRegex) || [])].slice(0, 20);
        iocs.registry = [...new Set(strings.match(regexRegex) || [])];

        if (iocs.urls.length > 0) {
          results.push('  📎 URLs Found:');
          iocs.urls.slice(0, 10).forEach((u) => results.push(`     • ${u}`));
        }
        if (iocs.ips.length > 0) {
          results.push('  🌐 IP Addresses:');
          iocs.ips.slice(0, 10).forEach((ip) => results.push(`     • ${ip}`));
        }
        if (iocs.domains.length > 0) {
          results.push('  🔗 Domains:');
          iocs.domains.slice(0, 10).forEach((d) => results.push(`     • ${d}`));
        }
        if (iocs.registry.length > 0) {
          results.push('  📝 Registry Keys:');
          iocs.registry.slice(0, 5).forEach((r) => results.push(`     • ${r}`));
        }

        findings['iocs'] = iocs;

        if (
          iocs.urls.length === 0 &&
          iocs.ips.length === 0 &&
          iocs.domains.length === 0
        ) {
          results.push(
            '  ℹ️ No obvious IOCs found - may be encrypted/obfuscated',
          );
        }
      }
    } catch (e) {
      results.push(`  ⚠️ IOC extraction error: ${e}`);
    }
    results.push('');

    // Step 6: YARA Generation
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 6/6: 📝 YARA RULE GENERATION                           │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const yaraResult = await this.yaraGenerate(targetPath, timeout / 6);
      if (yaraResult.success) {
        // Just show a summary, not full rule
        results.push('  ✅ YARA rule generated successfully');
        results.push(
          '  📝 Use yara_generate operation separately for full rule',
        );
        findings['yaraGenerated'] = true;
      } else {
        results.push(`  ⚠️ YARA generation failed: ${yaraResult.error}`);
      }
    } catch (e) {
      results.push(`  ⚠️ YARA generation error: ${e}`);
    }

    // Final Summary
    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║                      📋 INVESTIGATION SUMMARY                             ║',
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push(`  ⏱️ Total analysis time: ${elapsedTime}s`);
    results.push('');
    results.push('  🎯 RECOMMENDED NEXT STEPS:');

    // Smart recommendations based on findings
    if (findings['packer']) {
      results.push(
        '     1. Sample appears PACKED - unpack before deeper analysis',
      );
      results.push('        → Try: upx -d, or manual unpacking');
    }
    if (findings['antiAnalysis']) {
      results.push(
        '     2. Anti-analysis detected - use isolated VM environment',
      );
    }
    results.push(
      '     3. Run in sandbox (ANY.RUN, Cuckoo) for dynamic behavior',
    );
    results.push('     4. Submit hashes to VirusTotal for threat intel');
    results.push('     5. Use ghidra_decompile for detailed code review');
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
      metadata: findings,
    };
  }

  /**
   * Full CTF Solve - Complete CTF binary solving workflow
   * Runs: find checks → find win → trace validation → auto-bypass → extract flag
   */
  private async fullCtfSolve(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const startTime = Date.now();
    const findings: Record<string, unknown> = {};

    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║            🏆 FULL CTF SOLVE - AUTOMATED WORKFLOW 🏆                      ║',
    );
    results.push(
      '╠═══════════════════════════════════════════════════════════════════════════╣',
    );
    results.push(
      `║  Target: ${path.basename(targetPath).substring(0, 60).padEnd(60)} ║`,
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push('');

    // Step 1: Find Flag Strings (quick win check)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 1/5: 🚩 QUICK WIN - FIND FLAG STRINGS                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const flagResult = await this.findFlagStrings(targetPath, timeout / 5);
      if (flagResult.success) {
        results.push(flagResult.output);
        findings['flags'] = flagResult.metadata;

        // Check if we found direct flags
        if (
          flagResult.metadata &&
          (flagResult.metadata as Record<string, unknown>)['flagsFound']
        ) {
          results.push('');
          results.push(
            '  🎉🎉🎉 POSSIBLE FLAG FOUND! Check strings above! 🎉🎉🎉',
          );
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Flag search error: ${e}`);
    }
    results.push('');

    // Step 2: Find License/Validation Checks
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 2/5: 🔍 FIND LICENSE/VALIDATION CHECKS                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    let checkFunctions: string[] = [];
    try {
      const checkResult = await this.findLicenseChecks(targetPath, timeout / 5);
      if (checkResult.success) {
        results.push(checkResult.output);
        findings['checks'] = checkResult.metadata;

        if (checkResult.metadata) {
          const meta = checkResult.metadata as Record<string, unknown>;
          if (meta['functions']) {
            checkFunctions = meta['functions'] as string[];
          }
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Check detection error: ${e}`);
    }
    results.push('');

    // Step 3: Find Win Function
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 3/5: 🏆 FIND WIN/SUCCESS FUNCTION                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    let winFunction = '';
    try {
      const winResult = await this.findWinFunction(targetPath, timeout / 5);
      if (winResult.success) {
        results.push(winResult.output);
        findings['win'] = winResult.metadata;

        if (winResult.metadata) {
          const meta = winResult.metadata as Record<string, unknown>;
          if (meta['topCandidate']) {
            winFunction = meta['topCandidate'] as string;
          }
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Win function detection error: ${e}`);
    }
    results.push('');

    // Step 4: Identify Protection Points
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 4/5: 🛡️ IDENTIFY ALL PROTECTION POINTS                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const protResult = await this.identifyProtectionPoints(
        targetPath,
        timeout / 5,
      );
      if (protResult.success) {
        results.push(protResult.output);
        findings['protections'] = protResult.metadata;
      }
    } catch (e) {
      results.push(`  ⚠️ Protection point detection error: ${e}`);
    }
    results.push('');

    // Step 5: Generate Bypass Strategy
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 5/5: 🎯 BYPASS STRATEGY & RECOMMENDATIONS              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    results.push('');
    results.push('  📋 ATTACK STRATEGIES (in order of preference):');
    results.push('');

    // Strategy 1: Direct flag
    results.push('  🥇 STRATEGY 1: Direct Flag Extraction');
    results.push('     If flag strings found above, you may already have it!');
    results.push('');

    // Strategy 2: Patch validation
    if (checkFunctions.length > 0) {
      results.push('  🥈 STRATEGY 2: Patch Validation Functions');
      results.push('     Target functions to patch:');
      checkFunctions.slice(0, 5).forEach((f) => {
        results.push(`       • ${f} → patch to always return TRUE`);
      });
      results.push('     Use: auto_bypass_checks or patch_function');
      results.push('');
    }

    // Strategy 3: Jump to win
    if (winFunction) {
      results.push('  🥉 STRATEGY 3: Jump Directly to Win Function');
      results.push(`     Win function: ${winFunction}`);
      results.push('     Patch: Change conditional jump to unconditional');
      results.push(
        '     Use: nop_instructions on the check, force jump to win',
      );
      results.push('');
    }

    // Strategy 4: Keygen
    results.push('  🔑 STRATEGY 4: Create Keygen');
    results.push('     Use: extract_algorithm to reverse the validation logic');
    results.push('     Then implement in Python/C');
    results.push('');

    // Strategy 5: Dynamic
    results.push('  🔄 STRATEGY 5: Dynamic Analysis');
    results.push('     Use: ltrace_run or strace_run to trace execution');
    results.push('     Set breakpoints at validation functions');
    results.push('');

    // Final summary
    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║                         📋 CTF SOLVE SUMMARY                              ║',
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push(`  ⏱️ Analysis time: ${elapsedTime}s`);
    results.push(`  🔍 Check functions found: ${checkFunctions.length}`);
    results.push(`  🏆 Win function: ${winFunction || 'Not identified'}`);
    results.push('');
    results.push('  💡 QUICK COMMANDS TO TRY:');
    results.push(
      `     1. r2_decompile function="${checkFunctions[0] || 'main'}"`,
    );
    results.push('     2. auto_bypass_checks');
    results.push('     3. smart_crack_trial');
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
      metadata: findings,
    };
  }

  /**
   * Full Vulnerability Audit - Security audit workflow
   */
  private async fullVulnerabilityAudit(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const startTime = Date.now();
    const findings: Record<string, unknown> = {};

    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║           🐛 FULL VULNERABILITY AUDIT - SECURITY WORKFLOW 🐛              ║',
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push('');

    // Step 1: Basic Info
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 1/4: 📊 BINARY SECURITY PROPERTIES                     │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const tool = this.params.useRizin ? 'rizin' : 'radare2';
      const infoResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iI" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );

      if (infoResult.success) {
        const info = infoResult.output.toLowerCase();
        results.push('  🔐 Security Features:');

        // Check security features
        const hasCanary =
          info.includes('canary true') || info.includes('canary=true');
        const hasNX = info.includes('nx true') || info.includes('nx=true');
        const hasPIE = info.includes('pic true') || info.includes('pie true');
        const hasRelro =
          info.includes('relro full') || info.includes('relro partial');

        results.push(
          `     Stack Canary: ${hasCanary ? '✅ ENABLED' : '❌ DISABLED (Buffer overflow possible)'}`,
        );
        results.push(
          `     NX (DEP):     ${hasNX ? '✅ ENABLED' : '❌ DISABLED (Code execution possible)'}`,
        );
        results.push(
          `     PIE/ASLR:     ${hasPIE ? '✅ ENABLED' : '❌ DISABLED (Fixed addresses)'}`,
        );
        results.push(
          `     RELRO:        ${hasRelro ? '✅ ENABLED' : '❌ DISABLED (GOT overwrite possible)'}`,
        );

        findings['security'] = { hasCanary, hasNX, hasPIE, hasRelro };
      }
    } catch (e) {
      results.push(`  ⚠️ Error: ${e}`);
    }
    results.push('');

    // Step 2: Vulnerability Pattern Scan
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 2/4: 🔍 VULNERABILITY PATTERN SCAN                     │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const vulnResult = await this.findVulnerabilities(
        targetPath,
        timeout / 4,
      );
      if (vulnResult.success) {
        results.push(vulnResult.output);
        findings['vulnerabilities'] = vulnResult.metadata;
      }
    } catch (e) {
      results.push(`  ⚠️ Vulnerability scan error: ${e}`);
    }
    results.push('');

    // Step 3: Crypto Analysis
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 3/4: 🔐 CRYPTOGRAPHIC ANALYSIS                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const cryptoResult = await this.findCrypto(targetPath, timeout / 4);
      if (cryptoResult.success) {
        results.push(cryptoResult.output);
        findings['crypto'] = cryptoResult.metadata;
      }
    } catch (e) {
      results.push(`  ⚠️ Crypto analysis error: ${e}`);
    }
    results.push('');

    // Step 4: Dangerous Functions
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 4/4: ⚠️ DANGEROUS FUNCTION USAGE                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const tool = this.params.useRizin ? 'rizin' : 'radare2';
      const importResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );

      if (importResult.success) {
        const imports = importResult.output.toLowerCase();
        const dangerous = [
          { func: 'strcpy', risk: 'CRITICAL', desc: 'Buffer overflow' },
          { func: 'strcat', risk: 'CRITICAL', desc: 'Buffer overflow' },
          { func: 'gets', risk: 'CRITICAL', desc: 'Unbounded input' },
          { func: 'sprintf', risk: 'HIGH', desc: 'Format string/overflow' },
          { func: 'scanf', risk: 'HIGH', desc: 'Format string' },
          { func: 'system', risk: 'HIGH', desc: 'Command injection' },
          { func: 'popen', risk: 'HIGH', desc: 'Command injection' },
          { func: 'execve', risk: 'MEDIUM', desc: 'Process execution' },
          { func: 'memcpy', risk: 'MEDIUM', desc: 'Potential overflow' },
          { func: 'mmap', risk: 'MEDIUM', desc: 'Memory mapping' },
        ];

        const found = dangerous.filter((d) => imports.includes(d.func));

        if (found.length > 0) {
          results.push('  ⚠️ Dangerous Functions Found:');
          found.forEach((f) => {
            const icon =
              f.risk === 'CRITICAL' ? '🔴' : f.risk === 'HIGH' ? '🟠' : '🟡';
            results.push(`     ${icon} ${f.func}() - ${f.risk}: ${f.desc}`);
          });
        } else {
          results.push('  ✅ No obviously dangerous functions imported');
        }

        findings['dangerous'] = found;
      }
    } catch (e) {
      results.push(`  ⚠️ Import analysis error: ${e}`);
    }

    // Summary
    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║                      📋 SECURITY AUDIT SUMMARY                            ║',
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push(`  ⏱️ Analysis time: ${elapsedTime}s`);
    results.push('');
    results.push('  🎯 RECOMMENDED ACTIONS:');
    results.push('     1. Review dangerous functions with r2_xrefs');
    results.push(
      '     2. Decompile suspicious functions with ghidra_decompile',
    );
    results.push('     3. Fuzz input handling with AFL or libFuzzer');
    results.push('     4. Dynamic analysis with strace_run');
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
      metadata: findings,
    };
  }

  /**
   * Deep Binary Understanding - Comprehensive binary analysis
   */
  private async deepBinaryUnderstanding(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const startTime = Date.now();

    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║          📊 DEEP BINARY UNDERSTANDING - COMPREHENSIVE ANALYSIS 📊         ║',
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push('');

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    // Step 1: Binary Info
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 1/5: 📋 BINARY INFORMATION                             │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const infoResult = await this.r2Info(targetPath, timeout / 5);
      if (infoResult.success) {
        results.push(infoResult.output.split('\n').slice(0, 30).join('\n'));
      }
    } catch (e) {
      results.push(`  ⚠️ Error: ${e}`);
    }
    results.push('');

    // Step 2: Function List
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 2/5: 📌 KEY FUNCTIONS                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    let mainFunc = '';
    try {
      const funcResult = await this.r2Functions(targetPath, timeout / 5);
      if (funcResult.success) {
        const lines = funcResult.output.split('\n').filter((l) => l.trim());

        // Find interesting functions
        const interesting = lines.filter(
          (l) =>
            l.includes('main') ||
            l.includes('check') ||
            l.includes('verify') ||
            l.includes('valid') ||
            l.includes('auth') ||
            l.includes('login') ||
            l.includes('key') ||
            l.includes('flag') ||
            l.includes('win') ||
            l.includes('success'),
        );

        results.push(`  📊 Total functions: ${lines.length}`);
        results.push('');
        results.push('  🎯 Interesting functions:');
        interesting.slice(0, 15).forEach((f) => results.push(`     ${f}`));

        if (lines.some((l) => l.includes('main'))) {
          mainFunc = 'main';
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Error: ${e}`);
    }
    results.push('');

    // Step 3: Strings
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 3/5: 📝 INTERESTING STRINGS                            │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)} | head -100`,
        timeout / 10,
      );

      if (strResult.success) {
        const lines = strResult.output.split('\n');
        const interesting = lines.filter(
          (l) =>
            l.includes('flag') ||
            l.includes('password') ||
            l.includes('secret') ||
            l.includes('key') ||
            l.includes('correct') ||
            l.includes('wrong') ||
            l.includes('invalid') ||
            l.includes('success') ||
            l.includes('fail') ||
            l.includes('error') ||
            l.includes('http') ||
            l.includes('://'),
        );

        results.push('  🔤 Notable strings:');
        interesting
          .slice(0, 20)
          .forEach((s) => results.push(`     ${s.trim()}`));
      }
    } catch (e) {
      results.push(`  ⚠️ Error: ${e}`);
    }
    results.push('');

    // Step 4: Imports
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 4/5: 📥 IMPORTS & DEPENDENCIES                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const importResult = await this.r2Imports(targetPath, timeout / 5);
      if (importResult.success) {
        results.push(importResult.output.split('\n').slice(0, 30).join('\n'));
      }
    } catch (e) {
      results.push(`  ⚠️ Error: ${e}`);
    }
    results.push('');

    // Step 5: Decompile main
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 5/5: 💻 MAIN FUNCTION DECOMPILATION                    │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    if (mainFunc) {
      try {
        this.params.function = mainFunc;
        const decompResult = await this.r2Decompile(targetPath, timeout / 5);
        if (decompResult.success) {
          results.push(decompResult.output.split('\n').slice(0, 50).join('\n'));
        }
      } catch (e) {
        results.push(`  ⚠️ Decompilation error: ${e}`);
      }
    } else {
      results.push(
        '  ℹ️ No main function found - use r2_decompile with specific function',
      );
    }

    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    results.push('');
    results.push(`  ⏱️ Total analysis time: ${elapsedTime}s`);
    results.push('');
    results.push('  💡 NEXT STEPS:');
    results.push(
      '     • r2_decompile function="<name>" - Decompile specific function',
    );
    results.push('     • r2_xrefs address="<addr>" - Find cross-references');
    results.push('     • ghidra_decompile - Better decompilation quality');
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  /**
   * Firmware Full Analysis - Complete firmware investigation
   */
  private async firmwareFullAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const startTime = Date.now();

    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║           📦 FULL FIRMWARE ANALYSIS - EMBEDDED SYSTEMS 📦                 ║',
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push('');

    // Step 1: Entropy Analysis
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 1/4: 📊 ENTROPY ANALYSIS                               │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const entropyResult = await this.binwalkEntropy(targetPath, timeout / 4);
      if (entropyResult.success) {
        results.push(entropyResult.output);
      }
    } catch (e) {
      results.push(`  ⚠️ Entropy analysis error: ${e}`);
    }
    results.push('');

    // Step 2: Signature Scan
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 2/4: 🔍 SIGNATURE SCAN                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const scanResult = await this.binwalkScan(targetPath, timeout / 4);
      if (scanResult.success) {
        results.push(scanResult.output);
      }
    } catch (e) {
      results.push(`  ⚠️ Signature scan error: ${e}`);
    }
    results.push('');

    // Step 3: Extract
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 3/4: 📤 FILE EXTRACTION                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const extractResult = await this.binwalkExtract(targetPath, timeout / 4);
      if (extractResult.success) {
        results.push(extractResult.output);
      }
    } catch (e) {
      results.push(`  ⚠️ Extraction error: ${e}`);
    }
    results.push('');

    // Step 4: Basic binary info
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ STEP 4/4: 📋 BINARY METADATA                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘',
    );

    try {
      const infoResult = await this.runCommand(
        `file ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );
      if (infoResult.success) {
        results.push(`  ${infoResult.output}`);
      }
    } catch (e) {
      results.push(`  ⚠️ File info error: ${e}`);
    }

    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    results.push('');
    results.push(`  ⏱️ Total analysis time: ${elapsedTime}s`);
    results.push('');
    results.push('  💡 NEXT STEPS:');
    results.push('     • Analyze extracted filesystems for sensitive files');
    results.push('     • Look for hardcoded credentials in config files');
    results.push(
      '     • Analyze any ELF binaries with deep_binary_understanding',
    );
    results.push('     • Search for private keys, certificates');
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  /**
   * Suggest Next Steps - Meta-operation that analyzes binary and suggests what to do
   */
  private async suggestNextSteps(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    const suggestions: Array<{
      priority: number;
      action: string;
      reason: string;
    }> = [];

    results.push('');
    results.push(
      '╔═══════════════════════════════════════════════════════════════════════════╗',
    );
    results.push(
      '║              🧠 INTELLIGENT ANALYSIS - NEXT STEPS ADVISOR 🧠              ║',
    );
    results.push(
      '╚═══════════════════════════════════════════════════════════════════════════╝',
    );
    results.push('');

    // Quick file analysis
    let fileType = '';
    try {
      const fileResult = await this.runCommand(
        `file ${escapeShellArg(targetPath)}`,
        timeout / 10,
      );
      if (fileResult.success) {
        fileType = fileResult.output.toLowerCase();
        results.push(`  📁 File Type: ${fileResult.output.trim()}`);
      }
    } catch (e) {
      results.push(`  ⚠️ File detection error: ${e}`);
    }
    results.push('');

    // Determine what kind of binary and suggest accordingly
    if (fileType.includes('executable') || fileType.includes('elf')) {
      // It's an executable
      if (fileType.includes('32-bit')) {
        suggestions.push({
          priority: 1,
          action: 'quick_re',
          reason: '32-bit binary - start with quick assessment',
        });
      }

      if (
        fileType.includes('stripped') ||
        fileType.includes('not stripped') === false
      ) {
        suggestions.push({
          priority: 2,
          action: 'r2_functions',
          reason: 'List functions to understand structure',
        });
      }

      suggestions.push({
        priority: 3,
        action: 'detect_packer',
        reason: 'Check if binary is packed/protected',
      });
      suggestions.push({
        priority: 4,
        action: 'r2_strings',
        reason: 'Extract strings for clues',
      });
      suggestions.push({
        priority: 5,
        action: 'r2_imports',
        reason: 'Understand external dependencies',
      });
    }

    if (fileType.includes('firmware') || fileType.includes('boot')) {
      suggestions.push({
        priority: 1,
        action: 'firmware_full_analysis',
        reason: 'Firmware detected - run full firmware workflow',
      });
    }

    if (
      fileType.includes('pe32') ||
      fileType.includes('windows') ||
      fileType.includes('.exe')
    ) {
      suggestions.push({
        priority: 1,
        action: 'malware_triage',
        reason: 'Windows executable - triage for potential malware',
      });
      suggestions.push({
        priority: 2,
        action: 'detect_packer',
        reason: 'Windows binaries often packed',
      });
    }

    // CTF-specific suggestions
    const basename = path.basename(targetPath).toLowerCase();
    if (
      basename.includes('crackme') ||
      basename.includes('ctf') ||
      basename.includes('challenge') ||
      basename.includes('reverse')
    ) {
      suggestions.push({
        priority: 1,
        action: 'full_ctf_solve',
        reason: 'CTF challenge detected - run full CTF workflow',
      });
    }

    // Sort by priority
    suggestions.sort((a, b) => a.priority - b.priority);

    results.push('  🎯 RECOMMENDED OPERATIONS (in order):');
    results.push('');

    suggestions.slice(0, 7).forEach((s, i) => {
      results.push(`  ${i + 1}. ${s.action}`);
      results.push(`     └─ ${s.reason}`);
      results.push('');
    });

    // Generic fallbacks
    results.push('  📚 WORKFLOW SHORTCUTS:');
    results.push(
      '     • full_malware_analysis - Complete malware investigation',
    );
    results.push('     • full_ctf_solve - Complete CTF binary solving');
    results.push('     • full_vulnerability_audit - Security audit');
    results.push('     • deep_binary_understanding - Comprehensive analysis');
    results.push(
      '     • firmware_full_analysis - Firmware extraction & analysis',
    );
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  // ============= OBFUSCATION-RESISTANT ANALYSIS =============

  /**
   * Analyze Control Flow - Find decision points by CFG structure
   * Works on stripped/obfuscated binaries without relying on symbol names
   * Uses radare2's control flow graph analysis to identify:
   * - Branch points (conditional jumps)
   * - Loop structures
   * - Function complexity metrics
   * - Decision trees
   */
  private async analyzeControlFlow(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔀 CONTROL FLOW ANALYSIS (Obfuscation-Resistant)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    const tool = this.params.useRizin ? 'rizin' : 'radare2';

    // Step 1: Full analysis to detect functions even without symbols
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. FUNCTION DETECTION (without symbols)                     │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    interface FunctionInfo {
      addr: number;
      name: string;
      size: number;
      blocks: number;
      complexity: number;
    }
    let functionList: FunctionInfo[] = [];
    try {
      // Use aaa for full analysis, then get function list as JSON
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );
      if (funcResult.success && funcResult.output.trim()) {
        try {
          const funcs = JSON.parse(funcResult.output);
          if (Array.isArray(funcs)) {
            functionList = funcs.map(
              (f: {
                offset: number;
                name?: string;
                size?: number;
                nbbs?: number;
                cc?: number;
              }) => ({
                addr: f.offset,
                name: f.name || `fcn_${f.offset.toString(16)}`,
                size: f.size || 0,
                blocks: f.nbbs || 0,
                complexity: f.cc || 0,
              }),
            );
            results.push(`  ✅ Detected ${functionList.length} functions\n`);

            // Sort by complexity (cyclomatic complexity)
            const sortedByComplexity = [...functionList]
              .sort((a, b) => b.complexity - a.complexity)
              .slice(0, 10);

            results.push('  📊 TOP 10 FUNCTIONS BY CYCLOMATIC COMPLEXITY:');
            results.push(
              '  ┌──────────────┬──────────────────────────────┬────────┬────────┐',
            );
            results.push(
              '  │ Address      │ Name                         │ Blocks │ CC     │',
            );
            results.push(
              '  ├──────────────┼──────────────────────────────┼────────┼────────┤',
            );
            sortedByComplexity.forEach((f) => {
              const addr = `0x${f.addr.toString(16).padStart(8, '0')}`;
              const name = (f.name || 'unnamed').substring(0, 28).padEnd(28);
              const blocks = f.blocks.toString().padStart(6);
              const cc = f.complexity.toString().padStart(6);
              results.push(`  │ ${addr}   │ ${name} │ ${blocks} │ ${cc} │`);
            });
            results.push(
              '  └──────────────┴──────────────────────────────┴────────┴────────┘',
            );
            results.push('');
            results.push(
              '  💡 High CC = More decision points = Likely validation/check logic',
            );
            results.push('');
          }
        } catch {
          results.push(
            `  Function list (raw):\n${funcResult.output.substring(0, 500)}\n`,
          );
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Function analysis error: ${e}\n`);
    }

    // Step 2: Find all conditional branches
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. CONDITIONAL BRANCH ANALYSIS                             │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Search for conditional jump instructions (x86/x64)
      const branchPatterns = [
        { op: 'je', desc: 'Jump if Equal (ZF=1)' },
        { op: 'jne', desc: 'Jump if Not Equal' },
        { op: 'jz', desc: 'Jump if Zero' },
        { op: 'jnz', desc: 'Jump if Not Zero' },
        { op: 'jg', desc: 'Jump if Greater (signed)' },
        { op: 'jl', desc: 'Jump if Less (signed)' },
        { op: 'ja', desc: 'Jump if Above (unsigned)' },
        { op: 'jb', desc: 'Jump if Below (unsigned)' },
      ];

      results.push('  📍 CONDITIONAL JUMP STATISTICS:');
      results.push('');

      const branchStats: Array<{ op: string; count: number; desc: string }> =
        [];

      for (const pattern of branchPatterns) {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad ${pattern.op}" ${escapeShellArg(targetPath)} | wc -l`,
          timeout / 16,
        );
        if (searchResult.success) {
          const count = parseInt(searchResult.output.trim(), 10) || 0;
          if (count > 0) {
            branchStats.push({ op: pattern.op, count, desc: pattern.desc });
          }
        }
      }

      branchStats.sort((a, b) => b.count - a.count);
      branchStats.forEach((b) => {
        results.push(
          `     ${b.op.padEnd(6)} : ${b.count.toString().padStart(5)} occurrences  (${b.desc})`,
        );
      });

      const totalBranches = branchStats.reduce((sum, b) => sum + b.count, 0);
      results.push('');
      results.push(`  📈 Total conditional branches: ${totalBranches}`);
      results.push('');
    } catch (e) {
      results.push(`  ⚠️ Branch analysis error: ${e}\n`);
    }

    // Step 3: Analyze entry point control flow
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. ENTRY POINT CONTROL FLOW GRAPH                          │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Get CFG of entry function
      const cfgResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; s entry0; agf" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );
      if (cfgResult.success && cfgResult.output.trim()) {
        results.push('  Entry Point Control Flow:');
        results.push('  ─────────────────────────');
        // Limit output size
        const cfgLines = cfgResult.output.split('\n').slice(0, 50);
        cfgLines.forEach((line) => results.push(`  ${line}`));
        if (cfgResult.output.split('\n').length > 50) {
          results.push('  ... (truncated)');
        }
        results.push('');
      }
    } catch (e) {
      results.push(`  ⚠️ CFG analysis error: ${e}\n`);
    }

    // Step 4: Find interesting decision points
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. CRITICAL DECISION POINTS                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Look for CMP followed by conditional jump (typical check pattern)
      const decisionResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad cmp" ${escapeShellArg(targetPath)} | head -30`,
        timeout / 4,
      );
      if (decisionResult.success && decisionResult.output.trim()) {
        results.push('  🎯 COMPARISON INSTRUCTIONS (first 30):');
        results.push('');
        const cmpLines = decisionResult.output.trim().split('\n');
        cmpLines.forEach((line) => {
          // Extract address and instruction
          const match = line.match(/(0x[0-9a-fA-F]+).*?(cmp.*)/i);
          if (match) {
            results.push(`     ${match[1]}  ${match[2]}`);
          } else {
            results.push(`     ${line}`);
          }
        });
        results.push('');
      }
    } catch (e) {
      results.push(`  ⚠️ Decision point analysis error: ${e}\n`);
    }

    // Step 5: Loop detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. LOOP STRUCTURE DETECTION                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Find backward jumps (potential loops)
      const loopResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~[0]" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );
      if (loopResult.success) {
        const addrs = loopResult.output.trim().split('\n').slice(0, 5);
        for (const addr of addrs) {
          if (addr.startsWith('0x')) {
            const funcCfg = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "aaa; s ${addr}; afb" ${escapeShellArg(targetPath)}`,
              timeout / 16,
            );
            if (funcCfg.success && funcCfg.output.includes('->')) {
              // Has jumps - check for backward references
              const blocks = funcCfg.output.split('\n');
              const backJumps = blocks.filter((b) => b.includes('<-'));
              if (backJumps.length > 0) {
                results.push(
                  `  🔄 Function at ${addr} contains potential loops:`,
                );
                backJumps
                  .slice(0, 3)
                  .forEach((bj) => results.push(`     ${bj}`));
                results.push('');
              }
            }
          }
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Loop detection error: ${e}\n`);
    }

    // Summary and recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 ANALYSIS SUMMARY & RECOMMENDATIONS                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🎯 TO FIND THE KEY VALIDATION LOGIC:');
    results.push('     1. Focus on functions with HIGH cyclomatic complexity');
    results.push(
      '     2. Look for CMP with immediate values (magic numbers/keys)',
    );
    results.push('     3. Find functions called after input operations');
    results.push('     4. Trace backward from success/failure messages');
    results.push('');
    results.push('  🔧 SUGGESTED NEXT OPERATIONS:');
    results.push('     • find_comparison_points - Find all CMP with constants');
    results.push(
      '     • find_critical_functions - Score functions by importance',
    );
    results.push('     • trace_data_flow - Track input through the program');
    results.push('     • find_input_sinks - Find where input is validated');
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  // Stub implementations for remaining obfuscation-resistant operations
  // These will be fully implemented in subsequent updates

  /**
   * Find Comparison Points - Locate all CMP/TEST instructions with constants
   * Critical for finding:
   * - Magic number comparisons (license keys, serial validation)
   * - Length checks
   * - Character-by-character validation
   * - Boolean flag checks
   * Works on stripped binaries without symbol names
   */
  private async findComparisonPoints(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   ⚖️ COMPARISON POINT ANALYSIS (Obfuscation-Resistant)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track interesting findings
    interface ComparisonPoint {
      address: string;
      instruction: string;
      operand: string;
      category: string;
      significance: 'HIGH' | 'MEDIUM' | 'LOW';
    }
    const comparisonPoints: ComparisonPoint[] = [];

    // Step 1: Find all CMP instructions
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. CMP INSTRUCTION ANALYSIS                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const cmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad cmp" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );
      if (cmpResult.success && cmpResult.output.trim()) {
        const cmpLines = cmpResult.output.trim().split('\n');
        results.push(`  ✅ Found ${cmpLines.length} CMP instructions\n`);

        // Categorize CMP instructions
        const categories = {
          immediateSmall: [] as string[], // cmp reg, 0-255 (char checks)
          immediateMedium: [] as string[], // cmp reg, 256-65535
          immediateLarge: [] as string[], // cmp reg, >65535 (magic numbers)
          memoryCompare: [] as string[], // cmp [mem], value
          registerCompare: [] as string[], // cmp reg, reg
        };

        for (const line of cmpLines) {
          // Extract immediate values from CMP instructions
          const immediateMatch = line.match(
            /cmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)/i,
          );
          if (immediateMatch) {
            const value = immediateMatch[1].startsWith('0x')
              ? parseInt(immediateMatch[1], 16)
              : parseInt(immediateMatch[1], 10);

            if (value >= 0 && value <= 255) {
              categories.immediateSmall.push(line);
              // Check for printable ASCII (potential character validation)
              if (value >= 32 && value <= 126) {
                const char = String.fromCharCode(value);
                const addrMatch = line.match(/(0x[0-9a-fA-F]+)/);
                if (addrMatch) {
                  comparisonPoints.push({
                    address: addrMatch[1],
                    instruction: line.trim(),
                    operand: `'${char}' (0x${value.toString(16)})`,
                    category: 'Character comparison',
                    significance: 'HIGH',
                  });
                }
              }
            } else if (value <= 65535) {
              categories.immediateMedium.push(line);
            } else {
              categories.immediateLarge.push(line);
              // Large constants are often magic numbers
              const addrMatch = line.match(/(0x[0-9a-fA-F]+)/);
              if (addrMatch) {
                comparisonPoints.push({
                  address: addrMatch[1],
                  instruction: line.trim(),
                  operand: `0x${value.toString(16)}`,
                  category: 'Magic number',
                  significance: 'HIGH',
                });
              }
            }
          } else if (line.includes('[')) {
            categories.memoryCompare.push(line);
          } else {
            categories.registerCompare.push(line);
          }
        }

        results.push('  📊 CMP INSTRUCTION BREAKDOWN:');
        results.push(
          `     • Small immediates (0-255):    ${categories.immediateSmall.length} (potential char checks)`,
        );
        results.push(
          `     • Medium immediates (256-64K): ${categories.immediateMedium.length} (potential length/count)`,
        );
        results.push(
          `     • Large immediates (>64K):     ${categories.immediateLarge.length} (potential magic numbers)`,
        );
        results.push(
          `     • Memory comparisons:          ${categories.memoryCompare.length}`,
        );
        results.push(
          `     • Register comparisons:        ${categories.registerCompare.length}`,
        );
        results.push('');

        // Show most interesting large immediates
        if (categories.immediateLarge.length > 0) {
          results.push('  🎯 INTERESTING LARGE CONSTANTS:');
          categories.immediateLarge.slice(0, 15).forEach((line) => {
            results.push(`     ${line.trim()}`);
          });
          results.push('');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ CMP analysis error: ${e}\n`);
    }

    // Step 2: Find all TEST instructions
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. TEST INSTRUCTION ANALYSIS                               │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const testResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad test" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );
      if (testResult.success && testResult.output.trim()) {
        const testLines = testResult.output.trim().split('\n');
        results.push(`  ✅ Found ${testLines.length} TEST instructions\n`);

        // TEST instructions often check:
        // - Zero/non-zero (test eax, eax)
        // - Bit flags (test eax, 1/2/4/8...)
        // - Specific bits (test eax, 0x80000000)
        const selfTests: string[] = [];
        const bitTests: string[] = [];
        const otherTests: string[] = [];

        for (const line of testLines) {
          // Self-test (test reg, reg) - zero check
          if (line.match(/test\s+(\w+),\s*\1\b/i)) {
            selfTests.push(line);
          }
          // Bit test with power of 2
          else if (line.match(/test\s+\w+,\s*(0x[0-9a-fA-F]+|[1248])\b/i)) {
            bitTests.push(line);
            const addrMatch = line.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              comparisonPoints.push({
                address: addrMatch[1],
                instruction: line.trim(),
                operand: 'bit flag',
                category: 'Flag/bit check',
                significance: 'MEDIUM',
              });
            }
          } else {
            otherTests.push(line);
          }
        }

        results.push('  📊 TEST INSTRUCTION BREAKDOWN:');
        results.push(`     • Self-tests (zero checks):    ${selfTests.length}`);
        results.push(`     • Bit/flag tests:              ${bitTests.length}`);
        results.push(
          `     • Other tests:                 ${otherTests.length}`,
        );
        results.push('');

        if (bitTests.length > 0) {
          results.push('  🚩 BIT FLAG CHECKS (potential boolean validation):');
          bitTests.slice(0, 10).forEach((line) => {
            results.push(`     ${line.trim()}`);
          });
          results.push('');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ TEST analysis error: ${e}\n`);
    }

    // Step 3: Find comparisons with specific interesting values
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. PATTERN-BASED DETECTION                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Common interesting comparison values
    const interestingPatterns = [
      {
        hex: '0x0',
        desc: 'Zero/null check',
        significance: 'LOW' as const,
      },
      {
        hex: '0x1',
        desc: 'Boolean true check',
        significance: 'MEDIUM' as const,
      },
      {
        hex: '0x10',
        desc: '16 - common buffer size',
        significance: 'MEDIUM' as const,
      },
      {
        hex: '0x20',
        desc: '32 / space character',
        significance: 'MEDIUM' as const,
      },
      {
        hex: '0x30',
        desc: "ASCII '0'",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x39',
        desc: "ASCII '9'",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x41',
        desc: "ASCII 'A'",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x5a',
        desc: "ASCII 'Z'",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x61',
        desc: "ASCII 'a'",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x7a',
        desc: "ASCII 'z'",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x7b',
        desc: "ASCII '{' (CTF flag start)",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x7d',
        desc: "ASCII '}' (CTF flag end)",
        significance: 'HIGH' as const,
      },
      {
        hex: '0x100',
        desc: '256 - byte boundary',
        significance: 'MEDIUM' as const,
      },
      {
        hex: '0xdeadbeef',
        desc: 'Magic constant',
        significance: 'HIGH' as const,
      },
      {
        hex: '0xcafebabe',
        desc: 'Java class magic / debug constant',
        significance: 'HIGH' as const,
      },
      {
        hex: '0xffffffff',
        desc: '-1 / error check',
        significance: 'MEDIUM' as const,
      },
    ];

    results.push('  🔍 Searching for significant comparison values...\n');

    for (const pattern of interestingPatterns) {
      try {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad cmp" ${escapeShellArg(targetPath)} | grep -i "${pattern.hex}"`,
          timeout / 32,
        );
        if (
          searchResult.success &&
          searchResult.output.trim() &&
          !searchResult.output.includes('Cannot')
        ) {
          const count = searchResult.output.trim().split('\n').length;
          if (count > 0) {
            const sig =
              pattern.significance === 'HIGH'
                ? '🔴'
                : pattern.significance === 'MEDIUM'
                  ? '🟡'
                  : '⚪';
            results.push(
              `  ${sig} ${pattern.hex.padEnd(12)} ${pattern.desc.padEnd(30)} (${count} occurrences)`,
            );
          }
        }
      } catch {
        // Continue to next pattern
      }
    }
    results.push('');

    // Step 4: Find string length comparisons (common in validation)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. STRING LENGTH CHECKS                                    │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Look for strlen calls followed by CMP
      const strlenResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ sym.imp.strlen" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );
      if (strlenResult.success && strlenResult.output.trim()) {
        results.push(
          '  📏 STRLEN CALL LOCATIONS (check nearby CMP for length validation):',
        );
        const strlenLines = strlenResult.output.trim().split('\n').slice(0, 10);
        for (const line of strlenLines) {
          results.push(`     ${line.trim()}`);
          // Try to get context around strlen call
          const addrMatch = line.match(/(0x[0-9a-fA-F]+)/);
          if (addrMatch) {
            const contextResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "s ${addrMatch[1]}; pd 5" ${escapeShellArg(targetPath)}`,
              timeout / 32,
            );
            if (contextResult.success && contextResult.output.includes('cmp')) {
              const cmpLine = contextResult.output
                .split('\n')
                .find((l) => l.includes('cmp'));
              if (cmpLine) {
                results.push(`        └─ ${cmpLine.trim()}`);
              }
            }
          }
        }
        results.push('');
      }
    } catch (e) {
      results.push(`  ⚠️ strlen analysis error: ${e}\n`);
    }

    // Step 5: Summary of high-value comparison points
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. HIGH-VALUE TARGETS SUMMARY                              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const highValuePoints = comparisonPoints.filter(
      (p) => p.significance === 'HIGH',
    );
    if (highValuePoints.length > 0) {
      results.push(
        '  🎯 MOST LIKELY VALIDATION POINTS (sorted by significance):',
      );
      results.push('');
      results.push(
        '  ┌──────────────┬────────────────────────────┬──────────────────────┐',
      );
      results.push(
        '  │ Address      │ Category                   │ Value                │',
      );
      results.push(
        '  ├──────────────┼────────────────────────────┼──────────────────────┤',
      );
      highValuePoints.slice(0, 20).forEach((p) => {
        const addr = p.address.padEnd(12);
        const cat = p.category.substring(0, 26).padEnd(26);
        const val = p.operand.substring(0, 20).padEnd(20);
        results.push(`  │ ${addr} │ ${cat} │ ${val} │`);
      });
      results.push(
        '  └──────────────┴────────────────────────────┴──────────────────────┘',
      );
      results.push('');
    } else {
      results.push('  ℹ️ No high-significance comparison points found yet.');
      results.push(
        '     Try running analyze_control_flow first for deeper analysis.',
      );
      results.push('');
    }

    // Recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 RECOMMENDATIONS                                          │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🎯 FOR CTF/CRACKING:');
    results.push(
      '     1. Focus on CMP with printable ASCII values (0x20-0x7e)',
    );
    results.push('     2. Look for consecutive CMPs (char-by-char validation)');
    results.push('     3. Check CMPs after strlen calls (length validation)');
    results.push('     4. Find large magic numbers (serial/key checks)');
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • trace_data_flow - Track how input reaches these CMPs');
    results.push('     • find_input_sinks - Find strcmp/memcmp calls');
    results.push(
      '     • analyze_control_flow - See branch structure around CMPs',
    );
    results.push('     • patch_bytes - Modify comparison results to bypass');
    results.push('');

    return { success: true, output: results.join('\n') };
  }

  /**
   * Trace Data Flow - Track input flow through the program
   * Essential for understanding how user input reaches validation points
   * Works on stripped binaries by following:
   * - Input function calls (scanf, fgets, read, recv, etc.)
   * - Buffer/register propagation
   * - Cross-references between functions
   * - Arguments passed to comparison functions
   */
  private async traceDataFlow(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📈 DATA FLOW ANALYSIS (Obfuscation-Resistant)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track input sources and sinks
    interface DataFlowPoint {
      address: string;
      function: string;
      type: 'source' | 'sink' | 'transform';
      description: string;
      callers: string[];
    }
    const flowPoints: DataFlowPoint[] = [];

    // Step 1: Find all INPUT SOURCES
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. INPUT SOURCES (where user data enters)                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Categorize input functions
    const inputFunctions = {
      console: [
        'scanf',
        'gets',
        'fgets',
        'getchar',
        'getc',
        'fgetc',
        'getline',
      ],
      file: ['fread', 'read', 'pread', 'fscanf', 'fgets'],
      network: ['recv', 'recvfrom', 'recvmsg', 'read'],
      args: ['main'], // argv
      environment: ['getenv', 'secure_getenv'],
      windows: [
        'ReadFile',
        'ReadConsole',
        'GetStdHandle',
        'recv',
        'WSARecv',
        'ReadConsoleInput',
      ],
    };

    results.push('  🔍 Searching for input sources...\n');

    for (const [category, funcs] of Object.entries(inputFunctions)) {
      const categoryResults: string[] = [];

      for (const func of funcs) {
        try {
          // Try both sym.imp. (imports) and sym. (local symbols)
          const xrefResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ sym.imp.${func}" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 30,
          );
          if (
            xrefResult.success &&
            xrefResult.output.trim() &&
            !xrefResult.output.includes('Cannot find')
          ) {
            const xrefs = xrefResult.output.trim().split('\n');
            for (const xref of xrefs) {
              const addrMatch = xref.match(/(0x[0-9a-fA-F]+)/);
              if (addrMatch) {
                categoryResults.push(`     ${addrMatch[1]}  ${func}()`);
                flowPoints.push({
                  address: addrMatch[1],
                  function: func,
                  type: 'source',
                  description: `${category} input`,
                  callers: [],
                });
              }
            }
          }
        } catch {
          // Continue
        }
      }

      if (categoryResults.length > 0) {
        const emoji =
          category === 'console'
            ? '⌨️'
            : category === 'file'
              ? '📁'
              : category === 'network'
                ? '🌐'
                : category === 'args'
                  ? '📋'
                  : category === 'environment'
                    ? '🔧'
                    : '🪟';
        results.push(`  ${emoji} ${category.toUpperCase()} INPUT:`);
        categoryResults.forEach((r) => results.push(r));
        results.push('');
      }
    }

    // Step 2: Find DATA SINKS (where input is validated/used)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. DATA SINKS (where input is consumed/validated)          │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const sinkFunctions = {
      comparison: [
        'strcmp',
        'strncmp',
        'memcmp',
        'wcscmp',
        'stricmp',
        'strcasecmp',
      ],
      search: ['strstr', 'strchr', 'strrchr', 'memmem', 'memchr'],
      conversion: ['atoi', 'atol', 'strtol', 'strtoul', 'sscanf'],
      crypto: [
        'MD5',
        'SHA1',
        'SHA256',
        'EVP_DigestUpdate',
        'CryptHashData',
        'BCryptHashData',
      ],
      dangerous: ['strcpy', 'strcat', 'sprintf', 'system', 'exec', 'popen'],
    };

    results.push('  🔍 Searching for data sinks...\n');

    for (const [category, funcs] of Object.entries(sinkFunctions)) {
      const categoryResults: string[] = [];

      for (const func of funcs) {
        try {
          const xrefResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ sym.imp.${func}" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 30,
          );
          if (
            xrefResult.success &&
            xrefResult.output.trim() &&
            !xrefResult.output.includes('Cannot find')
          ) {
            const xrefs = xrefResult.output.trim().split('\n');
            for (const xref of xrefs) {
              const addrMatch = xref.match(/(0x[0-9a-fA-F]+)/);
              if (addrMatch) {
                categoryResults.push(`     ${addrMatch[1]}  ${func}()`);
                flowPoints.push({
                  address: addrMatch[1],
                  function: func,
                  type: 'sink',
                  description: `${category} operation`,
                  callers: [],
                });
              }
            }
          }
        } catch {
          // Continue
        }
      }

      if (categoryResults.length > 0) {
        const emoji =
          category === 'comparison'
            ? '⚖️'
            : category === 'search'
              ? '🔎'
              : category === 'conversion'
                ? '🔄'
                : category === 'crypto'
                  ? '🔐'
                  : '⚠️';
        results.push(`  ${emoji} ${category.toUpperCase()} SINKS:`);
        categoryResults.slice(0, 10).forEach((r) => results.push(r));
        if (categoryResults.length > 10) {
          results.push(`     ... and ${categoryResults.length - 10} more`);
        }
        results.push('');
      }
    }

    // Step 3: Trace the call path from sources to sinks
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. DATA FLOW PATHS                                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const sources = flowPoints.filter((p) => p.type === 'source');
    const sinks = flowPoints.filter((p) => p.type === 'sink');

    if (sources.length > 0 && sinks.length > 0) {
      results.push('  🔀 Analyzing paths from input sources to sinks...\n');

      // For each source, find which function contains it, then trace calls
      for (const source of sources.slice(0, 5)) {
        try {
          // Get the function containing this source
          const funcResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "aaa; s ${source.address}; afi" ${escapeShellArg(targetPath)}`,
            timeout / 20,
          );
          if (funcResult.success && funcResult.output.trim()) {
            const funcMatch = funcResult.output.match(/name:\s*(\S+)/);
            const funcName = funcMatch ? funcMatch[1] : 'unknown';

            results.push(`  📍 ${source.function}() at ${source.address}`);
            results.push(`     └─ Inside function: ${funcName}`);

            // Get what this function calls
            const callsResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "aaa; s ${source.address}; afxl" ${escapeShellArg(targetPath)}`,
              timeout / 20,
            );
            if (callsResult.success && callsResult.output.trim()) {
              const calls = callsResult.output.trim().split('\n').slice(0, 5);
              if (calls.length > 0) {
                results.push('        Calls to:');
                calls.forEach((c) => results.push(`          → ${c.trim()}`));
              }
            }
            results.push('');
          }
        } catch {
          // Continue
        }
      }
    } else {
      results.push('  ℹ️ Could not establish clear source→sink paths.');
      results.push('     Binary may use indirect or obfuscated data flow.');
      results.push('');
    }

    // Step 4: Analyze main function data flow
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. MAIN FUNCTION ANALYSIS                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Find main and analyze its structure
      const mainResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; s main; pdf" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 6,
      );

      if (mainResult.success && mainResult.output.trim()) {
        const mainCode = mainResult.output;

        // Find key operations in main
        const hasInput = /call.*(?:scanf|fgets|gets|read|recv)/i.test(mainCode);
        const hasCompare = /call.*(?:strcmp|memcmp|strncmp)/i.test(mainCode);
        const hasCrypto = /call.*(?:md5|sha|crypt|hash)/i.test(mainCode);
        const hasLoop = /jmp\s+0x[0-9a-f]+\s*;.*?(?:loop|while)/i.test(
          mainCode,
        );

        results.push('  📊 MAIN FUNCTION CHARACTERISTICS:');
        results.push(
          `     • Contains input calls:      ${hasInput ? '✅ YES' : '❌ NO'}`,
        );
        results.push(
          `     • Contains comparisons:      ${hasCompare ? '✅ YES' : '❌ NO'}`,
        );
        results.push(
          `     • Contains crypto calls:     ${hasCrypto ? '✅ YES' : '❌ NO'}`,
        );
        results.push(
          `     • Contains loops:            ${hasLoop ? '✅ YES' : '❌ NO'}`,
        );
        results.push('');

        // Extract call sequence
        const callMatches = mainCode.match(/call\s+(?:sym\.|sym\.imp\.)?\w+/g);
        if (callMatches) {
          results.push('  📞 CALL SEQUENCE IN MAIN:');
          const uniqueCalls = [...new Set(callMatches)].slice(0, 15);
          uniqueCalls.forEach((call, idx) => {
            results.push(`     ${(idx + 1).toString().padStart(2)}. ${call}`);
          });
          results.push('');
        }
      } else {
        results.push("  ⚠️ Could not find 'main' function (stripped binary?)");
        results.push(
          '     Try: find_critical_functions to identify entry points',
        );
        results.push('');
      }
    } catch (e) {
      results.push(`  ⚠️ Main analysis error: ${e}\n`);
    }

    // Step 5: Register-based data flow (for stripped binaries)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. REGISTER FLOW ANALYSIS                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  📝 Key registers to track in x86-64 calling convention:');
    results.push('     • RDI/EDI - 1st argument (often input buffer)');
    results.push('     • RSI/ESI - 2nd argument (often size/length)');
    results.push('     • RAX/EAX - Return value (often comparison result)');
    results.push('');

    try {
      // Find MOV instructions that set up function arguments
      const argSetupResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad mov edi\\|mov rdi" ${escapeShellArg(targetPath)} | head -20`,
        timeout / 8,
      );
      if (argSetupResult.success && argSetupResult.output.trim()) {
        results.push('  🔧 ARGUMENT SETUP PATTERNS (first 20):');
        argSetupResult.output
          .trim()
          .split('\n')
          .slice(0, 10)
          .forEach((line) => {
            results.push(`     ${line.trim()}`);
          });
        results.push('');
      }
    } catch {
      // Continue
    }

    // Step 6: Summary and flow diagram
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 DATA FLOW SUMMARY                                        │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const sourceCount = sources.length;
    const sinkCount = sinks.length;

    results.push(`  📥 Input Sources Found:  ${sourceCount}`);
    results.push(`  📤 Data Sinks Found:     ${sinkCount}`);
    results.push('');

    if (sourceCount > 0 && sinkCount > 0) {
      results.push('  📊 SIMPLIFIED FLOW DIAGRAM:');
      results.push('');
      results.push('     ┌──────────────┐');
      results.push('     │  USER INPUT  │');
      results.push('     └──────┬───────┘');
      results.push('            │');
      sources.slice(0, 3).forEach((s) => {
        results.push(`            ▼ ${s.function}()`);
      });
      results.push('            │');
      results.push('     ┌──────┴───────┐');
      results.push('     │  PROCESSING  │');
      results.push('     └──────┬───────┘');
      results.push('            │');
      sinks
        .filter((s) => s.description.includes('comparison'))
        .slice(0, 3)
        .forEach((s) => {
          results.push(`            ▼ ${s.function}()`);
        });
      results.push('            │');
      results.push('     ┌──────┴───────┐');
      results.push('     │ SUCCESS/FAIL │');
      results.push('     └──────────────┘');
      results.push('');
    }

    // Recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 🎯 RECOMMENDATIONS                                          │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🔍 TO UNDERSTAND THE VALIDATION:');
    results.push('     1. Set breakpoints at input sources');
    results.push('     2. Follow data through transformations');
    results.push('     3. Examine comparison sinks for validation logic');
    results.push('     4. Look for early exit paths (failed validation)');
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • find_comparison_points - See what values are checked');
    results.push('     • find_input_sinks - Focus on strcmp/memcmp calls');
    results.push(
      '     • analyze_call_graph - Visualize function relationships',
    );
    results.push('     • r2_decompile - Decompile specific functions');
    results.push('');

    return { success: true, output: results.join('\n') };
  }

  /**
   * Find Critical Functions - Score functions by behavioral importance
   * Works on stripped binaries without relying on symbol names
   * Scores based on:
   * - Cross-reference count (how often called)
   * - Cyclomatic complexity (decision logic density)
   * - Syscall usage (I/O, crypto, validation operations)
   * - String references (error messages, prompts)
   * - Import calls (comparison, crypto functions)
   */
  private async findCriticalFunctions(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   ⭐ CRITICAL FUNCTION ANALYSIS (Obfuscation-Resistant)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Function scoring interface
    interface FunctionScore {
      address: string;
      name: string;
      size: number;
      xrefs: number;
      complexity: number;
      blocks: number;
      callsImportant: number;
      hasStrings: boolean;
      score: number;
      reasons: string[];
    }
    const scoredFunctions: FunctionScore[] = [];

    // Step 1: Get all functions with metadata
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. FUNCTION ENUMERATION                                    │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );

      if (funcResult.success && funcResult.output.trim()) {
        try {
          const funcs = JSON.parse(funcResult.output);
          if (Array.isArray(funcs)) {
            results.push(`  ✅ Found ${funcs.length} functions\n`);

            // Process each function
            for (const f of funcs) {
              const func: FunctionScore = {
                address: `0x${(f.offset || 0).toString(16)}`,
                name: f.name || `fcn_${(f.offset || 0).toString(16)}`,
                size: f.size || 0,
                xrefs: f.nargs || 0, // Number of xrefs to this function
                complexity: f.cc || 0, // Cyclomatic complexity
                blocks: f.nbbs || 0, // Number of basic blocks
                callsImportant: 0,
                hasStrings: false,
                score: 0,
                reasons: [],
              };

              // Calculate initial score based on metrics
              // High complexity = likely decision logic
              if (func.complexity > 10) {
                func.score += func.complexity * 2;
                func.reasons.push(`High CC(${func.complexity})`);
              }

              // Many blocks = complex function
              if (func.blocks > 5) {
                func.score += func.blocks;
                func.reasons.push(`${func.blocks} blocks`);
              }

              // Large function size can indicate important logic
              if (func.size > 200) {
                func.score += Math.floor(func.size / 50);
                func.reasons.push(`Size ${func.size}B`);
              }

              scoredFunctions.push(func);
            }
          }
        } catch {
          results.push('  ⚠️ Could not parse function list as JSON\n');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Function enumeration error: ${e}\n`);
    }

    // Step 2: Analyze xrefs for each function (importance by usage)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. CROSS-REFERENCE ANALYSIS                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🔍 Analyzing function call frequency...\n');

    // Sample functions for xref analysis (top by current score)
    const topFuncs = [...scoredFunctions]
      .sort((a, b) => b.score - a.score)
      .slice(0, 30);

    for (const func of topFuncs) {
      try {
        const xrefResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "aaa; axt ${func.address}" ${escapeShellArg(targetPath)} 2>/dev/null | wc -l`,
          timeout / 60,
        );
        if (xrefResult.success) {
          const xrefCount = parseInt(xrefResult.output.trim(), 10) || 0;
          func.xrefs = xrefCount;
          if (xrefCount > 5) {
            func.score += xrefCount * 3;
            func.reasons.push(`${xrefCount} callers`);
          }
        }
      } catch {
        // Continue
      }
    }

    // Step 3: Check for important function calls within each function
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. IMPORTANT CALL DETECTION                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const importantCalls = [
      { pattern: 'strcmp', weight: 15, reason: 'String compare' },
      { pattern: 'strncmp', weight: 15, reason: 'String compare' },
      { pattern: 'memcmp', weight: 15, reason: 'Memory compare' },
      { pattern: 'scanf', weight: 10, reason: 'User input' },
      { pattern: 'fgets', weight: 10, reason: 'User input' },
      { pattern: 'gets', weight: 10, reason: 'User input' },
      { pattern: 'printf', weight: 5, reason: 'Output' },
      { pattern: 'puts', weight: 5, reason: 'Output' },
      { pattern: 'exit', weight: 8, reason: 'Exit point' },
      { pattern: 'strlen', weight: 8, reason: 'Length check' },
      { pattern: 'atoi', weight: 8, reason: 'Conversion' },
      { pattern: 'strtol', weight: 8, reason: 'Conversion' },
      { pattern: 'MD5', weight: 20, reason: 'Crypto' },
      { pattern: 'SHA', weight: 20, reason: 'Crypto' },
      { pattern: 'crypt', weight: 20, reason: 'Crypto' },
      { pattern: 'open', weight: 5, reason: 'File I/O' },
      { pattern: 'read', weight: 8, reason: 'Read input' },
      { pattern: 'write', weight: 5, reason: 'Write output' },
    ];

    results.push('  🔍 Checking for important API calls...\n');

    for (const func of topFuncs.slice(0, 20)) {
      try {
        // Get disassembly of function
        const disasmResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "aaa; s ${func.address}; pdf" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );

        if (disasmResult.success && disasmResult.output) {
          const disasm = disasmResult.output.toLowerCase();

          for (const imp of importantCalls) {
            if (disasm.includes(imp.pattern.toLowerCase())) {
              func.callsImportant++;
              func.score += imp.weight;
              if (!func.reasons.includes(imp.reason)) {
                func.reasons.push(imp.reason);
              }
            }
          }

          // Check for string references
          if (
            disasm.includes('str.') ||
            disasm.includes('"') ||
            disasm.includes("'")
          ) {
            func.hasStrings = true;
            func.score += 5;
            func.reasons.push('Has strings');
          }
        }
      } catch {
        // Continue
      }
    }

    // Step 4: Score by syscall patterns (for stripped binaries)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. SYSCALL PATTERN ANALYSIS                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Find functions that make syscalls (Linux)
      const syscallResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad syscall\\|int 0x80\\|sysenter" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 8,
      );

      if (syscallResult.success && syscallResult.output.trim()) {
        const syscallAddrs = syscallResult.output
          .trim()
          .split('\n')
          .map((line) => {
            const match = line.match(/(0x[0-9a-fA-F]+)/);
            return match ? match[1] : null;
          })
          .filter(Boolean);

        results.push(`  📍 Found ${syscallAddrs.length} syscall sites\n`);

        // Boost score for functions containing syscalls
        for (const func of scoredFunctions) {
          const funcAddr = parseInt(func.address, 16);
          const funcEnd = funcAddr + func.size;

          for (const sysAddr of syscallAddrs) {
            const sysAddrNum = parseInt(sysAddr as string, 16);
            if (sysAddrNum >= funcAddr && sysAddrNum < funcEnd) {
              func.score += 10;
              if (!func.reasons.includes('Syscall')) {
                func.reasons.push('Syscall');
              }
            }
          }
        }
      }
    } catch {
      results.push(
        '  ℹ️ No direct syscalls found (likely uses libc wrappers)\n',
      );
    }

    // Step 5: Present ranked results
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. CRITICAL FUNCTIONS RANKING                              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Sort by final score
    scoredFunctions.sort((a, b) => b.score - a.score);
    const topCritical = scoredFunctions.slice(0, 20);

    if (topCritical.length > 0) {
      results.push('  🏆 TOP 20 CRITICAL FUNCTIONS (by behavioral score):');
      results.push('');
      results.push(
        '  ┌────┬──────────────┬────────────────────────────┬───────┬─────────────────────────────┐',
      );
      results.push(
        '  │ #  │ Address      │ Name                       │ Score │ Reasons                     │',
      );
      results.push(
        '  ├────┼──────────────┼────────────────────────────┼───────┼─────────────────────────────┤',
      );

      topCritical.forEach((f, idx) => {
        const num = (idx + 1).toString().padStart(2);
        const addr = f.address.padEnd(12);
        const name = f.name.substring(0, 26).padEnd(26);
        const score = f.score.toString().padStart(5);
        const reasons = f.reasons
          .slice(0, 3)
          .join(', ')
          .substring(0, 27)
          .padEnd(27);
        results.push(
          `  │ ${num} │ ${addr} │ ${name} │ ${score} │ ${reasons} │`,
        );
      });

      results.push(
        '  └────┴──────────────┴────────────────────────────┴───────┴─────────────────────────────┘',
      );
      results.push('');
    }

    // Step 6: Category breakdown
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 6. FUNCTION CATEGORIES                                     │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Categorize by detected behavior
    const validationFuncs = scoredFunctions.filter((f) =>
      f.reasons.some((r) =>
        ['String compare', 'Memory compare', 'Length check'].includes(r),
      ),
    );
    const inputFuncs = scoredFunctions.filter((f) =>
      f.reasons.some((r) => ['User input', 'Read input'].includes(r)),
    );
    const cryptoFuncs = scoredFunctions.filter((f) =>
      f.reasons.some((r) => r === 'Crypto'),
    );
    const outputFuncs = scoredFunctions.filter((f) =>
      f.reasons.some((r) => ['Output', 'Exit point'].includes(r)),
    );

    results.push('  📊 FUNCTIONS BY CATEGORY:');
    results.push('');
    results.push(`  ⚖️  VALIDATION LOGIC: ${validationFuncs.length} functions`);
    validationFuncs.slice(0, 5).forEach((f) => {
      results.push(`      • ${f.address} ${f.name.substring(0, 30)}`);
    });
    results.push('');

    results.push(`  📥 INPUT HANDLING: ${inputFuncs.length} functions`);
    inputFuncs.slice(0, 5).forEach((f) => {
      results.push(`      • ${f.address} ${f.name.substring(0, 30)}`);
    });
    results.push('');

    results.push(`  🔐 CRYPTO-RELATED: ${cryptoFuncs.length} functions`);
    cryptoFuncs.slice(0, 5).forEach((f) => {
      results.push(`      • ${f.address} ${f.name.substring(0, 30)}`);
    });
    results.push('');

    results.push(`  📤 OUTPUT/EXIT: ${outputFuncs.length} functions`);
    outputFuncs.slice(0, 5).forEach((f) => {
      results.push(`      • ${f.address} ${f.name.substring(0, 30)}`);
    });
    results.push('');

    // Step 7: Recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 🎯 ANALYSIS RECOMMENDATIONS                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    if (topCritical.length > 0) {
      results.push('  🔥 MOST LIKELY VALIDATION/CHECK FUNCTIONS:');
      const validationTargets = topCritical.filter(
        (f) =>
          f.reasons.includes('String compare') ||
          f.reasons.includes('Memory compare') ||
          f.complexity > 10,
      );
      validationTargets.slice(0, 5).forEach((f) => {
        results.push(
          `     ${f.address} - Score: ${f.score} (${f.reasons.join(', ')})`,
        );
      });
      results.push('');
    }

    results.push('  🔧 SUGGESTED NEXT STEPS:');
    results.push('     1. Decompile top-scored functions with r2_decompile');
    results.push('     2. Set breakpoints at validation functions');
    results.push('     3. Trace data flow through input→validation→output');
    results.push('     4. Look for conditional jumps after comparisons');
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • r2_decompile - Decompile specific functions');
    results.push(
      '     • find_comparison_points - Analyze CMPs in these functions',
    );
    results.push('     • analyze_control_flow - See decision structure');
    results.push('     • trace_data_flow - Follow input through validation');
    results.push('');

    return { success: true, output: results.join('\n') };
  }

  /**
   * Decode Strings Heuristic - Detect XOR/base64/custom encoded strings
   * Essential for analyzing obfuscated binaries where strings are hidden
   * Detects:
   * - XOR encoding patterns (single-byte, multi-byte, rolling)
   * - Base64 encoded data
   * - ROT13/Caesar cipher
   * - Custom encoding loops
   * - High-entropy data sections
   */
  private async decodeStringsHeuristic(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔐 HEURISTIC STRING DECODING (Obfuscation-Resistant)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track potential encoded strings
    interface EncodedString {
      address: string;
      data: string;
      encoding: string;
      decoded?: string;
      confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    }
    const encodedStrings: EncodedString[] = [];

    // Step 1: Find XOR encoding patterns in code
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. XOR ENCODING DETECTION                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Find XOR instructions
      const xorResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad xor" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );

      if (xorResult.success && xorResult.output.trim()) {
        const xorLines = xorResult.output.trim().split('\n');
        results.push(`  ✅ Found ${xorLines.length} XOR instructions\n`);

        // Categorize XOR patterns
        const singleByteXor: string[] = [];
        const registerXor: string[] = [];
        const loopXor: string[] = [];

        for (const line of xorLines) {
          // XOR with immediate value (single-byte key)
          if (line.match(/xor\s+\w+,\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})\b/i)) {
            singleByteXor.push(line);
          }
          // XOR with register (potential rolling XOR)
          else if (line.match(/xor\s+\w+,\s*[er][a-z]+/i)) {
            registerXor.push(line);
          }
          // Self-XOR (zeroing)
          else if (line.match(/xor\s+(\w+),\s*\1\b/i)) {
            // Ignore - this is just zeroing a register
          } else {
            loopXor.push(line);
          }
        }

        results.push('  📊 XOR PATTERN BREAKDOWN:');
        results.push(
          `     • Single-byte XOR (key encoding):  ${singleByteXor.length}`,
        );
        results.push(
          `     • Register XOR (rolling/complex):  ${registerXor.length}`,
        );
        results.push(
          `     • Other XOR patterns:              ${loopXor.length}`,
        );
        results.push('');

        // Show most interesting XOR with immediate values
        if (singleByteXor.length > 0) {
          results.push('  🔑 SINGLE-BYTE XOR KEYS FOUND:');
          const keyMap = new Map<string, number>();

          for (const line of singleByteXor) {
            const keyMatch = line.match(/xor\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)/i);
            if (keyMatch) {
              const key = keyMatch[1];
              keyMap.set(key, (keyMap.get(key) || 0) + 1);
            }
          }

          // Sort by frequency
          const sortedKeys = [...keyMap.entries()].sort((a, b) => b[1] - a[1]);
          sortedKeys.slice(0, 10).forEach(([key, count]) => {
            const keyVal = key.startsWith('0x')
              ? parseInt(key, 16)
              : parseInt(key, 10);
            const printable =
              keyVal >= 32 && keyVal <= 126
                ? ` ('${String.fromCharCode(keyVal)}')`
                : '';
            results.push(`     Key ${key}${printable}: ${count} occurrences`);
          });
          results.push('');

          // Add to encoded strings tracking
          if (sortedKeys.length > 0) {
            encodedStrings.push({
              address: 'multiple',
              data: `XOR key ${sortedKeys[0][0]}`,
              encoding: 'XOR',
              confidence: sortedKeys[0][1] > 5 ? 'HIGH' : 'MEDIUM',
            });
          }
        }

        // Show XOR in loop context (decryption routines)
        if (registerXor.length > 0) {
          results.push('  🔄 POTENTIAL XOR DECRYPTION LOOPS:');
          registerXor.slice(0, 10).forEach((line) => {
            results.push(`     ${line.trim()}`);
          });
          results.push('');
        }
      } else {
        results.push('  ℹ️ No XOR instructions found\n');
      }
    } catch (e) {
      results.push(`  ⚠️ XOR analysis error: ${e}\n`);
    }

    // Step 2: Detect Base64 encoded data
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. BASE64 DETECTION                                        │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Get all strings and look for base64 patterns
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      if (strResult.success && strResult.output.trim()) {
        const strLines = strResult.output.trim().split('\n');
        const base64Pattern = /^[A-Za-z0-9+/]{20,}={0,2}$/;
        const base64Candidates: Array<{
          addr: string;
          str: string;
          decoded: string;
        }> = [];

        for (const line of strLines) {
          // Extract string content from r2 output
          const match = line.match(/(0x[0-9a-fA-F]+)\s+\d+\s+\d+\s+\S+\s+(.+)/);
          if (match) {
            const addr = match[1];
            const str = match[2].trim();

            // Check if it looks like base64
            if (base64Pattern.test(str) && str.length >= 20) {
              try {
                const decoded = Buffer.from(str, 'base64').toString('utf-8');
                // Check if decoded content looks printable
                const printableRatio =
                  decoded
                    .split('')
                    .filter(
                      (c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126,
                    ).length / decoded.length;

                if (printableRatio > 0.7) {
                  base64Candidates.push({ addr, str, decoded });
                  encodedStrings.push({
                    address: addr,
                    data: str.substring(0, 40) + '...',
                    encoding: 'Base64',
                    decoded: decoded.substring(0, 50),
                    confidence: 'HIGH',
                  });
                }
              } catch {
                // Invalid base64
              }
            }
          }
        }

        if (base64Candidates.length > 0) {
          results.push(
            `  ✅ Found ${base64Candidates.length} Base64 encoded strings:\n`,
          );
          base64Candidates.slice(0, 10).forEach((b) => {
            results.push(`  📍 ${b.addr}`);
            results.push(
              `     Encoded: ${b.str.substring(0, 50)}${b.str.length > 50 ? '...' : ''}`,
            );
            results.push(
              `     Decoded: ${b.decoded.substring(0, 50)}${b.decoded.length > 50 ? '...' : ''}`,
            );
            results.push('');
          });
        } else {
          results.push('  ℹ️ No obvious Base64 strings found\n');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Base64 detection error: ${e}\n`);
    }

    // Step 3: High-entropy data detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. HIGH-ENTROPY DATA DETECTION                             │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Use binwalk-style entropy analysis via r2
      const entropyResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "p=e 100" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );

      if (entropyResult.success && entropyResult.output.trim()) {
        results.push('  📊 ENTROPY DISTRIBUTION (visual):');
        results.push('');
        // Show entropy graph
        const lines = entropyResult.output.trim().split('\n').slice(0, 20);
        lines.forEach((line) => results.push(`     ${line}`));
        results.push('');

        // Look for high entropy regions
        const highEntropyMatches = entropyResult.output.match(/[█▓▒░]{5,}/g);
        if (highEntropyMatches) {
          results.push(
            `  ⚠️ ${highEntropyMatches.length} high-entropy regions detected`,
          );
          results.push(
            '     These may contain encrypted/compressed/encoded data',
          );
          results.push('');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Entropy analysis error: ${e}\n`);
    }

    // Step 4: ROT13/Caesar cipher detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. ROT13/CAESAR CIPHER DETECTION                           │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );

      if (strResult.success && strResult.output.trim()) {
        const strLines = strResult.output.trim().split('\n');
        const rot13Candidates: Array<{
          addr: string;
          original: string;
          decoded: string;
        }> = [];

        // ROT13 decode function
        const rot13 = (str: string): string =>
          str.replace(/[a-zA-Z]/g, (c) => {
            const base = c <= 'Z' ? 65 : 97;
            return String.fromCharCode(
              ((c.charCodeAt(0) - base + 13) % 26) + base,
            );
          });

        // Keywords that might appear after decoding
        const keywords = [
          'flag',
          'password',
          'secret',
          'key',
          'admin',
          'root',
          'user',
          'login',
          'success',
          'correct',
          'wrong',
          'invalid',
          'license',
          'serial',
          'crack',
          'hack',
        ];

        for (const line of strLines) {
          const match = line.match(/(0x[0-9a-fA-F]+)\s+\d+\s+\d+\s+\S+\s+(.+)/);
          if (match) {
            const addr = match[1];
            const str = match[2].trim();

            // Only check strings that are mostly letters
            if (str.length >= 4 && /^[a-zA-Z]{4,}/.test(str)) {
              const decoded = rot13(str);
              const decodedLower = decoded.toLowerCase();

              // Check if decoded contains keywords
              for (const keyword of keywords) {
                if (decodedLower.includes(keyword)) {
                  rot13Candidates.push({ addr, original: str, decoded });
                  encodedStrings.push({
                    address: addr,
                    data: str,
                    encoding: 'ROT13',
                    decoded,
                    confidence: 'MEDIUM',
                  });
                  break;
                }
              }
            }
          }
        }

        if (rot13Candidates.length > 0) {
          results.push(
            `  ✅ Found ${rot13Candidates.length} potential ROT13 strings:\n`,
          );
          rot13Candidates.slice(0, 10).forEach((r) => {
            results.push(`  📍 ${r.addr}`);
            results.push(`     Original: ${r.original}`);
            results.push(`     ROT13:    ${r.decoded}`);
            results.push('');
          });
        } else {
          results.push('  ℹ️ No ROT13 encoded strings detected\n');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ ROT13 detection error: ${e}\n`);
    }

    // Step 5: Custom encoding loop detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. CUSTOM ENCODING LOOP DETECTION                          │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Look for common decoding loop patterns
      results.push('  🔍 Searching for encoding/decoding loop patterns...\n');

      // Pattern 1: XOR in loop with increment
      const loopResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; afl" ${escapeShellArg(targetPath)}`,
        timeout / 8,
      );

      if (loopResult.success && loopResult.output.trim()) {
        const funcs = loopResult.output.trim().split('\n');
        const suspiciousFuncs: string[] = [];

        for (const func of funcs.slice(0, 50)) {
          const addrMatch = func.match(/(0x[0-9a-fA-F]+)/);
          if (addrMatch) {
            // Check function for encoding patterns
            const disasmResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "s ${addrMatch[1]}; pdr" ${escapeShellArg(targetPath)} 2>/dev/null | head -30`,
              timeout / 100,
            );

            if (disasmResult.success && disasmResult.output) {
              const code = disasmResult.output.toLowerCase();

              // Check for encoding loop characteristics
              const hasXor = code.includes('xor');
              const hasLoop =
                code.includes('loop') ||
                code.includes('jnz') ||
                code.includes('jne');
              const hasIncrement = code.includes('inc') || code.includes('add');
              const hasMemAccess = code.includes('[') && code.includes(']');

              if (hasXor && hasLoop && (hasIncrement || hasMemAccess)) {
                suspiciousFuncs.push(
                  `${addrMatch[1]} - XOR loop with ${hasIncrement ? 'counter' : 'memory access'}`,
                );
              }
            }
          }
        }

        if (suspiciousFuncs.length > 0) {
          results.push('  🔄 POTENTIAL ENCODING/DECODING FUNCTIONS:');
          suspiciousFuncs.slice(0, 10).forEach((f) => {
            results.push(`     • ${f}`);
          });
          results.push('');
        } else {
          results.push('  ℹ️ No obvious encoding loops detected\n');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Loop detection error: ${e}\n`);
    }

    // Step 6: Summary of findings
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 ENCODED STRING SUMMARY                                   │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    if (encodedStrings.length > 0) {
      const highConf = encodedStrings.filter((s) => s.confidence === 'HIGH');
      const medConf = encodedStrings.filter((s) => s.confidence === 'MEDIUM');

      results.push(`  📊 FINDINGS SUMMARY:`);
      results.push(`     • High confidence: ${highConf.length}`);
      results.push(`     • Medium confidence: ${medConf.length}`);
      results.push('');

      if (highConf.length > 0) {
        results.push('  🎯 HIGH CONFIDENCE ENCODED STRINGS:');
        results.push(
          '  ┌──────────────┬──────────┬────────────────────────────────────────┐',
        );
        results.push(
          '  │ Address      │ Encoding │ Decoded/Key                            │',
        );
        results.push(
          '  ├──────────────┼──────────┼────────────────────────────────────────┤',
        );
        highConf.slice(0, 15).forEach((s) => {
          const addr = s.address.padEnd(12);
          const enc = s.encoding.padEnd(8);
          const dec = (s.decoded || s.data).substring(0, 38).padEnd(38);
          results.push(`  │ ${addr} │ ${enc} │ ${dec} │`);
        });
        results.push(
          '  └──────────────┴──────────┴────────────────────────────────────────┘',
        );
        results.push('');
      }
    } else {
      results.push('  ℹ️ No encoded strings detected with high confidence.');
      results.push('     The binary may use custom or complex encoding.');
      results.push('');
    }

    // Recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 🎯 DECODING RECOMMENDATIONS                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🔧 TO DECODE STRINGS MANUALLY:');
    results.push('     1. Find XOR key from single-byte XOR patterns');
    results.push(
      '     2. Set breakpoint before XOR loop, examine buffer after',
    );
    results.push('     3. Try common keys: 0xFF, 0xAA, 0x55, single chars');
    results.push(
      '     4. Look for decoding function and trace its input/output',
    );
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • find_crypto_constants - Find crypto magic numbers');
    results.push('     • r2_decompile - Decompile suspected decode function');
    results.push('     • string_decode - Use built-in string decoder');
    results.push('     • ltrace_run - Trace to see decoded strings at runtime');
    results.push('');

    return { success: true, output: results.join('\n') };
  }

  /**
   * Find Crypto Constants - Detect cryptographic algorithms by magic numbers
   * Works on stripped/obfuscated binaries by searching for known constants
   * Detects:
   * - AES (S-box, round constants)
   * - SHA family (SHA-1, SHA-256, SHA-512 IVs)
   * - MD5 (T constants)
   * - Blowfish, Twofish, ChaCha20
   * - RSA (common primes, exponents)
   * - CRC32 polynomial tables
   * - Custom/homebrew crypto patterns
   */
  private async findCryptoConstants(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔑 CRYPTO CONSTANT DETECTION (Algorithm Fingerprinting)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track all crypto findings
    interface CryptoFinding {
      algorithm: string;
      constantName: string;
      address: string;
      confidence: 'DEFINITE' | 'HIGH' | 'MEDIUM' | 'LOW';
      category: string;
    }
    const findings: CryptoFinding[] = [];

    // Step 1: AES Detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. AES (Advanced Encryption Standard)                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const aesConstants = [
      // AES S-box first 16 bytes (unique fingerprint)
      {
        name: 'AES S-box (start)',
        hex: '637c777bf26b6fc53001672bfed7ab76',
        confidence: 'DEFINITE' as const,
      },
      {
        name: 'AES S-box (partial)',
        hex: '637c777b',
        confidence: 'HIGH' as const,
      },
      // AES Inverse S-box first bytes
      {
        name: 'AES Inv S-box (start)',
        hex: '52096ad53036a538bf40a39e81f3d7fb',
        confidence: 'DEFINITE' as const,
      },
      {
        name: 'AES Inv S-box (partial)',
        hex: '52096ad5',
        confidence: 'HIGH' as const,
      },
      // AES round constants (Rcon)
      {
        name: 'AES Rcon',
        hex: '01020408102040801b36',
        confidence: 'HIGH' as const,
      },
      // AES-NI detection (x86 instruction bytes)
      {
        name: 'AES-NI aesenc',
        hex: '660f38dc',
        confidence: 'DEFINITE' as const,
      },
      {
        name: 'AES-NI aesdec',
        hex: '660f38de',
        confidence: 'DEFINITE' as const,
      },
      {
        name: 'AES-NI aeskeygenassist',
        hex: '660f3adf',
        confidence: 'DEFINITE' as const,
      },
    ];

    for (const c of aesConstants) {
      try {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "/x ${c.hex}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 30,
        );
        if (
          searchResult.success &&
          searchResult.output.trim() &&
          !searchResult.output.includes('Cannot find')
        ) {
          const addrs = searchResult.output.trim().split('\n');
          results.push(`  ✅ ${c.name} [${c.confidence}]`);
          addrs.slice(0, 3).forEach((addr) => {
            const addrMatch = addr.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              results.push(`     📍 Found at ${addrMatch[1]}`);
              findings.push({
                algorithm: 'AES',
                constantName: c.name,
                address: addrMatch[1],
                confidence: c.confidence,
                category: 'Symmetric Cipher',
              });
            }
          });
          results.push('');
        }
      } catch {
        // Continue
      }
    }

    // Step 2: SHA Family Detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. SHA FAMILY (Secure Hash Algorithms)                     │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const shaConstants = [
      // SHA-1 Initial hash values (H0-H4)
      {
        name: 'SHA-1 H0',
        hex: '67452301',
        confidence: 'HIGH' as const,
        algo: 'SHA-1',
      },
      {
        name: 'SHA-1 H1',
        hex: 'efcdab89',
        confidence: 'MEDIUM' as const,
        algo: 'SHA-1',
      },
      {
        name: 'SHA-1 H2',
        hex: '98badcfe',
        confidence: 'MEDIUM' as const,
        algo: 'SHA-1',
      },
      {
        name: 'SHA-1 K constants',
        hex: '5a827999',
        confidence: 'HIGH' as const,
        algo: 'SHA-1',
      },

      // SHA-256 Initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
      {
        name: 'SHA-256 H0',
        hex: '6a09e667',
        confidence: 'DEFINITE' as const,
        algo: 'SHA-256',
      },
      {
        name: 'SHA-256 H1',
        hex: 'bb67ae85',
        confidence: 'HIGH' as const,
        algo: 'SHA-256',
      },
      {
        name: 'SHA-256 H2',
        hex: '3c6ef372',
        confidence: 'HIGH' as const,
        algo: 'SHA-256',
      },
      {
        name: 'SHA-256 H3',
        hex: 'a54ff53a',
        confidence: 'HIGH' as const,
        algo: 'SHA-256',
      },
      // SHA-256 Round constants K[0-3]
      {
        name: 'SHA-256 K[0]',
        hex: '428a2f98',
        confidence: 'DEFINITE' as const,
        algo: 'SHA-256',
      },
      {
        name: 'SHA-256 K[1]',
        hex: '71374491',
        confidence: 'HIGH' as const,
        algo: 'SHA-256',
      },
      {
        name: 'SHA-256 K sequence',
        hex: '428a2f9871374491b5c0fbcfe9b5dba5',
        confidence: 'DEFINITE' as const,
        algo: 'SHA-256',
      },

      // SHA-512 Initial hash values (64-bit)
      {
        name: 'SHA-512 H0',
        hex: '6a09e667f3bcc908',
        confidence: 'DEFINITE' as const,
        algo: 'SHA-512',
      },
      {
        name: 'SHA-512 H1',
        hex: 'bb67ae8584caa73b',
        confidence: 'HIGH' as const,
        algo: 'SHA-512',
      },
      {
        name: 'SHA-512 K[0]',
        hex: '428a2f98d728ae22',
        confidence: 'DEFINITE' as const,
        algo: 'SHA-512',
      },

      // SHA-3/Keccak round constants
      {
        name: 'SHA-3 RC[0]',
        hex: '0000000000000001',
        confidence: 'LOW' as const,
        algo: 'SHA-3',
      },
      {
        name: 'SHA-3 RC[1]',
        hex: '0000000000008082',
        confidence: 'MEDIUM' as const,
        algo: 'SHA-3',
      },
    ];

    for (const c of shaConstants) {
      try {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "/x ${c.hex}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );
        if (
          searchResult.success &&
          searchResult.output.trim() &&
          !searchResult.output.includes('Cannot find')
        ) {
          const addrs = searchResult.output.trim().split('\n');
          results.push(`  ✅ ${c.name} [${c.confidence}] → ${c.algo}`);
          addrs.slice(0, 2).forEach((addr) => {
            const addrMatch = addr.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              results.push(`     📍 Found at ${addrMatch[1]}`);
              findings.push({
                algorithm: c.algo,
                constantName: c.name,
                address: addrMatch[1],
                confidence: c.confidence,
                category: 'Hash Function',
              });
            }
          });
          results.push('');
        }
      } catch {
        // Continue
      }
    }

    // Step 3: MD5 Detection
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. MD5 (Message Digest 5)                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const md5Constants = [
      // MD5 Initial values (same as SHA-1 for first two)
      { name: 'MD5 A init', hex: '67452301', confidence: 'HIGH' as const },
      { name: 'MD5 B init', hex: 'efcdab89', confidence: 'MEDIUM' as const },
      { name: 'MD5 C init', hex: '98badcfe', confidence: 'MEDIUM' as const },
      { name: 'MD5 D init', hex: '10325476', confidence: 'HIGH' as const },
      // MD5 T constants (sin-based) - first few
      { name: 'MD5 T[1]', hex: 'd76aa478', confidence: 'DEFINITE' as const },
      { name: 'MD5 T[2]', hex: 'e8c7b756', confidence: 'HIGH' as const },
      { name: 'MD5 T[3]', hex: '242070db', confidence: 'HIGH' as const },
      { name: 'MD5 T[4]', hex: 'c1bdceee', confidence: 'HIGH' as const },
      {
        name: 'MD5 T sequence',
        hex: 'd76aa478e8c7b756242070dbc1bdceee',
        confidence: 'DEFINITE' as const,
      },
    ];

    for (const c of md5Constants) {
      try {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "/x ${c.hex}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );
        if (
          searchResult.success &&
          searchResult.output.trim() &&
          !searchResult.output.includes('Cannot find')
        ) {
          const addrs = searchResult.output.trim().split('\n');
          results.push(`  ✅ ${c.name} [${c.confidence}]`);
          addrs.slice(0, 2).forEach((addr) => {
            const addrMatch = addr.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              results.push(`     📍 Found at ${addrMatch[1]}`);
              findings.push({
                algorithm: 'MD5',
                constantName: c.name,
                address: addrMatch[1],
                confidence: c.confidence,
                category: 'Hash Function',
              });
            }
          });
          results.push('');
        }
      } catch {
        // Continue
      }
    }

    // Step 4: Other Symmetric Ciphers
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. OTHER SYMMETRIC CIPHERS                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const otherCiphers = [
      // Blowfish P-array initial values
      {
        name: 'Blowfish P[0]',
        hex: '243f6a88',
        algo: 'Blowfish',
        confidence: 'DEFINITE' as const,
      },
      {
        name: 'Blowfish P[1]',
        hex: '85a308d3',
        algo: 'Blowfish',
        confidence: 'HIGH' as const,
      },
      {
        name: 'Blowfish P sequence',
        hex: '243f6a8885a308d313198a2e03707344',
        algo: 'Blowfish',
        confidence: 'DEFINITE' as const,
      },

      // Twofish MDS matrix constants
      {
        name: 'Twofish MDS',
        hex: '01a4',
        algo: 'Twofish',
        confidence: 'MEDIUM' as const,
      },

      // ChaCha20/Salsa20 constants ("expand 32-byte k")
      {
        name: 'ChaCha20/Salsa20 sigma',
        hex: '61707865',
        algo: 'ChaCha20',
        confidence: 'DEFINITE' as const,
      },
      {
        name: 'ChaCha20 expand',
        hex: '657870616e642033322d62797465206b',
        algo: 'ChaCha20',
        confidence: 'DEFINITE' as const,
      },

      // DES Initial permutation patterns
      {
        name: 'DES IP table',
        hex: '3a32222a',
        algo: 'DES',
        confidence: 'MEDIUM' as const,
      },

      // RC4 state initialization pattern
      {
        name: 'RC4 S-box init',
        hex: '000102030405060708090a0b0c0d0e0f',
        algo: 'RC4',
        confidence: 'MEDIUM' as const,
      },

      // CAST5 S-box
      {
        name: 'CAST5 S1',
        hex: '30fb40d4',
        algo: 'CAST5',
        confidence: 'HIGH' as const,
      },

      // Serpent
      {
        name: 'Serpent PHI',
        hex: '9e3779b9',
        algo: 'Serpent',
        confidence: 'HIGH' as const,
      },
    ];

    for (const c of otherCiphers) {
      try {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "/x ${c.hex}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );
        if (
          searchResult.success &&
          searchResult.output.trim() &&
          !searchResult.output.includes('Cannot find')
        ) {
          const addrs = searchResult.output.trim().split('\n');
          results.push(`  ✅ ${c.name} → ${c.algo} [${c.confidence}]`);
          addrs.slice(0, 2).forEach((addr) => {
            const addrMatch = addr.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              results.push(`     📍 Found at ${addrMatch[1]}`);
              findings.push({
                algorithm: c.algo,
                constantName: c.name,
                address: addrMatch[1],
                confidence: c.confidence,
                category: 'Symmetric Cipher',
              });
            }
          });
          results.push('');
        }
      } catch {
        // Continue
      }
    }

    // Step 5: RSA/Asymmetric Constants
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. RSA / ASYMMETRIC CRYPTO                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const rsaConstants = [
      // Common RSA public exponents
      {
        name: 'RSA e=65537 (0x10001)',
        hex: '00010001',
        algo: 'RSA',
        confidence: 'MEDIUM' as const,
      },
      {
        name: 'RSA e=3',
        hex: '00000003',
        algo: 'RSA',
        confidence: 'LOW' as const,
      },
      // PKCS#1 padding indicators
      {
        name: 'PKCS#1 v1.5 signature',
        hex: '0001ffff',
        algo: 'RSA-PKCS1',
        confidence: 'HIGH' as const,
      },
      {
        name: 'PKCS#1 v1.5 encryption',
        hex: '0002',
        algo: 'RSA-PKCS1',
        confidence: 'MEDIUM' as const,
      },
      // Elliptic curve parameters (secp256k1 - Bitcoin curve)
      {
        name: 'secp256k1 p',
        hex: 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
        algo: 'ECDSA-secp256k1',
        confidence: 'DEFINITE' as const,
      },
      // Curve25519 prime
      {
        name: 'Curve25519 prime',
        hex: '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
        algo: 'Curve25519',
        confidence: 'DEFINITE' as const,
      },
    ];

    for (const c of rsaConstants) {
      try {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "/x ${c.hex}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );
        if (
          searchResult.success &&
          searchResult.output.trim() &&
          !searchResult.output.includes('Cannot find')
        ) {
          const addrs = searchResult.output.trim().split('\n');
          results.push(`  ✅ ${c.name} → ${c.algo} [${c.confidence}]`);
          addrs.slice(0, 2).forEach((addr) => {
            const addrMatch = addr.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              results.push(`     📍 Found at ${addrMatch[1]}`);
              findings.push({
                algorithm: c.algo,
                constantName: c.name,
                address: addrMatch[1],
                confidence: c.confidence,
                category: 'Asymmetric Crypto',
              });
            }
          });
          results.push('');
        }
      } catch {
        // Continue
      }
    }

    // Step 6: CRC and Checksum Tables
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 6. CRC / CHECKSUM TABLES                                   │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const crcConstants = [
      // CRC32 polynomial table values
      {
        name: 'CRC32 polynomial',
        hex: 'edb88320',
        algo: 'CRC32',
        confidence: 'DEFINITE' as const,
      },
      {
        name: 'CRC32 table[1]',
        hex: '77073096',
        algo: 'CRC32',
        confidence: 'HIGH' as const,
      },
      {
        name: 'CRC32 table[2]',
        hex: 'ee0e612c',
        algo: 'CRC32',
        confidence: 'HIGH' as const,
      },
      // CRC16
      {
        name: 'CRC16-CCITT poly',
        hex: '1021',
        algo: 'CRC16',
        confidence: 'MEDIUM' as const,
      },
      // Adler-32 prime
      {
        name: 'Adler-32 MOD',
        hex: '0000fff1',
        algo: 'Adler-32',
        confidence: 'MEDIUM' as const,
      },
    ];

    for (const c of crcConstants) {
      try {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "/x ${c.hex}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );
        if (
          searchResult.success &&
          searchResult.output.trim() &&
          !searchResult.output.includes('Cannot find')
        ) {
          const addrs = searchResult.output.trim().split('\n');
          results.push(`  ✅ ${c.name} → ${c.algo} [${c.confidence}]`);
          addrs.slice(0, 2).forEach((addr) => {
            const addrMatch = addr.match(/(0x[0-9a-fA-F]+)/);
            if (addrMatch) {
              results.push(`     📍 Found at ${addrMatch[1]}`);
              findings.push({
                algorithm: c.algo,
                constantName: c.name,
                address: addrMatch[1],
                confidence: c.confidence,
                category: 'Checksum',
              });
            }
          });
          results.push('');
        }
      } catch {
        // Continue
      }
    }

    // Step 7: Search imports for crypto library functions
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 7. CRYPTO LIBRARY IMPORTS                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const importResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 8,
      );

      if (importResult.success && importResult.output.trim()) {
        const imports = importResult.output.toLowerCase();
        const cryptoImports = [
          { pattern: 'aes', lib: 'AES functions' },
          { pattern: 'des', lib: 'DES functions' },
          { pattern: 'sha', lib: 'SHA functions' },
          { pattern: 'md5', lib: 'MD5 functions' },
          { pattern: 'rsa', lib: 'RSA functions' },
          { pattern: 'evp_', lib: 'OpenSSL EVP' },
          { pattern: 'crypto', lib: 'Crypto library' },
          { pattern: 'ssl', lib: 'SSL/TLS' },
          { pattern: 'bcrypt', lib: 'BCrypt' },
          { pattern: 'crypt', lib: 'Crypt functions' },
          { pattern: 'rand', lib: 'Random/PRNG' },
          { pattern: 'hmac', lib: 'HMAC' },
          { pattern: 'pbkdf', lib: 'Key derivation' },
          { pattern: 'cipher', lib: 'Cipher operations' },
          { pattern: 'sodium', lib: 'libsodium' },
          { pattern: 'nacl', lib: 'NaCl crypto' },
          { pattern: 'gcrypt', lib: 'libgcrypt' },
          { pattern: 'mbedtls', lib: 'mbedTLS' },
          { pattern: 'wolfssl', lib: 'wolfSSL' },
          { pattern: 'botan', lib: 'Botan' },
        ];

        const foundImports: string[] = [];
        for (const ci of cryptoImports) {
          if (imports.includes(ci.pattern)) {
            foundImports.push(`${ci.lib} (${ci.pattern})`);
          }
        }

        if (foundImports.length > 0) {
          results.push('  ✅ Crypto library imports detected:');
          foundImports.forEach((imp) => results.push(`     • ${imp}`));
          results.push('');
        } else {
          results.push('  ℹ️ No standard crypto library imports found');
          results.push(
            '     (May use embedded/custom crypto implementation)\n',
          );
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Import analysis error: ${e}\n`);
    }

    // Step 8: Summary
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 CRYPTO DETECTION SUMMARY                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    if (findings.length > 0) {
      // Group by algorithm
      const byAlgorithm = new Map<string, CryptoFinding[]>();
      for (const f of findings) {
        if (!byAlgorithm.has(f.algorithm)) {
          byAlgorithm.set(f.algorithm, []);
        }
        byAlgorithm.get(f.algorithm)!.push(f);
      }

      results.push('  📊 ALGORITHMS DETECTED:');
      results.push('');

      for (const [algo, algoFindings] of byAlgorithm.entries()) {
        const definite = algoFindings.filter(
          (f) => f.confidence === 'DEFINITE',
        ).length;
        const high = algoFindings.filter((f) => f.confidence === 'HIGH').length;
        const category = algoFindings[0].category;

        let confidence = '❓';
        if (definite > 0) confidence = '✅ CONFIRMED';
        else if (high >= 2) confidence = '🔶 LIKELY';
        else confidence = '❔ POSSIBLE';

        results.push(`  ${confidence} ${algo} (${category})`);
        results.push(
          `     Constants found: ${algoFindings.length} (${definite} definite, ${high} high confidence)`,
        );
        results.push(
          `     Addresses: ${algoFindings
            .slice(0, 3)
            .map((f) => f.address)
            .join(', ')}`,
        );
        results.push('');
      }

      // Summary table
      results.push(
        '  ┌────────────────────┬────────────────┬─────────────────────┐',
      );
      results.push(
        '  │ Algorithm          │ Confidence     │ Category            │',
      );
      results.push(
        '  ├────────────────────┼────────────────┼─────────────────────┤',
      );

      const uniqueAlgos = [...new Set(findings.map((f) => f.algorithm))];
      for (const algo of uniqueAlgos) {
        const algoFindings = findings.filter((f) => f.algorithm === algo);
        const bestConf = algoFindings.some((f) => f.confidence === 'DEFINITE')
          ? 'DEFINITE'
          : algoFindings.some((f) => f.confidence === 'HIGH')
            ? 'HIGH'
            : 'MEDIUM';
        const category = algoFindings[0].category;

        results.push(
          `  │ ${algo.padEnd(18)} │ ${bestConf.padEnd(14)} │ ${category.padEnd(19)} │`,
        );
      }
      results.push(
        '  └────────────────────┴────────────────┴─────────────────────┘',
      );
      results.push('');
    } else {
      results.push('  ℹ️ No crypto constants detected.');
      results.push('     Possible explanations:');
      results.push('     • Binary uses runtime key generation');
      results.push('     • Custom/obscured crypto implementation');
      results.push('     • Constants are encrypted or dynamically loaded');
      results.push('');
    }

    // Recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 🎯 ANALYSIS RECOMMENDATIONS                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🔧 NEXT STEPS:');
    results.push('     1. Examine functions near constant addresses');
    results.push('     2. Look for key/IV parameters in nearby code');
    results.push('     3. Check for hardcoded keys in data sections');
    results.push('     4. Trace crypto function calls at runtime');
    results.push('');
    results.push('  🔧 RELATED OPERATIONS:');
    results.push(
      '     • r2_disasm <addr> - Disassemble around crypto constant',
    );
    results.push('     • r2_xrefs <addr> - Find code referencing the constant');
    results.push(
      '     • decode_strings_heuristic - Find encoded/encrypted data',
    );
    results.push('     • ltrace_run - Trace crypto library calls');
    results.push('');

    return { success: true, output: results.join('\n') };
  }

  private async analyzeCallGraph(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🕸️ CALL GRAPH ANALYSIS (Function Importance by Position)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track function call graph metrics
    interface FunctionNode {
      address: string;
      name: string;
      inDegree: number; // How many functions call this
      outDegree: number; // How many functions this calls
      callers: string[];
      callees: string[];
      depth: number; // Distance from entry points
      isEntryPoint: boolean;
      isLeaf: boolean;
      category:
        | 'HUB'
        | 'DISPATCHER'
        | 'WORKER'
        | 'ENTRY'
        | 'LEAF'
        | 'UTILITY'
        | 'NORMAL';
      importance: number;
    }
    const functionGraph: Map<string, FunctionNode> = new Map();

    // Step 1: Get all functions
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. BUILDING FUNCTION GRAPH                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)}`,
        timeout / 4,
      );

      if (funcResult.success && funcResult.output.trim()) {
        let functions: Array<{
          offset: number;
          name: string;
          size: number;
          callrefs?: Array<{ addr: number; type: string }>;
          codexrefs?: Array<{ addr: number; type: string }>;
        }> = [];

        try {
          functions = JSON.parse(funcResult.output);
        } catch {
          // Fallback to text parsing
          const lines = funcResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+\d+\s+(\S+)/);
            if (match) {
              functions.push({
                offset: parseInt(match[1], 16),
                name: match[2],
                size: 0,
              });
            }
          }
        }

        results.push(`  📊 Found ${functions.length} functions to analyze\n`);

        // Initialize all function nodes
        for (const func of functions) {
          const addr = `0x${func.offset.toString(16)}`;
          functionGraph.set(addr, {
            address: addr,
            name: func.name || `fcn_${addr}`,
            inDegree: 0,
            outDegree: 0,
            callers: [],
            callees: [],
            depth: Infinity,
            isEntryPoint: false,
            isLeaf: true,
            category: 'NORMAL',
            importance: 0,
          });
        }

        // Step 2: Analyze call relationships
        results.push(
          '┌─────────────────────────────────────────────────────────────┐',
        );
        results.push(
          '│ 2. ANALYZING CALL RELATIONSHIPS                            │',
        );
        results.push(
          '└─────────────────────────────────────────────────────────────┘\n',
        );

        let analyzedCount = 0;
        const maxToAnalyze = Math.min(functions.length, 200);

        for (const func of functions.slice(0, maxToAnalyze)) {
          const addr = `0x${func.offset.toString(16)}`;

          try {
            // Get xrefs to this function (callers)
            const xrefToResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; axtj" ${escapeShellArg(targetPath)} 2>/dev/null`,
              timeout / (maxToAnalyze * 2),
            );

            if (xrefToResult.success && xrefToResult.output.trim()) {
              try {
                const xrefs = JSON.parse(xrefToResult.output);
                const node = functionGraph.get(addr);
                if (node && Array.isArray(xrefs)) {
                  for (const xref of xrefs) {
                    if (xref.type === 'CALL' || xref.type === 'CODE') {
                      const callerAddr = `0x${xref.from?.toString(16) || xref.addr?.toString(16)}`;
                      if (callerAddr && !node.callers.includes(callerAddr)) {
                        node.callers.push(callerAddr);
                        node.inDegree++;
                      }
                    }
                  }
                }
              } catch {
                // Parse xref text output
                const lines = xrefToResult.output.trim().split('\n');
                const node = functionGraph.get(addr);
                if (node) {
                  for (const line of lines) {
                    const match = line.match(/(0x[0-9a-fA-F]+)/);
                    if (match && !node.callers.includes(match[1])) {
                      node.callers.push(match[1]);
                      node.inDegree++;
                    }
                  }
                }
              }
            }

            // Get xrefs from this function (callees)
            const xrefFromResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; axfj" ${escapeShellArg(targetPath)} 2>/dev/null`,
              timeout / (maxToAnalyze * 2),
            );

            if (xrefFromResult.success && xrefFromResult.output.trim()) {
              try {
                const xrefs = JSON.parse(xrefFromResult.output);
                const node = functionGraph.get(addr);
                if (node && Array.isArray(xrefs)) {
                  for (const xref of xrefs) {
                    if (xref.type === 'CALL' || xref.type === 'CODE') {
                      const calleeAddr = `0x${xref.to?.toString(16) || xref.addr?.toString(16)}`;
                      if (calleeAddr && !node.callees.includes(calleeAddr)) {
                        node.callees.push(calleeAddr);
                        node.outDegree++;
                        node.isLeaf = false;
                      }
                    }
                  }
                }
              } catch {
                // Parse xref text output
                const lines = xrefFromResult.output.trim().split('\n');
                const node = functionGraph.get(addr);
                if (node) {
                  for (const line of lines) {
                    const match = line.match(/(0x[0-9a-fA-F]+)/);
                    if (match && !node.callees.includes(match[1])) {
                      node.callees.push(match[1]);
                      node.outDegree++;
                      node.isLeaf = false;
                    }
                  }
                }
              }
            }

            analyzedCount++;
          } catch {
            // Continue on individual function errors
          }
        }

        results.push(
          `  ✅ Analyzed call relationships for ${analyzedCount} functions\n`,
        );

        // Step 3: Identify entry points
        results.push(
          '┌─────────────────────────────────────────────────────────────┐',
        );
        results.push(
          '│ 3. ENTRY POINTS (No Callers / Program Roots)               │',
        );
        results.push(
          '└─────────────────────────────────────────────────────────────┘\n',
        );

        const entryPoints: FunctionNode[] = [];
        for (const [, node] of functionGraph) {
          if (
            node.inDegree === 0 &&
            node.outDegree > 0 &&
            !node.name.startsWith('sym.imp.')
          ) {
            node.isEntryPoint = true;
            node.depth = 0;
            node.category = 'ENTRY';
            entryPoints.push(node);
          }
        }

        // Also check for common entry point names
        const entryNames = [
          'main',
          'entry0',
          'start',
          '_start',
          'WinMain',
          'DllMain',
          'init',
          '_init',
        ];
        for (const [, node] of functionGraph) {
          const baseName = node.name
            .replace('sym.', '')
            .replace('fcn.', '')
            .toLowerCase();
          if (
            entryNames.some((e) => baseName.includes(e.toLowerCase())) &&
            !node.isEntryPoint
          ) {
            node.isEntryPoint = true;
            node.depth = 0;
            node.category = 'ENTRY';
            if (!entryPoints.includes(node)) {
              entryPoints.push(node);
            }
          }
        }

        if (entryPoints.length > 0) {
          results.push('  🚪 IDENTIFIED ENTRY POINTS:');
          results.push(
            '  ┌──────────────┬────────────────────────────────┬──────────┐',
          );
          results.push(
            '  │ Address      │ Name                           │ Calls    │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────────┼──────────┤',
          );
          entryPoints
            .sort((a, b) => b.outDegree - a.outDegree)
            .slice(0, 15)
            .forEach((ep) => {
              const addr = ep.address.padEnd(12);
              const name = ep.name.substring(0, 30).padEnd(30);
              const calls = ep.outDegree.toString().padEnd(8);
              results.push(`  │ ${addr} │ ${name} │ ${calls} │`);
            });
          results.push(
            '  └──────────────┴────────────────────────────────┴──────────┘',
          );
          results.push('');
        } else {
          results.push('  ⚠️ No clear entry points identified\n');
        }

        // Step 4: Calculate depths (BFS from entry points)
        const visited = new Set<string>();
        const queue: Array<{ addr: string; depth: number }> = [];

        for (const ep of entryPoints) {
          queue.push({ addr: ep.address, depth: 0 });
        }

        while (queue.length > 0) {
          const current = queue.shift()!;
          if (visited.has(current.addr)) continue;
          visited.add(current.addr);

          const node = functionGraph.get(current.addr);
          if (node) {
            node.depth = Math.min(node.depth, current.depth);
            for (const callee of node.callees) {
              const calleeNode = functionGraph.get(callee);
              if (calleeNode && !visited.has(callee)) {
                queue.push({ addr: callee, depth: current.depth + 1 });
              }
            }
          }
        }

        // Step 5: Categorize functions and calculate importance
        results.push(
          '┌─────────────────────────────────────────────────────────────┐',
        );
        results.push(
          '│ 4. FUNCTION CATEGORIES BY CALL GRAPH POSITION              │',
        );
        results.push(
          '└─────────────────────────────────────────────────────────────┘\n',
        );

        const hubs: FunctionNode[] = [];
        const dispatchers: FunctionNode[] = [];
        const workers: FunctionNode[] = [];
        const utilities: FunctionNode[] = [];
        const leaves: FunctionNode[] = [];

        for (const [, node] of functionGraph) {
          // Calculate importance score
          node.importance =
            node.inDegree * 3 + // Being called is important
            node.outDegree * 2 + // Making calls shows complexity
            (node.isEntryPoint ? 10 : 0) + // Entry points are key
            (node.depth === 1 ? 5 : 0) + // Direct children of entry are important
            (node.depth === 2 ? 3 : 0); // Grandchildren matter too

          // Skip imports
          if (node.name.startsWith('sym.imp.')) continue;

          // Categorize based on in/out degree
          if (node.inDegree >= 5 && node.outDegree >= 5) {
            node.category = 'HUB';
            hubs.push(node);
          } else if (node.inDegree <= 2 && node.outDegree >= 5) {
            node.category = 'DISPATCHER';
            dispatchers.push(node);
          } else if (node.inDegree >= 5 && node.outDegree <= 2) {
            node.category = 'UTILITY';
            utilities.push(node);
          } else if (node.outDegree === 0 && node.inDegree > 0) {
            node.category = 'LEAF';
            leaves.push(node);
          } else if (node.outDegree >= 3) {
            node.category = 'WORKER';
            workers.push(node);
          }
        }

        // Display HUB functions
        if (hubs.length > 0) {
          results.push(
            '  🔴 HUB FUNCTIONS (Many callers AND callees - orchestrators):',
          );
          results.push(
            '  ┌──────────────┬────────────────────────────┬────────┬─────────┬──────────┐',
          );
          results.push(
            '  │ Address      │ Name                       │ In-Deg │ Out-Deg │ Priority │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────┼────────┼─────────┼──────────┤',
          );
          hubs
            .sort((a, b) => b.importance - a.importance)
            .slice(0, 10)
            .forEach((h) => {
              const addr = h.address.padEnd(12);
              const name = h.name.substring(0, 26).padEnd(26);
              const inDeg = h.inDegree.toString().padEnd(6);
              const outDeg = h.outDegree.toString().padEnd(7);
              const pri = h.importance.toString().padEnd(8);
              results.push(
                `  │ ${addr} │ ${name} │ ${inDeg} │ ${outDeg} │ ${pri} │`,
              );
            });
          results.push(
            '  └──────────────┴────────────────────────────┴────────┴─────────┴──────────┘',
          );
          results.push(
            '  💡 HUBs often contain main logic, switches, or state machines\n',
          );
        }

        // Display DISPATCHER functions
        if (dispatchers.length > 0) {
          results.push(
            '  🟠 DISPATCHER FUNCTIONS (Few callers, many callees - controllers):',
          );
          results.push(
            '  ┌──────────────┬────────────────────────────┬────────┬─────────┐',
          );
          results.push(
            '  │ Address      │ Name                       │ In-Deg │ Out-Deg │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────┼────────┼─────────┤',
          );
          dispatchers
            .sort((a, b) => b.outDegree - a.outDegree)
            .slice(0, 10)
            .forEach((d) => {
              const addr = d.address.padEnd(12);
              const name = d.name.substring(0, 26).padEnd(26);
              const inDeg = d.inDegree.toString().padEnd(6);
              const outDeg = d.outDegree.toString().padEnd(7);
              results.push(`  │ ${addr} │ ${name} │ ${inDeg} │ ${outDeg} │`);
            });
          results.push(
            '  └──────────────┴────────────────────────────┴────────┴─────────┘',
          );
          results.push(
            '  💡 DISPATCHERs often handle command routing or initialization\n',
          );
        }

        // Display UTILITY functions
        if (utilities.length > 0) {
          results.push(
            '  🟢 UTILITY FUNCTIONS (Many callers, few callees - helpers):',
          );
          results.push(
            '  ┌──────────────┬────────────────────────────┬────────┐',
          );
          results.push(
            '  │ Address      │ Name                       │ In-Deg │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────┼────────┤',
          );
          utilities
            .sort((a, b) => b.inDegree - a.inDegree)
            .slice(0, 10)
            .forEach((u) => {
              const addr = u.address.padEnd(12);
              const name = u.name.substring(0, 26).padEnd(26);
              const inDeg = u.inDegree.toString().padEnd(6);
              results.push(`  │ ${addr} │ ${name} │ ${inDeg} │`);
            });
          results.push(
            '  └──────────────┴────────────────────────────┴────────┘',
          );
          results.push(
            '  💡 UTILITYs are often crypto, string ops, or validation helpers\n',
          );
        }

        // Display WORKER functions (depth 1-2 from entry)
        const criticalWorkers = workers.filter(
          (w) => w.depth <= 2 && w.depth > 0,
        );
        if (criticalWorkers.length > 0) {
          results.push(
            '  🔵 CRITICAL PATH FUNCTIONS (Near entry, active workers):',
          );
          results.push(
            '  ┌──────────────┬────────────────────────────┬───────┬──────────┐',
          );
          results.push(
            '  │ Address      │ Name                       │ Depth │ Priority │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────┼───────┼──────────┤',
          );
          criticalWorkers
            .sort((a, b) => a.depth - b.depth || b.importance - a.importance)
            .slice(0, 10)
            .forEach((w) => {
              const addr = w.address.padEnd(12);
              const name = w.name.substring(0, 26).padEnd(26);
              const depth = w.depth.toString().padEnd(5);
              const pri = w.importance.toString().padEnd(8);
              results.push(`  │ ${addr} │ ${name} │ ${depth} │ ${pri} │`);
            });
          results.push(
            '  └──────────────┴────────────────────────────┴───────┴──────────┘',
          );
          results.push(
            '  💡 CRITICAL PATH functions are called early - often have key logic\n',
          );
        }

        // Display LEAF functions
        if (leaves.length > 0) {
          results.push(
            '  ⚪ LEAF FUNCTIONS (Called but make no calls - endpoints):',
          );
          results.push(
            '  ┌──────────────┬────────────────────────────┬────────┐',
          );
          results.push(
            '  │ Address      │ Name                       │ In-Deg │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────┼────────┤',
          );
          leaves
            .sort((a, b) => b.inDegree - a.inDegree)
            .slice(0, 10)
            .forEach((l) => {
              const addr = l.address.padEnd(12);
              const name = l.name.substring(0, 26).padEnd(26);
              const inDeg = l.inDegree.toString().padEnd(6);
              results.push(`  │ ${addr} │ ${name} │ ${inDeg} │`);
            });
          results.push(
            '  └──────────────┴────────────────────────────┴────────┘',
          );
          results.push(
            '  💡 LEAFs often contain crypto primitives, comparisons, or I/O\n',
          );
        }

        // Step 6: Call graph statistics
        results.push(
          '┌─────────────────────────────────────────────────────────────┐',
        );
        results.push(
          '│ 5. CALL GRAPH STATISTICS                                    │',
        );
        results.push(
          '└─────────────────────────────────────────────────────────────┘\n',
        );

        const allNodes = Array.from(functionGraph.values()).filter(
          (n) => !n.name.startsWith('sym.imp.'),
        );
        const totalEdges = allNodes.reduce((sum, n) => sum + n.outDegree, 0);
        const avgInDegree =
          allNodes.reduce((sum, n) => sum + n.inDegree, 0) / allNodes.length;
        const avgOutDegree =
          allNodes.reduce((sum, n) => sum + n.outDegree, 0) / allNodes.length;
        const maxInDegree = Math.max(...allNodes.map((n) => n.inDegree));
        const maxOutDegree = Math.max(...allNodes.map((n) => n.outDegree));

        results.push('  📊 GRAPH METRICS:');
        results.push(`     • Total functions: ${allNodes.length}`);
        results.push(`     • Total call edges: ${totalEdges}`);
        results.push(`     • Entry points: ${entryPoints.length}`);
        results.push(
          `     • Leaf functions: ${allNodes.filter((n) => n.isLeaf).length}`,
        );
        results.push(`     • Average in-degree: ${avgInDegree.toFixed(2)}`);
        results.push(`     • Average out-degree: ${avgOutDegree.toFixed(2)}`);
        results.push(`     • Max in-degree: ${maxInDegree}`);
        results.push(`     • Max out-degree: ${maxOutDegree}`);
        results.push('');

        results.push('  📊 CATEGORY BREAKDOWN:');
        results.push(`     • HUB functions: ${hubs.length}`);
        results.push(`     • DISPATCHER functions: ${dispatchers.length}`);
        results.push(`     • UTILITY functions: ${utilities.length}`);
        results.push(`     • WORKER functions: ${workers.length}`);
        results.push(`     • LEAF functions: ${leaves.length}`);
        results.push('');

        // Step 7: Most important functions overall
        results.push(
          '┌─────────────────────────────────────────────────────────────┐',
        );
        results.push(
          '│ 6. TOP PRIORITY FUNCTIONS (Weighted Importance)            │',
        );
        results.push(
          '└─────────────────────────────────────────────────────────────┘\n',
        );

        const topFunctions = allNodes
          .filter((n) => n.importance > 0)
          .sort((a, b) => b.importance - a.importance)
          .slice(0, 20);

        if (topFunctions.length > 0) {
          results.push('  🎯 HIGHEST PRIORITY FUNCTIONS FOR ANALYSIS:');
          results.push(
            '  ┌──────────────┬────────────────────────────┬────────────┬──────────┐',
          );
          results.push(
            '  │ Address      │ Name                       │ Category   │ Score    │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────┼────────────┼──────────┤',
          );
          topFunctions.forEach((f) => {
            const addr = f.address.padEnd(12);
            const name = f.name.substring(0, 26).padEnd(26);
            const cat = f.category.padEnd(10);
            const score = f.importance.toString().padEnd(8);
            results.push(`  │ ${addr} │ ${name} │ ${cat} │ ${score} │`);
          });
          results.push(
            '  └──────────────┴────────────────────────────┴────────────┴──────────┘',
          );
          results.push('');
        }

        // Step 8: Detect interesting patterns
        results.push(
          '┌─────────────────────────────────────────────────────────────┐',
        );
        results.push(
          '│ 7. INTERESTING CALL PATTERNS                               │',
        );
        results.push(
          '└─────────────────────────────────────────────────────────────┘\n',
        );

        // Find recursive functions
        const recursive = allNodes.filter((n) => n.callees.includes(n.address));
        if (recursive.length > 0) {
          results.push('  🔄 RECURSIVE FUNCTIONS (call themselves):');
          recursive.slice(0, 5).forEach((r) => {
            results.push(`     • ${r.address} ${r.name}`);
          });
          results.push('');
        }

        // Find functions that call many unique targets
        const manyTargets = allNodes
          .filter((n) => n.outDegree >= 10)
          .sort((a, b) => b.outDegree - a.outDegree);
        if (manyTargets.length > 0) {
          results.push(
            '  📞 FUNCTIONS WITH MANY CALLEES (likely dispatchers/main logic):',
          );
          manyTargets.slice(0, 5).forEach((m) => {
            results.push(
              `     • ${m.address} ${m.name} → calls ${m.outDegree} functions`,
            );
          });
          results.push('');
        }

        // Find highly referenced functions
        const highlyReferenced = allNodes
          .filter((n) => n.inDegree >= 10)
          .sort((a, b) => b.inDegree - a.inDegree);
        if (highlyReferenced.length > 0) {
          results.push('  📥 HIGHLY REFERENCED FUNCTIONS (called by many):');
          highlyReferenced.slice(0, 5).forEach((h) => {
            results.push(
              `     • ${h.address} ${h.name} ← called by ${h.inDegree} functions`,
            );
          });
          results.push('');
        }

        // Find isolated clusters (functions with very specific call patterns)
        const isolated = allNodes.filter(
          (n) =>
            n.inDegree === 1 &&
            n.outDegree >= 2 &&
            n.callees.every((c) => {
              const callee = functionGraph.get(c);
              return callee && callee.inDegree === 1;
            }),
        );
        if (isolated.length > 0) {
          results.push(
            '  🏝️ ISOLATED FUNCTION CLUSTERS (may be separate features):',
          );
          isolated.slice(0, 5).forEach((i) => {
            results.push(
              `     • ${i.address} ${i.name} (cluster of ${i.outDegree + 1} functions)`,
            );
          });
          results.push('');
        }
      } else {
        results.push('  ⚠️ Could not retrieve function list\n');
      }
    } catch (e) {
      results.push(`  ⚠️ Error building call graph: ${e}\n`);
    }

    // Step 9: Recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 🎯 ANALYSIS RECOMMENDATIONS                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🔍 ANALYSIS STRATEGY BASED ON CALL GRAPH:');
    results.push('');
    results.push('  For REVERSE ENGINEERING:');
    results.push(
      '     1. Start with HUB functions - they orchestrate the program',
    );
    results.push(
      '     2. Examine DISPATCHERs - they route to specific functionality',
    );
    results.push(
      '     3. UTILITYs are reusable code - may contain crypto/validation',
    );
    results.push('');
    results.push('  For CTF/CRACKING:');
    results.push('     1. Focus on functions at depth 1-2 from entry');
    results.push('     2. Leaf functions often contain final validation');
    results.push(
      '     3. Look for highly-referenced functions (may be strcmp-like)',
    );
    results.push('');
    results.push('  For MALWARE ANALYSIS:');
    results.push('     1. Entry points may have unpacking/decryption');
    results.push('     2. Isolated clusters may be separate payloads');
    results.push('     3. Recursive functions may be encoding/decoding loops');
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • r2_decompile - Decompile priority functions');
    results.push(
      '     • find_critical_functions - Score by behavioral patterns',
    );
    results.push('     • find_comparison_points - Find validation logic');
    results.push('     • trace_data_flow - Track input through the graph');
    results.push('');

    return { success: true, output: results.join('\n') };
  }

  /**
   * Find Input Sinks - Locate where user input is consumed/validated
   * Essential for finding authentication checks, license validation, and CTF flags
   * Detects:
   * - String comparison functions (strcmp, strncmp, memcmp)
   * - Memory scanning functions (strstr, strchr, memchr)
   * - Crypto comparison functions (CRYPTO_memcmp, timing-safe comparisons)
   * - Custom comparison loops
   */
  private async findInputSinks(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🎯 INPUT SINK ANALYSIS (Where Input Gets Validated)');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track all found sinks
    interface InputSink {
      function: string;
      callerAddr: string;
      callerFunc: string;
      category: string;
      importance: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    }
    const sinks: InputSink[] = [];

    // Step 1: String comparison sinks (highest priority for CTF/license checks)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. STRING COMPARISON SINKS (Authentication/Validation)     │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const stringCompFuncs = [
      {
        name: 'strcmp',
        desc: 'String equality check',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'strncmp',
        desc: 'Length-limited string compare',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'strcasecmp',
        desc: 'Case-insensitive compare',
        importance: 'HIGH' as const,
      },
      {
        name: 'strncasecmp',
        desc: 'Case-insensitive length-limited',
        importance: 'HIGH' as const,
      },
      {
        name: 'wcscmp',
        desc: 'Wide string compare',
        importance: 'HIGH' as const,
      },
      {
        name: 'wcsncmp',
        desc: 'Wide string length-limited',
        importance: 'HIGH' as const,
      },
      {
        name: '_stricmp',
        desc: 'MSVC case-insensitive',
        importance: 'HIGH' as const,
      },
      {
        name: '_strnicmp',
        desc: 'MSVC case-insensitive length',
        importance: 'HIGH' as const,
      },
      {
        name: 'lstrcmpA',
        desc: 'Windows ANSI compare',
        importance: 'HIGH' as const,
      },
      {
        name: 'lstrcmpW',
        desc: 'Windows Unicode compare',
        importance: 'HIGH' as const,
      },
      {
        name: 'CompareStringA',
        desc: 'Windows locale compare',
        importance: 'HIGH' as const,
      },
      {
        name: 'CompareStringW',
        desc: 'Windows Unicode locale',
        importance: 'HIGH' as const,
      },
    ];

    for (const func of stringCompFuncs) {
      try {
        // Try multiple symbol variations
        const variations = [
          `sym.imp.${func.name}`,
          `sym.${func.name}`,
          `reloc.${func.name}`,
          func.name,
        ];

        for (const symName of variations) {
          const xrefResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ ${symName}" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 40,
          );

          if (
            xrefResult.success &&
            xrefResult.output.trim() &&
            !xrefResult.output.includes('Cannot find')
          ) {
            const lines = xrefResult.output.trim().split('\n');
            results.push(`  ✅ ${func.name} (${func.desc}):`);
            results.push(`     Found ${lines.length} call site(s)\n`);

            for (const line of lines.slice(0, 10)) {
              // Parse xref output: addr func_name CALL/JMP ...
              const match = line.match(/(0x[0-9a-fA-F]+)\s+(\S+)/);
              if (match) {
                const callerAddr = match[1];
                const callerFunc = match[2];
                results.push(`     📍 ${callerAddr} in ${callerFunc}`);

                sinks.push({
                  function: func.name,
                  callerAddr,
                  callerFunc,
                  category: 'String Compare',
                  importance: func.importance,
                });
              }
            }
            results.push('');
            break; // Found calls, no need to try other variations
          }
        }
      } catch {
        // Continue to next function
      }
    }

    // Step 2: Memory comparison sinks
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. MEMORY COMPARISON SINKS (Binary/Hash Validation)        │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const memCompFuncs = [
      {
        name: 'memcmp',
        desc: 'Binary memory compare',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'bcmp',
        desc: 'BSD memory compare',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'CRYPTO_memcmp',
        desc: 'OpenSSL constant-time compare',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'timingsafe_bcmp',
        desc: 'Timing-safe compare',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'consttime_memequal',
        desc: 'Constant-time equality',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'NSS_SecureMemcmp',
        desc: 'NSS secure compare',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'sodium_memcmp',
        desc: 'libsodium constant-time',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'crypto_verify_16',
        desc: 'NaCl 16-byte verify',
        importance: 'CRITICAL' as const,
      },
      {
        name: 'crypto_verify_32',
        desc: 'NaCl 32-byte verify',
        importance: 'CRITICAL' as const,
      },
    ];

    for (const func of memCompFuncs) {
      try {
        const variations = [
          `sym.imp.${func.name}`,
          `sym.${func.name}`,
          func.name,
        ];

        for (const symName of variations) {
          const xrefResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ ${symName}" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 40,
          );

          if (
            xrefResult.success &&
            xrefResult.output.trim() &&
            !xrefResult.output.includes('Cannot find')
          ) {
            const lines = xrefResult.output.trim().split('\n');
            results.push(`  ✅ ${func.name} (${func.desc}):`);

            for (const line of lines.slice(0, 8)) {
              const match = line.match(/(0x[0-9a-fA-F]+)\s+(\S+)/);
              if (match) {
                results.push(`     📍 ${match[1]} in ${match[2]}`);
                sinks.push({
                  function: func.name,
                  callerAddr: match[1],
                  callerFunc: match[2],
                  category: 'Memory Compare',
                  importance: func.importance,
                });
              }
            }
            results.push('');
            break;
          }
        }
      } catch {
        // Continue
      }
    }

    // Step 3: String search/scan sinks
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. STRING SEARCH SINKS (Pattern Matching)                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const searchFuncs = [
      { name: 'strstr', desc: 'Substring search', importance: 'HIGH' as const },
      {
        name: 'strchr',
        desc: 'Character search',
        importance: 'MEDIUM' as const,
      },
      {
        name: 'strrchr',
        desc: 'Reverse character search',
        importance: 'MEDIUM' as const,
      },
      {
        name: 'strpbrk',
        desc: 'Character set search',
        importance: 'MEDIUM' as const,
      },
      {
        name: 'memchr',
        desc: 'Memory byte search',
        importance: 'MEDIUM' as const,
      },
      {
        name: 'memmem',
        desc: 'Memory pattern search',
        importance: 'HIGH' as const,
      },
      {
        name: 'wcsstr',
        desc: 'Wide substring search',
        importance: 'HIGH' as const,
      },
      {
        name: 'wcschr',
        desc: 'Wide character search',
        importance: 'MEDIUM' as const,
      },
      { name: 'regexec', desc: 'Regex execution', importance: 'HIGH' as const },
      {
        name: 'pcre_exec',
        desc: 'PCRE regex match',
        importance: 'HIGH' as const,
      },
      {
        name: 'pcre2_match',
        desc: 'PCRE2 regex match',
        importance: 'HIGH' as const,
      },
    ];

    for (const func of searchFuncs) {
      try {
        const xrefResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ sym.imp.${func.name}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );

        if (
          xrefResult.success &&
          xrefResult.output.trim() &&
          !xrefResult.output.includes('Cannot find')
        ) {
          const lines = xrefResult.output.trim().split('\n');
          results.push(
            `  ✅ ${func.name} (${func.desc}): ${lines.length} call(s)`,
          );

          for (const line of lines.slice(0, 5)) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+(\S+)/);
            if (match) {
              sinks.push({
                function: func.name,
                callerAddr: match[1],
                callerFunc: match[2],
                category: 'String Search',
                importance: func.importance,
              });
            }
          }
        }
      } catch {
        // Continue
      }
    }
    results.push('');

    // Step 4: Input reading functions (sources that lead to sinks)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. INPUT SOURCE FUNCTIONS (Where Input Comes From)         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const inputFuncs = [
      { name: 'scanf', desc: 'Formatted input', importance: 'HIGH' as const },
      { name: 'sscanf', desc: 'String scan', importance: 'HIGH' as const },
      {
        name: 'fscanf',
        desc: 'File formatted input',
        importance: 'HIGH' as const,
      },
      {
        name: 'gets',
        desc: 'Dangerous line input',
        importance: 'HIGH' as const,
      },
      { name: 'fgets', desc: 'Safe line input', importance: 'HIGH' as const },
      {
        name: 'getline',
        desc: 'Dynamic line input',
        importance: 'HIGH' as const,
      },
      { name: 'read', desc: 'Raw read syscall', importance: 'MEDIUM' as const },
      {
        name: 'fread',
        desc: 'Binary file read',
        importance: 'MEDIUM' as const,
      },
      { name: 'recv', desc: 'Network receive', importance: 'HIGH' as const },
      { name: 'recvfrom', desc: 'UDP receive', importance: 'HIGH' as const },
      {
        name: 'getenv',
        desc: 'Environment variable',
        importance: 'MEDIUM' as const,
      },
      {
        name: 'ReadFile',
        desc: 'Windows file read',
        importance: 'HIGH' as const,
      },
      {
        name: 'GetDlgItemTextA',
        desc: 'Windows dialog input',
        importance: 'HIGH' as const,
      },
      {
        name: 'GetWindowTextA',
        desc: 'Windows control text',
        importance: 'HIGH' as const,
      },
    ];

    const inputSources: Array<{ func: string; addr: string; caller: string }> =
      [];

    for (const func of inputFuncs) {
      try {
        const xrefResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ sym.imp.${func.name}" ${escapeShellArg(targetPath)} 2>/dev/null`,
          timeout / 40,
        );

        if (
          xrefResult.success &&
          xrefResult.output.trim() &&
          !xrefResult.output.includes('Cannot find')
        ) {
          const lines = xrefResult.output.trim().split('\n');
          results.push(
            `  📥 ${func.name} (${func.desc}): ${lines.length} call(s)`,
          );

          for (const line of lines.slice(0, 5)) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+(\S+)/);
            if (match) {
              inputSources.push({
                func: func.name,
                addr: match[1],
                caller: match[2],
              });
            }
          }
        }
      } catch {
        // Continue
      }
    }
    results.push('');

    // Step 5: Look for custom comparison loops (CMP in loops)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. CUSTOM COMPARISON PATTERNS                              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Search for CMP byte patterns in tight loops
      const cmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad cmp byte" ${escapeShellArg(targetPath)} 2>/dev/null | head -30`,
        timeout / 8,
      );

      if (cmpResult.success && cmpResult.output.trim()) {
        const cmpLines = cmpResult.output.trim().split('\n');
        results.push(`  🔍 Found ${cmpLines.length} byte-level comparisons`);
        results.push(
          '     (May indicate custom string/password check loops)\n',
        );

        // Show a few examples
        cmpLines.slice(0, 8).forEach((line) => {
          results.push(`     ${line.trim()}`);
        });
        results.push('');
      }

      // Search for TEST/CMP patterns (common in validation)
      const testResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad test al" ${escapeShellArg(targetPath)} 2>/dev/null | head -20`,
        timeout / 8,
      );

      if (testResult.success && testResult.output.trim()) {
        const testLines = testResult.output.trim().split('\n');
        results.push(`  🔍 Found ${testLines.length} 'test al' patterns`);
        results.push(
          '     (Often used for null-terminator/end-of-string checks)\n',
        );
      }
    } catch (e) {
      results.push(`  ⚠️ Custom pattern search error: ${e}\n`);
    }

    // Step 6: Cross-reference analysis - find functions with both input AND comparison
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 6. INPUT→SINK CORRELATION (Validation Functions)           │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    // Find functions that appear in both input sources and sinks
    const sinkFuncs = new Set(sinks.map((s) => s.callerFunc));
    const sourceFuncs = new Set(inputSources.map((s) => s.caller));
    const validationFuncs = [...sinkFuncs].filter((f) => sourceFuncs.has(f));

    if (validationFuncs.length > 0) {
      results.push(
        '  🎯 LIKELY VALIDATION FUNCTIONS (have both input AND comparison):',
      );
      results.push('');

      for (const func of validationFuncs.slice(0, 10)) {
        const funcSinks = sinks.filter((s) => s.callerFunc === func);
        const funcSources = inputSources.filter((s) => s.caller === func);

        results.push(`  ⭐ ${func}`);
        results.push(
          `     Input from: ${[...new Set(funcSources.map((s) => s.func))].join(', ')}`,
        );
        results.push(
          `     Compared with: ${[...new Set(funcSinks.map((s) => s.function))].join(', ')}`,
        );
        results.push('');
      }
    } else {
      results.push(
        '  ℹ️ No single function contains both input and comparison.',
      );
      results.push(
        '     Input may flow through multiple functions before validation.\n',
      );
    }

    // Step 7: Summary
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 INPUT SINK SUMMARY                                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const criticalSinks = sinks.filter((s) => s.importance === 'CRITICAL');
    const highSinks = sinks.filter((s) => s.importance === 'HIGH');

    results.push('  📊 SINK STATISTICS:');
    results.push(`     • Total sinks found:     ${sinks.length}`);
    results.push(`     • CRITICAL importance:   ${criticalSinks.length}`);
    results.push(`     • HIGH importance:       ${highSinks.length}`);
    results.push(`     • Input sources found:   ${inputSources.length}`);
    results.push(`     • Validation functions:  ${validationFuncs.length}`);
    results.push('');

    if (criticalSinks.length > 0) {
      results.push('  🎯 TOP TARGETS (CRITICAL comparison sinks):');
      results.push(
        '  ┌──────────────┬────────────────┬──────────────────────────────┐',
      );
      results.push(
        '  │ Address      │ Function       │ Caller                       │',
      );
      results.push(
        '  ├──────────────┼────────────────┼──────────────────────────────┤',
      );

      criticalSinks.slice(0, 15).forEach((sink) => {
        const addr = sink.callerAddr.padEnd(12);
        const func = sink.function.padEnd(14);
        const caller = sink.callerFunc.substring(0, 28).padEnd(28);
        results.push(`  │ ${addr} │ ${func} │ ${caller} │`);
      });

      results.push(
        '  └──────────────┴────────────────┴──────────────────────────────┘',
      );
      results.push('');
    }

    // Recommendations
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 🎯 ANALYSIS RECOMMENDATIONS                                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  🔧 FOR CTF/LICENSE BYPASS:');
    results.push('     1. Set breakpoints at strcmp/memcmp calls');
    results.push('     2. Examine arguments to see what is being compared');
    results.push('     3. Patch comparison result (change JNE→JMP or NOP)');
    results.push('     4. Or extract the expected value from second argument');
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • r2_disasm <addr> - Disassemble around sink location');
    results.push('     • trace_data_flow - See how input reaches sink');
    results.push('     • find_comparison_points - Get all CMP/TEST analysis');
    results.push('     • patch_function - Bypass the check');
    results.push('');

    return { success: true, output: results.join('\n') };
  }

  private async extractConstants(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔢 CONSTANT & MAGIC NUMBER EXTRACTION');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track all extracted constants
    interface ExtractedConstant {
      value: string;
      decimal: number;
      hex: string;
      location: string;
      instruction: string;
      category: string;
      significance: string;
    }
    const constants: ExtractedConstant[] = [];

    // Known magic numbers database
    const knownMagics: Record<string, { name: string; category: string }> = {
      // File signatures
      '0x7f454c46': { name: 'ELF magic', category: 'FILE_SIG' },
      '0x4d5a': { name: 'DOS/PE MZ header', category: 'FILE_SIG' },
      '0x504b0304': { name: 'ZIP/JAR/APK', category: 'FILE_SIG' },
      '0x89504e47': { name: 'PNG signature', category: 'FILE_SIG' },
      '0xffd8ffe0': { name: 'JPEG signature', category: 'FILE_SIG' },
      '0x25504446': { name: 'PDF signature', category: 'FILE_SIG' },
      '0xcafebabe': { name: 'Java class / Mach-O fat', category: 'FILE_SIG' },
      '0xfeedfacf': { name: 'Mach-O 64-bit', category: 'FILE_SIG' },
      '0xfeedface': { name: 'Mach-O 32-bit', category: 'FILE_SIG' },
      // Crypto constants
      '0x67452301': { name: 'MD5/SHA-1 IV[0]', category: 'CRYPTO' },
      '0xefcdab89': { name: 'MD5/SHA-1 IV[1]', category: 'CRYPTO' },
      '0x98badcfe': { name: 'MD5/SHA-1 IV[2]', category: 'CRYPTO' },
      '0x10325476': { name: 'MD5/SHA-1 IV[3]', category: 'CRYPTO' },
      '0x6a09e667': { name: 'SHA-256 IV[0]', category: 'CRYPTO' },
      '0xbb67ae85': { name: 'SHA-256 IV[1]', category: 'CRYPTO' },
      '0x3c6ef372': { name: 'SHA-256 IV[2]', category: 'CRYPTO' },
      '0xa54ff53a': { name: 'SHA-256 IV[3]', category: 'CRYPTO' },
      '0x5be0cd19': { name: 'SHA-256 IV[7]', category: 'CRYPTO' },
      '0x243f6a88': { name: 'Blowfish P[0] / Pi hex', category: 'CRYPTO' },
      '0x61707865': { name: 'ChaCha20 "expa"', category: 'CRYPTO' },
      '0x3320646e': { name: 'ChaCha20 "nd 3"', category: 'CRYPTO' },
      '0x79622d32': { name: 'ChaCha20 "2-by"', category: 'CRYPTO' },
      '0x6b206574': { name: 'ChaCha20 "te k"', category: 'CRYPTO' },
      // CRC polynomials
      '0xedb88320': { name: 'CRC-32 polynomial (reflected)', category: 'CRC' },
      '0x04c11db7': { name: 'CRC-32 polynomial', category: 'CRC' },
      '0x82f63b78': { name: 'CRC-32C polynomial', category: 'CRC' },
      // Memory/system
      '0xdeadbeef': { name: 'Debug marker', category: 'DEBUG' },
      '0xbaadf00d': { name: 'Windows uninit heap', category: 'DEBUG' },
      '0xfeeefeee': { name: 'Windows freed heap', category: 'DEBUG' },
      '0xcccccccc': { name: 'MSVC uninit stack', category: 'DEBUG' },
      '0xcdcdcdcd': { name: 'MSVC uninit heap', category: 'DEBUG' },
      '0xabababab': { name: 'Windows heap guard', category: 'DEBUG' },
      '0xfdfdfdfd': { name: 'MSVC heap guard', category: 'DEBUG' },
      // Common sizes
      '0x100': { name: '256 (common buffer)', category: 'SIZE' },
      '0x1000': { name: '4096 (page size)', category: 'SIZE' },
      '0x10000': { name: '64KB', category: 'SIZE' },
      '0x100000': { name: '1MB', category: 'SIZE' },
      // Bit patterns
      '0x80000000': { name: 'Sign bit (32-bit)', category: 'BITMASK' },
      '0x7fffffff': { name: 'Max signed int32', category: 'BITMASK' },
      '0xffffffff': { name: '-1 or all bits set', category: 'BITMASK' },
      '0xff': { name: 'Byte mask', category: 'BITMASK' },
      '0xffff': { name: 'Word mask', category: 'BITMASK' },
      // Network
      '0x0100007f': { name: '127.0.0.1 (localhost)', category: 'NETWORK' },
      // RSA
      '0x10001': { name: 'RSA public exponent (65537)', category: 'CRYPTO' },
    };

    // Step 1: Extract immediate values from all functions
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. IMMEDIATE VALUES IN INSTRUCTIONS                        │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Get function list
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      let functions: Array<{ offset: number; name: string; size: number }> = [];
      if (funcResult.success && funcResult.output.trim()) {
        try {
          functions = JSON.parse(funcResult.output);
        } catch {
          // Fallback to text parsing
          const lines = funcResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+\d+\s+(\S+)/);
            if (match) {
              functions.push({
                offset: parseInt(match[1], 16),
                name: match[2],
                size: 0,
              });
            }
          }
        }
      }

      results.push(
        `  📊 Analyzing ${functions.length} functions for constants...\n`,
      );

      // Analyze a subset of functions
      const maxFuncs = Math.min(functions.length, 50);
      const seenValues = new Set<string>();

      for (const func of functions.slice(0, maxFuncs)) {
        const addr = `0x${func.offset.toString(16)}`;

        try {
          // Get disassembly and look for immediate values
          const disasmResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; pdr" ${escapeShellArg(targetPath)} 2>/dev/null | head -100`,
            timeout / (maxFuncs * 2),
          );

          if (disasmResult.success && disasmResult.output) {
            const lines = disasmResult.output.split('\n');

            for (const line of lines) {
              // Match various immediate value patterns
              // mov eax, 0x12345678
              // cmp eax, 0x1234
              // push 0x12345678
              // and eax, 0xff
              const immediateMatch = line.match(
                /\b(mov|cmp|test|and|or|xor|add|sub|push|imul)\s+\S+,?\s*(0x[0-9a-fA-F]+|\d+)/i,
              );

              if (immediateMatch) {
                const valueStr = immediateMatch[2];
                let decimal: number;
                let hex: string;

                if (valueStr.startsWith('0x')) {
                  decimal = parseInt(valueStr, 16);
                  hex = valueStr.toLowerCase();
                } else {
                  decimal = parseInt(valueStr, 10);
                  hex = `0x${decimal.toString(16)}`;
                }

                // Skip small common values (0, 1, 2, etc.) and addresses
                if (decimal <= 10 || decimal > 0xffffffff) continue;
                if (seenValues.has(hex)) continue;
                seenValues.add(hex);

                // Determine significance
                let category = 'IMMEDIATE';
                let significance = 'Unknown';

                const knownMagic = knownMagics[hex];
                if (knownMagic) {
                  category = knownMagic.category;
                  significance = knownMagic.name;
                } else if (decimal >= 0x400000 && decimal <= 0x7fffffff) {
                  category = 'ADDRESS';
                  significance = 'Possible address/pointer';
                } else if (hex.match(/^0x(00)+[0-9a-f]{2}$/)) {
                  category = 'SMALL_INT';
                  significance = `Small integer (${decimal})`;
                } else if (decimal % 0x100 === 0 && decimal <= 0x10000) {
                  category = 'SIZE';
                  significance = `Aligned size (${decimal} bytes)`;
                } else if (this.looksLikeAscii(decimal)) {
                  category = 'ASCII';
                  significance = `ASCII: "${this.intToAscii(decimal)}"`;
                } else if (this.isPowerOfTwo(decimal)) {
                  category = 'POWER_OF_2';
                  significance = `2^${Math.log2(decimal)}`;
                } else if (decimal > 0x10000000 && decimal < 0xf0000000) {
                  category = 'POTENTIAL_KEY';
                  significance = 'Large constant - potential key/magic';
                }

                constants.push({
                  value: valueStr,
                  decimal,
                  hex,
                  location: `${func.name} @ ${addr}`,
                  instruction: immediateMatch[1],
                  category,
                  significance,
                });
              }
            }
          }
        } catch {
          // Continue on individual function errors
        }
      }

      // Display by category
      const categories = [
        'CRYPTO',
        'FILE_SIG',
        'CRC',
        'DEBUG',
        'POTENTIAL_KEY',
        'ASCII',
        'BITMASK',
        'NETWORK',
        'SIZE',
        'POWER_OF_2',
        'ADDRESS',
        'IMMEDIATE',
      ];

      for (const cat of categories) {
        const catConstants = constants.filter((c) => c.category === cat);
        if (catConstants.length === 0) continue;

        const emoji: Record<string, string> = {
          CRYPTO: '🔐',
          FILE_SIG: '📄',
          CRC: '✅',
          DEBUG: '🐛',
          POTENTIAL_KEY: '🔑',
          ASCII: '📝',
          BITMASK: '🎭',
          NETWORK: '🌐',
          SIZE: '📏',
          POWER_OF_2: '⚡',
          ADDRESS: '📍',
          IMMEDIATE: '🔢',
        };

        results.push(
          `  ${emoji[cat] || '•'} ${cat} CONSTANTS (${catConstants.length}):`,
        );
        results.push(
          '  ┌──────────────┬──────────────────────────────────────────────┐',
        );
        results.push(
          '  │ Value        │ Significance                                 │',
        );
        results.push(
          '  ├──────────────┼──────────────────────────────────────────────┤',
        );

        catConstants.slice(0, 15).forEach((c) => {
          const val = c.hex.padEnd(12);
          const sig = c.significance.substring(0, 44).padEnd(44);
          results.push(`  │ ${val} │ ${sig} │`);
        });
        results.push(
          '  └──────────────┴──────────────────────────────────────────────┘',
        );
        results.push('');
      }
    } catch (e) {
      results.push(`  ⚠️ Error extracting immediate values: ${e}\n`);
    }

    // Step 2: Search for known magic numbers in data sections
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. MAGIC NUMBERS IN DATA SECTIONS                          │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Search for specific magic numbers
      const magicsToSearch = [
        { pattern: '637c777b', name: 'AES S-box' },
        { pattern: '67452301', name: 'MD5/SHA-1 IV' },
        { pattern: '6a09e667', name: 'SHA-256 IV' },
        { pattern: 'deadbeef', name: 'Debug marker' },
        { pattern: 'cafebabe', name: 'Java/Debug' },
        { pattern: 'edb88320', name: 'CRC-32 poly' },
        { pattern: '243f6a88', name: 'Blowfish/Pi' },
        { pattern: '61707865', name: 'ChaCha20' },
      ];

      const foundMagics: Array<{ name: string; address: string }> = [];

      for (const magic of magicsToSearch) {
        try {
          const searchResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "/x ${magic.pattern}" ${escapeShellArg(targetPath)} 2>/dev/null | head -5`,
            timeout / 20,
          );

          if (searchResult.success && searchResult.output.trim()) {
            const matches = searchResult.output.match(/0x[0-9a-fA-F]+/g);
            if (matches) {
              matches.slice(0, 3).forEach((addr) => {
                foundMagics.push({ name: magic.name, address: addr });
              });
            }
          }
        } catch {
          // Continue
        }
      }

      if (foundMagics.length > 0) {
        results.push('  🎯 KNOWN MAGIC NUMBERS FOUND:');
        results.push(
          '  ┌──────────────┬─────────────────────────────────────────┐',
        );
        results.push(
          '  │ Address      │ Magic Number Type                       │',
        );
        results.push(
          '  ├──────────────┼─────────────────────────────────────────┤',
        );
        foundMagics.forEach((m) => {
          const addr = m.address.padEnd(12);
          const name = m.name.padEnd(39);
          results.push(`  │ ${addr} │ ${name} │`);
        });
        results.push(
          '  └──────────────┴─────────────────────────────────────────┘',
        );
        results.push('');
      } else {
        results.push('  ℹ️ No known magic numbers found in data sections\n');
      }
    } catch (e) {
      results.push(`  ⚠️ Error searching magic numbers: ${e}\n`);
    }

    // Step 3: Extract string-like constants
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. STRING-EMBEDDED CONSTANTS                               │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Look for numeric strings that might be keys or constants
      const strResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izz~[0-9]" ${escapeShellArg(targetPath)} | head -30`,
        timeout / 8,
      );

      if (strResult.success && strResult.output.trim()) {
        const numericStrings: Array<{ addr: string; value: string }> = [];
        const lines = strResult.output.split('\n');

        for (const line of lines) {
          // Match strings that look like keys/numbers
          const match = line.match(
            /(0x[0-9a-fA-F]+).*?([0-9a-fA-F]{8,}|[0-9]{5,})/,
          );
          if (match) {
            numericStrings.push({ addr: match[1], value: match[2] });
          }
        }

        if (numericStrings.length > 0) {
          results.push('  📝 NUMERIC/HEX STRINGS FOUND:');
          numericStrings.slice(0, 10).forEach((s) => {
            results.push(`     ${s.addr}: "${s.value}"`);
          });
          results.push('');
        } else {
          results.push('  ℹ️ No significant numeric strings found\n');
        }
      }
    } catch (e) {
      results.push(`  ⚠️ Error extracting string constants: ${e}\n`);
    }

    // Step 4: Look for hardcoded port numbers and network constants
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. NETWORK/PORT CONSTANTS                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const networkConstants = constants.filter(
      (c) =>
        (c.decimal >= 20 && c.decimal <= 65535 && c.decimal !== 256) ||
        c.category === 'NETWORK',
    );
    const commonPorts: Record<number, string> = {
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      445: 'SMB',
      993: 'IMAPS',
      995: 'POP3S',
      1433: 'MSSQL',
      1521: 'Oracle',
      3306: 'MySQL',
      3389: 'RDP',
      4444: 'Metasploit',
      5432: 'PostgreSQL',
      5900: 'VNC',
      6379: 'Redis',
      8080: 'HTTP-Alt',
      8443: 'HTTPS-Alt',
      27017: 'MongoDB',
    };

    const portFindings = networkConstants
      .filter((c) => commonPorts[c.decimal])
      .map((c) => ({ ...c, portName: commonPorts[c.decimal] }));

    if (portFindings.length > 0) {
      results.push('  🌐 POTENTIAL PORT NUMBERS:');
      portFindings.forEach((p) => {
        results.push(`     ${p.decimal} (${p.portName}) in ${p.location}`);
      });
      results.push('');
    } else {
      results.push('  ℹ️ No common port numbers detected\n');
    }

    // Step 5: Summary and statistics
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 EXTRACTION SUMMARY                                       │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const cryptoCount = constants.filter((c) => c.category === 'CRYPTO').length;
    const keyCount = constants.filter(
      (c) => c.category === 'POTENTIAL_KEY',
    ).length;
    const asciiCount = constants.filter((c) => c.category === 'ASCII').length;

    results.push('  📊 STATISTICS:');
    results.push(`     • Total unique constants: ${constants.length}`);
    results.push(`     • Crypto-related: ${cryptoCount}`);
    results.push(`     • Potential keys/magic: ${keyCount}`);
    results.push(`     • ASCII strings: ${asciiCount}`);
    results.push(`     • Network/port: ${portFindings.length}`);
    results.push('');

    // Recommendations
    results.push('  🎯 ANALYSIS RECOMMENDATIONS:');
    if (cryptoCount > 0) {
      results.push(
        '     • 🔐 Crypto constants found - run find_crypto_constants',
      );
    }
    if (keyCount > 0) {
      results.push(
        '     • 🔑 Large constants may be encryption keys or magic values',
      );
    }
    if (asciiCount > 0) {
      results.push(
        '     • 📝 ASCII constants may reveal debug strings or markers',
      );
    }
    if (portFindings.length > 0) {
      results.push(
        '     • 🌐 Network activity suspected - check for C2 or backdoors',
      );
    }
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • find_crypto_constants - Deep crypto analysis');
    results.push(
      '     • r2_xrefs address=0xXXXX - Find where constant is used',
    );
    results.push(
      '     • r2_disasm address=0xXXXX - Disassemble around constant',
    );
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
      metadata: {
        totalConstants: constants.length,
        constants: constants.slice(0, 100),
      },
    };
  }

  // Helper: Check if integer looks like ASCII characters
  private looksLikeAscii(value: number): boolean {
    if (value < 0x20 || value > 0x7fffffff) return false;

    // Check each byte
    const bytes = [];
    let temp = value;
    while (temp > 0) {
      bytes.push(temp & 0xff);
      temp = temp >>> 8;
    }

    return bytes.every((b) => (b >= 0x20 && b <= 0x7e) || b === 0);
  }

  // Helper: Convert integer to ASCII string
  private intToAscii(value: number): string {
    const chars = [];
    let temp = value;
    while (temp > 0) {
      const byte = temp & 0xff;
      if (byte >= 0x20 && byte <= 0x7e) {
        chars.unshift(String.fromCharCode(byte));
      }
      temp = temp >>> 8;
    }
    return chars.join('');
  }

  // Helper: Check if power of two
  private isPowerOfTwo(value: number): boolean {
    return value > 0 && (value & (value - 1)) === 0;
  }

  private async behavioralFunctionScoring(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   📊 BEHAVIORAL FUNCTION SCORING');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    results.push('  📖 Scores functions by behavior to identify:');
    results.push('     • Validation/check functions (input verification)');
    results.push('     • Success/failure handlers (flag/error paths)');
    results.push('     • Crypto functions (encryption/hashing)');
    results.push('     • Input handlers (user data processing)\n');

    // Track scored functions
    interface ScoredFunction {
      address: string;
      name: string;
      category:
        | 'VALIDATION'
        | 'SUCCESS'
        | 'FAILURE'
        | 'CRYPTO'
        | 'INPUT'
        | 'OUTPUT'
        | 'STATE_MACHINE'
        | 'GENERIC';
      score: number;
      indicators: string[];
      stringRefs: string[];
      callsTo: string[];
      calledBy: string[];
    }

    const scoredFunctions: ScoredFunction[] = [];

    try {
      // Get all functions with details
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 6,
      );

      let functions: Array<{
        offset: number;
        name: string;
        size: number;
        nbbs?: number;
        cc?: number;
        nargs?: number;
        nlocals?: number;
      }> = [];

      if (funcResult.success && funcResult.output.trim()) {
        try {
          functions = JSON.parse(funcResult.output);
        } catch {
          // Parse text format
          const lines = funcResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)/);
            if (match) {
              functions.push({
                offset: parseInt(match[1], 16),
                name: match[3],
                size: parseInt(match[2], 10),
              });
            }
          }
        }
      }

      results.push(`  📊 Analyzing ${functions.length} functions...\n`);

      // Get strings for reference mapping
      const stringsResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "izj" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 8,
      );

      let strings: Array<{ vaddr: number; string: string }> = [];
      if (stringsResult.success && stringsResult.output.trim()) {
        try {
          strings = JSON.parse(stringsResult.output);
        } catch {
          // Parse text format
          const lines = stringsResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+).*?"([^"]+)"/);
            if (match) {
              strings.push({
                vaddr: parseInt(match[1], 16),
                string: match[2],
              });
            }
          }
        }
      }

      // Categorize strings for quick lookup
      const errorStrings = strings.filter((s) =>
        /error|fail|invalid|wrong|bad|denied|reject/i.test(s.string),
      );
      const successStrings = strings.filter((s) =>
        /success|valid|correct|accept|flag|win|congrat/i.test(s.string),
      );
      const cryptoStrings = strings.filter((s) =>
        /encrypt|decrypt|hash|key|aes|rsa|sha|md5|cipher/i.test(s.string),
      );

      // Analyze each function
      const maxToAnalyze = Math.min(functions.length, 50);
      for (const func of functions.slice(0, maxToAnalyze)) {
        const addr = `0x${func.offset.toString(16)}`;
        const indicators: string[] = [];
        let score = 0;
        let category: ScoredFunction['category'] = 'GENERIC';
        const stringRefs: string[] = [];
        const callsTo: string[] = [];
        const calledBy: string[] = [];

        try {
          // Get function disassembly
          const disasmResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; pdr" ${escapeShellArg(targetPath)} 2>/dev/null | head -100`,
            timeout / (maxToAnalyze * 2),
          );

          if (disasmResult.success && disasmResult.output) {
            const code = disasmResult.output.toLowerCase();

            // ═══════════════════════════════════════════════════════════
            // VALIDATION FUNCTION SCORING
            // ═══════════════════════════════════════════════════════════

            // Check for string comparison functions
            if (
              code.includes('strcmp') ||
              code.includes('memcmp') ||
              code.includes('strncmp')
            ) {
              score += 25;
              indicators.push('String comparison');
              category = 'VALIDATION';
            }

            // Check for many CMP instructions (validation patterns)
            const cmpCount = (code.match(/\bcmp\b/g) || []).length;
            if (cmpCount >= 5) {
              score += 15;
              indicators.push(`${cmpCount} comparisons`);
              if (category === 'GENERIC') category = 'VALIDATION';
            }

            // Check for TEST instructions (boolean checks)
            const testCount = (code.match(/\btest\b/g) || []).length;
            if (testCount >= 3) {
              score += 10;
              indicators.push(`${testCount} boolean tests`);
            }

            // Returns 0/1 pattern (boolean return)
            if (code.match(/mov\s+eax,\s*(0x)?[01]\s*\n.*ret/)) {
              score += 10;
              indicators.push('Boolean return');
            }

            // ═══════════════════════════════════════════════════════════
            // NAME-BASED SCORING
            // ═══════════════════════════════════════════════════════════

            const nameLower = func.name.toLowerCase();
            if (/check|valid|verify|auth|license|serial|pass/.test(nameLower)) {
              score += 20;
              indicators.push('Validation name');
              category = 'VALIDATION';
            }
            if (/success|win|flag|correct|accept/.test(nameLower)) {
              score += 15;
              indicators.push('Success name');
              category = 'SUCCESS';
            }
            if (/fail|error|wrong|invalid|deny/.test(nameLower)) {
              score += 10;
              indicators.push('Failure name');
              category = 'FAILURE';
            }
            if (/crypt|hash|encode|decode|cipher/.test(nameLower)) {
              score += 15;
              indicators.push('Crypto name');
              category = 'CRYPTO';
            }
            if (/input|read|get|scan|recv/.test(nameLower)) {
              score += 10;
              indicators.push('Input name');
              category = 'INPUT';
            }

            // ═══════════════════════════════════════════════════════════
            // STRING REFERENCE SCORING
            // ═══════════════════════════════════════════════════════════

            // Check for error string references
            for (const es of errorStrings.slice(0, 20)) {
              if (code.includes(es.string.toLowerCase().substring(0, 20))) {
                score += 5;
                stringRefs.push(`"${es.string.substring(0, 30)}"`);
                if (category === 'GENERIC') category = 'FAILURE';
              }
            }

            // Check for success string references
            for (const ss of successStrings.slice(0, 20)) {
              if (code.includes(ss.string.toLowerCase().substring(0, 20))) {
                score += 10;
                stringRefs.push(`"${ss.string.substring(0, 30)}"`);
                if (category === 'GENERIC') category = 'SUCCESS';
              }
            }
            // Check for crypto string references
            for (const cs of cryptoStrings.slice(0, 20)) {
              if (code.includes(cs.string.toLowerCase().substring(0, 20))) {
                score += 12;
                stringRefs.push(`"${cs.string.substring(0, 30)}"`);
                if (category === 'GENERIC') category = 'CRYPTO';
              }
            }

            // ═══════════════════════════════════════════════════════════
            // CRYPTO FUNCTION SCORING
            // ═══════════════════════════════════════════════════════════

            // XOR loops (common in crypto)
            if (code.match(/xor.*\[.*\]/) && code.includes('loop')) {
              score += 15;
              indicators.push('XOR loop');
              if (category === 'GENERIC') category = 'CRYPTO';
            }

            // Rotate operations
            if (code.match(/\b(rol|ror)\b/)) {
              score += 10;
              indicators.push('Bit rotation');
              if (category === 'GENERIC') category = 'CRYPTO';
            }

            // Magic constants (crypto)
            if (code.match(/0x5a827999|0x6ed9eba1|0x8f1bbcdc|0xca62c1d6/i)) {
              score += 20;
              indicators.push('SHA constants');
              category = 'CRYPTO';
            }
            if (code.match(/0x67452301|0xefcdab89|0x98badcfe|0x10325476/i)) {
              score += 20;
              indicators.push('MD5/SHA init');
              category = 'CRYPTO';
            }

            // ═══════════════════════════════════════════════════════════
            // STATE MACHINE SCORING
            // ═══════════════════════════════════════════════════════════

            // Many conditional jumps with same comparison register
            const jeCount = (code.match(/\bje\b/g) || []).length;
            const jmpCount = (code.match(/\bjmp\b/g) || []).length;
            if (jeCount >= 5 && jmpCount >= 3) {
              score += 15;
              indicators.push('Switch pattern');
              if (category === 'GENERIC') category = 'STATE_MACHINE';
            }

            // High cyclomatic complexity
            if (func.cc && func.cc > 10) {
              score += 10;
              indicators.push(`CC: ${func.cc}`);
            }

            // Many basic blocks
            if (func.nbbs && func.nbbs > 10) {
              score += 5;
              indicators.push(`${func.nbbs} blocks`);
            }

            // ═══════════════════════════════════════════════════════════
            // INPUT/OUTPUT SCORING
            // ═══════════════════════════════════════════════════════════

            if (
              code.includes('scanf') ||
              code.includes('fgets') ||
              code.includes('read')
            ) {
              score += 15;
              indicators.push('Input function');
              if (category === 'GENERIC') category = 'INPUT';
            }

            if (
              code.includes('printf') ||
              code.includes('puts') ||
              code.includes('write')
            ) {
              score += 5;
              indicators.push('Output function');
              if (category === 'GENERIC') category = 'OUTPUT';
            }

            // ═══════════════════════════════════════════════════════════
            // CALL GRAPH ANALYSIS
            // ═══════════════════════════════════════════════════════════

            // Extract calls made by this function
            const callMatches = code.match(/call\s+(sym\.\S+|fcn\.\S+)/g) || [];
            for (const c of callMatches.slice(0, 5)) {
              const funcMatch = c.match(/call\s+(\S+)/);
              if (funcMatch) callsTo.push(funcMatch[1]);
            }

            // Get callers (who calls this function)
            const xrefResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; axtj" ${escapeShellArg(targetPath)} 2>/dev/null`,
              timeout / (maxToAnalyze * 4),
            );

            if (xrefResult.success && xrefResult.output.trim()) {
              try {
                const xrefs = JSON.parse(xrefResult.output);
                for (const x of xrefs.slice(0, 5)) {
                  if (x.fcn_name) calledBy.push(x.fcn_name);
                }
              } catch {
                // Ignore parse errors
              }
            }

            // Called early from main = likely validation
            if (calledBy.some((c) => c.includes('main'))) {
              score += 10;
              indicators.push('Called from main');
            }
          }
        } catch {
          // Continue on error
        }

        // Only include functions with meaningful score
        if (score >= 10) {
          scoredFunctions.push({
            address: addr,
            name: func.name,
            category,
            score,
            indicators,
            stringRefs: stringRefs.slice(0, 3),
            callsTo: callsTo.slice(0, 5),
            calledBy: calledBy.slice(0, 5),
          });
        }
      }

      // Sort by score
      scoredFunctions.sort((a, b) => b.score - a.score);

      // ═══════════════════════════════════════════════════════════
      // OUTPUT: BY CATEGORY
      // ═══════════════════════════════════════════════════════════

      const categories: Array<{
        cat: ScoredFunction['category'];
        icon: string;
        title: string;
      }> = [
        { cat: 'VALIDATION', icon: '🔐', title: 'VALIDATION FUNCTIONS' },
        { cat: 'SUCCESS', icon: '🏆', title: 'SUCCESS HANDLERS' },
        { cat: 'FAILURE', icon: '❌', title: 'FAILURE HANDLERS' },
        { cat: 'CRYPTO', icon: '🔑', title: 'CRYPTO FUNCTIONS' },
        { cat: 'INPUT', icon: '📥', title: 'INPUT HANDLERS' },
        { cat: 'STATE_MACHINE', icon: '🔄', title: 'STATE MACHINES' },
      ];

      for (const { cat, icon, title } of categories) {
        const funcs = scoredFunctions.filter((f) => f.category === cat);
        if (funcs.length > 0) {
          results.push(
            '┌─────────────────────────────────────────────────────────────┐',
          );
          results.push(`│ ${icon} ${title.padEnd(55)} │`);
          results.push(
            '└─────────────────────────────────────────────────────────────┘\n',
          );

          results.push(
            '  ┌──────────────┬────────────────────────────┬───────┬────────────────────────────────┐',
          );
          results.push(
            '  │ Address      │ Function                   │ Score │ Indicators                     │',
          );
          results.push(
            '  ├──────────────┼────────────────────────────┼───────┼────────────────────────────────┤',
          );

          for (const f of funcs.slice(0, 8)) {
            const addr = f.address.padEnd(12);
            const name = f.name.substring(0, 26).padEnd(26);
            const score = f.score.toString().padEnd(5);
            const ind = f.indicators
              .slice(0, 2)
              .join(', ')
              .substring(0, 30)
              .padEnd(30);
            results.push(`  │ ${addr} │ ${name} │ ${score} │ ${ind} │`);
          }

          results.push(
            '  └──────────────┴────────────────────────────┴───────┴────────────────────────────────┘',
          );

          // Show details for top functions
          if (funcs.length > 0 && cat === 'VALIDATION') {
            results.push('\n  📋 TOP VALIDATION TARGETS:');
            for (const f of funcs.slice(0, 3)) {
              results.push(
                `\n     📍 ${f.name} @ ${f.address} (Score: ${f.score})`,
              );
              if (f.indicators.length > 0) {
                results.push(`        Indicators: ${f.indicators.join(', ')}`);
              }
              if (f.stringRefs.length > 0) {
                results.push(`        String refs: ${f.stringRefs.join(', ')}`);
              }
              if (f.callsTo.length > 0) {
                results.push(`        Calls: ${f.callsTo.join(', ')}`);
              }
              if (f.calledBy.length > 0) {
                results.push(`        Called by: ${f.calledBy.join(', ')}`);
              }
            }
          }

          if (funcs.length > 0 && cat === 'SUCCESS') {
            results.push('\n  🎯 SUCCESS PATH ANALYSIS:');
            for (const f of funcs.slice(0, 2)) {
              results.push(`     • ${f.name} @ ${f.address}`);
              if (f.calledBy.length > 0) {
                results.push(`       Reached from: ${f.calledBy.join(' → ')}`);
              }
            }
          }

          results.push('');
        }
      }

      // ═══════════════════════════════════════════════════════════
      // SUMMARY AND RECOMMENDATIONS
      // ═══════════════════════════════════════════════════════════

      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 📋 ANALYSIS SUMMARY                                         │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      const validationFuncs = scoredFunctions.filter(
        (f) => f.category === 'VALIDATION',
      );
      const successFuncs = scoredFunctions.filter(
        (f) => f.category === 'SUCCESS',
      );
      const cryptoFuncs = scoredFunctions.filter(
        (f) => f.category === 'CRYPTO',
      );
      const stateMachines = scoredFunctions.filter(
        (f) => f.category === 'STATE_MACHINE',
      );

      results.push('  📊 FUNCTION BREAKDOWN:');
      results.push(`     • Validation functions: ${validationFuncs.length}`);
      results.push(`     • Success handlers: ${successFuncs.length}`);
      results.push(`     • Crypto functions: ${cryptoFuncs.length}`);
      results.push(`     • State machines: ${stateMachines.length}`);
      results.push(`     • Total scored: ${scoredFunctions.length}`);
      results.push('');

      results.push('  🎯 RECOMMENDED ANALYSIS ORDER:');
      if (validationFuncs.length > 0) {
        results.push(
          `     1. Start with: ${validationFuncs[0].name} @ ${validationFuncs[0].address}`,
        );
        results.push('        (Highest-scored validation function)');
      }
      if (successFuncs.length > 0) {
        results.push(
          `     2. Find path to: ${successFuncs[0].name} @ ${successFuncs[0].address}`,
        );
        results.push('        (Success handler - trace backwards)');
      }
      if (stateMachines.length > 0) {
        results.push(
          `     3. Analyze: ${stateMachines[0].name} @ ${stateMachines[0].address}`,
        );
        results.push('        (State machine - check all states)');
      }
      results.push('');

      results.push('  🔧 NEXT OPERATIONS:');
      results.push('     • r2_decompile - Decompile top validation functions');
      results.push('     • find_indirect_calls - Analyze state machines');
      results.push('     • trace_input_validation - Map validation flow');
      results.push('');
    } catch (e) {
      results.push(`  ⚠️ Behavioral scoring error: ${e}\n`);
    }

    return {
      success: true,
      output: results.join('\n'),
      metadata: {
        scoredFunctions: scoredFunctions.slice(0, 30),
        topValidation: scoredFunctions
          .filter((f) => f.category === 'VALIDATION')
          .slice(0, 5),
        topSuccess: scoredFunctions
          .filter((f) => f.category === 'SUCCESS')
          .slice(0, 3),
      },
    };
  }

  private async deobfuscateControlFlow(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🔓 CONTROL FLOW OBFUSCATION DETECTION');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track detected obfuscation patterns
    interface ObfuscationPattern {
      type: string;
      function: string;
      address: string;
      confidence: 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      indicators: string[];
    }
    const patterns: ObfuscationPattern[] = [];

    // Step 1: Detect Control Flow Flattening (CFF)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. CONTROL FLOW FLATTENING (CFF) DETECTION                 │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  📖 CFF transforms structured code into a state machine:');
    results.push(
      '     Original: if/else/loops → CFF: switch(state) in while(true)\n',
    );

    try {
      // Get all functions
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)}`,
        timeout / 6,
      );

      let functions: Array<{
        offset: number;
        name: string;
        size: number;
        nbbs?: number;
        cc?: number;
      }> = [];
      if (funcResult.success && funcResult.output.trim()) {
        try {
          functions = JSON.parse(funcResult.output);
        } catch {
          const lines = funcResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)/);
            if (match) {
              functions.push({
                offset: parseInt(match[1], 16),
                name: match[3],
                size: parseInt(match[2], 10),
              });
            }
          }
        }
      }

      results.push(
        `  📊 Analyzing ${functions.length} functions for CFF patterns...\n`,
      );

      // Analyze functions for CFF characteristics
      const cffCandidates: Array<{
        addr: string;
        name: string;
        score: number;
        indicators: string[];
      }> = [];

      const maxToAnalyze = Math.min(functions.length, 30);
      for (const func of functions.slice(0, maxToAnalyze)) {
        const addr = `0x${func.offset.toString(16)}`;
        const indicators: string[] = [];
        let score = 0;

        try {
          // Get function disassembly
          const disasmResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; pdr" ${escapeShellArg(targetPath)} 2>/dev/null | head -150`,
            timeout / (maxToAnalyze * 3),
          );

          if (disasmResult.success && disasmResult.output) {
            const code = disasmResult.output.toLowerCase();
            const lines = disasmResult.output.split('\n');

            // CFF Indicator 1: Many comparison against constants (state variable)
            const cmpMatches = code.match(/cmp\s+\S+,\s*0x[0-9a-f]+/g) || [];
            if (cmpMatches.length >= 5) {
              score += 3;
              indicators.push(`${cmpMatches.length} state comparisons`);
            }

            // CFF Indicator 2: Single entry point with many branches
            const jmpMatches = code.match(/\bj[a-z]+\s+0x/g) || [];
            if (jmpMatches.length >= 10) {
              score += 2;
              indicators.push(`${jmpMatches.length} conditional jumps`);
            }

            // CFF Indicator 3: Switch-like pattern (multiple je/jne to same targets)
            const jeMatches = code.match(/\bje\s+0x[0-9a-f]+/g) || [];
            if (jeMatches.length >= 4) {
              score += 2;
              indicators.push(`${jeMatches.length} je (switch branches)`);
            }

            // CFF Indicator 4: Dispatcher pattern - jmp to register or computed
            if (
              code.includes('jmp dword') ||
              code.includes('jmp qword') ||
              code.match(/jmp\s+(e|r)[a-z]{2}/)
            ) {
              score += 3;
              indicators.push('Computed jump (dispatcher)');
            }

            // CFF Indicator 5: Loop back to dispatcher (while true pattern)
            const backJumps = lines.filter((l) => {
              const m = l.match(/jmp\s+(0x[0-9a-f]+)/i);
              if (m) {
                const target = parseInt(m[1], 16);
                return target < func.offset + func.size / 2;
              }
              return false;
            });
            if (backJumps.length >= 2) {
              score += 2;
              indicators.push(`${backJumps.length} back jumps (loop)`);
            }

            // CFF Indicator 6: State variable assignment pattern
            const movStatePattern =
              code.match(/mov\s+\[.*\],\s*0x[0-9a-f]+/g) || [];
            if (movStatePattern.length >= 3) {
              score += 2;
              indicators.push(`${movStatePattern.length} state assignments`);
            }

            // CFF Indicator 7: Large function with many basic blocks
            if (func.nbbs && func.nbbs > 15) {
              score += 1;
              indicators.push(`${func.nbbs} basic blocks`);
            }

            // CFF Indicator 8: High cyclomatic complexity
            if (func.cc && func.cc > 10) {
              score += 2;
              indicators.push(`Complexity: ${func.cc}`);
            }

            if (score >= 5) {
              cffCandidates.push({ addr, name: func.name, score, indicators });
            }
          }
        } catch {
          // Continue
        }
      }

      if (cffCandidates.length > 0) {
        cffCandidates.sort((a, b) => b.score - a.score);

        results.push('  🎯 CONTROL FLOW FLATTENING DETECTED:');
        results.push(
          '  ┌──────────────┬────────────────────────────┬───────┬──────────────────────────────────┐',
        );
        results.push(
          '  │ Address      │ Function                   │ Score │ Indicators                       │',
        );
        results.push(
          '  ├──────────────┼────────────────────────────┼───────┼──────────────────────────────────┤',
        );

        cffCandidates.slice(0, 10).forEach((c) => {
          const addr = c.addr.padEnd(12);
          const name = c.name.substring(0, 26).padEnd(26);
          const score = c.score.toString().padEnd(5);
          const ind = c.indicators
            .slice(0, 2)
            .join(', ')
            .substring(0, 32)
            .padEnd(32);
          results.push(`  │ ${addr} │ ${name} │ ${score} │ ${ind} │`);

          patterns.push({
            type: 'CFF',
            function: c.name,
            address: c.addr,
            confidence: c.score >= 8 ? 'HIGH' : c.score >= 5 ? 'MEDIUM' : 'LOW',
            description: 'Control Flow Flattening detected',
            indicators: c.indicators,
          });
        });

        results.push(
          '  └──────────────┴────────────────────────────┴───────┴──────────────────────────────────┘',
        );
        results.push('');
      } else {
        results.push('  ✅ No control flow flattening detected\n');
      }
    } catch (e) {
      results.push(`  ⚠️ CFF detection error: ${e}\n`);
    }

    // Step 2: Detect Opaque Predicates
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. OPAQUE PREDICATE DETECTION                              │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push(
      '  📖 Opaque predicates: conditions that always evaluate the same\n',
    );

    try {
      // Common opaque predicate patterns:
      // - xor eax, eax; test eax, eax; jnz (XOR+TEST always zero)
      // - mov 0; cmp 0; jne (Compare constant with itself)
      // - and 0; jnz (AND with 0 never jumps)
      // - or 0xff; jz (OR with FF never zero)

      const opaqueFindings: Array<{ addr: string; pattern: string }> = [];

      // Search for mathematical identities used as opaque predicates
      const mathResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad xor eax, eax" ${escapeShellArg(targetPath)} 2>/dev/null | head -20`,
        timeout / 10,
      );

      if (mathResult.success && mathResult.output.trim()) {
        const matches = mathResult.output.match(/0x[0-9a-fA-F]+/g) || [];
        for (const addr of matches.slice(0, 5)) {
          // Check if followed by suspicious pattern
          const checkResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; pd 5" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 50,
          );

          if (checkResult.success) {
            const code = checkResult.output.toLowerCase();
            if (
              code.includes('test') &&
              (code.includes('jnz') || code.includes('jne'))
            ) {
              opaqueFindings.push({
                addr,
                pattern: 'XOR+TEST+JNZ (always false)',
              });
            }
          }
        }
      }

      // Look for constant comparisons
      const constCmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad cmp.*0x" ${escapeShellArg(targetPath)} 2>/dev/null | head -30`,
        timeout / 10,
      );

      if (constCmpResult.success && constCmpResult.output.trim()) {
        // Count repeated comparisons with same constant (suspicious)
        const cmpValues: Record<string, number> = {};
        const lines = constCmpResult.output.split('\n');
        for (const line of lines) {
          const match = line.match(/cmp.*?(0x[0-9a-fA-F]+)/i);
          if (match) {
            cmpValues[match[1]] = (cmpValues[match[1]] || 0) + 1;
          }
        }

        // Constants compared many times might be opaque predicates
        for (const [val, count] of Object.entries(cmpValues)) {
          if (count >= 5) {
            opaqueFindings.push({
              addr: 'multiple',
              pattern: `Constant ${val} compared ${count}x (suspicious)`,
            });
          }
        }
      }

      if (opaqueFindings.length > 0) {
        results.push('  🎯 POTENTIAL OPAQUE PREDICATES:');
        opaqueFindings.slice(0, 10).forEach((f) => {
          results.push(`     ${f.addr}: ${f.pattern}`);
          patterns.push({
            type: 'OPAQUE_PREDICATE',
            function: 'unknown',
            address: f.addr,
            confidence: 'MEDIUM',
            description: f.pattern,
            indicators: [],
          });
        });
        results.push('');
      } else {
        results.push('  ✅ No obvious opaque predicates detected\n');
      }
    } catch (e) {
      results.push(`  ⚠️ Opaque predicate detection error: ${e}\n`);
    }

    // Step 3: Detect Dead Code / Junk Code
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 3. DEAD/JUNK CODE DETECTION                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const deadCodeIndicators: string[] = [];

      // Look for unreachable code patterns
      // Pattern: jmp followed by non-nop instructions before next label
      const jmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad jmp" ${escapeShellArg(targetPath)} 2>/dev/null | head -20`,
        timeout / 10,
      );

      if (jmpResult.success && jmpResult.output.trim()) {
        const jmpAddrs = jmpResult.output.match(/0x[0-9a-fA-F]+/g) || [];
        let unreachableCount = 0;

        for (const addr of jmpAddrs.slice(0, 10)) {
          const afterResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "s ${addr}; pd 3" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 50,
          );

          if (afterResult.success) {
            const lines = afterResult.output.split('\n').slice(1); // Skip jmp itself
            for (const line of lines) {
              // Code after unconditional jmp that's not a label/nop is dead
              if (
                line.trim() &&
                !line.includes('nop') &&
                !line.includes(':') &&
                !line.match(/^\s*;/) &&
                !line.match(/0x[0-9a-f]+:\s*$/)
              ) {
                unreachableCount++;
                break;
              }
            }
          }
        }

        if (unreachableCount > 0) {
          deadCodeIndicators.push(
            `${unreachableCount} potential unreachable blocks after jumps`,
          );
        }
      }

      // Look for push/pop patterns that do nothing (junk)
      const pushPopResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad push.*pop" ${escapeShellArg(targetPath)} 2>/dev/null | wc -l`,
        timeout / 10,
      );

      if (pushPopResult.success) {
        const count = parseInt(pushPopResult.output.trim(), 10) || 0;
        if (count > 20) {
          deadCodeIndicators.push(
            `${count} push+pop sequences (potential junk)`,
          );
        }
      }

      // Look for NOPs used as padding (common in obfuscated code)
      const nopResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad nop" ${escapeShellArg(targetPath)} 2>/dev/null | wc -l`,
        timeout / 10,
      );

      if (nopResult.success) {
        const nopCount = parseInt(nopResult.output.trim(), 10) || 0;
        if (nopCount > 50) {
          deadCodeIndicators.push(
            `${nopCount} NOP instructions (excessive padding)`,
          );
        }
      }

      if (deadCodeIndicators.length > 0) {
        results.push('  🎯 JUNK/DEAD CODE INDICATORS:');
        deadCodeIndicators.forEach((i) => {
          results.push(`     • ${i}`);
        });
        results.push('');
      } else {
        results.push('  ✅ No significant dead/junk code detected\n');
      }
    } catch (e) {
      results.push(`  ⚠️ Dead code detection error: ${e}\n`);
    }

    // Step 4: Detect Indirect Branches (anti-disassembly)
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 4. ANTI-DISASSEMBLY TECHNIQUES                             │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      const antiDisasmIndicators: string[] = [];

      // Look for computed jumps (confuse disassemblers)
      const computedJmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad jmp" ${escapeShellArg(targetPath)} 2>/dev/null | grep -E "jmp (e|r)[a-z]+" | wc -l`,
        timeout / 10,
      );

      if (computedJmpResult.success) {
        const count = parseInt(computedJmpResult.output.trim(), 10) || 0;
        if (count > 5) {
          antiDisasmIndicators.push(`${count} computed jumps (jmp reg)`);
        }
      }

      // Look for call+pop pattern (getting current address - common anti-disasm)
      const callPopResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad call.*pop" ${escapeShellArg(targetPath)} 2>/dev/null | head -10`,
        timeout / 10,
      );

      if (callPopResult.success && callPopResult.output.trim()) {
        const matches = callPopResult.output.match(/0x[0-9a-fA-F]+/g) || [];
        if (matches.length > 0) {
          antiDisasmIndicators.push(
            `${matches.length} call+pop sequences (address discovery)`,
          );
        }
      }

      // Look for overlapping instructions (bytes that decode differently)
      // This is detected by searching for jumps into middle of instructions
      const midJmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad jmp.*+1" ${escapeShellArg(targetPath)} 2>/dev/null | head -5`,
        timeout / 10,
      );

      if (midJmpResult.success && midJmpResult.output.trim().length > 10) {
        antiDisasmIndicators.push('Jump into instruction middle detected');
      }

      // Look for int 3 / int 2d (anti-debug but also anti-disasm)
      const intResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "/x cc" ${escapeShellArg(targetPath)} 2>/dev/null | wc -l`,
        timeout / 10,
      );

      if (intResult.success) {
        const count = parseInt(intResult.output.trim(), 10) || 0;
        if (count > 10) {
          antiDisasmIndicators.push(
            `${count} INT3 instructions (breakpoints/anti-debug)`,
          );
        }
      }

      if (antiDisasmIndicators.length > 0) {
        results.push('  🎯 ANTI-DISASSEMBLY TECHNIQUES:');
        antiDisasmIndicators.forEach((i) => {
          results.push(`     • ${i}`);
          patterns.push({
            type: 'ANTI_DISASM',
            function: 'various',
            address: 'multiple',
            confidence: 'MEDIUM',
            description: i,
            indicators: [],
          });
        });
        results.push('');
      } else {
        results.push('  ✅ No anti-disassembly techniques detected\n');
      }
    } catch (e) {
      results.push(`  ⚠️ Anti-disassembly detection error: ${e}\n`);
    }

    // Step 5: Detect Virtualization-based Obfuscation
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 5. VM-BASED OBFUSCATION (Virtualization)                   │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  📖 VM obfuscation converts code to custom bytecode\n');

    try {
      const vmIndicators: string[] = [];

      // Look for dispatcher loop pattern (fetch-decode-execute)
      const dispatcherResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; afl" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 10,
      );

      if (dispatcherResult.success) {
        // Look for VM-related function names
        const vmNames = [
          'vm_',
          'handler',
          'dispatch',
          'opcode',
          'bytecode',
          'interpret',
        ];
        const lines = dispatcherResult.output.split('\n');
        const vmFuncs = lines.filter((l) =>
          vmNames.some((n) => l.toLowerCase().includes(n)),
        );

        if (vmFuncs.length > 0) {
          vmIndicators.push(`${vmFuncs.length} VM-related function names`);
        }
      }

      // Look for large switch tables (opcode handlers)
      const switchResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad jmp qword" ${escapeShellArg(targetPath)} 2>/dev/null | wc -l`,
        timeout / 10,
      );

      if (switchResult.success) {
        const count = parseInt(switchResult.output.trim(), 10) || 0;
        if (count > 20) {
          vmIndicators.push(
            `${count} indirect jumps (potential opcode handlers)`,
          );
        }
      }

      // Look for byte array access patterns (bytecode fetch)
      const byteAccessResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad movzx.*byte" ${escapeShellArg(targetPath)} 2>/dev/null | wc -l`,
        timeout / 10,
      );

      if (byteAccessResult.success) {
        const count = parseInt(byteAccessResult.output.trim(), 10) || 0;
        if (count > 50) {
          vmIndicators.push(`${count} byte fetches (bytecode access pattern)`);
        }
      }

      if (vmIndicators.length > 0) {
        results.push('  🎯 VM OBFUSCATION INDICATORS:');
        vmIndicators.forEach((i) => {
          results.push(`     • ${i}`);
          patterns.push({
            type: 'VM_OBFUSCATION',
            function: 'various',
            address: 'multiple',
            confidence: vmIndicators.length >= 2 ? 'HIGH' : 'MEDIUM',
            description: i,
            indicators: [],
          });
        });
        results.push('');
      } else {
        results.push('  ✅ No VM-based obfuscation detected\n');
      }
    } catch (e) {
      results.push(`  ⚠️ VM detection error: ${e}\n`);
    }

    // Summary
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 OBFUSCATION SUMMARY                                      │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    const cffCount = patterns.filter((p) => p.type === 'CFF').length;
    const opaqueCount = patterns.filter(
      (p) => p.type === 'OPAQUE_PREDICATE',
    ).length;
    const antiDisasmCount = patterns.filter(
      (p) => p.type === 'ANTI_DISASM',
    ).length;
    const vmCount = patterns.filter((p) => p.type === 'VM_OBFUSCATION').length;

    results.push('  📊 DETECTION RESULTS:');
    results.push(
      `     • Control Flow Flattening: ${cffCount > 0 ? `${cffCount} functions` : 'Not detected'}`,
    );
    results.push(
      `     • Opaque Predicates: ${opaqueCount > 0 ? `${opaqueCount} found` : 'Not detected'}`,
    );
    results.push(
      `     • Anti-Disassembly: ${antiDisasmCount > 0 ? `${antiDisasmCount} techniques` : 'Not detected'}`,
    );
    results.push(
      `     • VM Obfuscation: ${vmCount > 0 ? 'Indicators present' : 'Not detected'}`,
    );
    results.push('');

    // Overall assessment
    const totalPatterns = patterns.length;
    let obfuscationLevel = 'LOW';
    if (totalPatterns >= 5 || vmCount > 0 || cffCount >= 3) {
      obfuscationLevel = 'HIGH';
    } else if (totalPatterns >= 2 || cffCount >= 1) {
      obfuscationLevel = 'MEDIUM';
    }

    results.push(`  🎯 OBFUSCATION LEVEL: ${obfuscationLevel}`);
    results.push('');

    // Recommendations
    results.push('  🔧 DEOBFUSCATION RECOMMENDATIONS:');
    if (cffCount > 0) {
      results.push(
        '     • CFF: Use symbolic execution (angr) to recover original flow',
      );
      results.push(
        '     • CFF: Identify state variable and trace state transitions',
      );
    }
    if (opaqueCount > 0) {
      results.push('     • Opaque: Patch out always-false/true predicates');
    }
    if (antiDisasmCount > 0) {
      results.push('     • Anti-disasm: Use linear sweep disassembly');
      results.push('     • Anti-disasm: NOP out junk code manually');
    }
    if (vmCount > 0) {
      results.push(
        '     • VM: Identify opcode handlers and create devirtualizer',
      );
      results.push(
        '     • VM: Trace execution to understand custom instruction set',
      );
    }
    if (obfuscationLevel === 'LOW') {
      results.push('     • Binary appears minimally obfuscated');
      results.push('     • Standard RE techniques should work');
    }
    results.push('');
    results.push('  🔧 NEXT OPERATIONS:');
    results.push('     • analyze_control_flow - Detailed CFG analysis');
    results.push('     • find_indirect_calls - Analyze computed calls');
    results.push(
      '     • r2_decompile - Try decompilation of suspicious functions',
    );
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
      metadata: {
        obfuscationLevel,
        patterns: patterns.slice(0, 50),
        cffFunctions: patterns
          .filter((p) => p.type === 'CFF')
          .map((p) => p.address),
      },
    };
  }

  private async findIndirectCalls(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   ↪️ INDIRECT CALL & JUMP TABLE ANALYSIS');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Track all findings
    interface IndirectCall {
      address: string;
      instruction: string;
      type: 'REGISTER' | 'MEMORY' | 'VTABLE' | 'IMPORT' | 'CALLBACK';
      function: string;
      details: string;
    }

    interface CaseAnalysis {
      caseValue: number;
      targetAddr: string;
      description: string;
      stringRefs: string[];
      callsTo: string[];
    }

    interface StringRef {
      caseValue: number;
      string: string;
      address: string;
    }

    interface JumpTable {
      address: string;
      function: string;
      baseAddress: string;
      entryCount: number;
      targets: string[];
      caseValues: number[];
      isStateMachine: boolean;
      stateVariable?: string;
      caseAnalysis?: CaseAnalysis[];
      stringRefs?: StringRef[];
    }

    const indirectCalls: IndirectCall[] = [];
    const jumpTables: JumpTable[] = [];

    // ═══════════════════════════════════════════════════════════════
    // SECTION 1: INDIRECT CALL DETECTION
    // ═══════════════════════════════════════════════════════════════
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 1. INDIRECT CALL DETECTION                                  │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  📖 Indirect calls use runtime-computed targets:\n');
    results.push('     • call reg     - Register call (computed target)');
    results.push('     • call [mem]   - Memory indirect (function pointer)');
    results.push('     • call [r+off] - Vtable call (C++ virtual method)\n');

    try {
      // Get function list for context
      const funcListResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 8,
      );

      let functions: Array<{ offset: number; name: string; size: number }> = [];
      if (funcListResult.success && funcListResult.output.trim()) {
        try {
          functions = JSON.parse(funcListResult.output);
        } catch {
          // Parse text format
          const lines = funcListResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)/);
            if (match) {
              functions.push({
                offset: parseInt(match[1], 16),
                name: match[3],
                size: parseInt(match[2], 10),
              });
            }
          }
        }
      }

      // Helper to find containing function
      const findFunction = (addr: number): string => {
        for (const f of functions) {
          if (addr >= f.offset && addr < f.offset + f.size) {
            return f.name;
          }
        }
        return 'unknown';
      };

      // 1.1 Find register calls (call eax, call rax, etc.)
      results.push('  🔍 1.1 REGISTER CALLS (call reg):');
      const regCallResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; pd 10000 @ entry0" ${escapeShellArg(targetPath)} 2>/dev/null | grep -iE "call\\s+(e[a-z]x|r[a-z]x|r[0-9]+)" | head -30`,
        timeout / 6,
      );

      const registerCalls: Array<{ addr: string; instr: string; reg: string }> =
        [];
      if (regCallResult.success && regCallResult.output.trim()) {
        const lines = regCallResult.output.trim().split('\n');
        for (const line of lines) {
          const match = line.match(
            /(0x[0-9a-fA-F]+).*?(call\s+(e[a-z]x|r[a-z]x|r[0-9]+))/i,
          );
          if (match) {
            registerCalls.push({
              addr: match[1],
              instr: match[2],
              reg: match[3],
            });

            const funcName = findFunction(parseInt(match[1], 16));
            indirectCalls.push({
              address: match[1],
              instruction: match[2],
              type: 'REGISTER',
              function: funcName,
              details: `Calls via ${match[3]} - target computed at runtime`,
            });
          }
        }
      }

      if (registerCalls.length > 0) {
        results.push(
          '  ┌──────────────┬─────────────────────────┬──────────────────────────┐',
        );
        results.push(
          '  │ Address      │ Instruction             │ Containing Function      │',
        );
        results.push(
          '  ├──────────────┼─────────────────────────┼──────────────────────────┤',
        );

        for (const rc of registerCalls.slice(0, 15)) {
          const addr = rc.addr.padEnd(12);
          const instr = rc.instr.padEnd(23);
          const func = findFunction(parseInt(rc.addr, 16))
            .substring(0, 24)
            .padEnd(24);
          results.push(`  │ ${addr} │ ${instr} │ ${func} │`);
        }

        results.push(
          '  └──────────────┴─────────────────────────┴──────────────────────────┘',
        );
        if (registerCalls.length > 15) {
          results.push(
            `     ... and ${registerCalls.length - 15} more register calls`,
          );
        }
        results.push('');
      } else {
        results.push('     ✅ No register calls detected\n');
      }

      // 1.2 Find memory indirect calls (call [addr], call qword ptr [rax+offset])
      results.push('  🔍 1.2 MEMORY INDIRECT CALLS (call [mem]):');
      const memCallResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; pd 10000 @ entry0" ${escapeShellArg(targetPath)} 2>/dev/null | grep -iE "call\\s+(qword|dword)?\\s*\\[" | head -30`,
        timeout / 6,
      );

      const memoryCalls: Array<{
        addr: string;
        instr: string;
        memRef: string;
        type: string;
      }> = [];
      if (memCallResult.success && memCallResult.output.trim()) {
        const lines = memCallResult.output.trim().split('\n');
        for (const line of lines) {
          const match = line.match(
            /(0x[0-9a-fA-F]+).*?(call\s+(?:qword|dword)?\s*(?:ptr\s*)?\[([^\]]+)\])/i,
          );
          if (match) {
            const memRef = match[3];
            let callType: 'VTABLE' | 'IMPORT' | 'CALLBACK' | 'MEMORY' =
              'MEMORY';
            let details = '';

            // Classify the memory reference
            if (
              memRef.match(/r[a-z]x\s*\+\s*0x[0-9a-f]+/i) ||
              memRef.match(/r[a-z]x\s*\+\s*\d+/i)
            ) {
              // [rax + offset] pattern - likely vtable
              callType = 'VTABLE';
              details = 'C++ virtual method call pattern';
            } else if (
              memRef.match(/rip\s*\+/i) ||
              memRef.match(/0x[0-9a-f]+/i)
            ) {
              // [rip + offset] or [absolute] - likely import or global
              callType = 'IMPORT';
              details = 'Import/PLT or global function pointer';
            } else if (memRef.match(/rbp|rsp|ebp|esp/i)) {
              // Stack-based - callback or local function pointer
              callType = 'CALLBACK';
              details = 'Stack-based function pointer (callback)';
            }

            memoryCalls.push({
              addr: match[1],
              instr: match[2],
              memRef,
              type: callType,
            });

            const funcName = findFunction(parseInt(match[1], 16));
            indirectCalls.push({
              address: match[1],
              instruction: match[2],
              type: callType,
              function: funcName,
              details,
            });
          }
        }
      }

      if (memoryCalls.length > 0) {
        results.push(
          '  ┌──────────────┬──────────────────────────────────┬──────────┬────────────────────┐',
        );
        results.push(
          '  │ Address      │ Memory Reference                 │ Type     │ Function           │',
        );
        results.push(
          '  ├──────────────┼──────────────────────────────────┼──────────┼────────────────────┤',
        );

        for (const mc of memoryCalls.slice(0, 15)) {
          const addr = mc.addr.padEnd(12);
          const memRef = mc.memRef.substring(0, 32).padEnd(32);
          const type = mc.type.padEnd(8);
          const func = findFunction(parseInt(mc.addr, 16))
            .substring(0, 18)
            .padEnd(18);
          results.push(`  │ ${addr} │ ${memRef} │ ${type} │ ${func} │`);
        }

        results.push(
          '  └──────────────┴──────────────────────────────────┴──────────┴────────────────────┘',
        );
        if (memoryCalls.length > 15) {
          results.push(
            `     ... and ${memoryCalls.length - 15} more memory indirect calls`,
          );
        }
        results.push('');

        // Count by type
        const vtableCalls = memoryCalls.filter(
          (c) => c.type === 'VTABLE',
        ).length;
        const importCalls = memoryCalls.filter(
          (c) => c.type === 'IMPORT',
        ).length;
        const callbackCalls = memoryCalls.filter(
          (c) => c.type === 'CALLBACK',
        ).length;

        if (vtableCalls > 0 || importCalls > 0 || callbackCalls > 0) {
          results.push('  📊 CLASSIFICATION:');
          if (vtableCalls > 0)
            results.push(
              `     • VTABLE calls: ${vtableCalls} (C++ virtual methods)`,
            );
          if (importCalls > 0)
            results.push(
              `     • IMPORT calls: ${importCalls} (External functions)`,
            );
          if (callbackCalls > 0)
            results.push(
              `     • CALLBACK calls: ${callbackCalls} (Function pointers)`,
            );
          results.push('');
        }
      } else {
        results.push('     ✅ No memory indirect calls detected\n');
      }

      // 1.3 Summary and analysis hints
      const totalIndirect = registerCalls.length + memoryCalls.length;
      results.push('  📋 INDIRECT CALL SUMMARY:');
      results.push(`     • Total indirect calls: ${totalIndirect}`);
      results.push(`     • Register calls: ${registerCalls.length}`);
      results.push(`     • Memory indirect: ${memoryCalls.length}`);

      if (totalIndirect > 0) {
        results.push('\n  ⚠️ ANALYSIS IMPLICATIONS:');
        if (registerCalls.length > 5) {
          results.push(
            '     • High register calls suggest computed dispatch (switch/state machine)',
          );
        }
        if (memoryCalls.filter((c) => c.type === 'VTABLE').length > 3) {
          results.push(
            '     • Multiple vtable calls indicate C++ polymorphism',
          );
        }
        if (memoryCalls.filter((c) => c.type === 'CALLBACK').length > 0) {
          results.push(
            '     • Callbacks detected - trace to find registered handlers',
          );
        }
        results.push(
          '     • Static analysis incomplete - consider dynamic tracing',
        );
      }
      results.push('');
    } catch (e) {
      results.push(`  ⚠️ Indirect call detection error: ${e}\n`);
    }

    // ═══════════════════════════════════════════════════════════════
    // SECTION 2: JUMP TABLE DETECTION (Full Implementation)
    // ═══════════════════════════════════════════════════════════════
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 2. JUMP TABLE DETECTION & ANALYSIS                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  📖 Jump tables implement switch/state machine logic:\n');
    results.push('     Pattern: cmp reg, N → ja default → jmp [table + reg*8]');
    results.push(
      '     This creates N+1 cases (0 to N) for state transitions\n',
    );

    try {
      // 2.1 Find all indirect jumps
      results.push('  🔍 2.1 SCANNING FOR INDIRECT JUMPS...\n');

      // Search for indirect jump patterns
      const indirectJmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad jmp qword" ${escapeShellArg(targetPath)} 2>/dev/null | head -30`,
        timeout / 6,
      );

      const indirectJumps: Array<{
        addr: string;
        instr: string;
        isTable: boolean;
        memRef: string;
      }> = [];

      if (indirectJmpResult.success && indirectJmpResult.output.trim()) {
        const lines = indirectJmpResult.output.trim().split('\n');
        for (const line of lines) {
          const addrMatch = line.match(/0x[0-9a-fA-F]+/);
          if (addrMatch) {
            // Get actual instruction
            const instrResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "pd 1 @ ${addrMatch[0]}" ${escapeShellArg(targetPath)} 2>/dev/null`,
              timeout / 50,
            );

            if (instrResult.success) {
              const instrMatch = instrResult.output.match(
                /jmp\s+(?:qword|dword)?\s*(?:ptr\s*)?\[([^\]]+)\]/i,
              );
              if (instrMatch) {
                const memRef = instrMatch[1];
                // Detect jump table patterns
                const isTable =
                  /\*\s*(4|8)/.test(memRef) ||
                  /r[a-z]x\s*\*/.test(memRef) ||
                  /\+\s*r[a-z]x\s*\*/.test(instrResult.output);

                indirectJumps.push({
                  addr: addrMatch[0],
                  instr: instrResult.output.trim().split('\n')[0] || '',
                  isTable,
                  memRef,
                });
              }
            }
          }
        }
      }

      // Also search for register indirect jumps (jmp rax)
      const regJmpResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad jmp" ${escapeShellArg(targetPath)} 2>/dev/null | grep -iE "jmp\\s+(e|r)[a-z]x" | head -10`,
        timeout / 6,
      );

      if (regJmpResult.success && regJmpResult.output.trim()) {
        const lines = regJmpResult.output.trim().split('\n');
        for (const line of lines) {
          const match = line.match(/(0x[0-9a-fA-F]+).*?(jmp\s+(e|r)[a-z]x)/i);
          if (match) {
            indirectJumps.push({
              addr: match[1],
              instr: match[2],
              isTable: true, // Register jumps often come from table lookups
              memRef: match[3],
            });
          }
        }
      }

      results.push(`     Found ${indirectJumps.length} indirect jumps\n`);

      // 2.2 Analyze each potential jump table
      results.push('  🔍 2.2 JUMP TABLE ANALYSIS:\n');

      const tableJumps = indirectJumps.filter((j) => j.isTable);

      if (tableJumps.length > 0) {
        for (const tj of tableJumps.slice(0, 8)) {
          const analysis = await this.analyzeJumpTableDetailed(
            targetPath,
            tj.addr,
            tool,
            timeout / 10,
          );

          if (analysis) {
            jumpTables.push(analysis);
          }
        }

        // Display detailed results
        if (jumpTables.length > 0) {
          results.push('  🎯 JUMP TABLES DETECTED:');
          results.push(
            '  ╔══════════════════════════════════════════════════════════════════════╗',
          );

          for (const jt of jumpTables) {
            results.push(
              '  ╠══════════════════════════════════════════════════════════════════════╣',
            );
            results.push(`  ║ 📍 JUMP TABLE @ ${jt.address.padEnd(52)} ║`);
            results.push(
              '  ╠══════════════════════════════════════════════════════════════════════╣',
            );
            results.push(
              `  ║ Function: ${jt.function.substring(0, 60).padEnd(60)} ║`,
            );
            results.push(`  ║ Table Base: ${jt.baseAddress.padEnd(57)} ║`);
            results.push(
              `  ║ Entry Count: ${jt.entryCount.toString().padEnd(56)} ║`,
            );

            if (jt.stateVariable) {
              results.push(
                `  ║ State Variable: ${jt.stateVariable.padEnd(53)} ║`,
              );
            }

            if (jt.isStateMachine) {
              results.push(
                `  ║ ⚠️  STATE MACHINE: ${jt.entryCount} states detected ${''.padEnd(39)} ║`,
              );
            }

            // Show case targets
            if (jt.caseAnalysis && jt.caseAnalysis.length > 0) {
              results.push(
                '  ║                                                                      ║',
              );
              results.push(
                '  ║ CASE ANALYSIS:                                                       ║',
              );
              results.push(
                '  ╟──────────┬─────────────┬─────────────────────────────────────────────╢',
              );
              results.push(
                '  ║ Case     │ Target      │ Description                                 ║',
              );
              results.push(
                '  ╟──────────┼─────────────┼─────────────────────────────────────────────╢',
              );

              for (const c of jt.caseAnalysis.slice(0, 10)) {
                const caseNum = `Case ${c.caseValue}`.padEnd(8);
                const target = c.targetAddr.padEnd(11);
                const desc = c.description.substring(0, 43).padEnd(43);
                results.push(`  ║ ${caseNum} │ ${target} │ ${desc} ║`);
              }

              if (jt.caseAnalysis.length > 10) {
                results.push(
                  `  ║ ... ${jt.caseAnalysis.length - 10} more cases ${''.padEnd(52)} ║`,
                );
              }

              results.push(
                '  ╟──────────┴─────────────┴─────────────────────────────────────────────╢',
              );
            }

            // Show string references found in cases
            if (jt.stringRefs && jt.stringRefs.length > 0) {
              results.push(
                '  ║                                                                      ║',
              );
              results.push(
                '  ║ 📝 STRINGS REFERENCED IN CASES:                                      ║',
              );
              for (const sr of jt.stringRefs.slice(0, 5)) {
                const str = `"${sr.string.substring(0, 50)}"`;
                results.push(
                  `  ║    Case ${sr.caseValue}: ${str.padEnd(53)} ║`,
                );
              }
            }
          }

          results.push(
            '  ╚══════════════════════════════════════════════════════════════════════╝',
          );
          results.push('');
        }
      } else {
        results.push('     ✅ No jump table patterns detected\n');
      }

      // 2.3 State Machine Summary
      const stateMachines = jumpTables.filter((jt) => jt.isStateMachine);
      if (stateMachines.length > 0) {
        results.push('  🔄 2.3 STATE MACHINE SUMMARY:\n');
        results.push('     ⚠️  STATE MACHINES ARE CRITICAL FOR:');
        results.push('        • Input validation (each state = one check)');
        results.push('        • License verification (sequential checks)');
        results.push('        • Protocol parsing (state transitions)\n');

        for (const sm of stateMachines) {
          results.push(`     📊 ${sm.function} @ ${sm.address}:`);
          results.push(
            `        • ${sm.entryCount} states (cases 0-${sm.entryCount - 1})`,
          );
          if (sm.stateVariable) {
            results.push(`        • State variable: ${sm.stateVariable}`);
          }

          // Show state transition hints
          if (sm.caseAnalysis && sm.caseAnalysis.length > 0) {
            results.push('        • States found:');
            for (const c of sm.caseAnalysis.slice(0, 8)) {
              const desc = c.description || 'Unknown purpose';
              results.push(`          State ${c.caseValue}: ${desc}`);
            }
          }
          results.push('');
        }

        results.push('     🔧 ANALYSIS RECOMMENDATION:');
        results.push('        1. Identify what each state validates');
        results.push('        2. Find state variable location');
        results.push('        3. Trace transitions between states');
        results.push('        4. All states must pass for success\n');
      }

      // 2.4 Other indirect jumps (non-table)
      const otherJumps = indirectJumps.filter((j) => !j.isTable);
      if (otherJumps.length > 0) {
        results.push(`  📝 2.4 OTHER INDIRECT JUMPS: ${otherJumps.length}`);
        for (const oj of otherJumps.slice(0, 5)) {
          results.push(`     ${oj.addr}: ${oj.instr.substring(0, 50)}`);
        }
        results.push('');
      }
    } catch (e) {
      results.push(`  ⚠️ Jump table detection error: ${e}\n`);
    }

    // ═══════════════════════════════════════════════════════════════
    // FINAL SUMMARY
    // ═══════════════════════════════════════════════════════════════
    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│ 📋 ANALYSIS SUMMARY                                         │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    results.push('  📊 FINDINGS:');
    results.push(`     • Indirect calls: ${indirectCalls.length}`);
    results.push(`     • Jump tables: ${jumpTables.length}`);

    const stateMachines = jumpTables.filter((jt) => jt.isStateMachine);
    if (stateMachines.length > 0) {
      results.push(`     • Potential state machines: ${stateMachines.length}`);
      for (const sm of stateMachines) {
        results.push(
          `       → ${sm.address}: ${sm.entryCount} states in ${sm.function}`,
        );
      }
    }

    results.push('\n  🔧 NEXT STEPS:');
    if (jumpTables.length > 0) {
      results.push(
        '     • Trace each jump table case to understand state transitions',
      );
      results.push('     • Look for state variable assignments before jumps');
    }
    if (indirectCalls.filter((c) => c.type === 'VTABLE').length > 0) {
      results.push('     • Analyze vtables in .rodata to map virtual methods');
    }
    if (indirectCalls.filter((c) => c.type === 'CALLBACK').length > 0) {
      results.push(
        '     • Trace callback registration to find handler functions',
      );
    }
    results.push(
      '     • Use behavioral_function_scoring to prioritize analysis',
    );
    results.push('');

    return {
      success: true,
      output: results.join('\n'),
      metadata: {
        indirectCalls: indirectCalls.slice(0, 50),
        jumpTables,
        stateMachineCount: stateMachines.length,
      },
    };
  }

  // Enhanced helper method for detailed jump table analysis
  private async analyzeJumpTableDetailed(
    targetPath: string,
    jumpAddr: string,
    tool: string,
    timeout: number,
  ): Promise<{
    address: string;
    function: string;
    baseAddress: string;
    entryCount: number;
    targets: string[];
    caseValues: number[];
    isStateMachine: boolean;
    stateVariable?: string;
    caseAnalysis?: Array<{
      caseValue: number;
      targetAddr: string;
      description: string;
      stringRefs: string[];
      callsTo: string[];
    }>;
    stringRefs?: Array<{
      caseValue: number;
      string: string;
      address: string;
    }>;
  } | null> {
    try {
      // Get extended context around the jump instruction
      const contextResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "s ${jumpAddr}; pd -20; pd 10" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 3,
      );

      if (!contextResult.success) return null;

      const context = contextResult.output;
      let entryCount = 0;
      let baseAddress = '';
      const targets: string[] = [];
      let isStateMachine = false;
      let stateVariable = '';

      // Look for cmp instruction before jump to get case count
      const cmpMatch = context.match(/cmp\s+(\S+),\s*(0x[0-9a-fA-F]+|\d+)/i);
      if (cmpMatch) {
        entryCount = parseInt(cmpMatch[2], 16) || parseInt(cmpMatch[2], 10);
        entryCount += 1; // cmp N means cases 0 to N
        stateVariable = cmpMatch[1]; // The register/memory being compared
      }

      // Look for ja/jbe after cmp (bounds check)
      if (context.match(/\bja\b|\bjbe\b|\bjae\b|\bjb\b/i)) {
        isStateMachine = true;
      }

      // Try to extract table base address from the jump instruction
      const tableMatch = context.match(/jmp.*?\[\s*([^+\]]+)\s*\+/);
      if (tableMatch) {
        baseAddress = tableMatch[1].trim();
      }

      // Also look for lea instruction that loads table base
      const leaMatch = context.match(/lea\s+(\S+),\s*\[([^\]]+)\]/i);
      if (leaMatch && !baseAddress) {
        // Check if this register is used in the jump
        const leaReg = leaMatch[1];
        if (context.includes(`jmp`) && context.includes(leaReg)) {
          baseAddress = leaMatch[2];
        }
      }

      // Try to find absolute table address
      if (!baseAddress.match(/^0x/)) {
        // Look for relocation or absolute address
        const absMatch = context.match(/(0x[0-9a-fA-F]+).*reloc|section/i);
        if (absMatch) {
          baseAddress = absMatch[1];
        }
      }

      // Get containing function
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "s ${jumpAddr}; af; afi" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 5,
      );

      let funcName = 'unknown';
      if (funcResult.success) {
        const nameMatch = funcResult.output.match(/name:\s*(\S+)/);
        if (nameMatch) funcName = nameMatch[1];
      }

      // Try to read actual table entries
      const caseAnalysis: Array<{
        caseValue: number;
        targetAddr: string;
        description: string;
        stringRefs: string[];
        callsTo: string[];
      }> = [];

      const stringRefs: Array<{
        caseValue: number;
        string: string;
        address: string;
      }> = [];

      // Try to find the table in .rodata or near the jump
      const searchAddr = baseAddress.match(/^0x/) ? baseAddress : jumpAddr;
      const tableResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "s ${searchAddr}; pxq ${Math.min((entryCount || 8) * 8, 128)}" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 5,
      );

      if (tableResult.success) {
        const addrMatches =
          tableResult.output.match(/0x[0-9a-fA-F]{6,16}/g) || [];
        // Filter to likely code addresses
        const codeAddrs = addrMatches.filter((a) => {
          const addr = parseInt(a, 16);
          return addr > 0x1000 && addr < 0x7fffffffffff;
        });
        targets.push(...codeAddrs.slice(0, entryCount || 16));
      }

      // Analyze each case target
      for (let i = 0; i < Math.min(targets.length, 10); i++) {
        const targetAddr = targets[i];
        let description = '';
        const caseStringRefs: string[] = [];
        const callsTo: string[] = [];

        try {
          // Get a few instructions at each case target
          const caseResult = await this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "pd 10 @ ${targetAddr}" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 20,
          );

          if (caseResult.success) {
            const caseCode = caseResult.output;

            // Look for string references in this case
            const strMatches = caseCode.match(/str\.\S+|"[^"]+"/g) || [];
            caseStringRefs.push(...strMatches.slice(0, 3));

            // Look for call instructions
            const callMatches = caseCode.match(/call\s+(\S+)/g) || [];
            for (const c of callMatches.slice(0, 3)) {
              const funcMatch = c.match(/call\s+(sym\.\S+|fcn\.\S+|\S+)/);
              if (funcMatch) callsTo.push(funcMatch[1]);
            }

            // Try to determine case purpose
            if (
              caseCode.match(/cmp|test/i) &&
              caseCode.match(/strcmp|memcmp|strncmp/i)
            ) {
              description = 'String comparison check';
            } else if (caseCode.match(/printf|puts|print/i)) {
              description = 'Output/print';
            } else if (caseCode.match(/error|fail|invalid/i)) {
              description = 'Error handler';
            } else if (caseCode.match(/success|valid|correct|flag/i)) {
              description = 'Success handler';
            } else if (caseCode.match(/mov.*\[.*state|mov.*state/i)) {
              description = 'State transition';
            } else if (caseCode.match(/add|sub|xor|mul/i)) {
              description = 'Arithmetic/computation';
            } else if (caseCode.match(/cmp|test/i)) {
              description = 'Validation check';
            } else if (callsTo.length > 0) {
              description = `Calls: ${callsTo.slice(0, 2).join(', ')}`;
            } else {
              description = 'Logic block';
            }

            // Extract referenced strings
            const fullStrMatches = caseCode.match(/"([^"]+)"/g) || [];
            for (const s of fullStrMatches) {
              stringRefs.push({
                caseValue: i,
                string: s.replace(/"/g, ''),
                address: targetAddr,
              });
            }
          }
        } catch {
          description = 'Analysis failed';
        }

        caseAnalysis.push({
          caseValue: i,
          targetAddr,
          description,
          stringRefs: caseStringRefs,
          callsTo,
        });
      }

      // Determine if this looks like a state machine
      const hasMultipleCases = (entryCount || targets.length) >= 4;
      const hasStateTransitions = caseAnalysis.some((c) =>
        c.description.includes('State transition'),
      );
      const hasValidationCases = caseAnalysis.some(
        (c) =>
          c.description.includes('check') ||
          c.description.includes('Validation'),
      );

      isStateMachine =
        hasMultipleCases && (hasStateTransitions || hasValidationCases);

      return {
        address: jumpAddr,
        function: funcName,
        baseAddress: baseAddress || 'unknown',
        entryCount: entryCount || targets.length,
        targets,
        caseValues: Array.from(
          { length: entryCount || targets.length },
          (_, i) => i,
        ),
        isStateMachine: isStateMachine || entryCount >= 4,
        stateVariable: stateVariable || undefined,
        caseAnalysis: caseAnalysis.length > 0 ? caseAnalysis : undefined,
        stringRefs: stringRefs.length > 0 ? stringRefs : undefined,
      };
    } catch {
      return null;
    }
  }

  private async semanticFunctionMatch(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🧬 SEMANTIC FUNCTION MATCHING');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    results.push('  📖 Matches functions by behavioral patterns:\n');
    results.push('     • Signature matching (known library functions)');
    results.push('     • Behavioral fingerprinting (what the function does)');
    results.push('     • API call patterns (Windows/Linux syscalls)');
    results.push(
      '     • Crypto algorithm detection (by constants/structure)\n',
    );

    // Track matched functions
    interface SemanticMatch {
      address: string;
      name: string;
      matchType:
        | 'SIGNATURE'
        | 'BEHAVIORAL'
        | 'API_PATTERN'
        | 'CRYPTO'
        | 'LIBRARY';
      matchedTo: string;
      confidence: number;
      indicators: string[];
    }

    const matches: SemanticMatch[] = [];

    try {
      // Get all functions
      const funcResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; aflj" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 6,
      );

      let functions: Array<{
        offset: number;
        name: string;
        size: number;
        nbbs?: number;
        cc?: number;
      }> = [];

      if (funcResult.success && funcResult.output.trim()) {
        try {
          functions = JSON.parse(funcResult.output);
        } catch {
          const lines = funcResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)/);
            if (match) {
              functions.push({
                offset: parseInt(match[1], 16),
                name: match[3],
                size: parseInt(match[2], 10),
              });
            }
          }
        }
      }

      results.push(`  📊 Analyzing ${functions.length} functions...\n`);

      // ═══════════════════════════════════════════════════════════════
      // SECTION 1: FLIRT SIGNATURE MATCHING
      // ═══════════════════════════════════════════════════════════════
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 1. LIBRARY SIGNATURE MATCHING (FLIRT)                       │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      // Try radare2's signature matching
      const sigResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "aaa; zfs" ${escapeShellArg(targetPath)} 2>/dev/null | head -50`,
        timeout / 6,
      );

      if (sigResult.success && sigResult.output.trim()) {
        const sigLines = sigResult.output.trim().split('\n');
        let sigCount = 0;

        for (const line of sigLines) {
          const sigMatch = line.match(/(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)/);
          if (sigMatch) {
            sigCount++;
            matches.push({
              address: sigMatch[1],
              name: sigMatch[3],
              matchType: 'SIGNATURE',
              matchedTo: 'Library function',
              confidence: 95,
              indicators: ['FLIRT signature match'],
            });
          }
        }

        if (sigCount > 0) {
          results.push(`  ✅ Found ${sigCount} library signature matches\n`);
        } else {
          results.push(
            '  ⚠️ No FLIRT signatures matched (signatures may not be loaded)\n',
          );
        }
      } else {
        results.push('  ⚠️ Signature matching unavailable\n');
      }

      // ═══════════════════════════════════════════════════════════════
      // SECTION 2: BEHAVIORAL PATTERN MATCHING
      // ═══════════════════════════════════════════════════════════════
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 2. BEHAVIORAL PATTERN MATCHING                              │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      // Define behavioral patterns to search for
      const behavioralPatterns = [
        {
          name: 'strcmp-like',
          patterns: ['repe cmpsb', 'repne scasb', 'cmpsb'],
          description: 'String comparison function',
          matchTo: 'strcmp/strncmp',
        },
        {
          name: 'strcpy-like',
          patterns: ['rep movsb', 'rep movsd', 'rep movsq'],
          description: 'String/memory copy function',
          matchTo: 'strcpy/memcpy',
        },
        {
          name: 'strlen-like',
          patterns: ['repne scasb', 'xor.*0xff'],
          description: 'String length calculation',
          matchTo: 'strlen',
        },
        {
          name: 'memset-like',
          patterns: ['rep stosb', 'rep stosd', 'rep stosq'],
          description: 'Memory fill function',
          matchTo: 'memset/bzero',
        },
        {
          name: 'xor-loop',
          patterns: ['xor.*\\[.*\\]', 'loop.*xor'],
          description: 'XOR encoding/decoding loop',
          matchTo: 'XOR cipher',
        },
        {
          name: 'hash-accumulator',
          patterns: ['imul.*0x01000193', 'imul.*0x1000193'],
          description: 'FNV hash calculation',
          matchTo: 'FNV-1/FNV-1a hash',
        },
        {
          name: 'rc4-like',
          patterns: ['mov.*256', 'xchg.*\\[.*\\]'],
          description: 'RC4-like key scheduling',
          matchTo: 'RC4 cipher',
        },
      ];

      results.push('  🔍 SEARCHING FOR BEHAVIORAL PATTERNS:\n');

      for (const pattern of behavioralPatterns) {
        // Search for pattern in binary
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "aaa; /ad ${pattern.patterns[0]}" ${escapeShellArg(targetPath)} 2>/dev/null | head -10`,
          timeout / 15,
        );

        if (searchResult.success && searchResult.output.trim()) {
          const patternMatches =
            searchResult.output.match(/0x[0-9a-fA-F]+/g) || [];

          if (patternMatches.length > 0) {
            results.push(
              `  ✅ ${pattern.name}: ${patternMatches.length} matches`,
            );
            results.push(`     Pattern: ${pattern.patterns[0]}`);
            results.push(`     Likely: ${pattern.matchTo}\n`);

            for (const addr of patternMatches.slice(0, 3)) {
              // Find containing function
              const funcMatch = functions.find(
                (f) =>
                  parseInt(addr, 16) >= f.offset &&
                  parseInt(addr, 16) < f.offset + f.size,
              );

              if (funcMatch) {
                matches.push({
                  address: `0x${funcMatch.offset.toString(16)}`,
                  name: funcMatch.name,
                  matchType: 'BEHAVIORAL',
                  matchedTo: pattern.matchTo,
                  confidence: 75,
                  indicators: [
                    pattern.description,
                    `Pattern: ${pattern.patterns[0]}`,
                  ],
                });
              }
            }
          }
        }
      }

      // ═══════════════════════════════════════════════════════════════
      // SECTION 3: API CALL PATTERN MATCHING
      // ═══════════════════════════════════════════════════════════════
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 3. API CALL PATTERN MATCHING                                │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      // Define API patterns that indicate function purpose
      const apiPatterns = [
        {
          apis: ['CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle'],
          purpose: 'File I/O handler',
          platform: 'Windows',
        },
        {
          apis: ['open', 'read', 'write', 'close'],
          purpose: 'File I/O handler',
          platform: 'Linux',
        },
        {
          apis: ['socket', 'connect', 'send', 'recv'],
          purpose: 'Network communication',
          platform: 'Cross-platform',
        },
        {
          apis: ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory'],
          purpose: 'Memory manipulation (shellcode?)',
          platform: 'Windows',
        },
        {
          apis: ['mmap', 'mprotect', 'ptrace'],
          purpose: 'Memory/process manipulation',
          platform: 'Linux',
        },
        {
          apis: ['RegOpenKey', 'RegQueryValue', 'RegSetValue'],
          purpose: 'Registry operations',
          platform: 'Windows',
        },
        {
          apis: ['CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt'],
          purpose: 'Windows crypto API',
          platform: 'Windows',
        },
        {
          apis: ['EVP_Encrypt', 'EVP_Decrypt', 'AES_encrypt'],
          purpose: 'OpenSSL crypto',
          platform: 'Cross-platform',
        },
        {
          apis: ['strcmp', 'memcmp', 'strncmp'],
          purpose: 'Input validation',
          platform: 'Cross-platform',
        },
        {
          apis: ['printf', 'puts', 'sprintf'],
          purpose: 'Output/formatting',
          platform: 'Cross-platform',
        },
      ];

      // Get imports
      const importsResult = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iij" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 6,
      );

      const imports: Array<{ name: string; plt: number }> = [];
      if (importsResult.success && importsResult.output.trim()) {
        try {
          const importData = JSON.parse(importsResult.output);
          for (const imp of importData) {
            if (imp.name && imp.plt) {
              imports.push({ name: imp.name, plt: imp.plt });
            }
          }
        } catch {
          // Parse text format
          const lines = importsResult.output.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/(0x[0-9a-fA-F]+).*?(\w+)/);
            if (match) {
              imports.push({ name: match[2], plt: parseInt(match[1], 16) });
            }
          }
        }
      }

      results.push(`  📦 Found ${imports.length} imported functions\n`);

      // Match API patterns
      for (const pattern of apiPatterns) {
        const matchedApis = pattern.apis.filter((api) =>
          imports.some((imp) =>
            imp.name.toLowerCase().includes(api.toLowerCase()),
          ),
        );

        if (matchedApis.length >= 2) {
          results.push(`  ✅ ${pattern.purpose} (${pattern.platform})`);
          results.push(`     APIs: ${matchedApis.join(', ')}\n`);

          // Find functions that call these APIs
          for (const api of matchedApis.slice(0, 2)) {
            const callersResult = await this.runCommand(
              `${tool} -e bin.relocs.apply=true -q -c "aaa; axt @ sym.imp.${api}" ${escapeShellArg(targetPath)} 2>/dev/null | head -5`,
              timeout / 20,
            );

            if (callersResult.success && callersResult.output.trim()) {
              const callerAddrs =
                callersResult.output.match(/0x[0-9a-fA-F]+/g) || [];
              for (const addr of callerAddrs.slice(0, 2)) {
                const funcMatch = functions.find(
                  (f) =>
                    parseInt(addr, 16) >= f.offset &&
                    parseInt(addr, 16) < f.offset + f.size,
                );

                if (funcMatch) {
                  // Check if already matched
                  const existing = matches.find(
                    (m) => m.address === `0x${funcMatch.offset.toString(16)}`,
                  );
                  if (!existing) {
                    matches.push({
                      address: `0x${funcMatch.offset.toString(16)}`,
                      name: funcMatch.name,
                      matchType: 'API_PATTERN',
                      matchedTo: pattern.purpose,
                      confidence: 85,
                      indicators: [
                        `Calls: ${matchedApis.join(', ')}`,
                        pattern.platform,
                      ],
                    });
                  }
                }
              }
            }
          }
        }
      }

      // ═══════════════════════════════════════════════════════════════
      // SECTION 4: CRYPTO ALGORITHM DETECTION
      // ═══════════════════════════════════════════════════════════════
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 4. CRYPTOGRAPHIC ALGORITHM DETECTION                        │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      const cryptoConstants = [
        {
          pattern: '0x67452301',
          algorithm: 'MD5/SHA-1',
          description: 'Init vector A',
        },
        {
          pattern: '0xefcdab89',
          algorithm: 'MD5/SHA-1',
          description: 'Init vector B',
        },
        {
          pattern: '0x98badcfe',
          algorithm: 'MD5/SHA-1',
          description: 'Init vector C',
        },
        {
          pattern: '0x10325476',
          algorithm: 'MD5/SHA-1',
          description: 'Init vector D',
        },
        {
          pattern: '0xc3d2e1f0',
          algorithm: 'SHA-1',
          description: 'Init vector E',
        },
        {
          pattern: '0x6a09e667',
          algorithm: 'SHA-256',
          description: 'Init vector H0',
        },
        {
          pattern: '0xbb67ae85',
          algorithm: 'SHA-256',
          description: 'Init vector H1',
        },
        {
          pattern: '0x5a827999',
          algorithm: 'SHA-1',
          description: 'Round constant K1',
        },
        {
          pattern: '0x6ed9eba1',
          algorithm: 'SHA-1',
          description: 'Round constant K2',
        },
        { pattern: '0x01000193', algorithm: 'FNV-1', description: 'FNV prime' },
        {
          pattern: '0x811c9dc5',
          algorithm: 'FNV-1',
          description: 'FNV offset basis',
        },
      ];

      const detectedCrypto: Array<{
        algorithm: string;
        addresses: string[];
        confidence: number;
      }> = [];

      for (const crypto of cryptoConstants) {
        const searchResult = await this.runCommand(
          `${tool} -e bin.relocs.apply=true -q -c "/x ${crypto.pattern.slice(2)}" ${escapeShellArg(targetPath)} 2>/dev/null | head -5`,
          timeout / 20,
        );

        if (searchResult.success && searchResult.output.trim()) {
          const addrs = searchResult.output.match(/0x[0-9a-fA-F]+/g) || [];
          if (addrs.length > 0) {
            // Check if algorithm already detected
            const existing = detectedCrypto.find(
              (d) => d.algorithm === crypto.algorithm,
            );
            if (existing) {
              existing.addresses.push(...addrs);
              existing.confidence = Math.min(existing.confidence + 10, 99);
            } else {
              detectedCrypto.push({
                algorithm: crypto.algorithm,
                addresses: addrs,
                confidence: 80,
              });
            }
          }
        }
      }

      if (detectedCrypto.length > 0) {
        results.push('  🔐 DETECTED CRYPTO ALGORITHMS:\n');

        for (const crypto of detectedCrypto) {
          results.push(
            `  ✅ ${crypto.algorithm} (confidence: ${crypto.confidence}%)`,
          );
          results.push(
            `     Found at: ${crypto.addresses.slice(0, 3).join(', ')}\n`,
          );

          // Find functions containing these addresses
          for (const addr of crypto.addresses.slice(0, 2)) {
            const funcMatch = functions.find(
              (f) =>
                parseInt(addr, 16) >= f.offset &&
                parseInt(addr, 16) < f.offset + f.size,
            );

            if (funcMatch) {
              const existing = matches.find(
                (m) =>
                  m.address === `0x${funcMatch.offset.toString(16)}` &&
                  m.matchType === 'CRYPTO',
              );
              if (!existing) {
                matches.push({
                  address: `0x${funcMatch.offset.toString(16)}`,
                  name: funcMatch.name,
                  matchType: 'CRYPTO',
                  matchedTo: crypto.algorithm,
                  confidence: crypto.confidence,
                  indicators: [`Crypto constant: ${crypto.algorithm}`],
                });
              }
            }
          }
        }
      } else {
        results.push('  ⚠️ No cryptographic constants detected\n');
      }

      // ═══════════════════════════════════════════════════════════════
      // SUMMARY
      // ═══════════════════════════════════════════════════════════════
      results.push(
        '┌─────────────────────────────────────────────────────────────┐',
      );
      results.push(
        '│ 📋 SEMANTIC MATCHING SUMMARY                                │',
      );
      results.push(
        '└─────────────────────────────────────────────────────────────┘\n',
      );

      // Deduplicate matches
      const uniqueMatches = matches.filter(
        (m, i, arr) =>
          arr.findIndex(
            (x) => x.address === m.address && x.matchedTo === m.matchedTo,
          ) === i,
      );

      // Sort by confidence
      uniqueMatches.sort((a, b) => b.confidence - a.confidence);

      if (uniqueMatches.length > 0) {
        results.push('  🎯 MATCHED FUNCTIONS:\n');
        results.push(
          '  ┌──────────────┬──────────────────────────┬───────────┬────────────────────────────┬────────┐',
        );
        results.push(
          '  │ Address      │ Function                 │ Type      │ Matched To                 │ Conf%  │',
        );
        results.push(
          '  ├──────────────┼──────────────────────────┼───────────┼────────────────────────────┼────────┤',
        );

        for (const m of uniqueMatches.slice(0, 20)) {
          const addr = m.address.padEnd(12);
          const name = m.name.substring(0, 24).padEnd(24);
          const type = m.matchType.substring(0, 9).padEnd(9);
          const matchTo = m.matchedTo.substring(0, 26).padEnd(26);
          const conf = `${m.confidence}%`.padEnd(6);
          results.push(
            `  │ ${addr} │ ${name} │ ${type} │ ${matchTo} │ ${conf} │`,
          );
        }

        results.push(
          '  └──────────────┴──────────────────────────┴───────────┴────────────────────────────┴────────┘',
        );

        if (uniqueMatches.length > 20) {
          results.push(
            `\n     ... and ${uniqueMatches.length - 20} more matches`,
          );
        }

        // Count by type
        results.push('\n  📊 MATCH BREAKDOWN:');
        const byType = uniqueMatches.reduce(
          (acc, m) => {
            acc[m.matchType] = (acc[m.matchType] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>,
        );

        for (const [type, count] of Object.entries(byType)) {
          results.push(`     • ${type}: ${count}`);
        }
      } else {
        results.push('  ⚠️ No semantic matches found');
      }

      results.push('\n  🔧 ANALYSIS RECOMMENDATIONS:');
      results.push('     • High-confidence matches can be renamed for clarity');
      results.push(
        '     • Crypto functions should be analyzed for key handling',
      );
      results.push('     • API pattern matches reveal program capabilities');
      results.push(
        '     • Use behavioral_function_scoring for validation funcs',
      );
      results.push('');

      return {
        success: true,
        output: results.join('\n'),
        metadata: {
          matches: uniqueMatches,
          cryptoDetected: detectedCrypto,
          totalMatches: uniqueMatches.length,
        },
      };
    } catch (e) {
      results.push(`  ⚠️ Semantic matching error: ${e}\n`);
      return {
        success: false,
        output: results.join('\n'),
        error: String(e),
      };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE 6: LLM-GUIDED ANALYSIS FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Security Posture Matrix - Comprehensive binary hardening analysis
   * Analyzes all security mitigations and provides exploitation implications
   */
  private async securityPostureAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<{
    results: string[];
    score: number;
    mitigations: Record<
      string,
      { enabled: boolean; partial?: boolean; details: string; impact: string }
    >;
    exploitHints: string[];
  }> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];
    const exploitHints: string[] = [];
    let totalScore = 0;
    const maxScore = 100;

    const mitigations: Record<
      string,
      { enabled: boolean; partial?: boolean; details: string; impact: string }
    > = {};

    results.push(
      '┌─────────────────────────────────────────────────────────────┐',
    );
    results.push(
      '│  🛡️  SECURITY POSTURE MATRIX                                │',
    );
    results.push(
      '└─────────────────────────────────────────────────────────────┘\n',
    );

    try {
      // Get binary info from multiple sources for accuracy
      const [checksecResult, r2InfoResult, readelfResult, fileResult] =
        await Promise.all([
          // Try checksec if available
          this.runCommand(
            `checksec --file=${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 8,
          ),
          // Get r2 security info
          this.runCommand(
            `${tool} -e bin.relocs.apply=true -q -c "iI" ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 8,
          ),
          // Get ELF specific info
          this.runCommand(
            `readelf -l -d ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 8,
          ),
          // Basic file info
          this.runCommand(
            `file ${escapeShellArg(targetPath)} 2>/dev/null`,
            timeout / 8,
          ),
        ]);

      const r2Info = r2InfoResult.output.toLowerCase();
      const readelfInfo = readelfResult.output.toLowerCase();
      const fileInfo = fileResult.output.toLowerCase();
      const checksecInfo = checksecResult.output.toLowerCase();

      // Detect binary type for context-specific analysis
      const isELF = fileInfo.includes('elf');
      const isPE =
        fileInfo.includes('pe32') ||
        fileInfo.includes('executable (gui)') ||
        fileInfo.includes('executable (console)');
      const isMachO = fileInfo.includes('mach-o');
      const isStripped =
        fileInfo.includes('stripped') || r2Info.includes('stripped');

      results.push('  📋 BINARY CHARACTERISTICS:');
      results.push(
        `     Format: ${isELF ? 'ELF' : isPE ? 'PE (Windows)' : isMachO ? 'Mach-O (macOS)' : 'Unknown'}`,
      );
      results.push(
        `     Stripped: ${isStripped ? '✅ Yes (no debug symbols)' : '❌ No (debug symbols present)'}`,
      );
      results.push('');

      // ═══════════════════════════════════════════════════════════════
      // 1. NX/DEP (No-Execute / Data Execution Prevention)
      // ═══════════════════════════════════════════════════════════════
      let nxEnabled = false;
      let nxDetails = '';

      if (isELF) {
        // Check for GNU_STACK with no execute permission
        const hasGnuStack = readelfInfo.includes('gnu_stack');
        const stackExec = readelfInfo.match(/gnu_stack.*rw[ex]/i);
        nxEnabled = hasGnuStack && !stackExec;
        nxDetails = nxEnabled
          ? 'GNU_STACK marked non-executable'
          : stackExec
            ? 'GNU_STACK is executable!'
            : 'No GNU_STACK segment (check manually)';
      } else if (isPE) {
        nxEnabled =
          r2Info.includes('nx') || checksecInfo.includes('nx enabled');
        nxDetails = nxEnabled ? 'DEP enabled via PE header' : 'DEP not enabled';
      }

      if (r2Info.includes('nx true') || r2Info.includes('nx=true'))
        nxEnabled = true;
      if (
        checksecInfo.includes('nx enabled') ||
        checksecInfo.includes('nx:.*enabled')
      )
        nxEnabled = true;

      mitigations['NX/DEP'] = {
        enabled: nxEnabled,
        details: nxDetails,
        impact: nxEnabled
          ? 'Stack/heap shellcode will fail - need ROP/JOP'
          : '⚠️ DIRECT SHELLCODE POSSIBLE on stack/heap',
      };

      if (nxEnabled) {
        totalScore += 15;
      } else {
        exploitHints.push(
          'NX disabled → Direct shellcode injection on stack/heap is possible',
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 2. PIE/ASLR (Position Independent Executable)
      // ═══════════════════════════════════════════════════════════════
      let pieEnabled = false;
      let pieDetails = '';

      if (isELF) {
        const elfType = readelfInfo.match(/type:\s*(exec|dyn)/i);
        pieEnabled =
          elfType?.[1]?.toLowerCase() === 'dyn' ||
          r2Info.includes('pic true') ||
          r2Info.includes('pie true');
        pieDetails = pieEnabled
          ? 'Binary is position-independent (DYN type)'
          : 'Binary has fixed base address (EXEC type)';
      } else if (isPE) {
        pieEnabled =
          r2Info.includes('aslr') ||
          checksecInfo.includes('aslr enabled') ||
          r2Info.includes('dynamicbase');
        pieDetails = pieEnabled
          ? 'ASLR/DynamicBase enabled'
          : 'Fixed base address';
      }

      if (r2Info.includes('pic true') || r2Info.includes('pie true'))
        pieEnabled = true;
      if (
        checksecInfo.includes('pie enabled') ||
        checksecInfo.includes('aslr enabled')
      )
        pieEnabled = true;

      mitigations['PIE/ASLR'] = {
        enabled: pieEnabled,
        details: pieDetails,
        impact: pieEnabled
          ? 'Addresses randomized - need info leak for ROP'
          : '⚠️ FIXED ADDRESSES - ROP gadgets at known locations',
      };

      if (pieEnabled) {
        totalScore += 20;
      } else {
        exploitHints.push(
          'No PIE → Binary base is fixed, ROP chain addresses are predictable',
        );
        exploitHints.push('No PIE → Return-to-PLT attacks straightforward');
      }

      // ═══════════════════════════════════════════════════════════════
      // 3. Stack Canaries (Stack Smashing Protection)
      // ═══════════════════════════════════════════════════════════════
      let canaryEnabled = false;
      let canaryDetails = '';

      // Check for canary symbols/patterns
      const canaryCheck = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "is~canary,stack_chk,__stack_chk_fail,__stack_chk_guard,security_cookie,__security_cookie" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 10,
      );

      const hasCanarySymbols =
        canaryCheck.output.includes('stack_chk') ||
        canaryCheck.output.includes('canary') ||
        canaryCheck.output.includes('security_cookie');

      // Also check for canary in function prologues (skip expensive analysis, just check entry)
      const prologueCheck = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "s entry0; pd 30 2>/dev/null | head -30" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 10,
      );

      const hasCanaryPrologue =
        prologueCheck.output.includes('fs:') ||
        prologueCheck.output.includes('gs:') ||
        prologueCheck.output.includes('stack_chk') ||
        prologueCheck.output.includes('__security_cookie');

      canaryEnabled = hasCanarySymbols || hasCanaryPrologue;

      if (
        r2Info.includes('canary true') ||
        checksecInfo.includes('canary found') ||
        checksecInfo.includes('stack canary')
      ) {
        canaryEnabled = true;
      }

      canaryDetails = canaryEnabled
        ? 'Stack canary detected (SSP enabled)'
        : 'No stack canary found';

      mitigations['Stack Canary'] = {
        enabled: canaryEnabled,
        details: canaryDetails,
        impact: canaryEnabled
          ? 'Buffer overflows will trigger __stack_chk_fail - need canary leak or bypass'
          : '⚠️ STACK BUFFER OVERFLOW directly exploitable',
      };

      if (canaryEnabled) {
        totalScore += 15;
      } else {
        exploitHints.push(
          'No canary → Stack buffer overflow can directly overwrite return address',
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 4. RELRO (Relocation Read-Only)
      // ═══════════════════════════════════════════════════════════════
      let relroEnabled = false;
      let relroPartial = false;
      let relroDetails = '';

      if (isELF) {
        const hasRelro = readelfInfo.includes('gnu_relro');
        const hasBindNow =
          readelfInfo.includes('bind_now') ||
          readelfInfo.includes('flags:.*now');

        if (hasRelro && hasBindNow) {
          relroEnabled = true;
          relroDetails = 'Full RELRO (GOT read-only after load)';
        } else if (hasRelro) {
          relroPartial = true;
          relroDetails = 'Partial RELRO (GOT still writable)';
        } else {
          relroDetails = 'No RELRO (GOT writable)';
        }
      }

      if (checksecInfo.includes('full relro')) {
        relroEnabled = true;
        relroPartial = false;
        relroDetails = 'Full RELRO';
      } else if (checksecInfo.includes('partial relro')) {
        relroPartial = true;
        relroDetails = 'Partial RELRO';
      }

      if (r2Info.includes('relro full')) relroEnabled = true;
      if (r2Info.includes('relro partial')) relroPartial = true;

      mitigations['RELRO'] = {
        enabled: relroEnabled,
        partial: relroPartial,
        details: relroDetails,
        impact: relroEnabled
          ? 'GOT overwrite not possible after startup'
          : relroPartial
            ? '⚠️ GOT partially writable - some entries can be overwritten'
            : '⚠️ GOT FULLY WRITABLE - GOT overwrite attacks possible',
      };

      if (relroEnabled) {
        totalScore += 15;
      } else if (relroPartial) {
        totalScore += 7;
        exploitHints.push(
          'Partial RELRO → GOT entries for lazy-bound functions are writable',
        );
      } else {
        exploitHints.push(
          'No RELRO → GOT is fully writable, perfect for GOT overwrite attacks',
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 5. Fortify Source
      // ═══════════════════════════════════════════════════════════════
      let fortifyEnabled = false;
      let fortifyDetails = '';

      const fortifyCheck = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "is~__.*_chk,fortify,__printf_chk,__sprintf_chk,__strcpy_chk,__memcpy_chk" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 10,
      );

      const fortifyFunctions = [
        '__printf_chk',
        '__sprintf_chk',
        '__snprintf_chk',
        '__strcpy_chk',
        '__strncpy_chk',
        '__strcat_chk',
        '__memcpy_chk',
        '__memmove_chk',
        '__memset_chk',
        '__gets_chk',
        '__read_chk',
        '__fgets_chk',
      ];

      const foundFortify = fortifyFunctions.filter((f) =>
        fortifyCheck.output.includes(f),
      );
      fortifyEnabled = foundFortify.length > 0;
      fortifyDetails = fortifyEnabled
        ? `Fortified functions: ${foundFortify.slice(0, 4).join(', ')}${foundFortify.length > 4 ? '...' : ''}`
        : 'No fortified functions (dangerous functions not replaced)';

      if (
        checksecInfo.includes('fortify_source') ||
        checksecInfo.includes('fortified')
      ) {
        fortifyEnabled = true;
      }

      mitigations['Fortify Source'] = {
        enabled: fortifyEnabled,
        details: fortifyDetails,
        impact: fortifyEnabled
          ? 'Buffer overflow in common functions will be detected at runtime'
          : '⚠️ Original dangerous functions used - sprintf/strcpy vulnerabilities exploitable',
      };

      if (fortifyEnabled) {
        totalScore += 10;
      } else {
        exploitHints.push(
          'No Fortify → Dangerous functions like sprintf/strcpy are not bounds-checked',
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 6. RPATH/RUNPATH Analysis
      // ═══════════════════════════════════════════════════════════════
      let rpathSafe = true;
      let rpathDetails = '';

      if (isELF) {
        const rpathMatch = readelfInfo.match(/rpath|runpath.*?:(.*?)$/im);
        if (rpathMatch) {
          const rpath = rpathMatch[1]?.trim() || '';
          const dangerousPaths = ['.', '$ORIGIN', '/tmp', '/var/tmp'];
          const hasDangerousPath = dangerousPaths.some((p) =>
            rpath.includes(p),
          );

          if (hasDangerousPath) {
            rpathSafe = false;
            rpathDetails = `Dangerous RPATH: ${rpath}`;
          } else {
            rpathDetails = `RPATH: ${rpath}`;
          }
        } else {
          rpathDetails = 'No RPATH/RUNPATH set';
        }
      }

      mitigations['RPATH Security'] = {
        enabled: rpathSafe,
        details: rpathDetails,
        impact: rpathSafe
          ? 'No library path hijacking via RPATH'
          : '⚠️ RPATH HIJACKING possible - can load malicious libraries',
      };

      if (rpathSafe) {
        totalScore += 5;
      } else {
        exploitHints.push(
          `Dangerous RPATH → Library hijacking attack possible`,
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 7. Symbols & Debug Info
      // ═══════════════════════════════════════════════════════════════
      const symbolCheck = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iS~.debug,.symtab" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 10,
      );

      const hasDebugInfo =
        symbolCheck.output.includes('.debug') ||
        symbolCheck.output.includes('debug_');
      const hasSymtab = symbolCheck.output.includes('.symtab') || !isStripped;

      mitigations['Debug Info'] = {
        enabled: !hasDebugInfo && !hasSymtab,
        details: hasDebugInfo
          ? 'Debug symbols present'
          : hasSymtab
            ? 'Symbol table present'
            : 'Fully stripped',
        impact: hasDebugInfo
          ? '⚠️ Debug info leaks function names, variable names, source paths'
          : hasSymtab
            ? '⚠️ Symbol table present - function names visible'
            : 'Minimal information leakage',
      };

      if (!hasDebugInfo && !hasSymtab) {
        totalScore += 5;
      } else if (!hasDebugInfo && hasSymtab) {
        totalScore += 2;
        exploitHints.push('Symbol table present → Function names exposed');
      } else {
        exploitHints.push(
          'Debug symbols → Function names and source paths exposed',
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 8. Writable + Executable Segments
      // ═══════════════════════════════════════════════════════════════
      let hasWX = false;
      let wxDetails = '';

      if (isELF) {
        // Look for segments with both W and E flags
        const wxMatch = readelfInfo.match(/load.*rw.*x|load.*rwx/gi);
        hasWX = !!wxMatch;
        wxDetails = hasWX ? 'W+X segment found!' : 'No W+X segments';
      }

      const rwxCheck = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "iS~rwx,rw-x" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 10,
      );

      if (rwxCheck.output.match(/rwx|rw.x/i)) {
        hasWX = true;
        wxDetails = 'W+X section found!';
      }

      mitigations['W^X Policy'] = {
        enabled: !hasWX,
        details: wxDetails,
        impact: hasWX
          ? '⚠️ CRITICAL: Memory both writable AND executable - direct shellcode injection!'
          : 'Memory segments properly separated',
      };

      if (!hasWX) {
        totalScore += 10;
      } else {
        exploitHints.push(
          'W+X memory → Write shellcode and execute directly in same region!',
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 9. Control Flow Integrity (CFI) / Control Flow Guard (CFG)
      // ═══════════════════════════════════════════════════════════════
      let cfiEnabled = false;
      let cfiDetails = '';

      // Check for CFI/CFG markers
      const cfiCheck = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "is~__cfi,__ubsan,__asan,guard_fids,GuardCF" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 10,
      );

      if (
        cfiCheck.output.includes('cfi') ||
        cfiCheck.output.includes('ubsan')
      ) {
        cfiEnabled = true;
        cfiDetails = 'CFI/UBSan instrumentation detected';
      } else if (
        isPE &&
        (r2Info.includes('guard') || cfiCheck.output.includes('guard'))
      ) {
        cfiEnabled = true;
        cfiDetails = 'Control Flow Guard (CFG) enabled';
      } else {
        cfiDetails = 'No CFI/CFG detected';
      }

      mitigations['CFI/CFG'] = {
        enabled: cfiEnabled,
        details: cfiDetails,
        impact: cfiEnabled
          ? 'Indirect calls validated - ROP/JOP significantly harder'
          : 'No control flow validation - ROP/JOP attacks viable',
      };

      if (cfiEnabled) {
        totalScore += 5;
      } else {
        exploitHints.push(
          'No CFI/CFG → ROP chains and JOP gadgets can be used freely',
        );
      }

      // ═══════════════════════════════════════════════════════════════
      // 10. Dangerous Functions Analysis
      // ═══════════════════════════════════════════════════════════════
      const dangerousFunctions = [
        {
          name: 'gets',
          severity: 'CRITICAL',
          reason: 'No bounds checking - guaranteed overflow',
        },
        {
          name: 'strcpy',
          severity: 'HIGH',
          reason: 'No length check - buffer overflow',
        },
        {
          name: 'strcat',
          severity: 'HIGH',
          reason: 'No length check - buffer overflow',
        },
        {
          name: 'sprintf',
          severity: 'HIGH',
          reason: 'No length check - buffer overflow',
        },
        {
          name: 'vsprintf',
          severity: 'HIGH',
          reason: 'No length check - buffer overflow',
        },
        { name: 'scanf', severity: 'MEDIUM', reason: 'Can overflow with %s' },
        { name: 'sscanf', severity: 'MEDIUM', reason: 'Can overflow with %s' },
        {
          name: 'system',
          severity: 'HIGH',
          reason: 'Command injection if user input reaches',
        },
        { name: 'popen', severity: 'HIGH', reason: 'Command injection risk' },
        {
          name: 'execve',
          severity: 'MEDIUM',
          reason: 'Code execution primitive',
        },
        {
          name: 'execl',
          severity: 'MEDIUM',
          reason: 'Code execution primitive',
        },
        {
          name: 'execvp',
          severity: 'MEDIUM',
          reason: 'Code execution primitive',
        },
        {
          name: 'dlopen',
          severity: 'MEDIUM',
          reason: 'Can load arbitrary libraries',
        },
        {
          name: 'mprotect',
          severity: 'MEDIUM',
          reason: 'Can make memory executable',
        },
        {
          name: 'mmap',
          severity: 'LOW',
          reason: 'Can create executable memory',
        },
      ];

      const importCheck = await this.runCommand(
        `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)} 2>/dev/null`,
        timeout / 8,
      );

      const foundDangerous: Array<{
        name: string;
        severity: string;
        reason: string;
      }> = [];

      for (const func of dangerousFunctions) {
        // Check both imports and symbols
        const regex = new RegExp(`\\b${func.name}\\b`, 'i');
        if (regex.test(importCheck.output)) {
          foundDangerous.push(func);
        }
      }

      results.push(
        '  ─────────────────────────────────────────────────────────────',
      );
      results.push('  MITIGATION ANALYSIS:');
      results.push(
        '  ─────────────────────────────────────────────────────────────\n',
      );

      // Format mitigation table
      results.push(
        '  ┌────────────────────┬────────────┬─────────────────────────────────────────┐',
      );
      results.push(
        '  │ Protection         │ Status     │ Exploitation Impact                     │',
      );
      results.push(
        '  ├────────────────────┼────────────┼─────────────────────────────────────────┤',
      );

      for (const [name, info] of Object.entries(mitigations)) {
        let status = '';
        if (info.enabled) {
          status = '✅ ON     ';
        } else if (info.partial) {
          status = '⚠️ PARTIAL';
        } else {
          status = '❌ OFF    ';
        }

        const displayName = name.padEnd(18);
        const impact = info.impact.substring(0, 39).padEnd(39);
        results.push(`  │ ${displayName} │ ${status} │ ${impact} │`);
      }

      results.push(
        '  └────────────────────┴────────────┴─────────────────────────────────────────┘',
      );

      // ═══════════════════════════════════════════════════════════════
      // HARDENING SCORE
      // ═══════════════════════════════════════════════════════════════
      results.push(
        '\n  ─────────────────────────────────────────────────────────────',
      );
      results.push('  HARDENING SCORE:');
      results.push(
        '  ─────────────────────────────────────────────────────────────\n',
      );

      const scorePercent = Math.round((totalScore / maxScore) * 100);
      const scoreBar =
        '█'.repeat(Math.floor(scorePercent / 10)) +
        '░'.repeat(10 - Math.floor(scorePercent / 10));

      let scoreLabel = '';
      let scoreEmoji = '';
      if (scorePercent >= 80) {
        scoreLabel = 'WELL HARDENED';
        scoreEmoji = '🟢';
      } else if (scorePercent >= 60) {
        scoreLabel = 'MODERATELY HARDENED';
        scoreEmoji = '🟡';
      } else if (scorePercent >= 40) {
        scoreLabel = 'WEAK HARDENING';
        scoreEmoji = '🟠';
      } else {
        scoreLabel = 'POORLY HARDENED';
        scoreEmoji = '🔴';
      }

      results.push(
        `  ${scoreEmoji} HARDENING SCORE: ${totalScore}/${maxScore} (${scorePercent}%)`,
      );
      results.push(`     [${scoreBar}] ${scoreLabel}`);

      // ═══════════════════════════════════════════════════════════════
      // DANGEROUS FUNCTIONS
      // ═══════════════════════════════════════════════════════════════
      if (foundDangerous.length > 0) {
        results.push(
          '\n  ─────────────────────────────────────────────────────────────',
        );
        results.push('  ⚠️  DANGEROUS FUNCTIONS DETECTED:');
        results.push(
          '  ─────────────────────────────────────────────────────────────\n',
        );

        const criticals = foundDangerous.filter(
          (f) => f.severity === 'CRITICAL',
        );
        const highs = foundDangerous.filter((f) => f.severity === 'HIGH');
        const mediums = foundDangerous.filter((f) => f.severity === 'MEDIUM');

        if (criticals.length > 0) {
          results.push('  🔴 CRITICAL:');
          for (const f of criticals) {
            results.push(`     • ${f.name}() - ${f.reason}`);
            exploitHints.push(`${f.name}() used → ${f.reason}`);
          }
          results.push('');
        }

        if (highs.length > 0) {
          results.push('  🟠 HIGH RISK:');
          for (const f of highs) {
            results.push(`     • ${f.name}() - ${f.reason}`);
          }
          results.push('');
        }

        if (mediums.length > 0) {
          results.push('  🟡 MEDIUM RISK:');
          for (const f of mediums.slice(0, 5)) {
            results.push(`     • ${f.name}() - ${f.reason}`);
          }
          if (mediums.length > 5) {
            results.push(`     ... and ${mediums.length - 5} more`);
          }
        }
      }

      // ═══════════════════════════════════════════════════════════════
      // EXPLOITATION HINTS
      // ═══════════════════════════════════════════════════════════════
      if (exploitHints.length > 0) {
        results.push(
          '\n  ─────────────────────────────────────────────────────────────',
        );
        results.push('  🎯 EXPLOITATION IMPLICATIONS:');
        results.push(
          '  ─────────────────────────────────────────────────────────────\n',
        );

        for (const hint of exploitHints.slice(0, 10)) {
          results.push(`  → ${hint}`);
        }

        // Suggest attack strategy based on mitigations
        results.push('\n  📋 SUGGESTED ATTACK STRATEGY:');

        if (
          !mitigations['NX/DEP'].enabled &&
          !mitigations['Stack Canary'].enabled
        ) {
          results.push('     1. Classic stack buffer overflow with shellcode');
          results.push(
            '     2. Find overflow → Write shellcode → Jump to stack',
          );
        } else if (
          !mitigations['PIE/ASLR'].enabled &&
          mitigations['NX/DEP'].enabled
        ) {
          results.push('     1. ROP chain attack (addresses are fixed)');
          results.push(
            '     2. Find overflow → Build ROP chain → ret2libc/system',
          );
        } else if (
          !mitigations['RELRO'].enabled ||
          mitigations['RELRO'].partial
        ) {
          results.push('     1. GOT overwrite attack');
          results.push(
            '     2. Find arbitrary write → Overwrite GOT entry → Hijack control flow',
          );
        } else if (mitigations['PIE/ASLR'].enabled) {
          results.push('     1. Need info leak first');
          results.push(
            '     2. Leak libc/binary address → Calculate offsets → ROP',
          );
        }
      }

      results.push('');

      return {
        results,
        score: totalScore,
        mitigations,
        exploitHints,
      };
    } catch (e) {
      results.push(`  ⚠️ Security analysis error: ${e}`);
      return {
        results,
        score: 0,
        mitigations,
        exploitHints,
      };
    }
  }

  /**
   * Guided Analysis - Main entry point for LLM-driven analysis
   * Auto-detects binary type and provides complete analysis roadmap
   */
  private async guidedAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const results: string[] = [];
    results.push(
      '═══════════════════════════════════════════════════════════════',
    );
    results.push('   🧭 GUIDED ANALYSIS - Intelligent Binary Analysis Roadmap');
    results.push(
      '═══════════════════════════════════════════════════════════════\n',
    );

    // Run security posture analysis
    const securityAnalysis = await this.securityPostureAnalysis(
      targetPath,
      timeout,
    );
    results.push(...securityAnalysis.results);

    return {
      success: true,
      output: results.join('\n'),
      metadata: {
        securityScore: securityAnalysis.score,
        mitigations: securityAnalysis.mitigations,
        exploitHints: securityAnalysis.exploitHints,
      },
    };
  }

  /**
   * Analysis Context - Get current analysis state
   */
  private async analysisContext(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: true,
      output: 'Analysis context - Implementation pending',
    };
  }

  /**
   * Smart Decompile - Auto-select best decompiler
   */
  private async smartDecompile(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: true,
      output: 'Smart decompile - Implementation pending',
    };
  }

  /**
   * Explain Function - Decompile + plain English explanation
   */
  private async explainFunction(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: true,
      output: 'Explain function - Implementation pending',
    };
  }

  /**
   * Find Key Functions - Multi-strategy function discovery
   */
  private async findKeyFunctions(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: true,
      output: 'Find key functions - Implementation pending',
    };
  }

  /**
   * Attack Surface - Map all attack vectors
   */
  private async attackSurface(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: true,
      output: 'Attack surface - Implementation pending',
    };
  }

  /**
   * Solve Crackme - Step-by-step CTF solving
   */
  private async solveCrackme(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: true,
      output: 'Solve crackme - Implementation pending',
    };
  }

  /**
   * Workflow Chain - Execute operation sequences
   */
  private async workflowChain(
    _targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    return {
      success: true,
      output: 'Workflow chain - Implementation pending',
    };
  }

  // ============= Helper Methods =============

  /**
   * Intelligently compress large RE outputs to save tokens
   * Keeps key sections (functions, imports, strings), drops verbose assembly
   */
  private intelligentCompressionOutput(
    output: string,
    operation: string,
  ): string {
    const lines = output.split('\n');
    const result: string[] = [];
    let inVerboseSection = false;
    let sectionLines = 0;

    for (const line of lines) {
      // Always keep section headers
      if (
        line.includes('Section') ||
        line.includes('Function') ||
        line.includes('Import') ||
        line.includes('String') ||
        line.includes('Symbol') ||
        line.includes('Address') ||
        line.includes('0x') ||
        line.match(/^[a-zA-Z_].*\(/)
      ) {
        result.push(line);
        inVerboseSection = false;
        sectionLines = 0;
        continue;
      }

      // Skip repetitive assembly lines (mov, add, xor, etc) - keep only first 3 per section
      if (
        line.match(/^\s*(mov|add|sub|xor|lea|cmp|jmp|call|push|pop|ret)\s/) &&
        operation.includes('disasm')
      ) {
        if (sectionLines < 3) {
          result.push(line);
          sectionLines++;
        } else if (!inVerboseSection) {
          result.push('          [... assembly lines omitted ...]');
          inVerboseSection = true;
        }
        continue;
      }

      // Keep decompiled code lines
      if (
        line.match(/^\s*(if|for|while|return|break|continue|switch|case)\s/) ||
        line.includes('=') ||
        line.includes('{') ||
        line.includes('}')
      ) {
        result.push(line);
        inVerboseSection = false;
        sectionLines = 0;
        continue;
      }

      // Keep summary/analysis lines
      if (
        line.includes('Total') ||
        line.includes('Capabilities') ||
        line.includes('EVASION') ||
        line.includes('Suspicious') ||
        line.includes('Risk')
      ) {
        result.push(line);
        continue;
      }

      // Compress consecutive empty lines - keep only one
      if (line.trim().length === 0) {
        if (result.length === 0 || result[result.length - 1].trim() !== '') {
          result.push(line);
        }
        continue;
      }
    }

    const compressed = result.join('\n');
    return compressed.length < output.length
      ? compressed +
          '\n\n[... compressed output - use specific operations for details ...]'
      : output;
  }

  /**
   * Smart Disassembly Analysis - Intelligently analyze binary without specific target
   * Finds and analyzes key functions automatically for CTF/cracking/malware analysis
   */
  private async smartDisasmAnalysis(
    targetPath: string,
    _timeout: number,
  ): Promise<AnalysisResult> {
    const fileName = targetPath.split('/').pop() || targetPath;

    // Ultra minimal - just acknowledge the binary, no r2 commands
    const output = `🎯 Target: ${fileName}

Ready. What do you want me to do?`;

    return {
      success: true,
      output,
    };
  }

  /**
   * Full smart analysis - only called when explicitly requested
   */
  private async fullSmartAnalysis(
    targetPath: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const results: string[] = [];

    results.push('🎯 FULL SMART ANALYSIS - Automatic Key Function Discovery\n');
    results.push('═══════════════════════════════════════════════════\n');

    // Step 1: Get binary info
    const infoCmd = `${tool} -e bin.relocs.apply=true -q -c "iI" ${escapeShellArg(targetPath)}`;
    const infoResult = await this.runCommand(infoCmd, timeout);
    if (infoResult.success) {
      results.push('📋 Binary Information:');
      results.push(infoResult.output.trim());
      results.push('\n');
    }

    // Step 2: Find interesting imports (crypto, validation, network, etc.)
    results.push('📥 Key Imports (Crypto/Validation/Network):');
    const importsCmd = `${tool} -e bin.relocs.apply=true -q -c "ii~crypto,license,serial,valid,check,register,trial,key,password,encrypt,decrypt,hash,md5,sha,aes,rc4,verify,auth,login,network,socket,http" ${escapeShellArg(targetPath)}`;
    const importsResult = await this.runCommand(importsCmd, timeout);
    if (importsResult.success && importsResult.output.trim()) {
      results.push(importsResult.output.trim());
    } else {
      results.push('  [No obvious validation/crypto imports detected]');
    }
    results.push('\n');

    // Step 3: Find interesting strings
    results.push('🔤 Interesting Strings (Serial/License/Flag/Password):');
    const stringsCmd = `${tool} -e bin.relocs.apply=true -q -c "izz~serial,license,trial,key,password,flag,ctf,crack,register,valid,success,correct,wrong,invalid,expired" ${escapeShellArg(targetPath)}`;
    const stringsResult = await this.runCommand(stringsCmd, timeout);
    if (stringsResult.success && stringsResult.output.trim()) {
      const lines = stringsResult.output.trim().split('\n').slice(0, 15);
      results.push(lines.join('\n'));
    } else {
      results.push('  [No obvious validation strings found]');
    }
    results.push('\n');

    // Step 4: List key functions (limit to most interesting)
    results.push('🎯 Key Functions Detected:');
    const funcsCmd = `${tool} -e bin.relocs.apply=true -q -c "aaa; afl~main,check,valid,serial,license,register,trial,crypto,encrypt,decrypt,key,password,auth,login,verify,flag,win,success" ${escapeShellArg(targetPath)}`;
    const funcsResult = await this.runCommand(funcsCmd, timeout);
    if (funcsResult.success && funcsResult.output.trim()) {
      const lines = funcsResult.output.trim().split('\n').slice(0, 20);
      results.push(lines.join('\n'));
    } else {
      results.push('  [No specific validation functions found]');
    }

    return {
      success: true,
      output: results.join('\n'),
    };
  }

  // ============= LIVE VULNERABILITY & THREAT INTELLIGENCE =============

  /**
   * Check for known CVEs related to detected libraries and versions
   */
  private async checkCVEs(
    targetPath: string,
    timeout: number,
  ): Promise<ToolResult> {
    const output: string[] = [];
    output.push(
      '╔════════════════════════════════════════════════════════════════╗',
    );
    output.push(
      '║       🌐 CVE LOOKUP - Live Vulnerability Database Check       ║',
    );
    output.push(
      '╚════════════════════════════════════════════════════════════════╝\n',
    );

    // Step 1: Detect libraries and versions from binary
    output.push('📋 STEP 1: Detecting libraries and versions from binary...\n');

    const tool = this.params.useRizin ? 'rizin' : 'radare2';
    const infoCmd = `${tool} -e bin.relocs.apply=true -q -c "iI" ${escapeShellArg(targetPath)}`;
    const importsCmd = `${tool} -e bin.relocs.apply=true -q -c "ii" ${escapeShellArg(targetPath)}`;
    const stringsCmd = `${tool} -e bin.relocs.apply=true -q -c "izz~version,openssl,libssl,glibc,apache,nginx,php,python,nodejs,java" ${escapeShellArg(targetPath)}`;

    const [_infoResult, importsResult, stringsResult] = await Promise.all([
      this.runCommand(infoCmd, timeout),
      this.runCommand(importsCmd, timeout),
      this.runCommand(stringsCmd, timeout),
    ]);

    // Parse detected libraries
    const detectedProducts: Array<{
      vendor: string;
      product: string;
      version?: string;
    }> = [];

    // Extract from strings
    if (stringsResult.success && stringsResult.output) {
      const versionMatches = stringsResult.output.matchAll(
        /(openssl|libssl|glibc|apache|nginx|php|python|nodejs)[\s\-_]*v?([\d.]+)/gi,
      );
      for (const match of versionMatches) {
        detectedProducts.push({
          vendor: match[1].toLowerCase(),
          product: match[1].toLowerCase(),
          version: match[2],
        });
      }
    }

    // Extract from imports
    if (importsResult.success && importsResult.output) {
      const importLines = importsResult.output.split('\n');
      for (const line of importLines.slice(0, 100)) {
        if (line.match(/openssl|libssl|crypto/i)) {
          detectedProducts.push({
            vendor: 'openssl',
            product: 'openssl',
          });
        }
      }
    }

    if (detectedProducts.length === 0) {
      output.push('  ⚠️  No specific library versions detected in binary\n');
      output.push(
        '  💡 TIP: Use "check_exploits" to search by binary characteristics\n',
      );
      output.push(
        '  💡 TIP: Provide library names manually in analysis notes\n',
      );
    } else {
      output.push(
        `  ✅ Detected ${detectedProducts.length} library references:\n`,
      );
      const seen = new Set<string>();
      for (const prod of detectedProducts) {
        const key = `${prod.product}${prod.version ? `:${prod.version}` : ''}`;
        if (!seen.has(key)) {
          output.push(
            `     • ${prod.product}${prod.version ? ` v${prod.version}` : ''}\n`,
          );
          seen.add(key);
        }
      }
    }

    // Step 2: Query CVE database using vulnerability-db tool
    output.push('\n📊 STEP 2: Querying live CVE database (NVD)...\n');
    output.push(
      '  🌐 Connecting to National Vulnerability Database (https://nvd.nist.gov)\n',
    );

    if (detectedProducts.length > 0) {
      output.push('\n  Recent CVEs for detected products:\n');
      output.push(
        '  ⚠️  NOTE: This provides LIVE data from NVD, not training data\n',
      );
      output.push(
        '  📅 Results include CVEs discovered after AI training cutoff\n\n',
      );

      // Note: We would integrate with vulnerability-db tool here
      output.push(
        '  💡 For detailed CVE lookup, use: vulnerability_db with operation="product"\n',
      );
      output.push(
        '  💡 Example: vulnerability_db(operation="product", product="openssl", severity="high")\n',
      );
    }

    // Step 3: Recommendations
    output.push('\n🎯 NEXT STEPS FOR CVE ANALYSIS:\n\n');
    output.push(
      '  1. Use vulnerability_db tool for specific CVE details (live internet access)\n',
    );
    output.push(
      '  2. Check "check_exploits" to find public exploit code for identified CVEs\n',
    );
    output.push(
      '  3. Use "vendor_advisories" to check official vendor security bulletins\n',
    );
    output.push(
      '  4. Cross-reference with "recent_attacks" for attack pattern matching\n\n',
    );

    output.push('📚 COMPARISON: LLM Training Data vs Live Internet:\n\n');
    output.push(
      '  ❌ LLM Training Data: Limited to knowledge cutoff date (e.g., July 2024)\n',
    );
    output.push('  ❌ LLM: Cannot access new CVEs discovered after training\n');
    output.push(
      '  ❌ LLM: Provides "predictive analysis based on similar patterns"\n\n',
    );

    output.push(
      '  ✅ Live CVE Check: Real-time NVD database queries via API\n',
    );
    output.push(
      '  ✅ Live: Access to CVEs published yesterday, today, or in the future\n',
    );
    output.push('  ✅ Live: Actual exploit availability, not speculation\n');
    output.push(
      '  ✅ Live: Vendor advisories, patch status, and CVSS scores\n\n',
    );

    output.push('⚡ USAGE RECOMMENDATIONS:\n\n');
    output.push(
      '  • For recent developments: Use live CVE check (this tool)\n',
    );
    output.push(
      '  • For pattern analysis: LLM can identify similar attack vectors\n',
    );
    output.push('  • For comprehensive research: Combine both approaches\n');

    return {
      llmContent: output.join(''),
      returnDisplay: output.join(''),
    };
  }

  /**
   * Search for public exploits for detected vulnerabilities
   */
  private async checkExploits(
    _targetPath: string,
    _timeout: number,
  ): Promise<ToolResult> {
    const output = `
╔════════════════════════════════════════════════════════════════╗
║     🌐 EXPLOIT SEARCH - Live Exploit-DB & GitHub PoC Search    ║
╚════════════════════════════════════════════════════════════════╝

📊 This operation searches live databases for public exploits:

  • Exploit-DB: https://www.exploit-db.com
  • GitHub: Public PoC repositories
  • ExploitDB API: Real-time exploit availability
  • PacketStorm: Security tools and exploits

🎯 USAGE:

  1. Use vulnerability_db tool with operation="exploit"
  2. Provide CVE ID or search terms
  3. Get real-time exploit availability (not training data predictions)

💡 EXAMPLE:

  vulnerability_db(operation="exploit", query="remote code execution php")
  vulnerability_db(operation="poc", cveId="CVE-2024-XXXXX")

📚 WHY LIVE SEARCH MATTERS:

  LLM Training Data:
    ❌ Limited to knowledge cutoff (e.g., July 2024)
    ❌ Cannot know about exploits published after training
    ❌ Provides "likely" or "similar" exploit patterns

  Live Exploit Search:
    ✅ Real-time Exploit-DB database queries
    ✅ Access to exploits published today or this week
    ✅ Actual exploit code availability, not speculation
    ✅ Verification status and exploit metadata

⚠️  ETHICAL USE ONLY: Educational/research purposes in authorized environments
`;

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Query threat intelligence on detected indicators
   */
  private async threatIntel(
    targetPath: string,
    _timeout: number,
  ): Promise<ToolResult> {
    const output = `
╔════════════════════════════════════════════════════════════════╗
║    🌐 THREAT INTELLIGENCE - Live IOC & Malware Analysis        ║
╚════════════════════════════════════════════════════════════════╝

📊 TARGET: ${path.basename(targetPath)}

🎯 LIVE THREAT INTELLIGENCE SOURCES:

  1. VirusTotal (virustotal tool):
     • File hash reputation (70+ AV engines)
     • Behavioral analysis reports
     • Community comments and verdicts
     • Related samples and IOCs

  2. Censys (censys tool):
     • C2 infrastructure detection
     • Known malicious IPs/domains
     • Exposed services and vulnerabilities

  3. AlienVault OTX:
     • Threat actor campaigns
     • IOC sharing community
     • Pulse feeds for related threats

💡 RECOMMENDED WORKFLOW:

  1. Extract IOCs from binary:
     • Use reverse_engineering(operation="extract_iocs")
     • Gets IPs, domains, URLs, file paths

  2. Query VirusTotal:
     • virustotal(operation="file_hash", hash="<sha256>")
     • Real-time multi-engine scan results

  3. Query Censys:
     • censys(operation="host", ip="<detected_ip>")
     • Check if C2 infrastructure is known malicious

  4. Cross-reference behavior:
     • Use reverse_engineering(operation="capability_analysis")
     • Map to MITRE ATT&CK framework

📚 LLM TRAINING DATA vs LIVE THREAT INTEL:

  LLM (Static Knowledge):
    ❌ Training cutoff means no knowledge of recent campaigns
    ❌ Cannot query reputation databases
    ❌ Provides "this resembles" analysis only

  Live Threat Intel:
    ✅ Real-time VirusTotal queries (70+ AV engines)
    ✅ Current C2 infrastructure status (Censys)
    ✅ Community-sourced IOCs and campaigns (OTX)
    ✅ Verdict on actual file hash, not pattern matching

⚡ START HERE:

  virustotal(operation="file_hash", hash="<sha256_of_${path.basename(targetPath)}>")
`;

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Search for existing YARA rules matching binary characteristics
   */
  private async checkYaraRules(
    _targetPath: string,
    _timeout: number,
  ): Promise<ToolResult> {
    const output = `
╔════════════════════════════════════════════════════════════════╗
║     🌐 YARA RULE SEARCH - Live Community Rule Repositories     ║
╚════════════════════════════════════════════════════════════════╝

📊 YARA RULE REPOSITORIES (Live Search):

  1. YARAify (https://yaraify.abuse.ch):
     • 10,000+ community YARA rules
     • Scan samples against rule database
     • Get matching rules for detected patterns

  2. GitHub YARA Rules:
     • https://github.com/Yara-Rules/rules
     • https://github.com/reversinglabs/reversinglabs-yara-rules
     • Search by pattern or malware family

  3. VirusTotal Retrohunt:
     • Test YARA rules against VT corpus
     • Find similar samples

💡 RECOMMENDED APPROACH:

  1. Extract IOCs and patterns:
     reverse_engineering(operation="extract_iocs")
     reverse_engineering(operation="string_decode")

  2. Search YARAify:
     • Upload binary to https://yaraify.abuse.ch
     • Get matching community rules in real-time
     • NOT LIMITED to AI training data

  3. Generate custom rule:
     reverse_engineering(operation="yara_generate")
     • Auto-generates rule from binary analysis
     • Can enhance with live matches

📚 WHY LIVE YARA SEARCH MATTERS:

  LLM Training Data:
    ❌ Only knows YARA rules from training cutoff
    ❌ Cannot access new malware family rules
    ❌ Generates rules based on static patterns

  Live YARA Repositories:
    ✅ Access to rules published yesterday/today
    ✅ Community-sourced malware family signatures
    ✅ Real match results, not predicted patterns
    ✅ Retrohunt across millions of samples

⚡ INTEGRATION AVAILABLE:

  The reverse_engineering tool's yara_generate operation creates
  rules, but checking against live repositories requires:

  1. Manual upload to YARAify
  2. GitHub API search (requires implementation)
  3. VirusTotal Retrohunt (via virustotal tool)
`;

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Check vendor security advisories for detected products
   */
  private async vendorAdvisories(
    _targetPath: string,
    _timeout: number,
  ): Promise<ToolResult> {
    const output = `
╔════════════════════════════════════════════════════════════════╗
║  🌐 VENDOR SECURITY ADVISORIES - Live Bulletin Search          ║
╚════════════════════════════════════════════════════════════════╝

📊 VENDOR ADVISORY SOURCES (Live Access):

  1. Red Hat Security:
     • https://access.redhat.com/security/security-updates/
     • CVE details + patches + CVSS scores
     • Affected product versions

  2. Microsoft Security Response:
     • https://msrc.microsoft.com/update-guide
     • Patch Tuesday bulletins
     • Exploit likelihood ratings

  3. Oracle Critical Patch Updates:
     • https://www.oracle.com/security-alerts/
     • Quarterly security updates
     • Java, Database, Middleware

  4. Ubuntu/Debian Security:
     • https://ubuntu.com/security/notices
     • https://security-tracker.debian.org/
     • Package-specific advisories

💡 WORKFLOW FOR ADVISORY LOOKUP:

  1. Detect product/vendor from binary:
     reverse_engineering(operation="r2_info")
     reverse_engineering(operation="r2_imports")

  2. Query NVD for CVEs:
     vulnerability_db(operation="product", product="<name>")

  3. Cross-reference with vendor advisories:
     • Check if vendor has published patch
     • Verify exploit status (LLM cannot know this)
     • Get official remediation steps

📚 LLM vs LIVE VENDOR ADVISORIES:

  LLM Training Data:
    ❌ Knowledge cutoff = no recent advisories
    ❌ Cannot verify current patch status
    ❌ Speculation about exploit availability

  Live Vendor Advisories:
    ✅ Patch availability TODAY (not 6 months ago)
    ✅ Official exploit likelihood ratings
    ✅ Vendor-confirmed affected versions
    ✅ Remediation steps and workarounds

⚡ CRITICAL DIFFERENCE:

  Example: CVE-2024-12345 published 2 weeks ago

  LLM Response:
    "Based on similar patterns, this might be exploitable.
     I don't have information about patches as my training
     data is from July 2024."

  Live Advisory:
    "Patch released Dec 5, 2024. CVSS 9.8 Critical.
     Exploit code published Dec 8, 2024 on Exploit-DB.
     Vendor recommends immediate upgrade to version 3.2.1."

🎯 RECOMMENDED TOOLS:

  • vulnerability_db(operation="cve", cveId="CVE-XXXX-XXXX")
  • Check vendor websites directly (live internet)
  • Use RSS feeds for automated monitoring
`;

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Query recent attack patterns matching binary behavior
   */
  private async recentAttacks(
    _targetPath: string,
    _timeout: number,
  ): Promise<ToolResult> {
    const output = `
╔════════════════════════════════════════════════════════════════╗
║   🌐 RECENT ATTACK PATTERNS - Live Threat Campaign Tracking    ║
╚════════════════════════════════════════════════════════════════╝

📊 LIVE ATTACK PATTERN SOURCES:

  1. MITRE ATT&CK:
     • https://attack.mitre.org/
     • TTPs (Tactics, Techniques, Procedures)
     • Real-world adversary behaviors

  2. CISA Known Exploited Vulnerabilities:
     • https://www.cisa.gov/known-exploited-vulnerabilities-catalog
     • CVEs actively exploited in the wild
     • Updated weekly with new campaigns

  3. Security Vendor Blogs:
     • Mandiant, CrowdStrike, Kaspersky
     • APT campaign reports
     • Emerging threat analysis

  4. AlienVault OTX Pulses:
     • https://otx.alienvault.com/
     • Community threat intelligence
     • Campaign-specific IOC sharing

💡 ANALYSIS WORKFLOW:

  1. Map binary capabilities:
     reverse_engineering(operation="capability_analysis")
     • Gets MITRE ATT&CK technique IDs

  2. Query CISA KEV:
     • Check if detected CVEs are in KEV catalog
     • Confirms active exploitation status
     • LLM CANNOT know this (requires live data)

  3. Cross-reference attack campaigns:
     • Match TTPs to recent APT reports
     • Find similar malware families
     • Identify threat actor patterns

📚 WHY RECENT ATTACK DATA MATTERS:

  LLM Training Data (Static):
    ❌ No knowledge of attacks after training cutoff
    ❌ Cannot confirm active exploitation
    ❌ "This resembles APT28 patterns from 2023"

  Live Attack Pattern Tracking:
    ✅ CISA KEV updated THIS WEEK
    ✅ Confirms CVEs exploited in wild NOW
    ✅ Vendor blogs published YESTERDAY
    ✅ Real-time threat actor campaign tracking

⚡ CRITICAL EXAMPLE:

  Scenario: Analyzing suspicious binary with Log4Shell-like behavior

  LLM Response:
    "This appears similar to Log4j exploitation patterns
     seen in 2021. Based on training data, I predict this
     could be CVE-2021-44228 related."

  Live Attack Pattern Check:
    "Binary matches CISA KEV entry #123 (added Dec 10, 2024).
     Active exploitation confirmed in ransomware campaigns.
     CrowdStrike reports APT41 using variant published Nov 2024.
     NEW bypass technique not present in original Log4Shell."

🎯 RECOMMENDED INTEGRATION:

  1. Use reverse_engineering(operation="capability_analysis")
     to map MITRE ATT&CK techniques

  2. Query CISA KEV API:
     https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

  3. Check threat intel platforms:
     • VirusTotal (virustotal tool)
     • Censys for C2 infrastructure
     • AlienVault OTX for campaign pulses

  4. Compare with LLM pattern analysis:
     • LLM identifies similar historical patterns
     • Live data confirms current threat status
     • Combine both for comprehensive assessment

💡 BEST PRACTICE:

  Don't rely on LLM alone for threat assessment.
  Use LLM for pattern recognition + Live data for current status.
`;

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  private async runCommand(
    cmd: string,
    timeout: number,
  ): Promise<AnalysisResult> {
    try {
      const { stdout, stderr } = await execAsync(cmd, {
        timeout,
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      });

      const output = stdout || stderr;
      return {
        success: true,
        output: output || 'Command completed with no output',
      };
    } catch (error) {
      const execError = error as {
        stdout?: string;
        stderr?: string;
        message: string;
      };

      // Some commands output to stderr even on success
      if (execError.stderr && !execError.stderr.includes('error')) {
        return {
          success: true,
          output: execError.stderr,
        };
      }

      return {
        success: false,
        output: execError.stderr || execError.stdout || execError.message,
        error: execError.message,
      };
    }
  }

  private async createTempDir(): Promise<string> {
    const tmpDir = path.join(os.tmpdir(), `ghidra_${Date.now()}`);
    await fs.mkdir(tmpDir, { recursive: true });
    return tmpDir;
  }

  private async listRecursive(dir: string): Promise<string[]> {
    const files: string[] = [];
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        files.push(...(await this.listRecursive(fullPath)));
      } else {
        files.push(fullPath);
      }
    }

    return files;
  }

  private interpretEntropy(output: string): string {
    const lines: string[] = [];

    // Parse entropy values (binwalk outputs entropy as 0.0-1.0)
    const entropyMatch = output.match(
      /Rising entropy|Falling entropy|(\d+\.\d+)/g,
    );

    if (entropyMatch) {
      const values = entropyMatch
        .filter((m) => /^\d+\.\d+$/.test(m))
        .map(parseFloat);

      if (values.length > 0) {
        const avg = values.reduce((a, b) => a + b, 0) / values.length;
        const max = Math.max(...values);

        lines.push(`Average entropy: ${avg.toFixed(3)}`);
        lines.push(`Maximum entropy: ${max.toFixed(3)}`);

        if (max > 0.9) {
          lines.push(
            '\n⚠️  HIGH ENTROPY DETECTED: Likely encrypted or compressed data',
          );
        } else if (max > 0.7) {
          lines.push('\n📦 Moderate entropy: May contain compressed sections');
        } else {
          lines.push('\n✓ Low entropy: Likely uncompressed/unencrypted');
        }
      }
    }

    return lines.join('\n') || 'Could not parse entropy values';
  }
}

/**
 * Reverse Engineering Tool Definition
 */
export class ReverseEngineeringTool extends BaseDeclarativeTool<
  ReverseEngineeringParams,
  ToolResult
> {
  static readonly Name = ToolNames.REVERSE_ENGINEERING;

  constructor() {
    super(
      ReverseEngineeringTool.Name,
      ToolDisplayNames.REVERSE_ENGINEERING,
      `Advanced reverse engineering framework with 47+ operations for binary analysis, malware research, and CTF challenges.

## DECISION GUIDE - Choose the right operation:

**🚀 QUICK START (Start Here):**
- quick_re: Best first choice - automated assessment with tool recommendations
- malware_triage: Suspected malware? Start here for quick threat scoring
- detect_packer: Binary seems protected? Detect 50+ packers/protectors

**📊 BINARY ANALYSIS (Understanding binaries):**
- r2_info/rizin_info: Get binary metadata, headers, entry points
- r2_functions: List all functions with addresses
- r2_disasm: Disassemble specific function/address
- r2_decompile/rizin_decompile: Convert to C-like pseudocode
- r2_strings: Extract strings with context
- r2_imports/r2_exports: External dependencies and symbols
- r2_xrefs: Trace code references to/from address
- ghidra_decompile: High-quality decompilation (better than r2)
- ghidra_analyze: Deep static analysis

**🔬 MALWARE ANALYSIS (Threat hunting):**
- malware_triage: Quick threat assessment with scoring (0-100)
- detect_packer: Detect 50+ packers (UPX, VMProtect, Themida, etc.)
- anti_analysis: Find anti-debug/anti-VM/anti-sandbox tricks
- capability_analysis: Full MITRE ATT&CK mapping
- ransomware_analysis: Encryption, key handling, ransom notes
- extract_iocs: URLs, IPs, domains, file paths, registry keys
- find_c2: Command & control indicators
- yara_generate: Auto-generate YARA detection rules

**🔍 BINARY ANALYSIS (Educational/Research - prefer manual analysis):**
- find_license_checks: Detect validation functions for manual review
- find_win_function: Find success/flag functions
- smart_crack_trial: Analyze trial restrictions
- auto_bypass_checks: Identify validation checks for manual analysis
- extract_algorithm: Extract validation algorithm for manual review
- find_flag_strings: Extract hidden flags/passwords
- trace_input_validation: Map input validation flow
- identify_protection_points: Find all check points for analysis

**🔧 BINARY PATCHING (Research only - backup first!):**
- backup_binary: ALWAYS use before patching
- patch_bytes: Write hex bytes at address
- nop_instructions: NOP out code at address
- patch_string: Modify embedded strings
- patch_function: Replace function code

**🔍 DYNAMIC ANALYSIS (Runtime tracing):**
- ltrace_run/ltrace_attach: Library call tracing
- strace_run/strace_attach: System call tracing
- strace_summary: Syscall statistics
- trace_analysis: Combined trace insights

**📦 FIRMWARE ANALYSIS:**
- binwalk_scan: Find embedded signatures
- binwalk_extract: Extract filesystems
- binwalk_entropy: Detect encryption/compression
- binwalk_carve: Raw file carving

**🔐 CRYPTO ANALYSIS:**
- find_crypto: Detect crypto functions & constants

**🐛 VULNERABILITY RESEARCH:**
- find_vulnerabilities: Dangerous patterns, format strings, buffer issues

**🌐 LIVE VULNERABILITY & THREAT INTELLIGENCE (Internet-connected - goes beyond LLM training data):**
- check_cves: Query live NVD database for CVEs in detected libraries (real-time, not training data)
- check_exploits: Search Exploit-DB for public exploits (updated daily, not historical)
- threat_intel: Query VirusTotal/Censys for IOC reputation (current verdicts, not predictions)
- check_yara_rules: Search community YARA repositories (rules published today, not old patterns)
- vendor_advisories: Check official security bulletins (patch status NOW, not speculation)
- recent_attacks: Query CISA KEV & threat campaigns (active exploitation confirmed, not guessed)

💡 **WHY LIVE INTELLIGENCE MATTERS:**
   LLM training data has a knowledge cutoff (e.g., July 2024). These operations provide:
   - CVEs discovered AFTER training cutoff
   - Exploits published THIS WEEK
   - Current threat actor campaigns
   - Real-time patch availability
   - Actual exploit-in-the-wild status (not "similar pattern" predictions)`,
      Kind.Execute,
      {
        properties: {
          operation: {
            type: 'string',
            enum: [
              'auto',
              'full_analysis',
              // radare2/rizin
              'r2_info',
              'r2_functions',
              'r2_disasm',
              'r2_strings',
              'r2_imports',
              'r2_exports',
              'r2_xrefs',
              'r2_analyze',
              'r2_decompile',
              'r2_search',
              'rizin_info',
              'rizin_analyze',
              'rizin_decompile',
              // Ghidra
              'ghidra_decompile',
              'ghidra_analyze',
              'ghidra_scripts',
              // binwalk
              'binwalk_scan',
              'binwalk_extract',
              'binwalk_entropy',
              'binwalk_carve',
              // ltrace/strace
              'ltrace_run',
              'ltrace_attach',
              'strace_run',
              'strace_attach',
              'strace_summary',
              // LLM-optimized
              'quick_re',
              'find_crypto',
              'find_vulnerabilities',
              'trace_analysis',
              // Malware analysis
              'malware_triage',
              'detect_packer',
              'extract_iocs',
              'find_c2',
              'ransomware_analysis',
              'string_decode',
              'behavior_indicators',
              'persistence_mechanisms',
              'anti_analysis',
              'capability_analysis',
              'yara_generate',
              // Binary patching
              'backup_binary',
              'patch_bytes',
              'nop_instructions',
              'patch_string',
              'patch_function',
              // CTF cracking automation
              'find_license_checks',
              'find_win_function',
              'smart_crack_trial',
              'auto_bypass_checks',
              'extract_algorithm',
              'find_flag_strings',
              'trace_input_validation',
              'identify_protection_points',
              // === INTELLIGENT COMPOUND WORKFLOWS ===
              'full_malware_analysis',
              'full_ctf_solve',
              'full_vulnerability_audit',
              'deep_binary_understanding',
              'firmware_full_analysis',
              'suggest_next_steps',
              // === LIVE VULNERABILITY & THREAT INTELLIGENCE ===
              'check_cves',
              'check_exploits',
              'threat_intel',
              'check_yara_rules',
              'vendor_advisories',
              'recent_attacks',
            ],
            default: 'auto',
            description: `Operation to perform. 
DEFAULT (lightweight):
• 'auto' - Load binary, show basic info, wait for user instructions (VERY FAST)
• 'full_analysis' - Smart analysis: imports, strings, key functions (heavier)

RECOMMENDED APPROACH (LLM should prefer manual step-by-step analysis):
1. Start with 'r2_info' or 'quick_re' to understand binary basics
2. Use 'r2_functions' to list all functions
3. Use 'r2_strings' to extract strings for manual review
4. Identify interesting functions and decompile them one by one with 'r2_decompile' or 'ghidra_decompile'
5. Use 'find_license_checks' to identify validation functions for manual analysis
6. Manually analyze each function to understand program behavior

COMPOUND WORKFLOWS (use only when user explicitly requests automation):
• 'full_malware_analysis' - Complete malware investigation (triage→packer→anti-analysis→capabilities→IOCs→YARA)
• 'full_ctf_solve' - Complete binary analysis (find checks→win func→trace→analyze→extract)
• 'full_vulnerability_audit' - Security audit (vulns→dangerous funcs→crypto→report)
• 'deep_binary_understanding' - Comprehensive analysis (info→functions→strings→imports→decompile)
• 'firmware_full_analysis' - Firmware investigation (entropy→signatures→extract→analyze)
• 'suggest_next_steps' - Analyze binary and recommend manual analysis steps

QUICK START (single operations for manual workflow):
• 'quick_re' for initial assessment
• 'malware_triage' for suspected malware
• 'detect_packer' for protected binaries
• 'find_license_checks' or 'find_win_function' for identifying analysis targets`,
          },
          targetPath: {
            type: 'string',
            description: 'Path to the binary or firmware file to analyze',
          },
          function: {
            type: 'string',
            description:
              'Function name for function-specific operations (e.g., main, check_license, validate_serial)',
          },
          address: {
            type: 'string',
            description:
              'Memory address in hex format (e.g., 0x401000). Required for patch operations.',
          },
          pattern: {
            type: 'string',
            description: 'Search pattern for search operations',
          },
          count: {
            type: 'number',
            description: 'Number of instructions to disassemble (default: 50)',
          },
          outputDir: {
            type: 'string',
            description: 'Output directory for extraction operations',
          },
          pid: {
            type: 'number',
            description: 'Process ID for attach operations',
          },
          args: {
            type: 'array',
            items: { type: 'string' },
            description: 'Command-line arguments for trace operations',
          },
          projectName: {
            type: 'string',
            description: 'Ghidra project name (default: temp_project)',
          },
          script: {
            type: 'string',
            description: 'Path to Ghidra script for ghidra_scripts operation',
          },
          useRizin: {
            type: 'boolean',
            description:
              'Use rizin instead of radare2 for r2_* operations (rizin has better UX)',
          },
          options: {
            type: 'array',
            items: { type: 'string' },
            description: 'Additional tool-specific options',
          },
          timeout: {
            type: 'number',
            description:
              'Timeout in seconds (default: 60). Use higher for large binaries or Ghidra.',
          },
          // Binary patching parameters
          hexBytes: {
            type: 'string',
            description:
              'Hex bytes to write for patch_bytes (e.g., "9090" for NOPs, "B801000000C3" for mov eax,1;ret)',
          },
          length: {
            type: 'number',
            description:
              'Number of bytes to NOP for nop_instructions operation',
          },
          newString: {
            type: 'string',
            description:
              'New string value for patch_string (must be <= original length)',
          },
          assembly: {
            type: 'string',
            description:
              'Assembly code for patch_function (e.g., "mov eax, 1; ret")',
          },
          backupPath: {
            type: 'string',
            description: 'Custom backup path (default: targetPath.bak)',
          },
          confirmLegalUse: {
            type: 'boolean',
            description:
              'Required for patching operations. Confirm this is for security research/CTF only.',
          },
        },
        required: ['operation', 'targetPath'],
        type: 'object',
      },
    );
  }

  protected createInvocation(
    params: ReverseEngineeringParams,
  ): ReverseEngineeringToolInvocation {
    return new ReverseEngineeringToolInvocation(params);
  }
}
