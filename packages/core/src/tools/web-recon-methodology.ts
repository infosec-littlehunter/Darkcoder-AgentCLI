/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Web Reconnaissance Methodology Tool
 *
 * Provides structured guidance for professional web penetration testing
 * following industry-standard methodologies:
 * - OWASP Testing Guide
 * - PTES (Penetration Testing Execution Standard)
 * - NIST SP 800-115
 * - Bug Bounty Hunter Methodology
 *
 * Phases:
 * 1. Passive Reconnaissance
 * 2. Active Reconnaissance
 * 3. Discovery & Enumeration
 * 4. Vulnerability Assessment
 * 5. Exploitation
 * 6. Post-Exploitation
 * 7. Reporting
 */

import { BaseDeclarativeTool, Kind, type ToolResult } from './tools.js';
import { BaseToolInvocation } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';

/**
 * Methodology phases
 */
type MethodologyPhase =
  | 'passive_recon'
  | 'active_recon'
  | 'discovery'
  | 'vulnerability_assessment'
  | 'exploitation'
  | 'post_exploitation'
  | 'reporting'
  | 'full_workflow';

/**
 * Target scope type
 */
type ScopeType =
  | 'single_target'
  | 'subdomain_scope'
  | 'wildcard_scope'
  | 'ip_range'
  | 'api_only';

/**
 * Methodology parameters
 */
interface MethodologyParams {
  /** Target URL or domain */
  target: string;

  /** Current phase to get guidance for */
  phase: MethodologyPhase;

  /** Scope type for the engagement */
  scopeType?: ScopeType;

  /** Bug bounty program context */
  bugBounty?: boolean;

  /** Stealth mode (minimize detection) */
  stealthMode?: boolean;

  /** Previous findings to consider */
  previousFindings?: string;

  /** Technologies detected */
  technologies?: string;

  /** Get tool recommendations */
  getToolRecommendations?: boolean;

  /** Get checklist for current phase */
  getChecklist?: boolean;

  /** OWASP category focus */
  owaspCategory?: string;
}

/**
 * Phase step definition
 */
interface PhaseStep {
  order: number;
  name: string;
  description: string;
  tools: string[];
  commands: string[];
  tips: string[];
  outputArtifacts: string[];
}

/**
 * OWASP Top 10 2021 Categories
 */
const OWASP_TOP_10 = {
  A01: {
    name: 'Broken Access Control',
    tests: [
      'IDOR testing on all endpoints',
      'Horizontal privilege escalation',
      'Vertical privilege escalation',
      'Missing function level access control',
      'Metadata manipulation (JWT, cookies)',
      'CORS misconfiguration',
      'Force browsing to authenticated pages',
    ],
    tools: ['ffuf', 'burp', 'nuclei'],
  },
  A02: {
    name: 'Cryptographic Failures',
    tests: [
      'SSL/TLS configuration analysis',
      'Weak cipher detection',
      'Certificate validation',
      'Sensitive data in transit',
      'Sensitive data at rest',
      'Password storage mechanisms',
      'Deprecated crypto algorithms',
    ],
    tools: ['ssl_scanner', 'testssl.sh', 'nuclei'],
  },
  A03: {
    name: 'Injection',
    tests: [
      'SQL injection (error, blind, time-based)',
      'NoSQL injection',
      'OS command injection',
      'LDAP injection',
      'XPath injection',
      'Header injection',
      'Template injection (SSTI)',
    ],
    tools: ['ffuf', 'sqlmap', 'nuclei', 'burp'],
  },
  A04: {
    name: 'Insecure Design',
    tests: [
      'Business logic flaws',
      'Missing rate limiting',
      'Credential stuffing protection',
      'Bot protection mechanisms',
      'Trust boundary analysis',
      'Threat modeling gaps',
    ],
    tools: ['manual', 'burp', 'ffuf'],
  },
  A05: {
    name: 'Security Misconfiguration',
    tests: [
      'Default credentials',
      'Unnecessary features enabled',
      'Error handling exposes info',
      'Missing security headers',
      'Outdated software versions',
      'Cloud storage misconfig (S3, GCS)',
      'Directory listing enabled',
    ],
    tools: ['nuclei', 'ffuf', 'ssl_scanner', 'nikto'],
  },
  A06: {
    name: 'Vulnerable & Outdated Components',
    tests: [
      'Component version detection',
      'Known CVE identification',
      'Dependency confusion',
      'Outdated JavaScript libraries',
      'Vulnerable server software',
      'End-of-life software',
    ],
    tools: ['nuclei', 'web_tech', 'retire.js', 'snyk'],
  },
  A07: {
    name: 'Identification & Authentication Failures',
    tests: [
      'Brute force protection',
      'Weak password policy',
      'Credential recovery flaws',
      'Session management issues',
      'Multi-factor auth bypass',
      'Session fixation',
      'JWT vulnerabilities',
    ],
    tools: ['ffuf', 'hydra', 'burp', 'nuclei'],
  },
  A08: {
    name: 'Software & Data Integrity Failures',
    tests: [
      'Insecure deserialization',
      'CI/CD pipeline security',
      'Unsigned updates',
      'Untrusted data deserialization',
      'Mass assignment',
    ],
    tools: ['nuclei', 'burp', 'ysoserial'],
  },
  A09: {
    name: 'Security Logging & Monitoring Failures',
    tests: [
      'Audit log coverage',
      'Log injection',
      'Alerting mechanisms',
      'Log integrity',
      'Penetration detection',
    ],
    tools: ['manual', 'burp'],
  },
  A10: {
    name: 'Server-Side Request Forgery (SSRF)',
    tests: [
      'URL parameter SSRF',
      'Webhook SSRF',
      'File upload SSRF',
      'PDF generation SSRF',
      'Cloud metadata access',
      'Internal service access',
    ],
    tools: ['ffuf', 'burp', 'nuclei'],
  },
};

/**
 * Professional methodology phases with detailed steps
 */
const METHODOLOGY_PHASES: Record<string, PhaseStep[]> = {
  passive_recon: [
    {
      order: 1,
      name: 'WHOIS & DNS Intelligence',
      description:
        'Gather domain registration and DNS infrastructure information',
      tools: ['whois', 'dig', 'host', 'dnsenum'],
      commands: [
        'whois {target}',
        'dig {target} ANY +noall +answer',
        'dig {target} TXT',
        'dig {target} MX',
        'host -t ns {target}',
      ],
      tips: [
        'Look for registrant email for social engineering',
        'Note DNS providers for potential zone transfer',
        'Check for SPF/DKIM/DMARC records',
        'Historical WHOIS via whoishistory.com',
      ],
      outputArtifacts: ['registrant_info.txt', 'dns_records.txt'],
    },
    {
      order: 2,
      name: 'Subdomain Enumeration (Passive)',
      description: 'Discover subdomains without directly querying the target',
      tools: ['subfinder', 'amass', 'crt.sh', 'wayback_machine', 'censys'],
      commands: [
        'subfinder -d {target} -silent',
        'curl -s "https://crt.sh/?q=%.{target}&output=json" | jq -r ".[].name_value" | sort -u',
        'curl -s "https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey"',
      ],
      tips: [
        'Use multiple sources for comprehensive coverage',
        'Check Certificate Transparency logs',
        'Search GitHub for leaked subdomains',
        'Use Google dorks: site:*.{target}',
      ],
      outputArtifacts: ['subdomains_passive.txt'],
    },
    {
      order: 3,
      name: 'Technology Fingerprinting (Passive)',
      description: 'Identify technologies from public sources',
      tools: ['web_tech', 'builtwith', 'wappalyzer'],
      commands: [
        'web_tech target={target}',
        'curl -s "https://api.builtwith.com/free1/api.json?KEY={api}&LOOKUP={target}"',
      ],
      tips: [
        'Check job postings for tech stack hints',
        'Analyze JavaScript files for framework signatures',
        'Look at HTTP headers from cached pages',
      ],
      outputArtifacts: ['technologies.txt'],
    },
    {
      order: 4,
      name: 'OSINT & Information Gathering',
      description: 'Collect publicly available information about the target',
      tools: ['google_dorks', 'censys', 'wayback_machine'],
      commands: [
        'censys_search query="{target}"',
        'censys_search query="{target}"',
        'wayback_machine operation=search target={target}',
      ],
      tips: [
        'Search for exposed credentials in breach databases',
        'Check Pastebin and GitHub for leaks',
        'Look for company documents with metadata',
        'Social media reconnaissance for employees',
      ],
      outputArtifacts: ['osint_findings.txt', 'exposed_services.txt'],
    },
    {
      order: 5,
      name: 'Historical Data Analysis',
      description: 'Analyze historical snapshots and archived content',
      tools: ['wayback_machine', 'google_cache'],
      commands: [
        'wayback_machine operation=urls target={target}',
        'wayback_machine operation=snapshots target={target}',
      ],
      tips: [
        'Look for removed sensitive pages',
        'Find old admin panels or dev environments',
        'Identify deprecated but accessible endpoints',
        'Check for exposed API keys in old versions',
      ],
      outputArtifacts: ['historical_urls.txt', 'archived_pages.txt'],
    },
  ],

  active_recon: [
    {
      order: 1,
      name: 'Port Scanning & Service Detection',
      description: 'Identify open ports and running services',
      tools: ['nmap', 'masscan', 'rustscan'],
      commands: [
        'nmap -sC -sV -p- -T4 {target} -oA nmap_full',
        'nmap -sU --top-ports 100 {target}',
        'nmap --script vuln {target}',
      ],
      tips: [
        'Start with top ports, then full scan',
        'Use -sV for version detection',
        'Check for non-standard ports (8080, 8443, etc.)',
        'UDP scan for DNS, SNMP, etc.',
      ],
      outputArtifacts: ['nmap_results.xml', 'open_ports.txt'],
    },
    {
      order: 2,
      name: 'Subdomain Enumeration (Active)',
      description: 'Brute-force subdomain discovery',
      tools: ['ffuf', 'gobuster', 'subfinder', 'amass'],
      commands: [
        'ffuf mode=vhost target=https://{target} autoCalibrate=true',
        'gobuster dns -d {target} -w ~/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt',
      ],
      tips: [
        'Use multiple wordlists for coverage',
        'Try zone transfer if DNS allows',
        'Check wildcard DNS response',
        'Verify discovered subdomains are in scope',
      ],
      outputArtifacts: ['subdomains_active.txt', 'live_hosts.txt'],
    },
    {
      order: 3,
      name: 'Web Server Fingerprinting',
      description: 'Identify web server type, version, and configuration',
      tools: ['whatweb', 'web_tech', 'curl'],
      commands: [
        'web_tech target={target}',
        'curl -I https://{target}',
        'whatweb -v https://{target}',
      ],
      tips: [
        'Note Server header for version info',
        'Check X-Powered-By header',
        'Look for framework-specific headers',
        'Identify WAF presence (Cloudflare, Akamai)',
      ],
      outputArtifacts: ['web_fingerprint.txt'],
    },
    {
      order: 4,
      name: 'SSL/TLS Security Assessment',
      description: 'Analyze SSL/TLS configuration and vulnerabilities',
      tools: ['ssl_scanner', 'testssl.sh', 'sslyze'],
      commands: [
        'ssl_scanner mode=standard target={target}',
        'ssl_scanner mode=vulnerabilities target={target}',
        'testssl.sh {target}',
      ],
      tips: [
        'Check for deprecated protocols (TLS 1.0/1.1)',
        'Identify weak cipher suites',
        'Verify certificate chain',
        'Check for known SSL vulnerabilities',
      ],
      outputArtifacts: ['ssl_report.txt', 'certificate_info.txt'],
    },
  ],

  discovery: [
    {
      order: 1,
      name: 'Directory & File Discovery',
      description: 'Find hidden directories, files, and endpoints',
      tools: ['ffuf', 'gobuster', 'dirsearch', 'feroxbuster'],
      commands: [
        'ffuf mode=dir target=https://{target} extensions=php,html,js,txt,bak',
        'ffuf mode=dir target=https://{target} wordlist=sensitive',
        'seclists operation=recommend useCase=directory scanType=thorough',
      ],
      tips: [
        'Start with common.txt, then larger wordlists',
        'Use -e for common extensions',
        'Check for backup files (.bak, .old, ~)',
        'Look for hidden API endpoints',
        'Try case variations on Windows servers',
      ],
      outputArtifacts: ['directories.txt', 'sensitive_files.txt'],
    },
    {
      order: 2,
      name: 'Sensitive File Discovery',
      description: 'Find configuration files, backups, and sensitive data',
      tools: ['ffuf', 'nuclei'],
      commands: [
        'ffuf mode=dir target=https://{target} wordlist=sensitive',
        'nuclei -u https://{target} -t exposures/',
        'nuclei -u https://{target} -t misconfiguration/',
      ],
      tips: [
        'Check for .git, .svn, .env exposure',
        'Look for phpinfo.php, info.php',
        'Find backup files (*.sql, *.bak)',
        'Check robots.txt and sitemap.xml',
        'Look for swagger.json, openapi.yaml',
      ],
      outputArtifacts: ['sensitive_findings.txt'],
    },
    {
      order: 3,
      name: 'API Endpoint Discovery',
      description: 'Enumerate API endpoints and documentation',
      tools: ['ffuf', 'nuclei', 'kiterunner'],
      commands: [
        'ffuf mode=api target=https://{target}/api',
        'ffuf mode=api target=https://{target}/api/v1',
        'nuclei -u https://{target} -t exposures/apis/',
      ],
      tips: [
        'Check /api, /v1, /v2, /graphql',
        'Look for Swagger/OpenAPI docs',
        'Test for GraphQL introspection',
        'Check for API versioning patterns',
        'Look for mobile API endpoints',
      ],
      outputArtifacts: ['api_endpoints.txt', 'api_documentation.txt'],
    },
    {
      order: 4,
      name: 'Parameter Discovery',
      description: 'Find hidden parameters in endpoints',
      tools: ['ffuf', 'arjun', 'paramspider'],
      commands: [
        'ffuf mode=param target=https://{target}/endpoint',
        'arjun -u https://{target}/endpoint',
      ],
      tips: [
        'Test common parameters (id, user, page, debug)',
        'Look for hidden form fields',
        'Check for parameter pollution',
        'Test for mass assignment',
      ],
      outputArtifacts: ['parameters.txt'],
    },
    {
      order: 5,
      name: 'JavaScript Analysis',
      description: 'Analyze JavaScript files for secrets and endpoints',
      tools: ['linkfinder', 'secretfinder', 'jsluice'],
      commands: [
        'linkfinder -i https://{target} -o cli',
        'secretfinder -i https://{target}/js/app.js -o cli',
      ],
      tips: [
        'Extract API endpoints from JS',
        'Look for hardcoded credentials',
        'Find hidden admin functions',
        'Check for source maps (.js.map)',
        'Analyze webpack chunks',
      ],
      outputArtifacts: ['js_endpoints.txt', 'js_secrets.txt'],
    },
  ],

  vulnerability_assessment: [
    {
      order: 1,
      name: 'Automated Vulnerability Scanning',
      description: 'Run automated scanners for known vulnerabilities',
      tools: ['nuclei', 'nikto', 'wpscan'],
      commands: [
        'nuclei operation=scan target=https://{target}',
        'nuclei operation=scan target=https://{target} severity=critical,high',
        'nikto -h https://{target}',
      ],
      tips: [
        'Run nuclei with multiple template categories',
        'Update templates before scanning',
        'Focus on critical/high severity first',
        'Cross-reference with manual testing',
      ],
      outputArtifacts: ['nuclei_results.json', 'vulnerabilities.txt'],
    },
    {
      order: 2,
      name: 'OWASP Top 10 Testing',
      description: 'Systematic testing for OWASP Top 10 vulnerabilities',
      tools: ['manual', 'burp', 'nuclei', 'ffuf'],
      commands: [
        'nuclei -u https://{target} -t cves/',
        'nuclei -u https://{target} -t vulnerabilities/',
      ],
      tips: [
        'Test each OWASP category systematically',
        'Document all findings with PoC',
        'Check for business logic flaws manually',
        'Test authentication mechanisms thoroughly',
      ],
      outputArtifacts: ['owasp_findings.txt'],
    },
    {
      order: 3,
      name: 'Injection Testing',
      description: 'Test for SQL, XSS, Command injection, etc.',
      tools: ['sqlmap', 'xsstrike', 'commix', 'ffuf'],
      commands: [
        'sqlmap -u "https://{target}/page?id=1" --batch --level=3',
        'xsstrike -u "https://{target}/search?q=test"',
      ],
      tips: [
        'Test all input parameters',
        'Try different injection contexts',
        'Check for blind injection',
        'Test file upload functionality',
        'Check for SSTI in templates',
      ],
      outputArtifacts: ['injection_results.txt'],
    },
    {
      order: 4,
      name: 'Authentication & Session Testing',
      description: 'Test authentication mechanisms and session management',
      tools: ['ffuf', 'hydra', 'burp'],
      commands: [
        'ffuf -u https://{target}/login -d "user=FUZZ&pass=test" -w users.txt',
        'hydra -l admin -P passwords.txt {target} https-post-form "/login:user=^USER^&pass=^PASS^:Invalid"',
      ],
      tips: [
        'Test password complexity requirements',
        'Check for account lockout',
        'Test session fixation',
        'Check JWT implementation',
        'Test MFA bypass techniques',
      ],
      outputArtifacts: ['auth_findings.txt'],
    },
    {
      order: 5,
      name: 'Access Control Testing',
      description:
        'Test for broken access control (IDOR, privilege escalation)',
      tools: ['burp', 'autorize', 'ffuf'],
      commands: ['ffuf -u https://{target}/api/users/FUZZ -w numbers.txt'],
      tips: [
        'Test horizontal privilege escalation',
        'Test vertical privilege escalation',
        'Check for IDOR on all resources',
        'Test role-based access control',
        'Check for missing function-level access control',
      ],
      outputArtifacts: ['access_control_findings.txt'],
    },
  ],

  exploitation: [
    {
      order: 1,
      name: 'Vulnerability Validation',
      description: 'Confirm and validate discovered vulnerabilities',
      tools: ['burp', 'curl', 'python'],
      commands: ['# Manual validation with curl/burp', '# Create PoC scripts'],
      tips: [
        'Validate all automated findings manually',
        'Create reliable PoC for each vulnerability',
        'Document exact reproduction steps',
        'Assess real-world impact',
      ],
      outputArtifacts: ['validated_vulns.txt', 'poc_scripts/'],
    },
    {
      order: 2,
      name: 'Exploit Development',
      description:
        'Develop or customize exploits for confirmed vulnerabilities',
      tools: ['metasploit', 'custom_scripts'],
      commands: [
        '# Customize exploit for target',
        '# Test in safe environment first',
      ],
      tips: [
        'Test exploits in isolated environment',
        'Have rollback plan ready',
        'Document all actions taken',
        'Coordinate with target if needed',
      ],
      outputArtifacts: ['exploits/', 'exploit_log.txt'],
    },
    {
      order: 3,
      name: 'Controlled Exploitation',
      description: 'Execute exploits in controlled manner with minimal impact',
      tools: ['metasploit', 'custom_scripts'],
      commands: ['# Execute with minimal footprint', '# Log all actions'],
      tips: [
        'Only exploit within agreed scope',
        'Minimize data access/extraction',
        'Maintain detailed logs',
        'Be prepared to stop immediately',
      ],
      outputArtifacts: ['exploitation_log.txt', 'evidence/'],
    },
  ],

  post_exploitation: [
    {
      order: 1,
      name: 'Impact Assessment',
      description: 'Assess the real impact of successful exploitation',
      tools: ['manual'],
      commands: [],
      tips: [
        'Document what data is accessible',
        'Identify potential lateral movement',
        'Assess business impact',
        'Take screenshots as evidence',
      ],
      outputArtifacts: ['impact_assessment.txt', 'screenshots/'],
    },
    {
      order: 2,
      name: 'Evidence Collection',
      description: 'Collect evidence for reporting',
      tools: ['manual', 'screenshot_tools'],
      commands: [],
      tips: [
        'Screenshot all findings',
        'Save HTTP requests/responses',
        'Document exact steps to reproduce',
        'Collect log evidence',
      ],
      outputArtifacts: ['evidence/', 'reproduction_steps.txt'],
    },
  ],

  reporting: [
    {
      order: 1,
      name: 'Finding Documentation',
      description: 'Document all findings with proper severity ratings',
      tools: ['manual'],
      commands: [],
      tips: [
        'Use CVSS for severity rating',
        'Include business impact',
        'Provide clear reproduction steps',
        'Include remediation recommendations',
      ],
      outputArtifacts: ['findings_report.md'],
    },
    {
      order: 2,
      name: 'Executive Summary',
      description: 'Prepare executive summary for stakeholders',
      tools: ['manual'],
      commands: [],
      tips: [
        'Highlight critical findings',
        'Include risk assessment',
        'Provide remediation priorities',
        'Use non-technical language',
      ],
      outputArtifacts: ['executive_summary.md'],
    },
    {
      order: 3,
      name: 'Technical Report',
      description: 'Detailed technical report with all findings',
      tools: ['manual'],
      commands: [],
      tips: [
        'Include all technical details',
        'Provide PoC code/requests',
        'Add remediation code examples',
        'Reference industry standards',
      ],
      outputArtifacts: ['technical_report.md', 'appendices/'],
    },
  ],
};

/**
 * Methodology invocation handler
 */
class MethodologyInvocation extends BaseToolInvocation<
  MethodologyParams,
  ToolResult
> {
  getDescription(): string {
    const { phase, target } = this.params;
    return `Getting ${phase.replace('_', ' ')} methodology for ${target}`;
  }

  async execute(): Promise<ToolResult> {
    const { phase, target } = this.params;

    let output: string;

    if (phase === 'full_workflow') {
      output = this.generateFullWorkflow();
    } else {
      output = this.generatePhaseGuide(phase);
    }

    // Add target-specific context
    output = output.replace(/\{target\}/g, target);

    // Add tool recommendations if requested
    if (this.params.getToolRecommendations) {
      output += this.getToolRecommendations(phase);
    }

    // Add OWASP-specific guidance if requested
    if (this.params.owaspCategory) {
      output += this.getOwaspGuidance(this.params.owaspCategory);
    }

    // Add checklist if requested
    if (this.params.getChecklist) {
      output += this.generateChecklist(phase);
    }

    return {
      llmContent: output,
      returnDisplay: output,
    };
  }

  /**
   * Generate full workflow overview
   */
  private generateFullWorkflow(): string {
    let output = `# Web Penetration Testing Methodology\n\n`;
    output += `**Target:** ${this.params.target}\n`;
    output += `**Scope:** ${this.params.scopeType || 'single_target'}\n`;
    output += `**Mode:** ${this.params.stealthMode ? 'Stealth' : 'Standard'}\n`;
    output += `**Date:** ${new Date().toISOString().split('T')[0]}\n\n`;

    output += `## Methodology Overview\n\n`;
    output += `This methodology follows industry standards:\n`;
    output += `- OWASP Testing Guide v4.2\n`;
    output += `- PTES (Penetration Testing Execution Standard)\n`;
    output += `- Bug Bounty Hunter Methodology\n\n`;

    output += `## Phase Progression\n\n`;
    output += '```\n';
    output += '┌─────────────────────┐\n';
    output += '│  1. PASSIVE RECON   │  OSINT, DNS, WHOIS, Historical\n';
    output += '└──────────┬──────────┘\n';
    output += '           ▼\n';
    output += '┌─────────────────────┐\n';
    output += '│  2. ACTIVE RECON    │  Port scan, SSL, Fingerprint\n';
    output += '└──────────┬──────────┘\n';
    output += '           ▼\n';
    output += '┌─────────────────────┐\n';
    output += '│  3. DISCOVERY       │  Dirs, Files, APIs, Params\n';
    output += '└──────────┬──────────┘\n';
    output += '           ▼\n';
    output += '┌─────────────────────┐\n';
    output += '│  4. VULN ASSESSMENT │  OWASP Top 10, CVEs\n';
    output += '└──────────┬──────────┘\n';
    output += '           ▼\n';
    output += '┌─────────────────────┐\n';
    output += '│  5. EXPLOITATION    │  Validate, PoC, Exploit\n';
    output += '└──────────┬──────────┘\n';
    output += '           ▼\n';
    output += '┌─────────────────────┐\n';
    output += '│  6. REPORTING       │  Document, Remediate\n';
    output += '└─────────────────────┘\n';
    output += '```\n\n';

    // Phase summary
    const phases = Object.keys(METHODOLOGY_PHASES);
    phases.forEach((phase, index) => {
      const steps = METHODOLOGY_PHASES[phase];
      output += `### ${index + 1}. ${this.formatPhaseName(phase)}\n`;
      steps.forEach((step) => {
        output += `   ${step.order}. ${step.name}\n`;
      });
      output += '\n';
    });

    output += `## Quick Start Commands\n\n`;
    output += '```bash\n';
    output += `# Phase 1: Passive Recon\n`;
    output += `subfinder -d {target} -silent > subdomains.txt\n`;
    output += `wayback_machine operation=urls target={target}\n\n`;
    output += `# Phase 2: Active Recon\n`;
    output += `nmap -sC -sV -p- {target}\n`;
    output += `ssl_scanner mode=standard target={target}\n\n`;
    output += `# Phase 3: Discovery\n`;
    output += `ffuf mode=dir target=https://{target}\n`;
    output += `ffuf mode=api target=https://{target}/api\n\n`;
    output += `# Phase 4: Vulnerability Assessment\n`;
    output += `nuclei operation=scan target=https://{target}\n`;
    output += '```\n';

    return output;
  }

  /**
   * Generate detailed guide for a specific phase
   */
  private generatePhaseGuide(phase: string): string {
    const steps = METHODOLOGY_PHASES[phase];
    if (!steps) {
      return `Unknown phase: ${phase}. Valid phases: ${Object.keys(METHODOLOGY_PHASES).join(', ')}`;
    }

    let output = `# ${this.formatPhaseName(phase)} - Detailed Guide\n\n`;
    output += `**Target:** ${this.params.target}\n`;
    output += `**Phase:** ${this.formatPhaseName(phase)}\n\n`;

    // Stealth mode notice
    if (this.params.stealthMode) {
      output += `> ⚠️ **STEALTH MODE:** Minimize active scanning, use passive techniques first.\n\n`;
    }

    // Bug bounty context
    if (this.params.bugBounty) {
      output += `> 🎯 **BUG BOUNTY MODE:** Focus on high-impact vulnerabilities, respect scope.\n\n`;
    }

    output += `## Steps\n\n`;

    steps.forEach((step) => {
      output += `### ${step.order}. ${step.name}\n\n`;
      output += `**Objective:** ${step.description}\n\n`;

      // Tools
      output += `**Tools:** ${step.tools.join(', ')}\n\n`;

      // Commands
      if (step.commands.length > 0) {
        output += `**Commands:**\n\`\`\`bash\n`;
        step.commands.forEach((cmd) => {
          output += `${cmd}\n`;
        });
        output += `\`\`\`\n\n`;
      }

      // Tips
      output += `**Tips:**\n`;
      step.tips.forEach((tip) => {
        output += `- ${tip}\n`;
      });
      output += '\n';

      // Output artifacts
      output += `**Output Artifacts:** ${step.outputArtifacts.join(', ')}\n\n`;
      output += `---\n\n`;
    });

    // Add next phase suggestion
    const phases = Object.keys(METHODOLOGY_PHASES);
    const currentIndex = phases.indexOf(phase);
    if (currentIndex < phases.length - 1) {
      const nextPhase = phases[currentIndex + 1];
      output += `## Next Phase\n\n`;
      output += `After completing ${this.formatPhaseName(phase)}, proceed to:\n`;
      output += `**${this.formatPhaseName(nextPhase)}**\n\n`;
      output += `Use: \`web_recon_methodology phase=${nextPhase} target={target}\`\n`;
    }

    return output;
  }

  /**
   * Get tool recommendations for a phase
   */
  private getToolRecommendations(phase: string): string {
    const toolMap: Record<string, Array<{ tool: string; usage: string }>> = {
      passive_recon: [
        {
          tool: 'wayback_machine',
          usage: 'wayback_machine operation=urls target={target}',
        },
        {
          tool: 'censys_search',
          usage: 'censys_search query="hostname:{target}"',
        },
        { tool: 'censys_search', usage: 'censys_search query="{target}"' },
      ],
      active_recon: [
        {
          tool: 'ssl_scanner',
          usage: 'ssl_scanner mode=standard target={target}',
        },
        {
          tool: 'ffuf',
          usage: 'ffuf mode=vhost target=https://{target} autoCalibrate=true',
        },
        { tool: 'web_tech', usage: 'web_tech target={target}' },
      ],
      discovery: [
        {
          tool: 'ffuf',
          usage: 'ffuf mode=dir target=https://{target} extensions=php,html,js',
        },
        {
          tool: 'seclists',
          usage: 'seclists operation=recommend useCase=directory',
        },
        { tool: 'ffuf', usage: 'ffuf mode=api target=https://{target}/api' },
      ],
      vulnerability_assessment: [
        {
          tool: 'nuclei',
          usage: 'nuclei operation=scan target=https://{target}',
        },
        {
          tool: 'nuclei',
          usage:
            'nuclei operation=scan target=https://{target} severity=critical,high',
        },
        {
          tool: 'ssl_scanner',
          usage: 'ssl_scanner mode=vulnerabilities target={target}',
        },
      ],
    };

    const recommendations = toolMap[phase] || [];
    if (recommendations.length === 0) return '';

    let output = `\n## 🛠️ DarkCoder Tool Recommendations\n\n`;
    output += `| Tool | Command |\n`;
    output += `|------|--------|\n`;
    recommendations.forEach(({ tool, usage }) => {
      output += `| ${tool} | \`${usage}\` |\n`;
    });

    return output;
  }

  /**
   * Get OWASP-specific guidance
   */
  private getOwaspGuidance(category: string): string {
    const owaspKey = category.toUpperCase() as keyof typeof OWASP_TOP_10;
    const owasp = OWASP_TOP_10[owaspKey];

    if (!owasp) {
      return `\n## OWASP Category\n\nUnknown category: ${category}. Valid: A01-A10\n`;
    }

    let output = `\n## OWASP ${owaspKey}: ${owasp.name}\n\n`;
    output += `### Testing Checklist\n`;
    owasp.tests.forEach((test, i) => {
      output += `- [ ] ${i + 1}. ${test}\n`;
    });
    output += `\n**Recommended Tools:** ${owasp.tools.join(', ')}\n`;

    return output;
  }

  /**
   * Generate phase checklist
   */
  private generateChecklist(phase: string): string {
    const steps = METHODOLOGY_PHASES[phase];
    if (!steps) return '';

    let output = `\n## ✅ ${this.formatPhaseName(phase)} Checklist\n\n`;

    steps.forEach((step) => {
      output += `### ${step.name}\n`;
      output += `- [ ] Complete ${step.name}\n`;
      step.outputArtifacts.forEach((artifact) => {
        output += `- [ ] Generate: ${artifact}\n`;
      });
      output += '\n';
    });

    return output;
  }

  /**
   * Format phase name for display
   */
  private formatPhaseName(phase: string): string {
    return phase
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }
}

/**
 * Web Reconnaissance Methodology Tool
 */
export class WebReconMethodologyTool extends BaseDeclarativeTool<
  MethodologyParams,
  ToolResult
> {
  static readonly Name = ToolNames.WEB_RECON_METHODOLOGY;

  constructor() {
    super(
      WebReconMethodologyTool.Name,
      ToolDisplayNames.WEB_RECON_METHODOLOGY,
      `Professional web penetration testing methodology guide. Provides structured 
approach following OWASP, PTES, and bug bounty standards.

Phases:
1. passive_recon - OSINT, DNS, WHOIS, historical data
2. active_recon - Port scanning, SSL analysis, fingerprinting
3. discovery - Directory/file/API/parameter enumeration
4. vulnerability_assessment - OWASP Top 10, CVE scanning
5. exploitation - Validate, develop PoC, controlled exploitation
6. post_exploitation - Impact assessment, evidence collection
7. reporting - Documentation, executive summary, technical report
8. full_workflow - Complete methodology overview

Use this tool FIRST to plan your approach, then follow the methodology systematically.`,
      Kind.Fetch,
      {
        type: 'object',
        properties: {
          target: {
            type: 'string',
            description: 'Target URL or domain (e.g., example.com)',
          },
          phase: {
            type: 'string',
            enum: [
              'passive_recon',
              'active_recon',
              'discovery',
              'vulnerability_assessment',
              'exploitation',
              'post_exploitation',
              'reporting',
              'full_workflow',
            ],
            description: 'Methodology phase to get guidance for',
          },
          scopeType: {
            type: 'string',
            enum: [
              'single_target',
              'subdomain_scope',
              'wildcard_scope',
              'ip_range',
              'api_only',
            ],
            description: 'Scope type for the engagement',
          },
          bugBounty: {
            type: 'boolean',
            description:
              'Enable bug bounty context (focus on high-impact, respect scope)',
          },
          stealthMode: {
            type: 'boolean',
            description:
              'Enable stealth mode (minimize detection, passive first)',
          },
          previousFindings: {
            type: 'string',
            description: 'Previous findings to consider for next steps',
          },
          technologies: {
            type: 'string',
            description: 'Detected technologies (e.g., PHP, WordPress, nginx)',
          },
          getToolRecommendations: {
            type: 'boolean',
            description: 'Include DarkCoder tool recommendations for the phase',
          },
          getChecklist: {
            type: 'boolean',
            description: 'Include checklist for the phase',
          },
          owaspCategory: {
            type: 'string',
            description: 'OWASP category for specific guidance (A01-A10)',
          },
        },
        required: ['target', 'phase'],
      },
    );
  }

  protected createInvocation(params: MethodologyParams): MethodologyInvocation {
    return new MethodologyInvocation(params);
  }
}
