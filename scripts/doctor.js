#!/usr/bin/env node
/**
 * DarkCoder Doctor - System Health Check
 *
 * Diagnoses common issues developers might face:
 * - Node.js version
 * - Memory configuration
 * - API keys
 * - Security tools availability
 * - Build status
 */

import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import * as v8 from 'v8';
import os from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
};

const icons = {
  pass: `${colors.green}✓${colors.reset}`,
  fail: `${colors.red}✗${colors.reset}`,
  warn: `${colors.yellow}⚠${colors.reset}`,
  info: `${colors.blue}ℹ${colors.reset}`,
};

let passCount = 0;
let warnCount = 0;
let failCount = 0;

function log(icon, message, detail = '') {
  console.log(
    `  ${icon} ${message}${detail ? ` ${colors.cyan}${detail}${colors.reset}` : ''}`,
  );
}

function pass(message, detail = '') {
  passCount++;
  log(icons.pass, message, detail);
}

function warn(message, detail = '') {
  warnCount++;
  log(icons.warn, message, detail);
}

function fail(message, detail = '') {
  failCount++;
  log(icons.fail, message, detail);
}

function info(message, detail = '') {
  log(icons.info, message, detail);
}

function header(title) {
  console.log(
    `\n${colors.bold}${colors.blue}═══ ${title} ═══${colors.reset}\n`,
  );
}

function commandExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function getCommandVersion(cmd, versionArg = '--version') {
  try {
    const output = execSync(`${cmd} ${versionArg}`, { stdio: 'pipe' })
      .toString()
      .trim();
    return output.split('\n')[0];
  } catch {
    return null;
  }
}

function checkNodeVersion() {
  header('Node.js Environment');

  const nodeVersion = process.version;
  const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0], 10);

  if (majorVersion >= 20) {
    pass(`Node.js version`, nodeVersion);
  } else if (majorVersion >= 18) {
    warn(`Node.js version ${nodeVersion}`, '(20+ recommended)');
  } else {
    fail(`Node.js version ${nodeVersion}`, '(20+ required)');
  }

  const npmVersion = getCommandVersion('npm');
  if (npmVersion) {
    pass(`npm version`, npmVersion.replace('npm ', ''));
  } else {
    fail('npm not found');
  }
}

function checkMemory() {
  header('Memory Configuration');

  const heapStats = v8.getHeapStatistics();
  const heapLimitMB = Math.round(heapStats.heap_size_limit / 1024 / 1024);
  const totalMemoryMB = Math.round(os.totalmem() / 1024 / 1024);

  info(`System RAM`, `${totalMemoryMB} MB`);

  if (heapLimitMB >= 8192) {
    pass(`Node.js heap limit`, `${heapLimitMB} MB`);
  } else if (heapLimitMB >= 4096) {
    warn(`Node.js heap limit ${heapLimitMB} MB`, '(8192 MB recommended)');
    info('Fix: export NODE_OPTIONS="--max-old-space-size=8192"');
  } else {
    fail(
      `Node.js heap limit ${heapLimitMB} MB`,
      '(8192 MB required for large operations)',
    );
    info('Fix: export NODE_OPTIONS="--max-old-space-size=8192"');
  }

  if (process.env.NODE_OPTIONS?.includes('max-old-space-size')) {
    pass('NODE_OPTIONS configured');
  } else {
    warn('NODE_OPTIONS not set', '(add --max-old-space-size=8192)');
  }
}

function checkAPIKeys() {
  header('API Keys');

  const aiProviders = [
    { name: 'Anthropic', env: 'ANTHROPIC_API_KEY' },
    { name: 'OpenAI', env: 'OPENAI_API_KEY' },
    { name: 'Google', env: 'GOOGLE_API_KEY' },
    { name: 'Qwen/DashScope', env: 'DASHSCOPE_API_KEY' },
    { name: 'DeepSeek', env: 'DEEPSEEK_API_KEY' },
    { name: 'OpenRouter', env: 'OPENROUTER_API_KEY' },
  ];

  const securityTools = [
    { name: 'Shodan', env: 'SHODAN_API_KEY' },
    { name: 'Censys', env: 'CENSYS_API_ID' },
    { name: 'VirusTotal', env: 'VIRUSTOTAL_API_KEY' },
    { name: 'URLScan', env: 'URLSCAN_API_KEY' },
  ];

  let hasAIKey = false;

  console.log('  AI Providers:');
  for (const provider of aiProviders) {
    if (process.env[provider.env]) {
      pass(`  ${provider.name}`, 'configured');
      hasAIKey = true;
    } else {
      info(`  ${provider.name}`, 'not set');
    }
  }

  if (!hasAIKey) {
    fail('No AI provider API key found', '(at least one required)');
  }

  console.log('\n  Security Tool APIs (optional):');
  for (const tool of securityTools) {
    if (process.env[tool.env]) {
      pass(`  ${tool.name}`, 'configured');
    } else {
      info(`  ${tool.name}`, 'not set');
    }
  }
}

function checkSecurityTools() {
  header('Security Tools');

  const tools = [
    { name: 'nuclei', purpose: 'vulnerability scanning', required: false },
    { name: 'ffuf', purpose: 'web fuzzing', required: false },
    { name: 'nmap', purpose: 'network scanning', required: false },
    { name: 'radare2', purpose: 'reverse engineering', required: false },
    { name: 'rizin', purpose: 'RE framework', required: false },
    { name: 'binwalk', purpose: 'firmware analysis', required: false },
    { name: 'strings', purpose: 'binary strings', required: false },
    { name: 'file', purpose: 'file type detection', required: false },
    { name: 'objdump', purpose: 'binary disassembly', required: false },
    { name: 'ROPgadget', purpose: 'ROP chain finder', required: false },
    { name: 'git', purpose: 'version control', required: true },
    { name: 'curl', purpose: 'HTTP requests', required: true },
  ];

  let installedCount = 0;

  for (const tool of tools) {
    if (commandExists(tool.name)) {
      pass(`${tool.name}`, `(${tool.purpose})`);
      installedCount++;
    } else if (tool.required) {
      fail(`${tool.name} not found`, `(${tool.purpose} - required)`);
    } else {
      info(`${tool.name} not found`, `(${tool.purpose} - optional)`);
    }
  }

  console.log(
    `\n  ${colors.cyan}${installedCount}/${tools.length} tools available${colors.reset}`,
  );
}

function checkBuildStatus() {
  header('Build Status');

  // Check if node_modules exists
  if (existsSync(join(rootDir, 'node_modules'))) {
    pass('node_modules installed');
  } else {
    fail('node_modules not found', '(run: npm install)');
  }

  // Check if dist exists
  if (existsSync(join(rootDir, 'dist'))) {
    pass('dist folder exists');
  } else {
    warn('dist folder not found', '(run: npm run build)');
  }

  // Check package.json
  try {
    const pkg = JSON.parse(
      readFileSync(join(rootDir, 'package.json'), 'utf-8'),
    );
    pass(`Package version`, pkg.version);
  } catch {
    fail('package.json not readable');
  }

  // Check for .env file
  if (existsSync(join(rootDir, '.env'))) {
    pass('.env file exists');
  } else if (existsSync(join(rootDir, '.env.example'))) {
    warn('.env not found', '(copy from .env.example)');
  } else {
    info('.env not found', '(use environment variables instead)');
  }
}

function checkGit() {
  header('Git Status');

  try {
    const branch = execSync('git rev-parse --abbrev-ref HEAD', {
      cwd: rootDir,
      stdio: 'pipe',
    })
      .toString()
      .trim();
    pass(`Current branch`, branch);
  } catch {
    warn('Not a git repository or git not installed');
  }

  try {
    const remote = execSync('git remote get-url origin', {
      cwd: rootDir,
      stdio: 'pipe',
    })
      .toString()
      .trim();
    pass(`Remote origin`, remote.replace(/https?:\/\/[^@]+@/, 'https://'));
  } catch {
    info('No remote origin configured');
  }
}

function printSummary() {
  header('Summary');

  console.log(`  ${icons.pass} Passed: ${passCount}`);
  console.log(`  ${icons.warn} Warnings: ${warnCount}`);
  console.log(`  ${icons.fail} Failed: ${failCount}`);

  console.log();

  if (failCount > 0) {
    console.log(
      `  ${colors.red}${colors.bold}Some critical issues found!${colors.reset}`,
    );
    console.log(
      `  ${colors.cyan}See docs/DEVELOPER_SETUP.md for solutions${colors.reset}`,
    );
    process.exit(1);
  } else if (warnCount > 0) {
    console.log(
      `  ${colors.yellow}${colors.bold}Some warnings, but you can proceed${colors.reset}`,
    );
    console.log(
      `  ${colors.cyan}See docs/DEVELOPER_SETUP.md to optimize your setup${colors.reset}`,
    );
  } else {
    console.log(
      `  ${colors.green}${colors.bold}All checks passed! You're ready to develop! 🚀${colors.reset}`,
    );
  }

  console.log();
}

// Main execution
console.log(`
${colors.bold}${colors.cyan}
╔═══════════════════════════════════════════════════════════╗
║          DarkCoder Doctor - System Health Check           ║
╚═══════════════════════════════════════════════════════════╝
${colors.reset}`);

checkNodeVersion();
checkMemory();
checkAPIKeys();
checkSecurityTools();
checkBuildStatus();
checkGit();
printSummary();
