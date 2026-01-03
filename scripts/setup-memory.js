#!/usr/bin/env node

/**
 * DarkCoder Memory Configuration Setup Script (Cross-Platform)
 * Configures NODE_OPTIONS for optimal memory management
 * Works on Windows, macOS, and Linux
 */

import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { createInterface } from 'node:readline';

// Colors for output (cross-platform)
const colors = {
  reset: '',
  green: '',
  blue: '',
  yellow: '',
  red: '',
};

if (process.stdout.isTTY) {
  colors.reset = '\x1b[0m';
  colors.green = '\x1b[32m';
  colors.blue = '\x1b[34m';
  colors.yellow = '\x1b[33m';
  colors.red = '\x1b[31m';
}

const c = colors;

async function getUserInput(prompt) {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function getShellConfig() {
  const home = homedir();
  const currentOS = platform();
  const shells = {
    bashrc: join(home, '.bashrc'),
    bash_profile: join(home, '.bash_profile'),
    zshrc: join(home, '.zshrc'),
    fish_config: join(home, '.config', 'fish', 'config.fish'),
  };

  // For Windows, recommend using .npmrc
  if (currentOS === 'win32') {
    return {
      isWindows: true,
      shell: 'windows',
      message: 'Windows detected - use .npmrc or npm config instead',
    };
  }

  return {
    isWindows: false,
    shell: 'unix',
    bashrc: shells.bashrc,
    bash_profile: shells.bash_profile,
    zshrc: shells.zshrc,
    fish_config: shells.fish_config,
  };
}

async function checkIfConfigured(configPath) {
  try {
    const content = await fs.readFile(configPath, 'utf-8');
    return content.includes('NODE_OPTIONS');
  } catch {
    return false;
  }
}

async function main() {
  console.log('');
  console.log(
    `${c.blue}╔═══════════════════════════════════════════════════════════╗${c.reset}`,
  );
  console.log(
    `${c.blue}║     DarkCoder Memory Configuration Setup (v2)            ║${c.reset}`,
  );
  console.log(
    `${c.blue}╚═══════════════════════════════════════════════════════════╝${c.reset}`,
  );
  console.log('');

  const config = getShellConfig();
  const heapSize = '8192'; // 8GB default

  if (config.isWindows) {
    console.log(
      `${c.yellow}→${c.reset} Windows detected. Use one of these methods:`,
    );
    console.log('');
    console.log('Method 1: npm config (recommended)');
    console.log(
      `  npm config set node-options "--max-old-space-size=${heapSize}"`,
    );
    console.log('');
    console.log('Method 2: Environment Variable');
    console.log('  setx NODE_OPTIONS "--max-old-space-size=8192"');
    console.log('  (Restart terminal after running)');
    console.log('');
    console.log('Method 3: Per-command');
    console.log('  npm run build');
    console.log('');
    return;
  }

  // Unix-like systems (macOS, Linux)
  console.log(`${c.green}✓${c.reset} Unix-like system detected`);
  console.log('');
  console.log('Recommended configuration files (check which one exists):');
  console.log(`  1) ${config.zshrc}`);
  console.log(`  2) ${config.bashrc}`);
  console.log(`  3) ${config.bash_profile}`);
  console.log(`  4) ${config.fish_config}`);
  console.log('');

  const configPath = await getUserInput(
    'Enter the full path to your shell config file: ',
  );

  if (!configPath) {
    console.log(
      `${c.yellow}→${c.reset} No path provided. Please manually add this to your shell config:`,
    );
    console.log('');
    console.log(
      `export NODE_OPTIONS="--max-old-space-size=${heapSize} --expose-gc"`,
    );
    console.log('');
    console.log('Then run: source ~/.bashrc  (or ~/.zshrc, etc.)');
    return;
  }

  try {
    // Check if already configured
    const isConfigured = await checkIfConfigured(configPath);

    if (isConfigured) {
      console.log(
        `${c.green}✓${c.reset} NODE_OPTIONS already configured in ${configPath}`,
      );
      return;
    }

    // Add configuration
    console.log(
      `${c.yellow}→${c.reset} Adding NODE_OPTIONS to ${configPath}...`,
    );
    const newConfig = `\n# DarkCoder Memory Configuration\nexport NODE_OPTIONS="--max-old-space-size=${heapSize} --expose-gc"\n`;
    await fs.appendFile(configPath, newConfig);

    console.log(`${c.green}✓${c.reset} Configuration added!`);
    console.log('');
    console.log(
      `${c.yellow}→${c.reset} Please run the following to apply changes:`,
    );
    console.log('');

    if (configPath.includes('.zshrc')) {
      console.log('  source ~/.zshrc');
    } else if (configPath.includes('.bashrc')) {
      console.log('  source ~/.bashrc');
    } else if (configPath.includes('.bash_profile')) {
      console.log('  source ~/.bash_profile');
    } else if (configPath.includes('fish')) {
      console.log('  source ~/.config/fish/config.fish');
    } else {
      console.log(`  source ${configPath}`);
    }

    console.log('');
    console.log('Or open a new terminal window.');
  } catch (error) {
    console.error(`${c.red}✗ Error:${c.reset}`, error.message);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`${c.red}✗ Unexpected error:${c.reset}`, error);
  process.exit(1);
});
