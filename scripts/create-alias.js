#!/usr/bin/env node

/**
 * DarkCoder CLI Alias Setup Script (Cross-Platform)
 * Creates a command alias for quick CLI access
 * Works on Windows, macOS, and Linux
 */

import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = dirname(__dirname);

// Colors for output
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

async function getUserConfirmation(prompt) {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(prompt + ' (y/n): ', (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y');
    });
  });
}

async function main() {
  const currentOS = platform();
  const home = homedir();

  console.log('');
  console.log(
    `${c.blue}╔═══════════════════════════════════════════════════════════╗${c.reset}`,
  );
  console.log(
    `${c.blue}║          DarkCoder CLI Alias Setup (v2)                  ║${c.reset}`,
  );
  console.log(
    `${c.blue}╚═══════════════════════════════════════════════════════════╝${c.reset}`,
  );
  console.log('');

  if (currentOS === 'win32') {
    console.log(
      `${c.yellow}→${c.reset} Windows detected. Create an alias differently:`,
    );
    console.log('');
    console.log('Option 1: Using doskey (temporary, for current session)');
    console.log(
      '  doskey darkcoder=node "' + PROJECT_DIR + '\\dist\\cli.js" $*',
    );
    console.log('');
    console.log('Option 2: Create a batch file (permanent)');
    console.log('  Create: C:\\Users\\YourUsername\\darkcoder.bat');
    console.log('  Content: @echo off');
    console.log('           node "' + PROJECT_DIR + '\\dist\\cli.js" %*');
    console.log('  Add C:\\Users\\YourUsername to PATH');
    console.log('');
    console.log('Option 3: Use npm directly');
    console.log('  npm start');
    console.log('');
    return;
  }

  // Unix-like systems
  const aliasCommand = `alias darkcoder='node "${PROJECT_DIR}/dist/cli.js"'`;
  const shells = [
    { name: 'zsh', path: join(home, '.zshrc') },
    { name: 'bash', path: join(home, '.bashrc') },
  ];

  console.log(`${c.green}✓${c.reset} Unix-like system detected`);
  console.log('');
  console.log('This script will add the following alias:');
  console.log(`  ${aliasCommand}`);
  console.log('');

  const proceed = await getUserConfirmation('Do you want to proceed?');

  if (!proceed) {
    console.log('Aborted. No changes were made.');
    return;
  }

  try {
    let aliasAdded = false;

    for (const shell of shells) {
      try {
        const content = await fs.readFile(shell.path, 'utf-8');

        // Skip if already has darkcoder alias
        if (content.includes('alias darkcoder=')) {
          console.log(
            `${c.green}✓${c.reset} Alias already exists in ${shell.path}`,
          );
          aliasAdded = true;
          continue;
        }

        // Add alias
        await fs.appendFile(
          shell.path,
          `\n# DarkCoder CLI Alias\n${aliasCommand}\n`,
        );
        console.log(`${c.green}✓${c.reset} Alias added to ${shell.path}`);
        aliasAdded = true;
      } catch (error) {
        // File might not exist, skip
        if (error.code !== 'ENOENT') {
          console.error(
            `${c.red}✗ Error reading ${shell.path}:${c.reset}`,
            error.message,
          );
        }
      }
    }

    if (aliasAdded) {
      console.log('');
      console.log('Setup complete!');
      console.log('');
      console.log(`${c.yellow}→${c.reset} To use the alias, run one of:`);
      console.log('  source ~/.zshrc');
      console.log('  source ~/.bashrc');
      console.log('  (or open a new terminal)');
      console.log('');
      console.log(`${c.yellow}→${c.reset} Then use: darkcoder --help`);
    } else {
      console.log(
        `${c.red}✗ Could not add alias to any shell config file${c.reset}`,
      );
      console.log(
        'Please manually add this line to your ~/.bashrc or ~/.zshrc:',
      );
      console.log(`  ${aliasCommand}`);
    }
  } catch (error) {
    console.error(`${c.red}✗ Error:${c.reset}`, error.message);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`${c.red}✗ Unexpected error:${c.reset}`, error);
  process.exit(1);
});
