#!/usr/bin/env node

/**
 * DarkCoder Settings Setup Script (Cross-Platform)
 * Sets up ~/.qwen/settings.json for DarkCoder
 * Works on Windows, macOS, and Linux
 */

import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = dirname(__dirname);

// Colors for output (cross-platform)
const colors = {
  reset: '',
  green: '',
  blue: '',
  yellow: '',
  red: '',
};

// Enable colors only on terminals that support them
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

async function main() {
  const SETTINGS_DIR = join(homedir(), '.qwen');
  const SETTINGS_FILE = join(SETTINGS_DIR, 'settings.json');
  const EXAMPLE_FILE = join(
    PROJECT_ROOT,
    'docs',
    'examples',
    'settings.example.json',
  );

  console.log(
    `${c.blue}╔═══════════════════════════════════════════════════════════╗${c.reset}`,
  );
  console.log(
    `${c.blue}║       DarkCoder Settings Configuration Setup              ║${c.reset}`,
  );
  console.log(
    `${c.blue}╚═══════════════════════════════════════════════════════════╝${c.reset}`,
  );
  console.log('');

  try {
    // Check if settings directory exists
    try {
      await fs.access(SETTINGS_DIR);
      console.log(`${c.green}✓${c.reset} Settings directory already exists`);
    } catch {
      console.log(`${c.yellow}→${c.reset} Creating ~/.qwen directory...`);
      await fs.mkdir(SETTINGS_DIR, { recursive: true });
      console.log(`${c.green}✓${c.reset} Directory created at ${SETTINGS_DIR}`);
    }

    // Check if settings file exists
    try {
      await fs.access(SETTINGS_FILE);
      console.log(
        `${c.green}✓${c.reset} Settings file already exists at ${SETTINGS_FILE}`,
      );
      console.log('');

      const choice = await getUserInput(
        'Do you want to restore from template? (y/n): ',
      );

      if (choice.toLowerCase() === 'y') {
        console.log(`${c.yellow}→${c.reset} Restoring from template...`);
        const exampleContent = await fs.readFile(EXAMPLE_FILE, 'utf-8');
        await fs.writeFile(SETTINGS_FILE, exampleContent);
        console.log(`${c.green}✓${c.reset} Settings restored from template`);
      } else {
        console.log('No changes made. Settings remain as-is.');
      }
    } catch {
      // File doesn't exist, create from template
      console.log(`${c.yellow}→${c.reset} Creating settings from template...`);
      const exampleContent = await fs.readFile(EXAMPLE_FILE, 'utf-8');
      await fs.writeFile(SETTINGS_FILE, exampleContent);
      console.log(
        `${c.green}✓${c.reset} Settings file created at ${SETTINGS_FILE}`,
      );
    }

    console.log('');
    console.log('Setup complete!');
    console.log(`Settings location: ${SETTINGS_FILE}`);
  } catch (error) {
    console.error(`${c.red}✗ Error:${c.reset}`, error.message);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`${c.red}✗ Unexpected error:${c.reset}`, error);
  process.exit(1);
});
