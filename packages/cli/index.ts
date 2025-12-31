#!/usr/bin/env node

/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import './src/gemini.js';
import { main } from './src/gemini.js';
import { FatalError } from '@darkcoder/darkcoder-core';
import { execSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';

// Run Python animated banner before starting CLI (only once)
if (!process.env['QWEN_BANNER_SHOWN']) {
  process.env['QWEN_BANNER_SHOWN'] = '1';
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const scriptPath = join(__dirname, 'scripts', 'animated-banner.py');

    if (existsSync(scriptPath)) {
      execSync(`python3 "${scriptPath}"`, { stdio: 'inherit' });
    } else {
      // Try from project root for installed version
      const rootScriptPath = join(
        __dirname,
        '..',
        '..',
        'scripts',
        'animated-banner.py',
      );
      if (existsSync(rootScriptPath)) {
        execSync(`python3 "${rootScriptPath}"`, { stdio: 'inherit' });
      }
    }
  } catch {
    // If Python not available or script fails, silently continue
  }
}

// --- Global Entry Point ---
main().catch((error) => {
  if (error instanceof FatalError) {
    let errorMessage = error.message;
    if (!process.env['NO_COLOR']) {
      errorMessage = `\x1b[31m${errorMessage}\x1b[0m`;
    }
    console.error(errorMessage);
    process.exit(error.exitCode);
  }
  console.error('An unexpected critical error occurred:');
  if (error instanceof Error) {
    console.error(error.stack);
  } else {
    console.error(String(error));
  }
  process.exit(1);
});
