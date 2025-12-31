/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import {
  writeFileSync,
  rmSync,
  copyFileSync,
  existsSync,
  mkdirSync,
} from 'node:fs';

let esbuild;
try {
  esbuild = (await import('esbuild')).default;
} catch (_error) {
  console.warn('esbuild not available, skipping bundle step');
  process.exit(0);
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);
const pkg = require(path.resolve(__dirname, 'package.json'));

// Clean dist directory (cross-platform)
rmSync(path.resolve(__dirname, 'dist'), { recursive: true, force: true });

const external = [
  '@lydell/node-pty',
  'node-pty',
  '@lydell/node-pty-darwin-arm64',
  '@lydell/node-pty-darwin-x64',
  '@lydell/node-pty-linux-x64',
  '@lydell/node-pty-win32-arm64',
  '@lydell/node-pty-win32-x64',
  'tiktoken',
];

esbuild
  .build({
    entryPoints: ['packages/cli/index.ts'],
    bundle: true,
    outfile: 'dist/cli.js',
    platform: 'node',
    format: 'esm',
    target: 'node20',
    external,
    packages: 'bundle',
    inject: [path.resolve(__dirname, 'scripts/esbuild-shims.js')],
    banner: {
      js: `// Force strict mode and setup for ESM
"use strict";`,
    },
    alias: {
      'is-in-ci': path.resolve(
        __dirname,
        'packages/cli/src/patches/is-in-ci.ts',
      ),
    },
    define: {
      'process.env.CLI_VERSION': JSON.stringify(pkg.version),
      // Make global available for compatibility
      global: 'globalThis',
    },
    loader: { '.node': 'file' },
    metafile: true,
    write: true,
    keepNames: true,
  })
  .then(({ metafile }) => {
    if (process.env.DEV === 'true') {
      writeFileSync('./dist/esbuild.json', JSON.stringify(metafile, null, 2));
    }

    // Copy required assets to dist
    const distDir = path.resolve(__dirname, 'dist');
    if (!existsSync(distDir)) {
      mkdirSync(distDir, { recursive: true });
    }

    // Copy system prompt file
    const promptFile = 'expert-ai-system-prompt.md';
    const promptSource = path.resolve(
      __dirname,
      'packages/core/src/core',
      promptFile,
    );
    const promptDest = path.resolve(distDir, promptFile);
    if (existsSync(promptSource)) {
      copyFileSync(promptSource, promptDest);
      console.log(`Copied ${promptFile} to dist/`);
    } else {
      console.warn(`Warning: ${promptFile} not found at ${promptSource}`);
    }

    // Copy animated banner script
    const scriptsDir = path.resolve(distDir, 'scripts');
    if (!existsSync(scriptsDir)) {
      mkdirSync(scriptsDir, { recursive: true });
    }
    const bannerFile = 'animated-banner.py';
    const bannerSource = path.resolve(__dirname, 'scripts', bannerFile);
    const bannerDest = path.resolve(scriptsDir, bannerFile);
    if (existsSync(bannerSource)) {
      copyFileSync(bannerSource, bannerDest);
      console.log(`Copied ${bannerFile} to dist/scripts/`);
    } else {
      console.warn(`Warning: ${bannerFile} not found at ${bannerSource}`);
    }
  })
  .catch((error) => {
    console.error('esbuild build failed:', error);
    process.exitCode = 1;
  });
