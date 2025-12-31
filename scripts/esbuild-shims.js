/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Shims for esbuild ESM bundles to support require() calls
 * This file is injected into the bundle via esbuild's inject option
 */

// Suppress Node.js deprecation warnings for url.parse() and punycode
// These come from third-party dependencies that we cannot directly update
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
  // Suppress DEP0169 (url.parse) and DEP0040 (punycode) deprecation warnings
  if (
    typeof warning === 'string' &&
    (warning.includes('url.parse()') || warning.includes('punycode'))
  ) {
    return;
  }
  if (args[0] === 'DeprecationWarning') {
    const code = args[1];
    if (code === 'DEP0169' || code === 'DEP0040') {
      return;
    }
  }
  return originalEmitWarning.call(this, warning, ...args);
};

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

// Create require function for the current module and make it global
const _require = createRequire(import.meta.url);

// Make require available globally for dynamic requires
if (typeof globalThis.require === 'undefined') {
  globalThis.require = _require;
}

// Export for esbuild injection
export const require = _require;

// Setup __filename and __dirname for compatibility
export const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);
