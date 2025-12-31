/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Setup coverage directories for all packages
 * This ensures the coverage/.tmp directories exist before running tests
 */

import { mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readdirSync } from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = join(__dirname, '..');

// Get all package directories
const packagesDir = join(root, 'packages');
const packages = readdirSync(packagesDir, { withFileTypes: true })
  .filter((dirent) => dirent.isDirectory())
  .map((dirent) => dirent.name);

console.log('📁 Setting up coverage directories...\n');

let created = 0;
let existed = 0;

for (const pkg of packages) {
  const coverageDir = join(packagesDir, pkg, 'coverage');
  const tmpDir = join(coverageDir, '.tmp');

  // Create coverage directory if it doesn't exist
  if (!existsSync(coverageDir)) {
    mkdirSync(coverageDir, { recursive: true });
  }

  // Create .tmp directory if it doesn't exist
  if (!existsSync(tmpDir)) {
    mkdirSync(tmpDir, { recursive: true });
    console.log(`✅ Created: packages/${pkg}/coverage/.tmp`);
    created++;
  } else {
    console.log(`✓  Exists:  packages/${pkg}/coverage/.tmp`);
    existed++;
  }
}

console.log(`\n📊 Summary:`);
console.log(`   Created: ${created} directories`);
console.log(`   Existed: ${existed} directories`);
console.log(`   Total:   ${created + existed} directories`);
console.log(`\n✅ Coverage directories ready!`);
