/* eslint-disable no-undef */
import { copyFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootScriptsDir = join(__dirname, '..', '..', 'scripts');
const distScriptsDir = join(__dirname, 'dist', 'scripts');

if (!existsSync(distScriptsDir)) {
  mkdirSync(distScriptsDir, { recursive: true });
}

const bannerScript = 'animated-banner.py';
const sourcePath = join(rootScriptsDir, bannerScript);
const destPath = join(distScriptsDir, bannerScript);

if (existsSync(sourcePath)) {
  copyFileSync(sourcePath, destPath);
  console.log(`Copied ${bannerScript} to dist/scripts/`);
} else {
  console.error(`Error: ${bannerScript} not found at ${sourcePath}`);
  process.exit(1);
}

// Copy system prompt file
const rootDir = join(__dirname, '..', '..');
const distDir = join(__dirname, 'dist');
const promptFile = 'expert-ai-system-prompt.md';
const promptSourcePath = join(
  rootDir,
  'packages',
  'core',
  'src',
  'core',
  promptFile,
);
const promptDestPath = join(distDir, promptFile);

if (existsSync(promptSourcePath)) {
  copyFileSync(promptSourcePath, promptDestPath);
  console.log(`Copied ${promptFile} to dist/`);
} else {
  console.error(`Error: ${promptFile} not found at ${promptSourcePath}`);
  process.exit(1);
}
