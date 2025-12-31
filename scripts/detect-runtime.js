#!/usr/bin/env node

/**
 * Runtime detection utility for Node.js vs Bun
 * Exports appropriate memory and performance flags for each runtime
 */

const isBun = typeof Bun !== 'undefined';
const isNode = !isBun;

/**
 * Get memory flags for the current runtime
 * @param {number} memoryMB - Memory limit in MB (e.g., 8192 for 8GB)
 * @returns {string} Runtime-specific flags
 */
function getMemoryFlags(memoryMB = 8192) {
  if (isBun) {
    // Bun uses --smol for memory efficiency
    // Bun manages memory more efficiently by default
    return '--smol';
  }

  // Node.js flags for memory management and GC
  return `--max-old-space-size=${memoryMB} --expose-gc --no-deprecation`;
}

/**
 * Get runtime command prefix for npm scripts
 * @returns {string} 'bun' or 'node'
 */
function getRuntimeCommand() {
  return isBun ? 'bun' : 'node';
}

/**
 * Get environment variable prefix for runtime-specific options
 * @param {number} memoryMB - Memory limit in MB
 * @returns {string} Environment variable setting
 */
function getOptionsEnvVar(memoryMB = 8192) {
  if (isBun) {
    return `BUN_FLAGS="${getMemoryFlags()}"`;
  }
  return `NODE_OPTIONS="${getMemoryFlags(memoryMB)}"`;
}

/**
 * Build full command with runtime detection
 * @param {string} scriptPath - Path to script to execute
 * @param {number} memoryMB - Memory limit in MB
 * @returns {string} Full command with appropriate flags
 */
function buildCommand(scriptPath, memoryMB = 8192) {
  const cmd = getRuntimeCommand();
  const flags = getMemoryFlags(memoryMB);

  if (isBun) {
    // Bun: bun --smol script.js
    return `${cmd} ${flags} ${scriptPath}`;
  }

  // Node: node --flags script.js
  return `${cmd} ${flags} ${scriptPath}`;
}

// Export for use in other scripts
export {
  isBun,
  isNode,
  getMemoryFlags,
  getRuntimeCommand,
  getOptionsEnvVar,
  buildCommand,
};

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'runtime':
      console.log(getRuntimeCommand());
      break;
    case 'flags': {
      const memoryMB = parseInt(args[1]) || 8192;
      console.log(getMemoryFlags(memoryMB));
      break;
    }
    case 'env': {
      const mem = parseInt(args[1]) || 8192;
      console.log(getOptionsEnvVar(mem));
      break;
    }
    case 'info': {
      // eslint-disable-next-line no-undef
      const bunVersion = typeof Bun !== 'undefined' ? Bun.version : undefined;
      console.log(
        JSON.stringify(
          {
            runtime: getRuntimeCommand(),
            isBun,
            isNode,
            flags: getMemoryFlags(),
            version: isBun ? bunVersion : process.version,
          },
          null,
          2,
        ),
      );
      break;
    }
    default:
      console.log('Usage: detect-runtime.js <command> [memory_mb]');
      console.log('Commands:');
      console.log('  runtime  - Print runtime name (bun or node)');
      console.log('  flags    - Print runtime-specific flags');
      console.log('  env      - Print environment variable setting');
      console.log('  info     - Print full runtime info as JSON');
      break;
  }
}
