/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Worker thread for heavy build operations
 * This isolates memory usage and prevents heap overflow in the main thread
 */

import { parentPort } from 'node:worker_threads';
import { execSync } from 'node:child_process';

if (!parentPort) {
  throw new Error('This script must be run as a worker thread');
}

/**
 * Task types that can be handled by this worker
 */
const taskHandlers = {
  /**
   * Build a specific package
   */
  buildPackage: (data) => {
    const { workspace, options = {} } = data;
    const cmd = `npm run build --workspace=${workspace}`;

    try {
      const result = execSync(cmd, {
        encoding: 'utf8',
        stdio: options.silent ? 'pipe' : 'inherit',
        maxBuffer: 50 * 1024 * 1024, // 50MB buffer
      });

      return {
        success: true,
        workspace,
        output: result,
      };
    } catch (error) {
      return {
        success: false,
        workspace,
        error: error.message,
        stdout: error.stdout?.toString(),
        stderr: error.stderr?.toString(),
      };
    }
  },

  /**
   * Run TypeScript compiler
   */
  typecheck: (data) => {
    const { workspace, options = {} } = data;
    const cmd = workspace
      ? `npm run typecheck --workspace=${workspace}`
      : 'npm run typecheck';

    try {
      const result = execSync(cmd, {
        encoding: 'utf8',
        stdio: options.silent ? 'pipe' : 'inherit',
        maxBuffer: 50 * 1024 * 1024,
      });

      return {
        success: true,
        workspace: workspace || 'all',
        output: result,
      };
    } catch (error) {
      return {
        success: false,
        workspace: workspace || 'all',
        error: error.message,
        stdout: error.stdout?.toString(),
        stderr: error.stderr?.toString(),
      };
    }
  },

  /**
   * Run tests
   */
  test: (data) => {
    const { workspace, testPath, options = {} } = data;
    let cmd = 'npx vitest run';

    if (workspace) {
      cmd += ` --root packages/${workspace}`;
    }
    if (testPath) {
      cmd += ` ${testPath}`;
    }

    try {
      const result = execSync(cmd, {
        encoding: 'utf8',
        stdio: options.silent ? 'pipe' : 'inherit',
        maxBuffer: 50 * 1024 * 1024,
      });

      return {
        success: true,
        workspace,
        testPath,
        output: result,
      };
    } catch (error) {
      return {
        success: false,
        workspace,
        testPath,
        error: error.message,
        stdout: error.stdout?.toString(),
        stderr: error.stderr?.toString(),
      };
    }
  },

  /**
   * Lint code
   */
  lint: (data) => {
    const { fix = false, options = {} } = data;
    const cmd = fix ? 'npm run lint:fix' : 'npm run lint';

    try {
      const result = execSync(cmd, {
        encoding: 'utf8',
        stdio: options.silent ? 'pipe' : 'inherit',
        maxBuffer: 50 * 1024 * 1024,
      });

      return {
        success: true,
        output: result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        stdout: error.stdout?.toString(),
        stderr: error.stderr?.toString(),
      };
    }
  },

  /**
   * Clean build artifacts
   */
  clean: (data) => {
    const { workspace, options = {} } = data;
    const cmd = workspace
      ? `npm run clean --workspace=${workspace}`
      : 'npm run clean';

    try {
      const result = execSync(cmd, {
        encoding: 'utf8',
        stdio: options.silent ? 'pipe' : 'inherit',
      });

      return {
        success: true,
        workspace: workspace || 'all',
        output: result,
      };
    } catch (error) {
      return {
        success: false,
        workspace: workspace || 'all',
        error: error.message,
      };
    }
  },
};

/**
 * Handle incoming messages
 */
parentPort.on('message', async (task) => {
  try {
    const { type, data } = task;

    if (!type || !taskHandlers[type]) {
      throw new Error(`Unknown task type: ${type}`);
    }

    const result = await taskHandlers[type](data);
    parentPort.postMessage(result);
  } catch (error) {
    parentPort.postMessage({
      success: false,
      error: error.message,
      stack: error.stack,
    });
  }
});
