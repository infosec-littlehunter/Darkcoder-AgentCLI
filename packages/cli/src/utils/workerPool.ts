/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { Worker } from 'node:worker_threads';
import { cpus } from 'node:os';
import { EventEmitter } from 'node:events';

/**
 * Configuration for worker pool
 */
export interface WorkerPoolConfig {
  /** Maximum number of workers (default: CPU count) */
  maxWorkers?: number;
  /** Minimum number of workers to keep alive (default: 0) */
  minWorkers?: number;
  /** Worker idle timeout in ms before termination (default: 60000) */
  idleTimeout?: number;
  /** Enable verbose logging */
  verbose?: boolean;
}

/**
 * Task to be executed by a worker
 */
export interface WorkerTask<T = unknown, R = unknown> {
  id: string;
  data: T;
  resolve: (result: R) => void;
  reject: (error: Error) => void;
}

/**
 * Worker instance wrapper
 */
interface WorkerInstance {
  worker: Worker;
  isBusy: boolean;
  idleTimer?: NodeJS.Timeout;
  tasksCompleted: number;
}

/**
 * Worker pool for offloading heavy operations to separate threads
 * This helps isolate memory usage and prevent heap overflow
 */
export class WorkerPool extends EventEmitter {
  private workers: WorkerInstance[] = [];
  private taskQueue: WorkerTask<unknown, unknown>[] = [];
  private readonly maxWorkers: number;
  private readonly minWorkers: number;
  private readonly idleTimeout: number;
  private readonly verbose: boolean;
  private readonly workerScript: string;
  private isShuttingDown = false;

  constructor(workerScript: string, config?: WorkerPoolConfig) {
    super();
    this.workerScript = workerScript;
    this.maxWorkers = config?.maxWorkers || cpus().length;
    this.minWorkers = config?.minWorkers || 0;
    this.idleTimeout = config?.idleTimeout || 60000;
    this.verbose = config?.verbose || false;

    if (this.verbose) {
      console.log(
        `🧵 Worker pool initialized (max: ${this.maxWorkers}, min: ${this.minWorkers})`,
      );
    }

    // Initialize minimum workers
    for (let i = 0; i < this.minWorkers; i++) {
      this.createWorker();
    }
  }

  /**
   * Creates a new worker instance
   */
  private createWorker(): WorkerInstance {
    const worker = new Worker(this.workerScript);
    const instance: WorkerInstance = {
      worker,
      isBusy: false,
      tasksCompleted: 0,
    };

    worker.on('error', (error) => {
      this.emit('worker-error', error);
      if (this.verbose) {
        console.error('❌ Worker error:', error);
      }
      this.removeWorker(instance);
    });

    worker.on('exit', (code) => {
      if (code !== 0 && this.verbose) {
        console.warn(`⚠️  Worker exited with code ${code}`);
      }
      this.removeWorker(instance);
    });

    this.workers.push(instance);
    this.emit('worker-created', instance);

    if (this.verbose) {
      console.log(`✅ Worker created (total: ${this.workers.length})`);
    }

    return instance;
  }

  /**
   * Removes a worker from the pool
   */
  private removeWorker(instance: WorkerInstance): void {
    const index = this.workers.indexOf(instance);
    if (index !== -1) {
      this.workers.splice(index, 1);
      if (instance.idleTimer) {
        clearTimeout(instance.idleTimer);
      }
      instance.worker.terminate();
      this.emit('worker-removed', instance);
    }
  }

  /**
   * Gets an available worker or creates a new one
   */
  private getAvailableWorker(): WorkerInstance | null {
    // Try to find an idle worker
    const idleWorker = this.workers.find((w) => !w.isBusy);
    if (idleWorker) {
      if (idleWorker.idleTimer) {
        clearTimeout(idleWorker.idleTimer);
        idleWorker.idleTimer = undefined;
      }
      return idleWorker;
    }

    // Create a new worker if we haven't reached the limit
    if (this.workers.length < this.maxWorkers) {
      return this.createWorker();
    }

    return null;
  }

  /**
   * Schedules a worker to be terminated after idle timeout
   */
  private scheduleWorkerTermination(instance: WorkerInstance): void {
    if (this.workers.length <= this.minWorkers) {
      return; // Don't terminate if we're at minimum
    }

    instance.idleTimer = setTimeout(() => {
      if (!instance.isBusy) {
        if (this.verbose) {
          console.log(
            `🗑️  Terminating idle worker (tasks completed: ${instance.tasksCompleted})`,
          );
        }
        this.removeWorker(instance);
      }
    }, this.idleTimeout);
  }

  /**
   * Processes the next task in the queue
   */
  private processNextTask(): void {
    if (this.taskQueue.length === 0 || this.isShuttingDown) {
      return;
    }

    const worker = this.getAvailableWorker();
    if (!worker) {
      return; // All workers busy, wait for one to become available
    }

    const task = this.taskQueue.shift();
    if (!task) {
      return;
    }

    worker.isBusy = true;
    worker.tasksCompleted++;

    // Set up one-time message listener for this task
    const onMessage = (result: unknown) => {
      worker.isBusy = false;
      task.resolve(result);
      this.emit('task-complete', task.id);

      // Schedule worker termination if idle
      this.scheduleWorkerTermination(worker);

      // Process next task
      this.processNextTask();
    };

    const onError = (error: Error) => {
      worker.isBusy = false;
      task.reject(error);
      this.emit('task-error', task.id, error);

      // Process next task
      this.processNextTask();
    };

    worker.worker.once('message', onMessage);
    worker.worker.once('error', onError);

    // Send task data to worker
    worker.worker.postMessage(task.data);
  }

  /**
   * Executes a task in the worker pool
   */
  public async exec<T = unknown, R = unknown>(data: T): Promise<R> {
    if (this.isShuttingDown) {
      throw new Error('Worker pool is shutting down');
    }

    return new Promise<R>((resolve, reject) => {
      const task: WorkerTask<unknown, unknown> = {
        id: `task-${Date.now()}-${Math.random()}`,
        data,
        resolve: resolve as (result: unknown) => void,
        reject,
      };

      this.taskQueue.push(task);
      this.emit('task-queued', task.id);

      if (this.verbose) {
        console.log(
          `📋 Task queued: ${task.id} (queue size: ${this.taskQueue.length})`,
        );
      }

      this.processNextTask();
    });
  }

  /**
   * Gets current pool statistics
   */
  public getStats() {
    return {
      totalWorkers: this.workers.length,
      busyWorkers: this.workers.filter((w) => w.isBusy).length,
      idleWorkers: this.workers.filter((w) => !w.isBusy).length,
      queuedTasks: this.taskQueue.length,
      totalTasksCompleted: this.workers.reduce(
        (sum, w) => sum + w.tasksCompleted,
        0,
      ),
    };
  }

  /**
   * Gracefully shuts down the worker pool
   */
  public async shutdown(timeoutMs: number = 5000): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;

    if (this.verbose) {
      console.log(`🛑 Shutting down worker pool...`);
    }

    // Wait for all tasks to complete or timeout
    const startTime = Date.now();
    while (
      this.taskQueue.length > 0 &&
      Date.now() - startTime < timeoutMs
    ) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Terminate all workers
    for (const instance of this.workers) {
      if (instance.idleTimer) {
        clearTimeout(instance.idleTimer);
      }
      await instance.worker.terminate();
    }

    this.workers = [];
    this.emit('shutdown');

    if (this.verbose) {
      console.log(`✅ Worker pool shut down`);
    }
  }
}

/**
 * Helper function to create a worker pool
 */
export function createWorkerPool(
  workerScript: string,
  config?: WorkerPoolConfig,
): WorkerPool {
  return new WorkerPool(workerScript, config);
}
