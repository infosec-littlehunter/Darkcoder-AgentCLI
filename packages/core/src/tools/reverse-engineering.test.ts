/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { ReverseEngineeringTool } from './reverse-engineering.js';
import { Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import * as child_process from 'node:child_process';
import * as fs from 'node:fs/promises';

// Mock child_process.exec
vi.mock('node:child_process', () => ({
  exec: vi.fn(),
  spawn: vi.fn(),
}));

// Mock fs/promises
vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
  mkdir: vi.fn(),
  rm: vi.fn(),
  readdir: vi.fn(),
}));

describe('ReverseEngineeringTool', () => {
  let tool: ReverseEngineeringTool;
  const mockBinaryPath = '/path/to/binary';
  const abortSignal = new AbortController().signal;

  beforeEach(() => {
    vi.clearAllMocks();
    tool = new ReverseEngineeringTool();

    // Default mock implementations
    vi.mocked(fs.access).mockResolvedValue(undefined);
    vi.mocked(fs.mkdir).mockResolvedValue(undefined);
    vi.mocked(fs.rm).mockResolvedValue(undefined);
    vi.mocked(fs.readdir).mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Tool metadata', () => {
    it('should have correct name', () => {
      expect(ReverseEngineeringTool.Name).toBe(ToolNames.REVERSE_ENGINEERING);
    });

    it('should have correct display name', () => {
      expect(tool.displayName).toBe(ToolDisplayNames.REVERSE_ENGINEERING);
    });

    it('should have description mentioning key tools', () => {
      expect(tool.description).toContain('radare2');
      expect(tool.description).toContain('rizin');
      expect(tool.description).toContain('Ghidra');
      expect(tool.description).toContain('binwalk');
      expect(tool.description).toContain('ltrace');
      expect(tool.description).toContain('strace');
    });

    it('should have Execute kind', () => {
      expect(tool.kind).toBe(Kind.Execute);
    });

    it('should require operation and targetPath', () => {
      const schema = tool.parameterSchema as any;
      expect(schema.required).toContain('operation');
      expect(schema.required).toContain('targetPath');
    });

    it('should have valid operation enum', () => {
      const schema = tool.parameterSchema as any;
      const operations = schema.properties.operation.enum;

      // Check for all tool families
      expect(operations).toContain('r2_info');
      expect(operations).toContain('rizin_info');
      expect(operations).toContain('ghidra_decompile');
      expect(operations).toContain('binwalk_scan');
      expect(operations).toContain('ltrace_run');
      expect(operations).toContain('strace_run');
      expect(operations).toContain('quick_re');
      expect(operations).toContain('find_vulnerabilities');
    });
  });

  describe('Parameter validation', () => {
    it('should reject empty targetPath', () => {
      expect(() =>
        tool.build({
          operation: 'r2_info',
          targetPath: '',
        }),
      ).toThrow("'targetPath' parameter cannot be empty");
    });

    it('should reject invalid count', () => {
      expect(() =>
        tool.build({
          operation: 'r2_disasm',
          targetPath: mockBinaryPath,
          count: 0,
        }),
      ).toThrow("'count' must be at least 1");
    });

    it('should reject invalid timeout', () => {
      expect(() =>
        tool.build({
          operation: 'r2_info',
          targetPath: mockBinaryPath,
          timeout: 0,
        }),
      ).toThrow("'timeout' must be at least 1 second");
    });

    it('should reject invalid address format', () => {
      expect(() =>
        tool.build({
          operation: 'r2_disasm',
          targetPath: mockBinaryPath,
          address: 'invalid',
        }),
      ).toThrow('Invalid address format');
    });

    it('should accept valid hex address formats', () => {
      const invocation = tool.build({
        operation: 'r2_disasm',
        targetPath: mockBinaryPath,
        address: '0x401000',
      });
      expect(invocation).toBeDefined();
    });

    it('should require PID for attach operations', () => {
      expect(() =>
        tool.build({
          operation: 'ltrace_attach',
          targetPath: mockBinaryPath,
        }),
      ).toThrow('PID is required');
    });
  });

  describe('Invocation creation', () => {
    it('should create invocation with valid params', () => {
      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: mockBinaryPath,
      });
      expect(invocation).toBeDefined();
      expect(invocation.params).toEqual({
        operation: 'r2_info',
        targetPath: mockBinaryPath,
      });
    });

    it('should create description for different operations', () => {
      const operations = [
        { op: 'r2_info', expected: 'Analyzing binary info' },
        { op: 'r2_functions', expected: 'Listing functions' },
        { op: 'binwalk_scan', expected: 'Scanning' },
        { op: 'ghidra_decompile', expected: 'Decompiling' },
        { op: 'ltrace_run', expected: 'Tracing library calls' },
        { op: 'strace_run', expected: 'Tracing system calls' },
        { op: 'quick_re', expected: 'Quick RE assessment' },
      ] as const;

      for (const { op, expected } of operations) {
        const invocation = tool.build({
          operation: op,
          targetPath: mockBinaryPath,
        });
        expect(invocation.getDescription()).toContain(expected);
      }
    });
  });

  describe('radare2 operations', () => {
    it('should execute r2_info command', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, {
            stdout: 'arch     x86\nbits     64\nendian   little',
            stderr: '',
          });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(result.llmContent).toContain('arch');
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('radare2'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should use rizin when useRizin is true', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'binary info output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: mockBinaryPath,
        useRizin: true,
      });

      await invocation.execute(abortSignal);

      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('rizin'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should execute r2_functions with analysis', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, {
            stdout: '0x00401000    main\n0x00401050    init',
            stderr: '',
          });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_functions',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('aaa; afl'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should disassemble specific function', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'disassembly output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_disasm',
        targetPath: mockBinaryPath,
        function: 'main',
        count: 100,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('sym.main'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should disassemble at specific address', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'disassembly at address', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_disasm',
        targetPath: mockBinaryPath,
        address: '0x401000',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('0x401000'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should search for patterns', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: '0x401000 hit0_0 "pattern"', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_search',
        targetPath: mockBinaryPath,
        pattern: 'password',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('/ password'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should return error for search without pattern', async () => {
      const invocation = tool.build({
        operation: 'r2_search',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
      expect(result.llmContent).toContain('Search pattern required');
    });
  });

  describe('rizin native operations', () => {
    it('should execute rizin_info command', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'rizin binary info', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'rizin_info',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('rizin'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should execute rizin_analyze command', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'analysis output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'rizin_analyze',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
    });
  });

  describe('binwalk operations', () => {
    it('should scan for signatures', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, {
            stdout:
              'DECIMAL       HEXADECIMAL     DESCRIPTION\n0             0x0             JPEG image data',
            stderr: '',
          });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'binwalk_scan',
        targetPath: '/path/to/firmware.bin',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('binwalk -B'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should extract embedded files', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'Extraction complete', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'binwalk_extract',
        targetPath: '/path/to/firmware.bin',
        outputDir: '/tmp/extracted',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('binwalk -e'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should analyze entropy', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'Rising entropy edge (0.95)', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'binwalk_entropy',
        targetPath: '/path/to/firmware.bin',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('binwalk -E'),
        expect.any(Object),
        expect.any(Function),
      );
    });
  });

  describe('ltrace operations', () => {
    it('should trace library calls', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'printf("Hello")\nmalloc(32)', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'ltrace_run',
        targetPath: mockBinaryPath,
        args: ['arg1', 'arg2'],
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('ltrace -f -C'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should attach to running process', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'Attached to process', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'ltrace_attach',
        targetPath: mockBinaryPath,
        pid: 1234,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('-p 1234'),
        expect.any(Object),
        expect.any(Function),
      );
    });
  });

  describe('strace operations', () => {
    it('should trace system calls', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'execve("/path/to/binary", ...', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'strace_run',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('strace -f -y'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should get syscall summary', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, {
            stdout:
              '% time     seconds  usecs/call     calls      syscall\n  50.00    0.001000           1      1000       read',
            stderr: '',
          });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'strace_summary',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('strace -c'),
        expect.any(Object),
        expect.any(Function),
      );
    });

    it('should attach to process', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'strace attached', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'strace_attach',
        targetPath: mockBinaryPath,
        pid: 1234,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(child_process.exec).toHaveBeenCalledWith(
        expect.stringContaining('-p 1234'),
        expect.any(Object),
        expect.any(Function),
      );
    });
  });

  describe('LLM-enhanced operations', () => {
    it('should perform quick RE assessment', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'arch x86_64\nfunctions: 42', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'quick_re',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(result.llmContent).toContain(
        'Quick Reverse Engineering Assessment',
      );
      expect(result.llmContent).toContain('Recommendations');
    });

    it('should find crypto functions', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'AES_encrypt\nSHA256_Init', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'find_crypto',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(result.llmContent).toContain('Cryptographic Function Analysis');
    });

    it('should find vulnerability patterns', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'strcpy\ngets', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'find_vulnerabilities',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeUndefined();
      expect(result.llmContent).toContain('Vulnerability Pattern Analysis');
      expect(result.llmContent).toContain('Checklist');
    });
  });

  describe('Security - Command injection prevention', () => {
    it('should escape shell arguments in radare2 commands', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'output', stderr: '' });
          return {} as any;
        },
      );

      const maliciousPath = "/path/to/binary'; rm -rf /; echo '";

      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: maliciousPath,
      });

      await invocation.execute(abortSignal);

      // Verify the command was called with escaped path
      const calledCmd = vi.mocked(child_process.exec).mock
        .calls[0][0] as string;
      // Escaping should prevent shell interpretation by wrapping in single quotes
      // and escaping embedded single quotes with '"'"'
      expect(calledCmd).toContain("'\"'\"'"); // Single quote escaping
      // The malicious command should be part of a properly quoted string
      // not executable as a separate command
      expect(calledCmd).toMatch(/radare2.*'/); // Entire path wrapped
    });

    it('should sanitize function names', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_disasm',
        targetPath: mockBinaryPath,
        function: 'main; rm -rf /',
      });

      await invocation.execute(abortSignal);

      const calledCmd = vi.mocked(child_process.exec).mock
        .calls[0][0] as string;
      // Function names should be sanitized to only allow alphanumerics and underscores
      expect(calledCmd).toContain('sym.mainrmrf');
      // The dangerous characters (spaces, slashes) should be stripped from function name
      // The function name should not contain the malicious command
      expect(calledCmd).not.toContain('rm -rf /');
      // Function name should be alphanumeric only
      expect(calledCmd).toMatch(/sym\.mainrmrf/);
    });

    it('should escape arguments in trace commands', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'ltrace_run',
        targetPath: mockBinaryPath,
        args: ['--flag', "'; cat /etc/passwd"],
      });

      await invocation.execute(abortSignal);

      const calledCmd = vi.mocked(child_process.exec).mock
        .calls[0][0] as string;
      // Arguments should be properly quoted to prevent injection
      expect(calledCmd).toContain("'\"'\"'"); // Single quote escaping
      // The command should be ltrace with properly escaped args
      expect(calledCmd).toMatch(/ltrace.*--flag/);
    });

    it('should escape search patterns', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_search',
        targetPath: mockBinaryPath,
        pattern: "test'; rm -rf /; echo '",
      });

      await invocation.execute(abortSignal);

      const calledCmd = vi.mocked(child_process.exec).mock
        .calls[0][0] as string;
      // Search pattern should be inside radare2's quoted command
      // The dangerous characters should not be at the shell level
      expect(calledCmd).toMatch(/radare2.*"\/.*test/);
    });

    it('should escape output directories', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'binwalk_extract',
        targetPath: mockBinaryPath,
        outputDir: "/tmp/'; rm -rf /; echo '",
      });

      await invocation.execute(abortSignal);

      const calledCmd = vi.mocked(child_process.exec).mock
        .calls[0][0] as string;
      // Output directory should be properly quoted
      expect(calledCmd).toContain("'\"'\"'"); // Single quote escaping
      expect(calledCmd).toMatch(/binwalk.*-C/);
    });
  });

  describe('Error handling', () => {
    it('should handle missing target file', async () => {
      vi.mocked(fs.access).mockRejectedValue(new Error('ENOENT'));

      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: '/nonexistent/file',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
      // Error message should indicate the operation failed
      expect(result.llmContent).toContain('failed');
    });

    it('should handle command execution errors', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(new Error('Command not found'), {
            stdout: '',
            stderr: 'radare2: command not found',
          });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
    });

    it('should handle unknown operations gracefully', async () => {
      // This test requires bypassing TypeScript type checking
      const invocation = tool.build({
        operation: 'r2_info', // Start with valid operation
        targetPath: mockBinaryPath,
      });

      // Manually override operation for test
      (invocation.params as any).operation = 'unknown_op';

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
      expect(result.llmContent).toContain('Unknown operation');
    });

    it('should handle abort signal', async () => {
      const controller = new AbortController();

      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          // Simulate delay and abort
          controller.abort();
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'output', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(controller.signal);

      // When aborted, the operation should handle it gracefully
      expect(result.llmContent).toBeDefined();
    });
  });

  describe('Ghidra operations', () => {
    it('should check for Ghidra installation', async () => {
      vi.mocked(fs.access).mockImplementation(async (path: any) => {
        if (typeof path === 'string' && path.includes('ghidra')) {
          throw new Error('ENOENT');
        }
        return undefined;
      });

      const invocation = tool.build({
        operation: 'ghidra_decompile',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
      expect(result.llmContent).toContain('Ghidra not found');
    });

    it('should return error for ghidra_scripts without script', async () => {
      const invocation = tool.build({
        operation: 'ghidra_scripts',
        targetPath: mockBinaryPath,
      });

      // Mock Ghidra installation check to pass
      vi.mocked(fs.access).mockResolvedValue(undefined);
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(new Error('Script required'), { stdout: '', stderr: '' });
          return {} as any;
        },
      );

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
    });
  });

  describe('Address validation', () => {
    it('should accept hex addresses with 0x prefix', () => {
      const invocation = tool.build({
        operation: 'r2_disasm',
        targetPath: mockBinaryPath,
        address: '0x401000',
      });
      expect(invocation).toBeDefined();
    });

    it('should accept addresses without prefix', () => {
      const invocation = tool.build({
        operation: 'r2_disasm',
        targetPath: mockBinaryPath,
        address: '401000',
      });
      expect(invocation).toBeDefined();
    });

    it('should reject addresses with special characters', () => {
      expect(() =>
        tool.build({
          operation: 'r2_disasm',
          targetPath: mockBinaryPath,
          address: '0x401000; rm -rf',
        }),
      ).toThrow('Invalid address format');
    });
  });

  describe('Output formatting', () => {
    it('should format radare2 output properly', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, {
            stdout:
              'arch     x86\nbits     64\nendian   little\ntype     executable',
            stderr: '',
          });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'r2_info',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('arch');
      expect(result.returnDisplay).toContain('r2_info');
    });

    it('should include tool suggestions in quick_re output', async () => {
      vi.mocked(child_process.exec).mockImplementation(
        (cmd: any, opts: any, callback?: any) => {
          const cb = typeof opts === 'function' ? opts : callback;
          cb(null, { stdout: 'arch x86_64\n10 functions found', stderr: '' });
          return {} as any;
        },
      );

      const invocation = tool.build({
        operation: 'quick_re',
        targetPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Recommendations');
    });
  });
});
