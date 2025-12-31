/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { BinaryAnalysisTool } from './binary-analysis.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import * as fs from 'node:fs/promises';
import * as child_process from 'node:child_process';

// Mock child_process.exec
vi.mock('node:child_process', () => ({
  exec: vi.fn(),
}));

// Mock fs.access
vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
}));

describe('BinaryAnalysisTool', () => {
  let tool: BinaryAnalysisTool;
  const mockBinaryPath = '/usr/bin/ls';
  const abortSignal = new AbortController().signal;

  beforeEach(() => {
    tool = new BinaryAnalysisTool();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Tool Properties', () => {
    it('should have the correct name', () => {
      expect(BinaryAnalysisTool.Name).toBe(ToolNames.BINARY_ANALYSIS);
    });

    it('should have the correct display name', () => {
      expect(tool.displayName).toBe(ToolDisplayNames.BINARY_ANALYSIS);
    });

    it('should have required parameters', () => {
      const schema = tool.parameterSchema as any;
      expect(schema.required).toContain('operation');
      expect(schema.required).toContain('binaryPath');
    });

    it('should have valid operation enum', () => {
      const schema = tool.parameterSchema as any;
      const operations = schema.properties.operation.enum;
      expect(operations).toContain('file');
      expect(operations).toContain('strings');
      expect(operations).toContain('checksec');
      expect(operations).toContain('readelf');
      expect(operations).toContain('symbols');
      expect(operations).toContain('dependencies');
      expect(operations).toContain('hexdump');
      expect(operations).toContain('disassemble');
      expect(operations).toContain('sections');
      expect(operations).toContain('headers');
    });
  });

  describe('Parameter Validation', () => {
    it('should reject empty binaryPath', () => {
      expect(() =>
        tool.build({
          operation: 'file',
          binaryPath: '',
        }),
      ).toThrow("'binaryPath' parameter cannot be empty");
    });

    it('should reject negative offset', () => {
      expect(() =>
        tool.build({
          operation: 'hexdump',
          binaryPath: mockBinaryPath,
          offset: -1,
        }),
      ).toThrow("'offset' cannot be negative");
    });

    it('should reject minStringLength less than 1', () => {
      expect(() =>
        tool.build({
          operation: 'strings',
          binaryPath: mockBinaryPath,
          minStringLength: 0,
        }),
      ).toThrow("'minStringLength' must be at least 1");
    });

    it('should accept valid parameters', () => {
      const invocation = tool.build({
        operation: 'file',
        binaryPath: mockBinaryPath,
      });
      expect(invocation).toBeDefined();
    });
  });

  describe('File Type Analysis', () => {
    it('should identify ELF binary', async () => {
      // Mock file access
      vi.mocked(fs.access).mockResolvedValue(undefined);

      // Mock exec to return ELF file type
      const mockExec = vi.fn((cmd: string, callback: Function) => {
        callback(
          null,
          { stdout: 'ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)' },
          '',
        );
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'file',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('File type analysis');
      expect(result.llmContent).toContain('ELF');
    });
  });

  describe('Strings Extraction', () => {
    it('should extract strings with default options', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockStrings = ['printf', 'malloc', 'free', 'main'].join('\n');
      const mockExec = vi.fn((cmd: string, _opts: any, callback: Function) => {
        if (typeof _opts === 'function') {
          callback = _opts;
        }
        callback(null, { stdout: mockStrings }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'strings',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Extracted strings');
      expect(result.returnDisplay).toContain('strings');
    });

    it('should respect minStringLength option', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockExec = vi.fn((cmd: string, _opts: any, callback: Function) => {
        if (typeof _opts === 'function') {
          callback = _opts;
        }
        // Verify the command includes correct min length
        expect(cmd).toContain('-n 10');
        callback(null, { stdout: 'longstring\n' }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'strings',
        binaryPath: mockBinaryPath,
        minStringLength: 10,
      });

      await invocation.execute(abortSignal);
    });
  });

  describe('Security Check', () => {
    it('should parse checksec output', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const checksecOutput = JSON.stringify({
        [mockBinaryPath]: {
          relro: 'Full RELRO',
          canary: 'Canary found',
          nx: 'NX enabled',
          pie: 'PIE enabled',
        },
      });

      const mockExec = vi.fn((cmd: string, callback: Function) => {
        if (cmd.includes('checksec')) {
          callback(null, { stdout: checksecOutput }, '');
        }
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'checksec',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Security features');
    });

    it('should fallback to manual check when checksec fails', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      let callCount = 0;
      const mockExec = vi.fn((cmd: string, callback: Function) => {
        callCount++;
        if (cmd.includes('checksec')) {
          // checksec not found
          callback(new Error('checksec not found'), { stdout: '' }, '');
        } else if (cmd.includes('readelf')) {
          callback(
            null,
            {
              stdout:
                'GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000\n                 0x0000000000000000 0x0000000000000000  RW     0x10',
            },
            '',
          );
        } else if (cmd.includes('nm')) {
          callback(null, { stdout: '' }, '');
        }
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'checksec',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Security features');
      expect(result.llmContent).toContain('manual check');
    });
  });

  describe('Symbol Listing', () => {
    it('should list symbols with nm', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockSymbols =
        '0000000000001234 T main\n0000000000001256 T foo\n0000000000001278 U printf';
      const mockExec = vi.fn((cmd: string, _opts: any, callback: Function) => {
        if (typeof _opts === 'function') {
          callback = _opts;
        }
        callback(null, { stdout: mockSymbols }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'symbols',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Symbols');
      expect(result.returnDisplay).toContain('symbols');
    });

    it('should filter symbols by pattern', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockSymbols =
        '0000000000001234 T main\n0000000000001256 T foo\n0000000000001278 U printf';
      const mockExec = vi.fn((cmd: string, _opts: any, callback: Function) => {
        if (typeof _opts === 'function') {
          callback = _opts;
        }
        callback(null, { stdout: mockSymbols }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'symbols',
        binaryPath: mockBinaryPath,
        symbolFilter: 'main',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Symbols');
    });
  });

  describe('Library Dependencies', () => {
    it('should list dependencies with ldd', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockDeps = `linux-vdso.so.1 (0x00007ffe123456)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1234567890)
/lib64/ld-linux-x86-64.so.2 (0x00007f9876543210)`;

      const mockExec = vi.fn((cmd: string, callback: Function) => {
        callback(null, { stdout: mockDeps }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'dependencies',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Library dependencies');
      expect(result.llmContent).toContain('libc.so');
    });

    it('should handle static binaries gracefully', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockExec = vi.fn((cmd: string, callback: Function) => {
        const error: any = new Error('not a dynamic executable');
        error.stdout = 'not a dynamic executable';
        callback(error, { stdout: 'not a dynamic executable' }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'dependencies',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('statically linked');
    });
  });

  describe('Hex Dump', () => {
    it('should produce hex dump with default options', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockHex = `00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 5010 0000 0000 0000  ..>.....P.......`;

      const mockExec = vi.fn((cmd: string, callback: Function) => {
        expect(cmd).toContain('-s 0');
        expect(cmd).toContain('-l 256');
        callback(null, { stdout: mockHex }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'hexdump',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Hex dump');
      expect(result.llmContent).toContain('7f45');
    });

    it('should respect offset and length options', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockExec = vi.fn((cmd: string, callback: Function) => {
        expect(cmd).toContain('-s 4096');
        expect(cmd).toContain('-l 512');
        callback(null, { stdout: '...' }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'hexdump',
        binaryPath: mockBinaryPath,
        offset: 4096,
        length: 512,
      });

      await invocation.execute(abortSignal);
    });
  });

  describe('Disassembly', () => {
    it('should disassemble with objdump', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockAsm = `0000000000001234 <main>:
    1234:       55                      push   rbp
    1235:       48 89 e5                mov    rbp,rsp`;

      const mockExec = vi.fn((cmd: string, _opts: any, callback: Function) => {
        if (typeof _opts === 'function') {
          callback = _opts;
        }
        expect(cmd).toContain('objdump -d -M intel');
        callback(null, { stdout: mockAsm }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'disassemble',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Disassembly');
      expect(result.llmContent).toContain('asm');
    });

    it('should disassemble specific function', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockExec = vi.fn((cmd: string, _opts: any, callback: Function) => {
        if (typeof _opts === 'function') {
          callback = _opts;
        }
        // Function name is sanitized (alphanumeric + underscore only) for security
        expect(cmd).toContain('--disassemble=main');
        callback(null, { stdout: 'main function disassembly' }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'disassemble',
        binaryPath: mockBinaryPath,
        function: 'main',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('of main');
    });
  });

  describe('ELF Analysis', () => {
    it('should analyze ELF headers', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockElf = `ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian`;

      const mockExec = vi.fn((cmd: string, _opts: any, callback: Function) => {
        if (typeof _opts === 'function') {
          callback = _opts;
        }
        expect(cmd).toContain('readelf -h -S -l');
        callback(null, { stdout: mockElf }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'readelf',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('ELF analysis');
      expect(result.llmContent).toContain('ELF Header');
    });
  });

  describe('Sections', () => {
    it('should list binary sections', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockSections = `Section Headers:
  [Nr] Name              Type             Address
  [ 0]                   NULL             0000000000000000
  [ 1] .text             PROGBITS         0000000000001000`;

      const mockExec = vi.fn((cmd: string, callback: Function) => {
        expect(cmd).toContain('readelf -S');
        callback(null, { stdout: mockSections }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'sections',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.llmContent).toContain('Binary sections');
      expect(result.llmContent).toContain('.text');
    });
  });

  describe('Error Handling', () => {
    it('should handle file not found', async () => {
      vi.mocked(fs.access).mockRejectedValue(new Error('ENOENT'));

      const invocation = tool.build({
        operation: 'file',
        binaryPath: '/nonexistent/binary',
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
      expect(result.llmContent).toContain('Binary file not found');
    });

    it('should handle command execution errors', async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const mockExec = vi.fn((cmd: string, callback: Function) => {
        callback(new Error('Command failed'), { stdout: '' }, '');
      });
      vi.mocked(child_process.exec).mockImplementation(mockExec as any);

      const invocation = tool.build({
        operation: 'file',
        binaryPath: mockBinaryPath,
      });

      const result = await invocation.execute(abortSignal);

      expect(result.error).toBeDefined();
      expect(result.llmContent).toContain('Error');
    });
  });

  // ==================== LLM-Enhanced Operations Tests ====================

  describe('LLM-Enhanced Operations', () => {
    describe('Quick Analysis', () => {
      it('should include new operations in enum', () => {
        const schema = tool.parameterSchema as any;
        const operations = schema.properties.operation.enum;
        expect(operations).toContain('quick_analysis');
        expect(operations).toContain('find_vulnerabilities');
        expect(operations).toContain('analyze_strings');
      });

      it('should return security assessment with score and findings', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        // Mock file command
        const fileOutput = 'ELF 64-bit LSB pie executable, stripped';
        // Mock nm for canary check
        const nmOutput = '                 U __stack_chk_fail@@GLIBC_2.17';
        // Mock readelf for NX and PIE
        const gnuStackOutput =
          'GNU_STACK      0x0000000 0x00000000 0x00000000 0x0000 0x0000 RW  0x10';
        const elfTypeOutput =
          'Type:                              DYN (Shared object file)';
        const relroOutput =
          'GNU_RELRO      0x000001 0x00000000 0x00000000 0x0000 0x0000 R   0x1';
        const bindNowOutput = '';
        // Mock strings
        const stringsOutput = '/bin/sh\nDEBUG_MODE';

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            if (cmd.includes('file -b')) {
              cb(null, { stdout: fileOutput }, '');
            } else if (cmd.includes('nm -D')) {
              cb(null, { stdout: nmOutput }, '');
            } else if (cmd.includes('GNU_STACK')) {
              cb(null, { stdout: gnuStackOutput }, '');
            } else if (cmd.includes('Type:')) {
              cb(null, { stdout: elfTypeOutput }, '');
            } else if (cmd.includes('GNU_RELRO')) {
              cb(null, { stdout: relroOutput }, '');
            } else if (cmd.includes('BIND_NOW')) {
              cb(null, { stdout: bindNowOutput }, '');
            } else if (cmd.includes('strings')) {
              cb(null, { stdout: stringsOutput }, '');
            } else if (cmd.includes('objdump')) {
              cb(null, { stdout: '' }, '');
            } else {
              cb(null, { stdout: '' }, '');
            }
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'quick_analysis',
          binaryPath: mockBinaryPath,
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('Binary Security Assessment');
        expect(result.llmContent).toContain('Security Score');
        expect(result.llmContent).toContain('Security Findings');
        expect(result.returnDisplay).toContain('/100');
      });

      it('should detect dangerous functions', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        const fileOutput = 'ELF 64-bit LSB executable';
        const nmOutput =
          '                 U gets@@GLIBC_2.0\n                 U strcpy@@GLIBC_2.0';

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            if (cmd.includes('file -b')) {
              cb(null, { stdout: fileOutput }, '');
            } else if (cmd.includes('nm -D') || cmd.includes('objdump -T')) {
              cb(null, { stdout: nmOutput }, '');
            } else if (cmd.includes('strings')) {
              cb(null, { stdout: '' }, '');
            } else {
              cb(null, { stdout: '' }, '');
            }
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'quick_analysis',
          binaryPath: mockBinaryPath,
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('Dangerous Functions');
        expect(result.llmContent).toContain('CRITICAL');
      });

      it('should detect hardcoded credentials', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        const fileOutput = 'ELF 64-bit LSB executable';
        const stringsOutput =
          'password=supersecret123\napi_key=AKIAIOSFODNN7EXAMPLE';

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            if (cmd.includes('file -b')) {
              cb(null, { stdout: fileOutput }, '');
            } else if (cmd.includes('nm -D') || cmd.includes('objdump')) {
              cb(null, { stdout: '' }, '');
            } else if (cmd.includes('strings')) {
              cb(null, { stdout: stringsOutput }, '');
            } else {
              cb(null, { stdout: '' }, '');
            }
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'quick_analysis',
          binaryPath: mockBinaryPath,
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('Hardcoded Credentials');
        expect(result.llmContent).toContain('CRITICAL'); // Note: uppercase in output
      });
    });

    describe('Find Vulnerabilities', () => {
      it('should search for default vulnerability patterns', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        const nmOutput =
          '                 U gets\n                 U strcpy\n                 U system';
        const objdumpOutput = 'call   <gets@plt>\ncall   <strcpy@plt>';

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            if (cmd.includes('nm -D')) {
              cb(null, { stdout: nmOutput }, '');
            } else if (cmd.includes('objdump')) {
              cb(null, { stdout: objdumpOutput }, '');
            } else {
              cb(null, { stdout: '' }, '');
            }
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'find_vulnerabilities',
          binaryPath: mockBinaryPath,
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('Vulnerability Pattern Search');
        expect(result.llmContent).toContain('gets');
        expect(result.llmContent).toContain('strcpy');
        expect(result.llmContent).toContain('Exploitation Guidance');
      });

      it('should accept custom vulnerability patterns', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        const nmOutput = '                 U custom_dangerous_func';

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            cb(null, { stdout: nmOutput }, '');
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'find_vulnerabilities',
          binaryPath: mockBinaryPath,
          vulnPatterns: ['custom_dangerous_func'],
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('custom_dangerous_func');
      });

      it('should report no findings when binary is clean', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            cb(null, { stdout: '' }, '');
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'find_vulnerabilities',
          binaryPath: mockBinaryPath,
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('No vulnerable patterns found');
      });
    });

    describe('Analyze Strings', () => {
      it('should categorize strings for security analysis', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        const stringsOutput = `
https://api.example.com/endpoint
192.168.1.1
/etc/passwd
password=secret
sh -c whoami
AES_ENCRYPT
DEBUG_MODE
admin_panel
`.trim();

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            cb(null, { stdout: stringsOutput }, '');
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'analyze_strings',
          binaryPath: mockBinaryPath,
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('String Analysis Report');
        expect(result.llmContent).toContain('URLs/Endpoints');
        expect(result.llmContent).toContain('IP Addresses');
        expect(result.llmContent).toContain('Potential Credentials');
        expect(result.llmContent).toContain('Shell Commands');
        expect(result.llmContent).toContain('Cryptographic References');
      });

      it('should highlight security-relevant findings', async () => {
        vi.mocked(fs.access).mockResolvedValue(undefined);

        const stringsOutput = 'api_key=secret123\nhttp://malware.com/callback';

        const mockExec = vi.fn(
          (cmd: string, options: any, callback?: Function) => {
            const cb = callback || options;
            cb(null, { stdout: stringsOutput }, '');
          },
        );
        vi.mocked(child_process.exec).mockImplementation(mockExec as any);

        const invocation = tool.build({
          operation: 'analyze_strings',
          binaryPath: mockBinaryPath,
        });

        const result = await invocation.execute(abortSignal);

        expect(result.llmContent).toContain('Analysis Summary');
        expect(result.llmContent).toContain('ACTION REQUIRED');
      });
    });
  });
});
