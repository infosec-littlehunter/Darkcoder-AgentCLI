# Binary Patching Guide

## ⚠️ LEGAL & ETHICAL DISCLAIMER

**These tools are provided for LEGAL purposes ONLY:**

### ✅ LEGAL Uses

- **Security Research**: Analysis of software you own or have permission to analyze
- **Malware Defanging**: Disabling malicious functionality for safe analysis
- **Vulnerability Research**: Finding and documenting security flaws
- **Educational Purposes**: Learning reverse engineering in controlled environments
- **Bug Fixes**: Patching your own software or with explicit permission
- **Interoperability**: Reverse engineering for compatibility (where legally permitted)

### ❌ ILLEGAL Uses

- Software cracking or piracy
- License bypass or key generation
- Circumventing copy protection (DMCA violation)
- Modifying software without permission
- Commercial use without proper licensing

**By using these tools, you accept full legal responsibility for your actions.**

---

## 🔧 Binary Modification Operations

### 1. **backup_binary** - Create Backup

**ALWAYS create a backup before any modification!**

```typescript
{
  operation: 'backup_binary',
  targetPath: '/path/to/binary.exe',
  backupPath: '/path/to/binary.exe.backup' // optional, auto-generated if not provided
}
```

**Output:**

- Backup file path
- Size verification
- Restore command

---

### 2. **patch_bytes** - Modify Hex Bytes

Patch specific bytes at a memory address.

**Use Cases:**

- Disable malware network callbacks
- Modify configuration values
- Fix bugs in binaries

**Parameters:**

```typescript
{
  operation: 'patch_bytes',
  targetPath: '/path/to/binary',
  address: '0x401000',           // Address to patch
  hexBytes: '90909090',          // Hex bytes to write
}
```

**Example - Disable a call:**

```typescript
// Before: E8 10 20 30 40  (call 0x403020)
// After:  90 90 90 90 90  (5 NOPs)
{
  operation: 'patch_bytes',
  targetPath: './malware.exe',
  address: '0x401234',
  hexBytes: '9090909090'
}
```

---

### 3. **nop_instructions** - NOP Out Code

Replace instructions with NOPs (No Operation).

**Common Uses:**

- Disable anti-debug checks for malware analysis
- Remove anti-VM detection
- Skip unwanted function calls
- Bypass time bombs in malware

**Parameters:**

```typescript
{
  operation: 'nop_instructions',
  targetPath: '/path/to/binary',
  address: '0x401000',
  length: 5                      // Number of bytes to NOP
}
```

**Example - Disable IsDebuggerPresent check:**

```asm
; Before:
401000: FF 15 00 20 40 00    call dword ptr [IsDebuggerPresent]
401006: 85 C0                 test eax, eax
401008: 74 05                 je 0x40100f

; After NOPing 6 bytes at 0x401000:
401000: 90 90 90 90 90 90    nop; nop; nop; nop; nop; nop
401006: 85 C0                 test eax, eax
401008: 74 05                 je 0x40100f
```

**Usage:**

```typescript
{
  operation: 'nop_instructions',
  targetPath: './malware.exe',
  address: '0x401000',
  length: 6
}
```

---

### 4. **patch_string** - Modify Strings

Change string values in the binary.

**Use Cases:**

- Redirect malware C2 to sinkhole/honeypot
- Modify debug output
- Change configuration strings
- Defang malware URLs

**Parameters:**

```typescript
{
  operation: 'patch_string',
  targetPath: '/path/to/binary',
  address: '0x403000',           // Address of string
  newString: 'localhost'         // New string (auto null-terminated)
}
```

**Example - Redirect C2 Server:**

```typescript
// Original: http://evil-c2.com/beacon
// New:      http://127.0.0.1/beacon
{
  operation: 'patch_string',
  targetPath: './malware.exe',
  address: '0x403050',
  newString: 'http://127.0.0.1/beacon'
}
```

**⚠️ Warning:** New string must fit in original space or you'll overwrite adjacent data!

---

### 5. **patch_function** - Replace Entire Function

**ADVANCED**: Replace function body with custom assembly.

**Use Cases:**

- Force function to always return success/failure
- Skip complex anti-analysis routines
- Implement custom behavior

**Parameters:**

```typescript
{
  operation: 'patch_function',
  targetPath: '/path/to/binary',
  address: '0x401000',           // Function start
  // OR
  function: 'check_license',     // Function name
  assembly: 'mov eax, 1; ret'    // Assembly code
}
```

**Example - Force License Check to Return True:**

```typescript
{
  operation: 'patch_function',
  targetPath: './program.exe',
  function: 'check_license',
  assembly: 'mov eax, 1; ret'    // Always return 1 (true)
}
```

**Example - Disable Anti-Debug Function:**

```typescript
{
  operation: 'patch_function',
  targetPath: './malware.exe',
  address: '0x401500',
  assembly: 'xor eax, eax; ret'  // Always return 0 (not debugging)
}
```

---

## 🎯 Real-World Examples

### Example 1: Malware Defanging

**Scenario:** Ransomware sample for analysis

```typescript
// Step 1: Backup
{
  operation: 'backup_binary',
  targetPath: './ransomware.exe'
}

// Step 2: NOP out file encryption call
{
  operation: 'nop_instructions',
  targetPath: './ransomware.exe',
  address: '0x401234',  // Call to EncryptFiles()
  length: 5
}

// Step 3: Redirect C2 to localhost
{
  operation: 'patch_string',
  targetPath: './ransomware.exe',
  address: '0x403000',
  newString: 'http://127.0.0.1:8080/c2'
}

// Step 4: Disable anti-VM check
{
  operation: 'patch_function',
  targetPath: './ransomware.exe',
  function: 'check_vm',
  assembly: 'xor eax, eax; ret'  // Return 0 (no VM detected)
}
```

### Example 2: Bypass Anti-Debug

**Scenario:** Malware with multiple anti-debug techniques

```typescript
// Disable IsDebuggerPresent check
{
  operation: 'nop_instructions',
  targetPath: './malware.exe',
  address: '0x401100',
  length: 6
}

// Disable CheckRemoteDebuggerPresent
{
  operation: 'nop_instructions',
  targetPath: './malware.exe',
  address: '0x401200',
  length: 10
}

// Force anti-debug function to return false
{
  operation: 'patch_function',
  targetPath: './malware.exe',
  function: 'detect_debugger',
  assembly: 'xor eax, eax; ret'
}
```

### Example 3: Redirect Network Traffic

**Scenario:** Redirect malware traffic to analysis server

```typescript
// Find C2 URL
{
  operation: 'r2_strings',
  targetPath: './malware.exe'
}
// Output shows: 0x403000: "http://malicious-c2.com/api"

// Patch C2 URL
{
  operation: 'patch_string',
  targetPath: './malware.exe',
  address: '0x403000',
  newString: 'http://192.168.1.100/api'  // Your analysis server
}
```

---

## 🛠️ Workflow Best Practices

### Standard Patching Workflow

```bash
1. Analyze binary first
   - Use: r2_info, r2_functions, r2_disasm
   - Identify target addresses/functions

2. Create backup
   - Use: backup_binary
   - NEVER skip this step

3. Apply patches
   - Use: patch_bytes, nop_instructions, etc.
   - Start with small, targeted patches

4. Verify patches
   - Use: r2_disasm to confirm changes
   - Test binary behavior

5. Document changes
   - Record all addresses patched
   - Note original vs patched bytes
```

### Finding Addresses to Patch

```typescript
// 1. List functions
{
  operation: 'r2_functions',
  targetPath: './binary.exe'
}

// 2. Disassemble specific function
{
  operation: 'r2_disasm',
  targetPath: './binary.exe',
  function: 'check_license'
}

// 3. Search for patterns
{
  operation: 'r2_search',
  targetPath: './binary.exe',
  pattern: 'IsDebuggerPresent'
}

// 4. Find cross-references
{
  operation: 'r2_xrefs',
  targetPath: './binary.exe',
  address: '0x401000'
}
```

---

## 🔍 Verification After Patching

Always verify your patches:

```typescript
// Disassemble patched area
{
  operation: 'r2_disasm',
  targetPath: './patched.exe',
  address: '0x401000',
  count: 20
}

// Check strings were modified
{
  operation: 'r2_strings',
  targetPath: './patched.exe'
}

// Verify imports still intact
{
  operation: 'r2_imports',
  targetPath: './patched.exe'
}
```

---

## ⚠️ Common Pitfalls

### 1. **Not Creating Backups**

```typescript
// ❌ WRONG - No backup
{ operation: 'patch_bytes', targetPath: './binary.exe', ... }

// ✅ CORRECT
{ operation: 'backup_binary', targetPath: './binary.exe' }
{ operation: 'patch_bytes', targetPath: './binary.exe', ... }
```

### 2. **String Too Long**

```typescript
// ❌ WRONG - New string longer than original
// Original: "http://c2.com" (13 chars)
{
  operation: 'patch_string',
  newString: 'http://my-very-long-analysis-server.com' // 39 chars!
}

// ✅ CORRECT - Pad or truncate
{
  operation: 'patch_string',
  newString: '127.0.0.1:80' // 12 chars, fits
}
```

### 3. **Wrong Instruction Length**

```typescript
// ❌ WRONG - Partial instruction NOPed
// call instruction is 5 bytes, but only NOPing 3
{
  operation: 'nop_instructions',
  address: '0x401000',
  length: 3  // Breaks instruction!
}

// ✅ CORRECT - NOP complete instruction
{
  operation: 'nop_instructions',
  address: '0x401000',
  length: 5  // Full call instruction
}
```

### 4. **Invalid Assembly Syntax**

```typescript
// ❌ WRONG - Intel syntax in AT&T mode
{
  operation: 'patch_function',
  assembly: 'mov $1, %eax'  // AT&T syntax
}

// ✅ CORRECT - Intel syntax
{
  operation: 'patch_function',
  assembly: 'mov eax, 1; ret'
}
```

---

## 🔒 Security Considerations

### For Malware Analysis:

1. **Isolated Environment**
   - Use VM or container
   - Network isolation
   - Snapshot before patching

2. **Verify Defanging**
   - Test patched malware doesn't execute malicious code
   - Monitor network traffic
   - Check file system changes

3. **Documentation**
   - Log all patches applied
   - Record original functionality
   - Document IOCs

### For Security Research:

1. **Responsible Disclosure**
   - Report vulnerabilities found
   - Follow disclosure timelines
   - Don't publish exploit code prematurely

2. **Legal Compliance**
   - Ensure you have permission
   - Check local laws (DMCA, CFAA, etc.)
   - Consult legal counsel if unsure

---

## 📚 Additional Resources

- [radare2 Book](https://book.rada.re/)
- [Practical Malware Analysis](https://nostarch.com/malware)
- [Reverse Engineering for Beginners](https://beginners.re/)
- [OWASP Reverse Engineering](https://owasp.org/www-community/controls/Reverse_Engineering)

---

## 🆘 Troubleshooting

### "Patch failed"

- Verify file has write permissions
- Check address is valid
- Ensure hex bytes are properly formatted

### "Invalid address format"

- Use hex format: `0x401000` or `401000`
- No spaces or special characters
- Must be valid memory address

### "Binary won't run after patching"

- Restore from backup
- Check you didn't corrupt PE/ELF headers
- Verify instruction alignment
- Use smaller, more targeted patches

### "String patch truncated"

- New string too long for space
- Use shorter string or find larger space
- Consider patching pointer instead

---

**Remember: With great power comes great responsibility. Use these tools ethically and legally.**
