# LLM-Friendly Software Cracking Workflow

> **⚠️ LEGAL WARNING**: This guide is for EDUCATIONAL and AUTHORIZED SECURITY RESEARCH ONLY. Only use on software you own or have explicit permission to analyze. Cracking commercial software without authorization is illegal in most jurisdictions.

## Overview

This guide explains how LLMs can efficiently use darkcoder's reverse engineering tools for software analysis and modification WITHOUT requiring manual disassembly or low-level knowledge.

## The Challenge

**Traditional Manual Approach (Inefficient for LLM)**:

1. Manually disassemble binary
2. Search for specific functions/strings
3. Calculate exact offsets and addresses
4. Determine opcodes for patches
5. Apply patches byte-by-byte

**LLM-Friendly Approach (Efficient)**:
Use high-level operations in combination - let the tools auto-locate targets!

---

## 🎯 Efficient LLM Workflow

### Step 1: Initial Reconnaissance (Auto-Discovery)

**Goal**: Understand binary structure WITHOUT manual analysis

```typescript
// Quick assessment - auto-identifies language, protections, capabilities
{
  operation: "quick_re",
  targetPath: "/path/to/software.exe"
}

// Find protection schemes automatically
{
  operation: "detect_packer",
  targetPath: "/path/to/software.exe"
}

// Extract all strings (license keys, trial messages, error text)
{
  operation: "strings",
  targetPath: "/path/to/software.exe"
}
```

**LLM Action**: Analyze output to identify protection keywords:

- "trial", "license", "registration", "serial", "activation"
- "expired", "demo", "evaluation", "purchase"
- Function names: "CheckLicense", "ValidateSerial", "IsRegistered"

---

### Step 2: Find Target Functions (Auto-Locate)

**Goal**: Let radare2/rizin AUTO-FIND functions - no manual searching!

```typescript
// Auto-analyze and list ALL functions
{
  operation: "r2_analyze",
  targetPath: "/path/to/software.exe"
}

// Search for specific patterns
{
  operation: "r2_search",
  targetPath: "/path/to/software.exe",
  pattern: "CheckLicense"  // String search
}

// Or hex pattern search
{
  operation: "r2_search",
  targetPath: "/path/to/software.exe",
  pattern: "74 0f 48 8d"  // Hex pattern
}
```

**LLM Action**: Extract function addresses from output:

- Output contains: `0x004015a0 sym.CheckLicense`
- LLM stores: `address = "0x004015a0"`

---

### Step 3: Analyze Protection Logic (Auto-Decompile)

**Goal**: Let Ghidra/radare2 DECOMPILE to C-like pseudocode

```typescript
// Decompile function to understand logic
{
  operation: "r2_decompile",
  targetPath: "/path/to/software.exe",
  function: "CheckLicense"
}

// Or use Ghidra for better decompilation
{
  operation: "ghidra_decompile",
  targetPath: "/path/to/software.exe"
}
```

**Example Output**:

```c
// CheckLicense pseudocode
bool CheckLicense() {
  if (ReadRegistryKey("Software\\MyApp\\License") == NULL) {
    return false;  // ← FOUND THE CHECK!
  }
  return true;
}
```

**LLM Analysis**: Identify the conditional jump:

- At address `0x004015b4`: `test eax, eax; je 0x004015c8` (jump if no license)
- Strategy: Invert `je` → `jne` OR force return value to `true`

---

### Step 4: Plan Patch Strategy (High-Level Thinking)

**Three Common Strategies**:

#### Strategy A: Force Function Return (Easiest)

Make function ALWAYS return success (true/1)

#### Strategy B: Invert Conditional Jump

Change `je` (jump if equal) → `jne` (jump if not equal)

#### Strategy C: NOP Out Entire Check

Replace check with NOPs (no operation)

**LLM Decision Making**:

- If function is simple boolean → Use Strategy A (force return)
- If specific jump identified → Use Strategy B (invert jump)
- If complex multi-part check → Use Strategy C (NOP region)

---

### Step 5: Apply Patches (Automated)

#### Strategy A: Force Return Value

```typescript
// Backup first (ALWAYS!)
{
  operation: "backup_binary",
  targetPath: "/path/to/software.exe"
}

// Patch function prologue to return 1 (true)
{
  operation: "patch_bytes",
  targetPath: "/path/to/software.exe",
  address: "0x004015a0",  // Function start
  bytes: "b801000000c3"    // mov eax, 1; ret
}
```

**How LLM Generates `bytes`**:

- x86 assembly: `mov eax, 1` = `B8 01 00 00 00`
- x86 assembly: `ret` = `C3`
- Combined: `b801000000c3`

#### Strategy B: Invert Conditional Jump

```typescript
// Find jump address from decompile
// je (74) → jne (75) at 0x004015b4

{
  operation: "patch_bytes",
  targetPath: "/path/to/software.exe",
  address: "0x004015b4",
  bytes: "75"  // Change opcode 74 (je) to 75 (jne)
}
```

**Jump Inversion Table** (for LLM reference):
| Original | Hex | Inverted | Hex |
|----------|-----|----------|-----|
| je (jump if equal) | 74 | jne | 75 |
| jne (jump if not equal) | 75 | je | 74 |
| jz (jump if zero) | 74 | jnz | 75 |
| jg (jump if greater) | 7F | jle | 7E |
| jl (jump if less) | 7C | jge | 7D |
| ja (jump if above) | 77 | jbe | 76 |
| jb (jump if below) | 72 | jae | 73 |

#### Strategy C: NOP Out Instructions

```typescript
// NOP = 0x90 (no operation)
// To NOP 5 bytes at 0x004015b4

{
  operation: "nop_instructions",
  targetPath: "/path/to/software.exe",
  address: "0x004015b4",
  count: 5  // NOPs 5 bytes: 90 90 90 90 90
}
```

---

### Step 6: String Patching (For Messages)

If you need to modify trial/nag messages:

```typescript
// Find string location
{
  operation: "strings",
  targetPath: "/path/to/software.exe"
}

// Output: "Trial expired" at 0x00405000

// Patch to say "Full version"
{
  operation: "patch_string",
  targetPath: "/path/to/software.exe",
  address: "0x00405000",
  pattern: "Trial expired",  // Must match exact length!
  bytes: "46756c6c2076657273696f6e00"  // "Full version\0" in hex
}
```

**How LLM Converts Strings to Hex**:

```
"Full version\0" → ASCII hex
F=46, u=75, l=6c, l=6c, space=20, v=76, e=65, r=72, s=73, i=69, o=6f, n=6e, \0=00
Result: 46756c6c2076657273696f6e00
```

---

### Step 7: Patch Anti-Debug Checks

Common anti-debug APIs to disable:

```typescript
// Find imports
{
  operation: "r2_analyze",
  targetPath: "/path/to/software.exe"
}

// Output shows: sym.imp.IsDebuggerPresent at 0x00401234

// Find all CALLS to IsDebuggerPresent
{
  operation: "r2_xrefs",
  targetPath: "/path/to/software.exe",
  function: "IsDebuggerPresent"
}

// Output: Called from 0x004015d0, 0x00402100

// NOP each call (e8 XX XX XX XX = 5 bytes)
{
  operation: "nop_instructions",
  targetPath: "/path/to/software.exe",
  address: "0x004015d0",
  count: 5
}

{
  operation: "nop_instructions",
  targetPath: "/path/to/software.exe",
  address: "0x00402100",
  count: 5
}
```

---

## 📋 Complete Example Workflow

**Scenario**: Crack trial version of "SuperApp.exe"

### 1. Reconnaissance

```typescript
{
  operation: "strings",
  targetPath: "/tmp/SuperApp.exe"
}
```

**LLM Analyzes Output**:

```
...
"Trial version - 30 days remaining"
"Please register to continue"
"License validation failed"
"CheckRegistration"
...
```

### 2. Find Registration Function

```typescript
{
  operation: "r2_analyze",
  targetPath: "/tmp/SuperApp.exe"
}
```

**LLM Finds**:

```
0x00401560 sym.CheckRegistration
```

### 3. Decompile Function

```typescript
{
  operation: "r2_decompile",
  targetPath: "/tmp/SuperApp.exe",
  function: "CheckRegistration"
}
```

**Output (pseudocode)**:

```c
bool CheckRegistration() {
  char* key = ReadRegistry("License");
  if (key == NULL) {
    return false;  // ← At 0x00401575
  }
  if (ValidateKey(key)) {
    return true;
  }
  return false;
}
```

### 4. Backup Binary

```typescript
{
  operation: "backup_binary",
  targetPath: "/tmp/SuperApp.exe"
}
```

### 5. Apply Patch (Force Return True)

```typescript
{
  operation: "patch_bytes",
  targetPath: "/tmp/SuperApp.exe",
  address: "0x00401560",  // Function start
  bytes: "b801000000c3"    // mov eax, 1; ret (always return true)
}
```

### 6. Verify Patch

```typescript
{
  operation: "r2_disassemble",
  targetPath: "/tmp/SuperApp.exe",
  address: "0x00401560",
  count: 10
}
```

**Expected Output**:

```asm
0x00401560  b801000000    mov eax, 1
0x00401565  c3            ret
...
```

✅ **Success!** Function now always returns `true` (registered)

---

## 🧠 LLM Decision Tree

```
START: Binary to crack
  │
  ├─→ Reconnaissance
  │   ├─ strings → Find keywords
  │   ├─ r2_analyze → List functions
  │   └─ detect_packer → Check protections
  │
  ├─→ Locate Target
  │   ├─ r2_search → Find by name/pattern
  │   └─ Store address
  │
  ├─→ Understand Logic
  │   ├─ r2_decompile OR ghidra_decompile
  │   └─ Identify check type
  │
  ├─→ Choose Strategy
  │   ├─ Simple boolean? → Force return (patch_bytes)
  │   ├─ Single jump? → Invert jump (patch_bytes)
  │   ├─ Complex check? → NOP region (nop_instructions)
  │   └─ Anti-debug? → Find xrefs + NOP calls
  │
  ├─→ Backup
  │   └─ backup_binary (ALWAYS!)
  │
  ├─→ Patch
  │   ├─ patch_bytes (precise)
  │   ├─ nop_instructions (remove)
  │   └─ patch_string (modify text)
  │
  └─→ Verify
      └─ r2_disassemble → Check patches applied
```

---

## 🎓 Key Principles for LLM Efficiency

### ✅ DO:

1. **Chain operations**: `strings` → `r2_analyze` → `r2_decompile` → `patch_bytes`
2. **Let tools auto-locate**: Use `r2_search`, `r2_xrefs` instead of manual hunting
3. **Think high-level first**: Understand WHAT to patch before HOW
4. **Use pseudocode**: Decompile to C-like code for easier analysis
5. **Always backup**: Call `backup_binary` before ANY modification

### ❌ DON'T:

1. **Manually calculate offsets**: Let r2/rizin find addresses
2. **Guess opcodes**: Use decompile to understand, then apply known patterns
3. **Skip analysis**: Always understand logic before patching
4. **Forget backups**: ALWAYS create backup first
5. **Over-complicate**: Simple patches (force return) usually work best

---

## 📚 Common Assembly Patterns for LLMs

### Function Return Values (x86/x64)

**Return true (1)**:

```asm
mov eax, 1    ; B8 01 00 00 00
ret           ; C3
```

Hex: `b801000000c3`

**Return false (0)**:

```asm
xor eax, eax  ; 31 C0
ret           ; C3
```

Hex: `31c0c3`

**Return specific value (e.g., 42)**:

```asm
mov eax, 42   ; B8 2A 00 00 00
ret           ; C3
```

Hex: `b82a000000c3`

### Jump Modifications

**Make jump unconditional** (always jump):

```asm
Original: je 0x401234    ; 74 XX
Patched:  jmp 0x401234   ; EB XX (same offset)
```

**Disable jump** (never jump):

```asm
Original: je 0x401234    ; 74 XX
Patched:  NOP; NOP       ; 90 90
```

### Call Removal

**NOP out call** (5 bytes):

```asm
Original: call 0x401234  ; E8 XX XX XX XX
Patched:  NOP×5          ; 90 90 90 90 90
```

---

## 🔧 Troubleshooting

### Patch Didn't Work?

1. **Verify address**:

   ```typescript
   { operation: "r2_disassemble", address: "0xADDRESS", count: 5 }
   ```

2. **Check if packed**:

   ```typescript
   {
     operation: 'detect_packer';
   }
   ```

   → If packed, unpack first!

3. **Try alternative strategy**:
   - Force return didn't work → Try inverting jump
   - Single patch insufficient → Patch multiple locations

4. **Check xrefs**:
   ```typescript
   { operation: "r2_xrefs", function: "CheckLicense" }
   ```
   → Patch ALL call sites, not just one!

---

## 🎯 LLM Workflow Summary

**Instead of asking user for addresses, the LLM should**:

1. **Auto-discover**: `strings` + `r2_analyze` → Extract function names
2. **Auto-locate**: `r2_search` → Get exact addresses
3. **Auto-analyze**: `r2_decompile` → Understand logic
4. **Auto-generate**: Create patch bytes from known patterns
5. **Auto-apply**: `patch_bytes` / `nop_instructions`
6. **Auto-verify**: `r2_disassemble` → Confirm success

**Result**: LLM can crack software efficiently WITHOUT manual user input for each offset!

---

## ⚖️ Legal Disclaimer

This workflow is provided for:

- ✅ **Educational purposes** (learning reverse engineering)
- ✅ **Authorized security research** (penetration testing with permission)
- ✅ **Analyzing your own software** (debugging, modding)
- ✅ **Malware analysis** (defanging for research)

**Illegal uses**:

- ❌ Cracking commercial software without authorization
- ❌ Distributing cracked software
- ❌ Bypassing DRM for piracy
- ❌ Violating DMCA/CFAA laws

**Check your local laws before using these techniques!**

---

## 📖 Additional Resources

- [Radare2 Book](https://book.rada.re/)
- [x86/x64 Opcode Reference](https://www.felixcloutier.com/x86/)
- [Ghidra User Guide](https://ghidra-sre.org/CheatSheet.html)
- [Reverse Engineering for Beginners](https://beginners.re/)

---

**Generated for darkcoder v0.5.0**  
_Efficient LLM-driven reverse engineering without manual disassembly_
