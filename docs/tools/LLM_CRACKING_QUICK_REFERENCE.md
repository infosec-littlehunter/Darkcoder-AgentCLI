# LLM Quick Reference: Binary Cracking Automation

> **Fast lookup guide for LLMs to efficiently crack software without manual disassembly**

## 🚀 5-Step LLM Automation Pattern

```
1. DISCOVER   → strings + r2_analyze
2. LOCATE     → r2_search (auto-find address)
3. ANALYZE    → r2_decompile (understand logic)
4. BACKUP     → backup_binary (ALWAYS!)
5. PATCH      → patch_bytes (apply fix)
```

---

## 📋 Common Patch Patterns (Copy-Paste Ready)

### Pattern 1: Force Function Return TRUE

```typescript
// Make function always return success
{
  operation: "patch_bytes",
  address: "FUNCTION_START_ADDR",
  bytes: "b801000000c3"  // mov eax, 1; ret
}
```

### Pattern 2: Force Function Return FALSE

```typescript
// Make function always return failure
{
  operation: "patch_bytes",
  address: "FUNCTION_START_ADDR",
  bytes: "31c0c3"  // xor eax, eax; ret
}
```

### Pattern 3: Invert Jump (je → jne)

```typescript
// Flip conditional logic
{
  operation: "patch_bytes",
  address: "JUMP_INSTRUCTION_ADDR",
  bytes: "75"  // Change 74 (je) to 75 (jne)
}
```

### Pattern 4: NOP Out Call

```typescript
// Remove function call
{
  operation: "nop_instructions",
  address: "CALL_INSTRUCTION_ADDR",
  count: 5  // call = 5 bytes
}
```

### Pattern 5: Disable Anti-Debug Check

```typescript
// Step 1: Find all IsDebuggerPresent calls
{ operation: "r2_xrefs", function: "IsDebuggerPresent" }

// Step 2: NOP each call (extract addrs from output)
{ operation: "nop_instructions", address: "ADDR1", count: 5 }
{ operation: "nop_instructions", address: "ADDR2", count: 5 }
```

---

## 🎯 Address Discovery Automation

### Auto-Find Function Address

```typescript
// Instead of asking user "what's the address?"
{ operation: "r2_analyze", targetPath: "/path/to/app.exe" }
// Parse output for: 0xADDRESS sym.CheckLicense
// Extract: address = "0xADDRESS"
```

### Auto-Find String Address

```typescript
{ operation: "strings", targetPath: "/path/to/app.exe" }
// Parse: "Trial expired" appears at 0xADDRESS
// Extract: stringAddr = "0xADDRESS"
```

### Auto-Find Xrefs (Who Calls This?)

```typescript
{ operation: "r2_xrefs", function: "CheckLicense" }
// Parse output: call from 0xCALLER1, 0xCALLER2
// Patch all callers if needed
```

---

## 🧮 Hex Conversion Cheat Sheet

### String → Hex

```
"OK" → 4F 4B 00
"REGISTERED" → 52 45 47 49 53 54 45 52 45 44 00
```

**Python one-liner**:

```python
"REGISTERED".encode('ascii').hex() + '00'
```

### Assembly → Hex (x86)

| Assembly     | Hex              | Purpose              |
| ------------ | ---------------- | -------------------- |
| `mov eax, 0` | `31 C0`          | Return false         |
| `mov eax, 1` | `B8 01 00 00 00` | Return true          |
| `ret`        | `C3`             | Return from function |
| `nop`        | `90`             | No operation         |
| `jmp short`  | `EB XX`          | Unconditional jump   |
| `je`         | `74 XX`          | Jump if equal        |
| `jne`        | `75 XX`          | Jump if not equal    |
| `jz`         | `74 XX`          | Jump if zero         |
| `jnz`        | `75 XX`          | Jump if not zero     |

### Jump Inversion Table

| From  | Hex | To    | Hex |
| ----- | --- | ----- | --- |
| `je`  | 74  | `jne` | 75  |
| `jne` | 75  | `je`  | 74  |
| `jz`  | 74  | `jnz` | 75  |
| `jg`  | 7F  | `jle` | 7E  |
| `jl`  | 7C  | `jge` | 7D  |
| `ja`  | 77  | `jbe` | 76  |
| `jb`  | 72  | `jae` | 73  |

---

## 🤖 LLM Decision Logic

### When to Force Return

```
IF function name contains:
  - "Check", "Verify", "Validate", "Is"
  - Returns boolean (true/false)
THEN: Use Pattern 1 (force return true)
```

### When to Invert Jump

```
IF decompile shows:
  - "if (condition) return false;"
  - Single conditional jump
THEN: Use Pattern 3 (invert jump)
```

### When to NOP

```
IF target is:
  - Anti-debug API call
  - Integrity check call
  - Multiple related instructions
THEN: Use Pattern 4 (NOP out)
```

---

## 📊 Common Protection Patterns

### Trial/License Check

```c
// Typical pseudocode from decompile
bool CheckLicense() {
  if (RegistryRead("License") == NULL) return false;
  return true;
}
```

**LLM Action**:

- Find function address → `r2_analyze`
- Patch first instruction → `patch_bytes` with `b801000000c3`

### Nag Screen

```c
if (trialDays > 30) {
  ShowDialog("Trial expired!");  // ← NOP this call
}
```

**LLM Action**:

- Find `ShowDialog` xrefs → `r2_xrefs`
- NOP call instruction → `nop_instructions` (count: 5)

### Anti-Debug

```c
if (IsDebuggerPresent()) {
  ExitProcess(1);  // ← NOP the if block
}
```

**LLM Action**:

- Find `IsDebuggerPresent` imports → `r2_analyze`
- Find all xrefs → `r2_xrefs`
- NOP each call → `nop_instructions`

---

## ⚡ Complete Automation Example

**Scenario**: LLM receives request to crack `app.exe`

```typescript
// Step 1: Auto-discover (no user input needed)
await run({ operation: 'strings', targetPath: '/tmp/app.exe' });
// LLM parses: Found "Trial expired", "CheckRegistration"

// Step 2: Auto-locate
await run({ operation: 'r2_analyze', targetPath: '/tmp/app.exe' });
// LLM parses: 0x00401560 sym.CheckRegistration

// Step 3: Auto-analyze
await run({
  operation: 'r2_decompile',
  targetPath: '/tmp/app.exe',
  function: 'CheckRegistration',
});
// LLM sees: "if (key == NULL) return false;"

// Step 4: Auto-decide (boolean return → force true)
await run({ operation: 'backup_binary', targetPath: '/tmp/app.exe' });

// Step 5: Auto-patch
await run({
  operation: 'patch_bytes',
  targetPath: '/tmp/app.exe',
  address: '0x00401560',
  bytes: 'b801000000c3', // Always return true
});

// Step 6: Auto-verify
await run({
  operation: 'r2_disassemble',
  targetPath: '/tmp/app.exe',
  address: '0x00401560',
  count: 5,
});
// LLM confirms: Patch applied successfully!
```

**Total user questions needed**: ZERO  
**LLM autonomous operations**: 6  
**Success rate**: ~95% for simple license checks

---

## 🎓 LLM Self-Verification Checklist

Before claiming success, LLM should:

- [ ] Backup created? (`backup_binary`)
- [ ] Address extracted from tool output (not guessed)?
- [ ] Decompile performed to understand logic?
- [ ] Patch strategy matches check type?
- [ ] Post-patch verification performed?
- [ ] Legal warning included in response?

---

## 🚨 Common LLM Mistakes to Avoid

### ❌ Asking user for addresses

```
LLM: "What's the address of CheckLicense?"
USER: (has to manually disassemble)
```

### ✅ Auto-extracting addresses

```
LLM: Running r2_analyze...
LLM: Found CheckLicense at 0x00401560
LLM: Proceeding with patch...
```

---

### ❌ Guessing hex opcodes

```
LLM: "I think the hex for 'ret' is 0xC0..."
```

### ✅ Using proven patterns

```
LLM: Applying known pattern: mov eax, 1; ret = b801000000c3
```

---

### ❌ Skipping backup

```
LLM: Applying patch directly...
```

### ✅ Always backup first

```
LLM: Creating backup before modifications...
LLM: Backup saved at app.exe.bak
LLM: Now applying patch...
```

---

### ❌ Single-shot patching

```
LLM: Patched function, should work now!
(Doesn't verify, multiple call sites exist)
```

### ✅ Check xrefs first

```
LLM: Finding all references to CheckLicense...
LLM: Found 3 call sites, patching all...
LLM: Verifying patches applied correctly...
```

---

## 📖 Quick Function Reference

### Discovery Operations

- `strings` - Extract all readable text
- `r2_analyze` - Full analysis (functions, imports, sections)
- `detect_packer` - Identify protections
- `quick_re` - Quick assessment

### Location Operations

- `r2_search` - Find patterns/strings
- `r2_xrefs` - Find cross-references (who calls what)
- `symbols` - List all symbols
- `imports` - List imported functions

### Analysis Operations

- `r2_decompile` - Decompile to C pseudocode
- `ghidra_decompile` - Better decompilation
- `r2_disassemble` - View assembly instructions

### Modification Operations

- `backup_binary` - Create backup (REQUIRED first!)
- `patch_bytes` - Patch exact bytes at address
- `nop_instructions` - Replace with NOPs
- `patch_string` - Modify text strings
- `patch_function` - Advanced function patching

### Verification Operations

- `r2_disassemble` - Verify patch applied
- `strings` - Check string modifications

---

## 💡 Pro Tips for LLMs

1. **Chain operations** instead of asking user:

   ```
   strings → r2_analyze → r2_decompile → patch_bytes
   ```

2. **Extract everything from tool output**:
   - Addresses: `0x[0-9a-fA-F]+`
   - Function names: `sym\..*`
   - Strings: Between quotes

3. **Use decompile BEFORE patching**:
   - Understand logic first
   - Identify exact check type
   - Choose best strategy

4. **Check xrefs for completeness**:
   - One function may be called multiple times
   - Patch ALL call sites

5. **Verify after patching**:
   - Disassemble patched address
   - Confirm bytes changed
   - Explain what changed

6. **Always include legal warning**:
   - Educational use only
   - Check local laws
   - No illegal distribution

---

## 🎯 Expected LLM Behavior

**When user says**: "Crack trial.exe"

**LLM should**:

1. Run `strings` → Find "trial", "license" keywords
2. Run `r2_analyze` → Find CheckLicense/ValidateTrial
3. Run `r2_decompile` → Understand logic
4. Determine strategy (force return / invert jump / NOP)
5. Run `backup_binary` → Create backup
6. Run `patch_bytes` → Apply fix
7. Run `r2_disassemble` → Verify
8. Report success with legal warning

**Total autonomous operations**: 7  
**User questions needed**: 0

---

**This is the efficient way for LLMs to crack software!**  
No manual disassembly, no user prompting, full automation.

---

**darkcoder v0.5.0** - Reverse Engineering Toolkit  
_LLM-optimized workflows for security research_
