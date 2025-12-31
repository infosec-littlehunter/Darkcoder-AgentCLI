# Large Binary Reverse Engineering Workflow

## Problem: LLM Limitations with Large Software Cracking

When reversing large software (DEF CON CTFs, commercial software with custom packers), traditional LLM approaches fail because:

1. **Context Window Overload**: Thousands of functions/variables exceed LLM token limits
2. **Custom Packers**: Obfuscated code makes static analysis ineffective
3. **No Persistent State**: LLM forgets previous findings between sessions
4. **Information Overload**: Dumping entire disassembly is useless

## Solution: Chunked Analysis with Persistent Memory

DarkCoder provides a **structured workflow** designed specifically for large binary RE projects:

### Phase 1: Initial Triage & Memory Setup

```bash
# 1. Create project-specific memory for this binary
reverse_engineering(
  operation="save_analysis_state",
  targetPath="./challenge.exe",
  stateName="main_analysis"
)

# 2. Detect & unpack if possible
reverse_engineering(
  operation="detect_packer",
  targetPath="./challenge.exe"
)

# 3. Smart triage - identifies key characteristics
reverse_engineering(
  operation="malware_triage",
  targetPath="./challenge.exe",
  maxOutput="small"  # Keep it concise
)
```

**What this does:**

- Creates a `.darkcoder/re_analysis/challenge_state.json` file to track findings
- Identifies packer (UPX, VMProtect, Themida, custom)
- Provides high-level overview without overwhelming context

### Phase 2: Incremental Function Discovery

Instead of analyzing all functions at once, use **behavioral scoring**:

```bash
# Find top 20 most critical functions by behavior
reverse_engineering(
  operation="behavioral_function_scoring",
  targetPath="./challenge.exe",
  options=["--limit", "20", "--save-state"]
)
```

**Output saved to memory:**

```json
{
  "critical_functions": [
    {
      "addr": "0x401000",
      "score": 95,
      "reason": "High xref density + crypto constants"
    },
    { "addr": "0x402550", "score": 88, "reason": "String comparison cluster" },
    { "addr": "0x403A20", "score": 82, "reason": "Network I/O syscalls" }
  ]
}
```

### Phase 3: Targeted Deep Dive

Now analyze **one function at a time** with full context:

```bash
# Decompile + explain + save findings
reverse_engineering(
  operation="explain_function",
  targetPath="./challenge.exe",
  address="0x401000",
  maxOutput="medium"  # Detailed analysis
)

# Save findings to memory
save_memory(
  fact="Function at 0x401000: License validation routine. Uses AES-256 for key derivation. Input: serial string. Returns: 0=invalid, 1=valid.",
  scope="project"
)
```

### Phase 4: Find Validation Points (Without Names)

For stripped/obfuscated binaries:

```bash
# Find all comparison instructions with constants
reverse_engineering(
  operation="find_comparison_points",
  targetPath="./challenge.exe"
)

# Trace how user input flows
reverse_engineering(
  operation="trace_data_flow",
  targetPath="./challenge.exe",
  pattern="user_input"  # Symbolic name
)
```

**Output:**

```
Comparison Points Found:
  0x4015C3: cmp eax, 0x539 (1337 decimal) - likely magic constant check
  0x401642: test al, al - boolean validation result
  0x4018A0: cmp [rbp-0x20], 0x10 - length check (16 bytes)
```

### Phase 5: Decode Obfuscated Strings

```bash
# Auto-detect encoding and decode
reverse_engineering(
  operation="decode_strings_heuristic",
  targetPath="./challenge.exe",
  options=["--detect-xor", "--detect-base64", "--detect-custom"]
)
```

**Saves to memory:**

```
Decoded Strings:
  0x405000: "License key invalid!" (XOR 0x42)
  0x405020: "https://c2.evil.com/beacon" (Base64)
  0x405100: "AES_KEY_DERIVATION_SALT" (XOR 0x13)
```

### Phase 6: Build Attack Surface Map

```bash
# Identify all input points and validators
reverse_engineering(
  operation="attack_surface",
  targetPath="./challenge.exe"
)
```

**Memory state updated:**

```json
{
  "input_points": [
    "stdin - read() at 0x401200",
    "command_line_args - main() at 0x400800",
    "file_read - fopen() at 0x402100"
  ],
  "validators": [
    "serial_check at 0x401000",
    "length_check at 0x4018A0",
    "checksum_verify at 0x402550"
  ]
}
```

### Phase 7: Automated Bypass Strategy

```bash
# Generate patch recommendations
reverse_engineering(
  operation="identify_protection_points",
  targetPath="./challenge.exe"
)

# Suggests patches like:
# 1. NOP out check at 0x4015C3 (5 bytes)
# 2. Patch JNE to JMP at 0x401642
# 3. Force return value to 1 at 0x401000
```

### Phase 8: Workflow Automation for Complex Chains

```bash
# Execute multi-step analysis automatically
reverse_engineering(
  operation="workflow_chain",
  targetPath="./challenge.exe",
  options=[
    "detect_packer",
    "behavioral_function_scoring",
    "find_comparison_points",
    "decode_strings_heuristic",
    "attack_surface",
    "identify_protection_points"
  ]
)
```

## Advanced Features for Custom Packers

### Control Flow Deobfuscation

```bash
reverse_engineering(
  operation="deobfuscate_control_flow",
  targetPath="./packed.exe",
  function="entry"  # Start from entry point
)
```

Handles:

- Control flow flattening
- Opaque predicates
- Jump table obfuscation
- Indirect call resolution

### Semantic Function Matching

When function names are stripped:

```bash
reverse_engineering(
  operation="semantic_function_match",
  targetPath="./stripped.exe",
  pattern="license_validation"  # Behavior pattern to match
)
```

Matches functions by **behavior signatures**, not names:

- String comparison patterns (strcmp, memcmp sequences)
- Crypto constant usage (S-boxes, round constants)
- Input validation patterns
- Return value conventions

### Call Graph Analysis

```bash
reverse_engineering(
  operation="analyze_call_graph",
  targetPath="./complex.exe",
  options=["--find-hub-functions", "--rank-by-importance"]
)
```

Identifies important functions by:

- Call graph centrality (functions called by many others)
- Xref density (highly referenced data/code)
- Distance from entry point

## Memory System Integration

All findings are automatically saved to:

```
.darkcoder/
  re_analysis/
    challenge_state.json         # Current analysis state
    function_notes.md            # Per-function annotations
    memory_map.json              # Address → purpose mapping
    attack_surface.json          # Input/validation points
    strings_decoded.txt          # Deobfuscated strings
```

### Query Memory During Analysis

```bash
# Ask LLM to recall findings
save_memory(
  fact="Check memory: What functions have we identified as critical?",
  scope="project"
)

# LLM reads from .darkcoder/re_analysis/challenge_state.json
# and provides context-aware response
```

## Example: DEF CON CTF Workflow

```bash
# Day 1: Initial recon
reverse_engineering(operation="detect_packer", targetPath="./defcon_chall.exe")
reverse_engineering(operation="behavioral_function_scoring", targetPath="./defcon_chall.exe", options=["--limit", "10"])

# Day 2: Analyze top functions
reverse_engineering(operation="explain_function", targetPath="./defcon_chall.exe", address="0x401000")
save_memory(fact="0x401000: Main validation logic, uses custom hash", scope="project")

# Day 3: Find comparison points
reverse_engineering(operation="find_comparison_points", targetPath="./defcon_chall.exe")

# Day 4: Decode strings
reverse_engineering(operation="decode_strings_heuristic", targetPath="./defcon_chall.exe")

# Day 5: Extract flag
reverse_engineering(operation="find_flag_strings", targetPath="./defcon_chall.exe")
```

## Key Principles

1. **Never analyze entire binary at once** - Use behavioral scoring to prioritize
2. **Save everything to memory** - Persistent state across sessions
3. **Work incrementally** - One function/address at a time
4. **Use behavior, not names** - Semantic matching works on obfuscated code
5. **Automate repetitive tasks** - Workflow chains for common patterns

## Tool Availability Check

```bash
# Check what RE tools are installed
reverse_engineering(operation="detect_tools", targetPath="./any.exe")
```

**Output:**

```
Available Tools:
  ✓ radare2 (v5.9.0)
  ✓ rizin (v0.7.0)
  ✗ Ghidra (not found - install for decompilation)
  ✓ binwalk (v2.3.4)
  ✓ ltrace
  ✓ strace

Recommended: Install Ghidra for best decompilation results
```

## Performance Tips

1. **Use maxOutput parameter** to control response size:
   - `maxOutput="tiny"` - 5K chars (quick checks)
   - `maxOutput="small"` - 15K chars (function summaries)
   - `maxOutput="medium"` - 30K chars (detailed analysis)
   - `maxOutput="large"` - 60K chars (comprehensive reports)

2. **Save critical findings immediately**:

   ```bash
   save_memory(fact="Your finding", scope="project")
   ```

3. **Use compound operations** for common workflows:
   ```bash
   reverse_engineering(operation="full_ctf_solve", targetPath="./challenge.exe")
   ```

## Integration with Other Tools

### Combine with Memory Tool

```bash
# Load previous session
read_file(filePath=".darkcoder/re_analysis/challenge_state.json")

# Continue analysis where you left off
```

### Combine with Security Intel

```bash
# Check if binary matches known threats
reverse_engineering(operation="threat_intel", targetPath="./suspicious.exe")

# Query for existing YARA rules
reverse_engineering(operation="check_yara_rules", targetPath="./suspicious.exe")
```

## Troubleshooting Large Binaries

**Problem**: "Binary has 50,000+ functions, LLM can't process"

**Solution**: Use progressive refinement:

```bash
# 1. Score all functions (fast, metadata only)
reverse_engineering(operation="behavioral_function_scoring", targetPath="./huge.exe", options=["--limit", "50"])

# 2. Analyze top 10 individually
# 3. Use call graph to find related functions
# 4. Build understanding incrementally
```

**Problem**: "Custom packer, can't get clean disassembly"

**Solution**: Multi-pronged approach:

```bash
# 1. Entropy analysis to find packed sections
reverse_engineering(operation="binwalk_entropy", targetPath="./packed.exe")

# 2. Dynamic analysis to dump unpacked code
reverse_engineering(operation="trace_analysis", targetPath="./packed.exe")

# 3. Memory dump at runtime
```

**Problem**: "Stripped binary, no function names"

**Solution**: Semantic analysis:

```bash
reverse_engineering(operation="semantic_function_match", targetPath="./stripped.exe")
reverse_engineering(operation="find_critical_functions", targetPath="./stripped.exe")
reverse_engineering(operation="analyze_call_graph", targetPath="./stripped.exe")
```

## Summary

DarkCoder solves the "large binary problem" through:

1. **Behavioral prioritization** - Focus on what matters
2. **Persistent memory** - Never lose progress
3. **Incremental analysis** - One chunk at a time
4. **Semantic matching** - Works without names/symbols
5. **Automated workflows** - Common patterns built-in

Instead of asking the LLM to understand everything at once, we guide it through a **structured discovery process** that builds understanding incrementally while maintaining state across sessions.
