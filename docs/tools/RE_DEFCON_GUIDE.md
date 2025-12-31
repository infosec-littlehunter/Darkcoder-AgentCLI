# DEF CON CTF Reverse Engineering Guide

## The Problem You're Facing

You're right - when dealing with large, packed binaries in DEF CON challenges, traditional LLM approaches fail:

❌ **What Doesn't Work:**

- Dumping entire disassembly → exceeds token limits
- Asking LLM to "analyze everything" → information overload
- No persistent memory → forgets findings between sessions
- Custom packers → static analysis gets garbage

✅ **What DarkCoder Does Differently:**

- **Chunked analysis** - one function at a time
- **Behavioral scoring** - finds important code without names
- **Persistent state** - never loses progress
- **Multi-tool approach** - combines static + dynamic analysis

## Quick Start: Your First DEF CON Challenge

### Step 1: Initial Reconnaissance (5 minutes)

```bash
# Detect packer/protector
reverse_engineering(
  operation="detect_packer",
  targetPath="./defcon_challenge.exe"
)
```

**Output you'll get:**

```
Packer Detection Results:
  Primary: UPX v3.96 (high confidence)
  Secondary indicators:
    - High entropy in .text section (7.8/8.0)
    - Suspicious section names: UPX0, UPX1
    - Small import table (3 imports)

Recommendation: Unpack with 'upx -d defcon_challenge.exe'
```

### Step 2: Unpack if Needed

```bash
# If UPX detected
upx -d defcon_challenge.exe -o defcon_unpacked.exe

# If custom packer, try dynamic unpacking
reverse_engineering(
  operation="strace_run",
  targetPath="./defcon_challenge.exe",
  args=["test_input"]
)
```

### Step 3: Find Critical Functions (10 minutes)

Instead of analyzing 10,000+ functions, score them by behavior:

```bash
reverse_engineering(
  operation="behavioral_function_scoring",
  targetPath="./defcon_unpacked.exe",
  options=["--limit", "20", "--save-state"]
)
```

**What you get:**

```
Top 20 Critical Functions (by behavioral analysis):

Score  Address    Reason                              Tags
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 96    0x401530   High xref density (45 refs)        [core_logic]
                  Contains crypto constants
                  Multiple string comparisons

 91    0x402840   Input validation cluster           [validation]
                  strcmp(), memcmp() calls
                  Branches on comparison results

 87    0x403A20   Network I/O + syscalls             [c2_beacon]
                  socket(), connect(), send()
                  Base64 encoding detected

 82    0x404100   String manipulation                [decoder]
                  XOR operations on buffers
                  Loops over byte arrays

... 16 more functions ...

State saved to: .darkcoder/re_analysis/defcon_unpacked_state.json
```

### Step 4: Analyze Top Function First

```bash
reverse_engineering(
  operation="explain_function",
  targetPath="./defcon_unpacked.exe",
  address="0x401530",
  maxOutput="medium"
)
```

**Detailed analysis:**

```
Function Analysis: 0x401530

Overview:
  This appears to be the main validation routine. It takes user input
  as a string parameter and performs a multi-stage verification process.

Decompiled Code:
  int check_serial(char *input) {
    if (strlen(input) != 16) return 0;

    // Stage 1: Length check
    if (validate_length(input) == 0) return 0;

    // Stage 2: Checksum validation
    uint32_t checksum = calculate_checksum(input);
    if (checksum != 0x1337BEEF) return 0;

    // Stage 3: Crypto validation
    char decoded[16];
    aes_decrypt(input, key_at_0x405000, decoded);
    if (memcmp(decoded, "DEFCON", 6) != 0) return 0;

    return 1;  // Valid!
  }

Key Findings:
  1. Input must be exactly 16 characters
  2. Checksum constant: 0x1337BEEF
  3. AES key located at 0x405000
  4. Expects decrypted value to start with "DEFCON"

Cross-References:
  - Called from: main() at 0x400800
  - Calls: validate_length() at 0x401200
  - Calls: calculate_checksum() at 0x401350
  - Calls: aes_decrypt() at 0x402000

Recommendation:
  Next steps:
  1. Analyze calculate_checksum() to understand algorithm
  2. Extract AES key from 0x405000
  3. Work backwards to generate valid input
```

Now save this to persistent memory:

```bash
save_memory(
  fact="0x401530 is main validation: checks length=16, checksum=0x1337BEEF, AES decrypts to 'DEFCON'. Key at 0x405000",
  scope="project"
)
```

### Step 5: Find All Comparison Points

For stripped binaries, find decision points without relying on names:

```bash
reverse_engineering(
  operation="find_comparison_points",
  targetPath="./defcon_unpacked.exe"
)
```

**Result:**

```
Comparison Points Found (32 total):

Critical Comparisons (likely validation checks):
  0x4015C3: cmp eax, 0x1337BEEF  ← checksum validation
  0x401642: test al, al          ← boolean result check
  0x4018A0: cmp [rbp-0x20], 0x10 ← length check (16 bytes)
  0x401A45: je 0x401A60           ← jump if equal (success path)

String Comparisons:
  0x402155: strcmp(input, "admin")
  0x402230: memcmp(decoded, "DEFCON", 6)

Loop Counters:
  0x403120: cmp ecx, 0x10        ← loop 16 times
  0x403456: dec edx; jnz 0x403400 ← decryption loop
```

### Step 6: Decode Obfuscated Strings

```bash
reverse_engineering(
  operation="decode_strings_heuristic",
  targetPath="./defcon_unpacked.exe",
  options=["--detect-xor", "--detect-base64", "--detect-rot13"]
)
```

**Output:**

```
Decoded Strings (18 found):

XOR-encoded (key 0x42):
  0x405000: "AES_KEY_DeF_C0n_2025" ← AES encryption key!
  0x405020: "Correct! Flag is: "
  0x405050: "https://c2.defcon.org/beacon"

Base64-encoded:
  0x406000: "RkxBR3t0aDFzXzFzX3RoM19mbDRnfQ=="
            Decoded: "FLAG{th1s_1s_th3_fl4g}"  ← FOUND THE FLAG!

ROT13-encoded:
  0x406100: "Guvf vf n qrpbl"
            Decoded: "This is a decoy"
```

### Step 7: Build Attack Surface Map

```bash
reverse_engineering(
  operation="attack_surface",
  targetPath="./defcon_unpacked.exe"
)
```

**Attack Surface Report:**

```
Input Points (3):
  1. Command-line args (main() at 0x400800)
  2. stdin via fgets() at 0x401100
  3. File read from "input.txt" at 0x402500

Validation Points (5):
  1. Length check at 0x4018A0 (must be 16)
  2. Checksum at 0x4015C3 (must equal 0x1337BEEF)
  3. AES decrypt at 0x402000
  4. String comparison at 0x402230
  5. Final validation at 0x401530

Output Points (2):
  1. stdout: Success message
  2. File: writes flag to "flag.txt"

Recommended Attack Vector:
  → Bypass checksum at 0x4015C3 by patching JNE to JMP
  → Or calculate valid input that produces checksum 0x1337BEEF
```

## Advanced: Custom Packer Analysis

### When Binary is Heavily Obfuscated

```bash
# 1. Entropy analysis to find packed sections
reverse_engineering(
  operation="binwalk_entropy",
  targetPath="./packed_challenge.exe"
)

# 2. Detect control flow flattening
reverse_engineering(
  operation="deobfuscate_control_flow",
  targetPath="./packed_challenge.exe",
  address="0x401000"
)

# 3. Find crypto by constants (works even when obfuscated)
reverse_engineering(
  operation="find_crypto_constants",
  targetPath="./packed_challenge.exe"
)
```

**Crypto constant detection:**

```
Cryptographic Constants Found:

AES S-box detected at 0x408000:
  63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ...
  Confidence: 100%

SHA-256 K constants at 0x409000:
  428a2f98 71374491 b5c0fbcf e9b5dba5 ...
  Confidence: 99%

Custom XOR pattern at 0x40A000:
  Repeating key: 0xDEADBEEF
  Used in function at 0x402500
```

## Workflow for Multi-Day Challenges

### Day 1: Reconnaissance

```bash
# Save everything to project memory
save_memory(
  fact="Starting DEF CON 2025 Reverse Engineering challenge #3",
  scope="project"
)

# Initial triage
reverse_engineering(operation="detect_packer", targetPath="./chall3.exe")
reverse_engineering(operation="behavioral_function_scoring", targetPath="./chall3.exe", options=["--limit", "30"])

# Save top functions to memory
save_memory(
  fact="Top 3 functions: 0x401530 (validation), 0x402840 (input), 0x403A20 (crypto)",
  scope="project"
)
```

### Day 2: Deep Dive

```bash
# Load previous findings (LLM reads from project memory)
# Then continue where you left off

# Analyze function #1
reverse_engineering(operation="explain_function", targetPath="./chall3.exe", address="0x401530")
save_memory(fact="0x401530 analysis: Main validator, uses custom hash", scope="project")

# Analyze function #2
reverse_engineering(operation="explain_function", targetPath="./chall3.exe", address="0x402840")
```

### Day 3: Exploitation

```bash
# Find all validation points
reverse_engineering(operation="identify_protection_points", targetPath="./chall3.exe")

# Generate patch strategy
# Output suggests: "Patch JNE at 0x4015C3 to force success path"

# Create backup
reverse_engineering(operation="backup_binary", targetPath="./chall3.exe")

# Apply patch
reverse_engineering(
  operation="patch_bytes",
  targetPath="./chall3.exe",
  address="0x4015C3",
  hexBytes="90909090",  # NOP out check
  confirmLegalUse=true
)
```

## Pro Tips for DEF CON

### 1. Always Use State Management

```bash
# Every session, check previous findings
cat .darkcoder/re_analysis/challenge_state.json
```

### 2. Limit Output Size

```bash
# For quick checks
reverse_engineering(operation="r2_info", targetPath="./file.exe", maxOutput="tiny")

# For detailed analysis
reverse_engineering(operation="explain_function", targetPath="./file.exe", address="0x401000", maxOutput="large")
```

### 3. Compound Workflows

```bash
# Auto-solve common CTF patterns
reverse_engineering(
  operation="full_ctf_solve",
  targetPath="./easy_challenge.exe"
)
```

**Output:**

```
Full CTF Analysis Pipeline:

[1/6] Finding validation checks...
  ✓ Found 3 license checks
  ✓ Found 1 win function
  ✓ Found 2 comparison points

[2/6] Analyzing win/success functions...
  ✓ Function at 0x402000 prints flag
  ✓ Triggered when: checksum == 0x1337

[3/6] Tracing input validation...
  ✓ Input flows through: main → validate → checksum
  ✓ Algorithm: sum of bytes XOR 0xFF

[4/6] Calculating valid input...
  ✓ Working backwards from target checksum
  ✓ Valid input: "CTF_2025_PWNED!"

[5/6] Extracting flag...
  ✓ Running: ./challenge "CTF_2025_PWNED!"
  ✓ Flag: FLAG{th1s_w4s_t00_e4sy}

[6/6] Summary saved to memory
```

### 4. Dynamic + Static Combined

```bash
# Run with instrumentation
strace -o trace.log ./challenge test_input

# Then analyze trace
reverse_engineering(
  operation="trace_analysis",
  targetPath="trace.log"
)
```

## Memory Management for Large Projects

All analysis state is automatically saved to:

```
.darkcoder/
  re_analysis/
    challenge_state.json      ← Main state file
    function_0x401530.md      ← Per-function notes
    strings_decoded.txt       ← Deobfuscated strings
    attack_surface.json       ← Input/validation map
    memory_dump_0x400000.bin  ← Memory dumps
```

## Key Differences from Traditional Approach

| Traditional RE with LLM  | DarkCoder Approach                       |
| ------------------------ | ---------------------------------------- |
| Dump entire disassembly  | Behavioral scoring → prioritize          |
| LLM analyzes everything  | Chunked analysis, one function at time   |
| No persistent memory     | State saved to .darkcoder/re_analysis/   |
| Relies on function names | Semantic matching works on stripped bins |
| Static analysis only     | Static + dynamic + heuristics            |
| Generic responses        | CTF-specific workflows built-in          |

## Summary

DarkCoder solves the "large binary problem" for DEF CON challenges:

1. **Never overwhelm the LLM** - Use behavioral scoring to find the 20 most important functions out of 10,000
2. **Persistent state** - Never lose progress across days
3. **Works on obfuscated code** - Semantic analysis doesn't need function names
4. **Incremental analysis** - One function at a time, building understanding gradually
5. **Automated workflows** - Common CTF patterns solved automatically

Your new workflow:

1. Detect packer → Score functions → Analyze top 5 individually
2. Find comparison points → Decode strings → Map attack surface
3. Save everything to memory → Continue tomorrow where you left off
