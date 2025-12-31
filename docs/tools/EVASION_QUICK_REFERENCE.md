# Modern Malware Evasion - Quick Reference

## TL;DR - What Can DarkCoder Detect?

| Technique             | Detection                                            | Confidence Scoring           | MITRE ATT&CK         |
| --------------------- | ---------------------------------------------------- | ---------------------------- | -------------------- |
| **Direct Syscalls**   | ✅ SSN resolution, syscall opcodes, Nt\* APIs        | Score ≥30: HIGH, ≥15: MED    | T1562.001, T1055     |
| **NTDLL Unhooking**   | ✅ NtProtectVirtualMemory + NtWriteVirtualMemory     | Instant HIGH if both present | T1562.001            |
| **Heaven's Gate**     | ✅ WoW64 transitions, 32→64 bit evasion              | +20 points, instant HIGH     | T1562.001            |
| **AMSI Bypass**       | ✅ AmsiScanBuffer, 0x80070057, patching APIs         | Score ≥25: HIGH, ≥10: MED    | T1562.001            |
| **ETW Bypass**        | ✅ EtwEventWrite, NtTraceControl, 0xC3 patch         | Score ≥25: HIGH, ≥10: MED    | T1562.001, T1070     |
| **Sleep Obfuscation** | ✅ Ekko, Zilean, Foliage, encryption+timers          | Score ≥20: HIGH              | T1497.003            |
| **API Hashing**       | ✅ ROR13, CRC32, FNV1a, PEB walking                  | Score ≥25: HIGH              | T1027, T1106         |
| **Module Stomping**   | ✅ NtMapView + Write + Unmap, Phantom DLL            | Score ≥25: HIGH              | T1055.013, T1574.002 |
| **Reflective DLL**    | ✅ VirtualAlloc + VirtualProtect without LoadLibrary | MEDIUM confidence            | T1620                |

## Common Malware Fingerprints

### Cobalt Strike Beacon

```
✅ Sleep obfuscation (Ekko/Zilean) - 35/100
✅ Syscall evasion - 45/100
✅ AMSI bypass - 30/100
✅ Named pipe communication
```

### Metasploit Meterpreter

```
✅ API hashing (ROR13) - 40/100
✅ Reflective DLL loading
✅ PEB walking without LoadLibrary
✅ Stage0 shellcode
```

### APT Malware (Lazarus, APT29)

```
✅ Direct syscalls - 55/100
✅ Heaven's Gate - 65/100
✅ Module stomping - 40/100
✅ API hashing (custom algorithms)
```

## Quick Command Reference

```bash
# Full malware analysis
darkcoder reverse-engineering capability_analysis malware.exe

# Combined analysis
darkcoder reverse-engineering \
  malware_triage sample.exe \
  anti_analysis sample.exe \
  capability_analysis sample.exe

# Generate YARA rule for IOCs
darkcoder reverse-engineering yara_generate malware.exe
```

## Evasion Technique Cheat Sheet

### 1. Syscall Evasion

```assembly
; Hell's Gate pattern
mov r10, rcx
mov eax, 0x0018    ; SSN
syscall
ret
```

**Detects:** `syscall` + `ssn` strings = +25 score

---

### 2. AMSI Bypass

```c
// Memory patch AmsiScanBuffer
VirtualProtect(AmsiScanBuffer, 6, PAGE_EXECUTE_READWRITE, &old);
memcpy(AmsiScanBuffer, "\xB8\x57\x00\x07\x80\xC3", 6);
```

**Detects:** `amsiscanbuffer` + `virtualprotect` + `0x80070057` = +40 score

---

### 3. ETW Bypass

```c
// Patch EtwEventWrite
VirtualProtect(EtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &old);
*(BYTE*)EtwEventWrite = 0xC3;  // ret
```

**Detects:** `etweventwrite` + `0xc3` + `virtualprotect` = +40 score

---

### 4. Sleep Obfuscation

```c
// Ekko technique
RtlEncryptMemory(beacon, size, 0);
CreateTimerQueueTimer(...);  // Not Sleep()!
RtlEncryptMemory(beacon, size, 0);
```

**Detects:** `ekko` + encryption + timer = +35 score

---

### 5. API Hashing

```c
// Walk PEB, hash API names
PPEB peb = (PPEB)__readgsqword(0x60);
for (module in peb->Ldr->InLoadOrderModuleList) {
    for (export in module) {
        if (ROR13(export.name) == 0x12345678) {
            return export.address;  // Found!
        }
    }
}
```

**Detects:** `peb` + `inloadordermodulelist` + `ror13` = +55 score

---

## Scoring Quick Guide

| Pattern                   | Points | Example                            |
| ------------------------- | ------ | ---------------------------------- |
| HIGH confidence indicator | +15    | `syscall` opcode, `AmsiScanBuffer` |
| MEDIUM confidence         | +10    | NTDLL strings, timer functions     |
| LOW confidence            | +3-5   | Common APIs (LoadLibrary)          |
| API combination           | +20-25 | NtProtect + NtWrite (unhooking)    |
| Manual PEB walk           | +25    | PEB without LoadLibrary            |
| Heaven's Gate             | +20    | Instant HIGH if WoW64 detected     |

**Thresholds:**

- **≥30:** HIGH confidence (definitely malicious)
- **≥20-25:** HIGH for specific techniques (AMSI, ETW, sleep, API hash, module stomp)
- **≥15:** MEDIUM confidence (needs deeper analysis)
- **<15:** LOW or no indicators

## Real-World Indicators

### ✅ Definite Malware (Score 50+)

- Direct syscalls (45+) + AMSI bypass (30+) + sleep obfuscation (35+)
- Heaven's Gate (65+) alone
- Manual PEB walk (25+) + API hashing (40+)

### 🟡 Likely Malware (Score 25-49)

- AMSI bypass (25+) without other indicators
- ETW bypass (25+) in non-security tools
- Sleep obfuscation (20+) in unknown binary

### 🟢 Suspicious But Maybe Legitimate (Score 15-24)

- Some syscall indicators (15-29)
- Dynamic API resolution with partial hashing

### ⚪ Normal Software (Score <15)

- Common Windows APIs
- Standard imports
- No evasion patterns

## Analysis Recommendations

When LLM detects high scores:

1. **Syscall evasion (30+):**
   - Analyze with API Monitor / x64dbg
   - Look for SSN lookup routines
   - Check .text section for syscall stubs

2. **AMSI bypass (25+):**
   - Check PowerShell/VBA scripts
   - Look for AmsiScanBuffer patches
   - Analyze reflection abuse patterns

3. **ETW bypass (25+):**
   - Verify ETW TI provider status
   - Check EtwEventWrite integrity
   - Look for trace session manipulation

4. **Sleep obfuscation (20+):**
   - Analyze timer-based delays
   - Look for encryption during sleep
   - Check for memory stomping

5. **API hashing (25+):**
   - Extract hash constants
   - Identify hashing algorithm
   - Map hashes to API names

6. **Module stomping (25+):**
   - Analyze memory mapping patterns
   - Check for transacted NTFS
   - Look for phantom DLL loading

## Known Evasion Frameworks

### Detected by Name:

- **SysWhispers** - Syscall stub generator
- **Hell's Gate** - SSN extraction from NTDLL
- **Halo's Gate** - Improved Hell's Gate (skips hooks)
- **Tartarus' Gate** - Advanced SSN resolution
- **FreshyCalls** - Dynamic syscall resolution
- **Ekko** - Sleep obfuscation via ROP
- **Zilean** - Thread-based sleep masking
- **Foliage** - Queue-based sleep technique

### Detected by Pattern:

- Cobalt Strike (sleep obfuscation + syscalls + named pipes)
- Metasploit Meterpreter (API hashing ROR13 + reflective DLL)
- Sliver (syscalls + AMSI/ETW bypass)
- Brute Ratel C4 (advanced syscalls + evasion)

## Integration with MITRE ATT&CK

All detections map to:

**Defense Evasion (TA0005):**

- T1562.001 - Impair Defenses (AMSI, ETW, syscalls, unhooking)
- T1497.003 - Time-Based Evasion (sleep obfuscation)
- T1027 - Obfuscated Files/Info (API hashing)
- T1055.013 - Process Doppelgänging (module stomping)
- T1620 - Reflective Code Loading
- T1574.002 - DLL Side-Loading

**Execution (TA0002):**

- T1106 - Native API (direct syscalls)

**Defense Evasion + Credential Access:**

- T1070 - Indicator Removal (ETW bypass)

## Summary

**Question:** Does DarkCoder help LLM detect modern malware evasion?

**Answer:** **YES** ✅

- ✅ **10 evasion techniques** detected with scoring
- ✅ **MITRE ATT&CK** mapping for all techniques
- ✅ **Real-world malware** fingerprints (Cobalt Strike, Metasploit, APT)
- ✅ **Actionable recommendations** for deeper analysis
- ✅ **Known frameworks** detected by name or pattern

The LLM can now analyze **modern APT malware, C2 beacons, and EDR evasion** with expert-level understanding.
