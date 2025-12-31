# Parallel Tool Execution - Quick Start Guide

## What is Parallel Tool Execution?

Parallel tool execution allows DarkCoder to run multiple independent security tools simultaneously, dramatically reducing engagement time.

**Before (Sequential):**

```
Shodan → Censys → URLScan → Nuclei
10s      15s      8s         7s       = 40 seconds total
```

**After (Parallel):**

```
Shodan  ┐
Censys  ├─→ All run simultaneously
URLScan │
Nuclei  ┘
         = 15 seconds total (fastest tool)
```

## Quick Examples

### Example 1: Multi-Tool Reconnaissance

```bash
# DarkCoder automatically parallelizes independent tools
darkcoder "Perform reconnaissance on target.com using Shodan, Censys, and URLScan"
```

**What happens:**

1. DarkCoder detects all 3 tools are independent
2. Executes them in parallel
3. Aggregates results when all complete
4. **Time saved:** ~70% faster than sequential

### Example 2: Comprehensive Malware Analysis

```bash
darkcoder "Analyze suspicious.exe with VirusTotal, YARAify, Hybrid Analysis, and hash lookups"
```

**Execution plan:**

```
Wave 1 (parallel hash lookups):
├─ VirusTotal hash lookup
├─ YARAify hash lookup
└─ MD5/SHA256 calculation

Wave 2 (parallel file scans - depends on Wave 1):
├─ VirusTotal file scan
├─ YARAify file scan
└─ Local YARA rule matching
```

### Example 3: Bug Bounty Program Discovery

```bash
darkcoder "Search for Web3 programs on HackerOne, Bugcrowd, Immunefi, and Intigriti"
```

**Result:** All 4 platforms queried simultaneously → 4x faster!

## Configuration

### Enable/Disable Parallel Execution

**Via Command Line:**

```bash
# Enable with custom limit
darkcoder --max-parallel 10 "Quick recon on target.com"

# Disable parallelism (force sequential)
darkcoder --no-parallel "Careful analysis of target.com"
```

**Via Settings File** (`~/.qwen/settings.json`):

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 5
  }
}
```

### Per-Category Limits

Control concurrency for different tool types:

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 8,
    "maxPerCategory": {
      "network": 4, // Shodan, Censys, URLScan, etc.
      "malware": 3, // VirusTotal, YARAify, Hybrid Analysis
      "filesystem": 1, // Read, Write, Edit (safer sequential)
      "shell": 2, // Shell commands
      "web_recon": 3 // Nuclei, ffuf, wayback
    }
  }
}
```

## When Tools Run in Parallel

DarkCoder automatically detects when tools can safely run in parallel:

### ✅ **Safe to Parallelize:**

1. **Independent Network Scans:**

   ```bash
   "Scan target.com with Shodan and Censys"
   # ✅ Both tools query different APIs, no dependency
   ```

2. **Multiple Platform Searches:**

   ```bash
   "Search all bug bounty platforms for crypto programs"
   # ✅ Independent API calls to different platforms
   ```

3. **Hash Lookups:**

   ```bash
   "Check file hash on VirusTotal, YARAify, and Hybrid Analysis"
   # ✅ Both tools perform independent lookups
   ```

4. **Subdomain Enumeration:**
   ```bash
   "Find subdomains using Wayback, Censys, and certificate transparency"
   # ✅ Different data sources, parallel queries
   ```

### ⚠️ **Automatic Sequential Execution:**

1. **Dependent Operations:**

   ```bash
   "Scan target.com with Shodan, then run Nuclei on discovered IPs"
   # ⚠️ Sequential: Nuclei needs Shodan results first
   ```

2. **File Conflicts:**

   ```bash
   "Write results to output.txt and then read output.txt"
   # ⚠️ Sequential: Write must complete before read
   ```

3. **Pipeline Operations:**
   ```bash
   "Download file, scan with VirusTotal, then submit to Cuckoo"
   # ⚠️ Sequential: Each step needs previous step's output
   ```

## Performance Tuning

### Scenario-Based Configurations

#### 1. Fast Reconnaissance (Aggressive)

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 10,
    "maxPerCategory": {
      "network": 6,
      "web_recon": 4
    }
  }
}
```

**Use case:** Quick initial recon, many network-based tools

#### 2. Malware Analysis (Balanced)

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 5,
    "maxPerCategory": {
      "malware": 3,
      "network": 2
    }
  }
}
```

**Use case:** Balanced approach for malware analysis workflows

#### 3. Careful Enumeration (Conservative)

```json
{
  "parallelExecution": {
    "enabled": true,
    "maxConcurrentTools": 3,
    "maxPerCategory": {
      "network": 2,
      "filesystem": 1,
      "shell": 1
    }
  }
}
```

**Use case:** Resource-constrained systems or careful testing

#### 4. Sequential Only (Legacy)

```json
{
  "parallelExecution": {
    "enabled": false
  }
}
```

**Use case:** Debugging, compatibility, or specific requirements

## Monitoring Parallel Execution

### CLI Output

When tools run in parallel, you'll see:

```
🔄 Executing 4 tools in parallel:
  ⠋ Shodan - Scanning 8.8.8.8...
  ⠙ Censys - Searching certificates...
  ⠹ URLScan - Analyzing https://target.com...
  ⠸ Nuclei - Running CVE templates...

✅ Completed: Nuclei (7.2s)
✅ Completed: URLScan (8.1s)
✅ Completed: Shodan (10.3s)
✅ Completed: Censys (14.8s)

📊 Total time: 14.8s (sequential would be ~40s)
```

### Debug Mode

Enable detailed parallel execution logs:

```bash
DEBUG=1 darkcoder "Run recon tools"
```

**Output includes:**

- Dependency analysis results
- Tool wave assignments
- Concurrency limits applied
- Individual tool timings

## Common Workflows

### 1. Initial Target Assessment

```bash
darkcoder "Assess target.com with Shodan, Censys, URLScan, and Wayback Machine"
```

**Expected speedup:** 3-4x (all tools run in parallel)

### 2. Vulnerability Discovery

```bash
darkcoder "Scan discovered hosts with Nuclei for CVEs and run ffuf for directory enumeration"
```

**Expected speedup:** 2x (if hosts don't overlap, tools run in parallel)

### 3. Multi-Platform Search

```bash
darkcoder "Find DeFi programs on Immunefi, HackerOne, Bugcrowd, Intigriti, and YesWeHack"
```

**Expected speedup:** 5x (all platforms queried simultaneously)

### 4. Comprehensive File Analysis

```bash
darkcoder "Analyze malware.exe with VirusTotal, YARAify, Hybrid Analysis, and local YARA rules"
```

**Expected speedup:** 3x (all malware analysis tools run in parallel)

## Troubleshooting

### Issue: Rate Limiting

**Symptom:** Tools failing with 429 errors when parallel execution is enabled

**Solution:**

```json
{
  "parallelExecution": {
    "maxPerCategory": {
      "network": 2 // Reduce from default 3
    }
  }
}
```

### Issue: High Memory Usage

**Symptom:** System slowing down during parallel execution

**Solution:**

```json
{
  "parallelExecution": {
    "maxConcurrentTools": 3 // Reduce from default 5
  }
}
```

### Issue: Inconsistent Results

**Symptom:** Results differ between parallel and sequential execution

**Solution:**

```bash
# Force sequential execution to verify
darkcoder --no-parallel "Your query here"

# Report the issue if results differ
```

## Best Practices

1. **Start Conservative:**
   - Begin with default settings (max 5 concurrent)
   - Increase limits gradually based on performance

2. **Monitor Resource Usage:**
   - Watch CPU and memory during parallel execution
   - Adjust limits if system becomes unstable

3. **Respect Rate Limits:**
   - Keep network tool concurrency ≤ 3
   - Some APIs have strict rate limits

4. **Test Both Modes:**
   - Verify results in sequential mode first
   - Enable parallel for production workflows

5. **Use Debug Mode:**
   - Debug complex dependency issues
   - Understand tool execution order

## FAQ

**Q: Is parallel execution enabled by default?**
A: Yes, with conservative defaults (max 5 concurrent tools).

**Q: Can I force sequential execution for specific queries?**
A: Yes, use `--no-parallel` flag or disable in settings.

**Q: Does parallelism work in non-interactive mode?**
A: Yes, parallel execution works in both interactive and non-interactive modes.

**Q: Will this increase API costs?**
A: No, the same number of API calls are made, just faster.

**Q: Can I parallelize custom MCP tools?**
A: Yes, MCP tools support parallel execution with proper categorization.

**Q: What if dependency detection is wrong?**
A: Report the issue! We'll improve detection or you can force sequential mode.

## Performance Expectations

### Typical Speedups by Scenario

| Scenario             | Tools | Sequential | Parallel | Speedup |
| -------------------- | ----- | ---------- | -------- | ------- |
| Basic Recon          | 4     | 40s        | 15s      | 2.7x    |
| Full Recon           | 8     | 90s        | 30s      | 3.0x    |
| Malware Analysis     | 6     | 120s       | 45s      | 2.7x    |
| Bug Bounty Search    | 5     | 25s        | 8s       | 3.1x    |
| Multi-Platform Intel | 7     | 65s        | 20s      | 3.2x    |

**Average speedup:** 2.5-3.5x across typical security workflows

## Getting Started

1. **Update DarkCoder:**

   ```bash
   npm update -g @darkcoder/darkcoder
   ```

2. **Verify Parallel Execution:**

   ```bash
   darkcoder --version  # Check for v0.7.0+
   ```

3. **Test with Simple Query:**

   ```bash
   darkcoder "Scan 8.8.8.8 with Shodan and Censys"
   # Should see parallel execution indicator
   ```

4. **Optimize Settings:**
   - Edit `~/.qwen/settings.json`
   - Adjust `maxConcurrentTools` based on your system

5. **Monitor Performance:**
   - Use `DEBUG=1` to see execution details
   - Compare times with `--no-parallel`

## Need Help?

- 📖 Full documentation: [PARALLEL_TOOL_EXECUTION.md](./PARALLEL_TOOL_EXECUTION.md)
- 🐛 Report issues: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions)
