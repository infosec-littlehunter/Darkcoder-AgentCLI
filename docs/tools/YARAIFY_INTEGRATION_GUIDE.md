# 🎯 YARAify Integration Guide

**Complete guide to using YARAify YARA rule scanning with DarkCoder**

---

## 📋 **Table of Contents**

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Getting Your API Key](#getting-your-api-key)
4. [Configuration](#configuration)
5. [Operations](#operations)
6. [Usage Examples](#usage-examples)
7. [Advanced Workflows](#advanced-workflows)
8. [API Key Manager](#api-key-manager)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

---

## 🎯 **Overview**

### **What is YARAify?**

[YARAify](https://yaraify.abuse.ch/) is a free YARA rule scanning and validation platform by abuse.ch that provides:

- ✅ **500+ Curated YARA Rules** from YARAhub
- ✅ **Malware Database** with hash lookup
- ✅ **YARA Rule Validation** and testing
- ✅ **ClamAV Integration** for signature matching
- ✅ **Threat Intelligence** from community submissions
- ✅ **Free API Access** with Auth-Key

### **Why Use YARAify with DarkCoder?**

1. **Enhance YARA Rule Generation**: Validate LLM-generated YARA rules
2. **Threat Intelligence**: Check if malware samples are already known
3. **Rule Testing**: Test rules against known malware corpus
4. **Community Knowledge**: Access 500+ professional YARA rules
5. **Complement Cuckoo**: Combine behavioral analysis with signature matching

---

## 🚀 **Quick Start**

### **1. Get API Key (2 minutes)**

Visit: **https://auth.abuse.ch/**

Sign in with:

- 🐦 Twitter/X
- 🔵 Google
- 💼 LinkedIn
- 🐙 GitHub

Copy your Auth-Key (looks like: `4d110c94c109864a6ad1e419d4dd4149d0fdfdb19bb29e5e`)

### **2. Configure DarkCoder**

```bash
# Add to your environment
export YARAIFY_API_KEY="your-auth-key-here"

# Or add to ~/.qwen/settings.json
{
  "yaraifyApiKey": "your-auth-key-here"
}
```

### **3. Test Integration**

```bash
darkcoder

# Test with hash lookup (safe, no file upload)
> Lookup this hash in YARAify: 44d88612fea8a8f36de82e1278abb02f
```

You should see malware information if the hash is known!

---

## 🔑 **Getting Your API Key**

### **Step-by-Step Process**

1. **Visit Authentication Portal**
   - URL: https://auth.abuse.ch/

2. **Sign In with OAuth**
   - Choose: Twitter/X, Google, LinkedIn, or GitHub
   - No manual registration needed!

3. **Accept Terms**
   - Review and accept abuse.ch Terms of Service

4. **Copy API Key**
   - Your Auth-Key will be displayed
   - Format: 40-character hexadecimal string

5. **Save Securely**
   - Store in environment variables
   - Or save to DarkCoder settings

### **API Key Benefits**

| Benefit          | Details                                |
| ---------------- | -------------------------------------- |
| **Cost**         | 100% FREE                              |
| **Rate Limits**  | No explicit limits (fair use)          |
| **Access Level** | Full API access                        |
| **Expiration**   | Never expires                          |
| **Sharing**      | Don't share (can regenerate if leaked) |

---

## ⚙️ **Configuration**

### **Option 1: Environment Variable (Recommended)**

```bash
# Add to ~/.bashrc or ~/.zshrc
export YARAIFY_API_KEY="4d110c94c109864a6ad1e419d4dd4149d0fdfdb19bb29e5e"

# Reload shell
source ~/.bashrc
```

### **Option 2: DarkCoder Settings File**

```bash
# Edit settings
nano ~/.qwen/settings.json
```

Add:

```json
{
  "yaraifyApiKey": "4d110c94c109864a6ad1e419d4dd4149d0fdfdb19bb29e5e"
}
```

### **Option 3: Project .env File**

```bash
# Create .env in your project
echo 'YARAIFY_API_KEY=4d110c94c109864a6ad1e419d4dd4149d0fdfdb19bb29e5e' >> .env
```

### **Verification**

```bash
# Check if configured
darkcoder
> Check YARAify API key status
```

---

## 🛠️ **Operations**

### **Available Operations**

| Operation     | Description                    | Use Case                  |
| ------------- | ------------------------------ | ------------------------- |
| `scan_file`   | Scan file with 500+ YARA rules | Malware detection         |
| `lookup_hash` | Check hash in database         | Identify known malware    |
| `lookup_yara` | Find files matching YARA rule  | Rule validation           |
| `lookup_task` | Check scan task status         | Monitor async scans       |
| `get_yarahub` | Get YARAhub rule collections   | Download rules            |
| `get_clamav`  | Get ClamAV signatures          | Signature-based detection |

---

## 💡 **Usage Examples**

### **Example 1: Scan File with YARA Rules**

```bash
darkcoder
> Scan this suspicious file with YARAify: /path/to/malware.exe
```

**What happens:**

1. File uploaded to YARAify
2. Scanned with 500+ YARA rules from YARAhub
3. Returns matching rules and threat intelligence
4. Optionally includes ClamAV signatures

**Output:**

```
## YARAify - File Scan Submitted

**File:** /path/to/malware.exe
**Task ID:** abc123
**SHA256:** d41d8cd98f00b204e9800998ecf8427e
**Status:** Scanning with YARAhub rules...

### Next Steps
1. Wait for scan to complete (typically 30-60 seconds)
2. Check status: operation: "lookup_task", taskId: "abc123"
```

### **Example 2: Lookup Known Malware Hash**

```bash
darkcoder
> Check if this hash is in YARAify database: 44d88612fea8a8f36de82e1278abb02f
```

**What happens:**

1. Hash queried in YARAify database
2. Returns file info, YARA matches, ClamAV signatures
3. Shows first/last seen dates

**Output:**

```
## YARAify - Hash Lookup Results

**Hash:** 44d88612fea8a8f36de82e1278abb02f
**File Name:** sample.exe
**File Type:** PE32 executable (application/x-dosexec)
**First Seen:** 2024-01-15 10:30:00
**Last Seen:** 2025-12-10 14:22:11

### YARA Rules Matched (3)
  - **MALWARE_Win_Generic**
    - Author: abuse.ch
    - Description: Generic Windows malware detection
    - Reference: https://yaraify.abuse.ch/...
```

### **Example 3: Validate Generated YARA Rule**

After LLM generates a YARA rule:

```bash
darkcoder
> Search YARAify for files matching this rule: MALWARE_Ransomware_Example
```

**What happens:**

1. Searches YARAify database for files matching rule
2. Returns list of known samples
3. Helps validate rule effectiveness

### **Example 4: Check Scan Status**

```bash
darkcoder
> Check status of YARAify scan task: abc123
```

**What happens:**

1. Queries task status
2. If complete: shows full results
3. If processing: asks to wait

### **Example 5: Get YARAhub Rules**

```bash
darkcoder
> Get YARAhub rule collections from YARAify
```

**What happens:**

1. Downloads index of available rule collections
2. Shows categories (malware families, APT groups, etc.)
3. Provides URLs for full rule downloads

### **Example 6: Enhanced Malware Analysis Workflow**

**Combined Cuckoo + YARAify:**

```bash
darkcoder
> I have a suspicious file at /tmp/malware.exe. Please:
> 1. Check if hash is known in YARAify
> 2. If unknown, submit to Cuckoo for behavioral analysis
> 3. After Cuckoo analysis, scan with YARAify YARA rules
> 4. Generate custom YARA rule based on both analyses
> 5. Validate the generated rule against YARAify database
```

**DarkCoder AI will:**

1. Calculate hash and lookup in YARAify
2. If not found → Submit to Cuckoo
3. Get Cuckoo behavioral report
4. Scan with YARAify rules
5. Generate YARA rule from IOCs
6. Test rule in YARAify
7. Return complete analysis + validated rule

---

## 🚀 **Advanced Workflows**

### **Workflow 1: YARA Rule Development**

```bash
# Step 1: Analyze malware
> Analyze malware.exe with Cuckoo and extract IOCs

# Step 2: Generate YARA rule
> Based on the Cuckoo analysis, generate a YARA detection rule

# Step 3: Validate against YARAify
> Test this YARA rule against YARAify to check effectiveness

# Step 4: Refine
> Refine the rule based on YARAify results to reduce false positives
```

### **Workflow 2: Threat Hunting**

```bash
# Step 1: Get suspicious hash from SIEM
> Lookup hash abc123... in YARAify

# Step 2: Get matching YARA rules
> What YARA rules matched this sample?

# Step 3: Hunt for related samples
> Search YARAify for other files matching MALWARE_APT_XYZ rule

# Step 4: Download rules for deployment
> Get YARAhub rules for APT detection
```

### **Workflow 3: False Positive Analysis**

```bash
# Step 1: User reports false positive
> This file is flagged but it's clean: sample.dll

# Step 2: Check YARAify
> Scan sample.dll with YARAify rules

# Step 3: Identify problematic rule
> Which YARA rule is causing false positive?

# Step 4: Report to community
> Document the false positive and adjust local rules
```

---

## 🔧 **API Key Manager**

### **Check API Key Status**

```bash
darkcoder
> Show API key status
```

Output includes YARAify:

```
## Security Tool API Keys

### YARAify
  - Status: ✅ Configured
  - Env Var: YARAIFY_API_KEY
  - Registration: https://auth.abuse.ch/
  - Documentation: https://yaraify.abuse.ch/api/
```

### **Test API Key**

```bash
darkcoder
> Test YARAify API connection
```

This will:

1. Attempt a simple API call
2. Verify authentication
3. Report success/failure

---

## 🐛 **Troubleshooting**

### **Issue 1: "API key is required" Error**

**Problem:**

```
Error: YARAify API key is required. Set YARAIFY_API_KEY environment variable
```

**Solutions:**

```bash
# Check if key is set
echo $YARAIFY_API_KEY

# Set for current session
export YARAIFY_API_KEY="your-key-here"

# Permanently add to shell
echo 'export YARAIFY_API_KEY="your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

### **Issue 2: "Hash not found" Response**

**Problem:**

```
Hash not found in YARAify database
```

**This is normal!** It means:

- File is not in YARAify database
- File might be new/unknown malware
- Or it's a clean file

**Next steps:**

```bash
# Submit file for scanning
> Scan the file with YARAify: /path/to/file
```

### **Issue 3: "Task still processing"**

**Problem:**

```
Scan still processing: abc123
```

**This is normal!** Scans take 30-60 seconds.

**Solution:**

```bash
# Wait 1 minute, then check again
> Check YARAify task status: abc123
```

### **Issue 4: 401 Unauthorized**

**Problem:**

```
YARAify API returned status 401: Unauthorized
```

**Causes:**

- Invalid API key
- Expired key
- Wrong key format

**Solutions:**

```bash
# Get new API key
1. Visit https://auth.abuse.ch/
2. Log in
3. Copy new key
4. Update configuration

# Verify key format (should be 40 hex characters)
echo $YARAIFY_API_KEY | wc -c  # Should be 41 (40 + newline)
```

### **Issue 5: Network Timeout**

**Problem:**

```
Error: Request timeout after 180000ms
```

**Causes:**

- Network connectivity issues
- YARAify server slow/down
- Large file upload

**Solutions:**

```bash
# Check network
ping yaraify-api.abuse.ch

# Try again (automatic retry)
> Retry YARAify scan

# For large files, use hash lookup instead
> Get SHA256 hash of file and lookup in YARAify
```

---

## ✅ **Best Practices**

### **1. Privacy Considerations**

```bash
# DON'T share sensitive files with community
> Scan file WITHOUT sharing: shareFile: false

# DO share malware samples (helps community)
> Scan malware WITH sharing: shareFile: true
```

### **2. Efficient Hash Lookups**

```bash
# GOOD: Check if known before uploading
> First lookup hash, then scan if unknown

# BAD: Always uploading files
> Just scan everything (wastes bandwidth)
```

### **3. YARA Rule Validation**

```bash
# GOOD: Test rules before deployment
> Generate rule → Test in YARAify → Deploy

# BAD: Deploy untested rules
> Generate rule → Deploy immediately (risk of FPs)
```

### **4. Rate Limiting**

- No explicit rate limits, but practice fair use
- Don't hammer API with thousands of requests
- Batch operations when possible
- Cache results locally

### **5. API Key Security**

```bash
# DO: Store in environment variables
export YARAIFY_API_KEY="..."

# DO: Use settings file with proper permissions
chmod 600 ~/.qwen/settings.json

# DON'T: Hardcode in scripts
api_key = "abc123..."  # ❌ Bad!

# DON'T: Commit to git
git add .env  # ❌ Bad! Use .gitignore
```

---

## 📊 **Feature Comparison**

| Feature                 | YARAify             | Cuckoo              | VirusTotal      |
| ----------------------- | ------------------- | ------------------- | --------------- |
| **YARA Scanning**       | ✅ 500+ rules       | ✅ Custom rules     | ✅ Multi-engine |
| **Behavioral Analysis** | ❌                  | ✅ Full analysis    | ❌              |
| **Hash Lookup**         | ✅ Free             | ❌                  | ✅ 500/day      |
| **File Submission**     | ✅ Free             | ✅ Self-hosted      | ✅ 500/day      |
| **API Access**          | ✅ Free             | ✅ REST API         | ✅ Limited free |
| **Privacy**             | 🟡 Optional sharing | ✅ Private          | ❌ Public DB    |
| **Cost**                | 🟢 FREE             | 🟢 FREE (self-host) | 🟡 Limited free |
| **Setup**               | 🟢 API key only     | 🟡 Docker required  | 🟢 API key only |

---

## 🎯 **Use Cases**

### **Security Operations Center (SOC)**

```bash
# Daily Threat Hunting
1. Export suspicious hashes from SIEM
2. Bulk lookup in YARAify
3. Identify known threats
4. Download matching YARA rules
5. Deploy rules to EDR
```

### **Malware Research**

```bash
# Sample Analysis
1. Submit sample to Cuckoo (behavioral)
2. Submit sample to YARAify (signature)
3. Generate YARA rule from findings
4. Validate rule against YARAify corpus
5. Publish to YARAhub (if significant)
```

### **Red Team / Pentesting**

```bash
# Payload Testing
1. Create custom payload
2. Scan with YARAify YARA rules
3. Identify triggering signatures
4. Refine payload to evade detection
5. Document for client report
```

### **Incident Response**

```bash
# Rapid Triage
1. Get suspicious file hash
2. YARAify hash lookup
3. If known → Get YARA rules
4. If unknown → Cuckoo analysis
5. Create detection rules
6. Deploy across environment
```

---

## 📚 **Additional Resources**

### **Official Documentation**

- [YARAify Homepage](https://yaraify.abuse.ch/)
- [API Documentation](https://yaraify.abuse.ch/api/)
- [YARAhub Rules](https://yaraify.abuse.ch/yarahub/)
- [abuse.ch Blog](https://abuse.ch/blog/)

### **YARA Resources**

- [YARA Official](https://virustotal.github.io/yara/)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Awesome YARA](https://github.com/InQuest/awesome-yara)

### **Community**

- [abuse.ch Twitter](https://twitter.com/abuse_ch)
- [YARAify GitHub](https://github.com/abusech/YARAify)

---

## 🎉 **Quick Reference**

### **Common Commands**

```bash
# Scan file
> Scan file with YARAify: /path/to/file

# Lookup hash
> Check YARAify for hash: abc123...

# Check status
> YARAify task status: taskId123

# Get rules
> Download YARAhub rules

# Combined workflow
> Analyze with Cuckoo and YARAify, then generate YARA rule
```

### **Environment Setup**

```bash
# Quick setup
export YARAIFY_API_KEY="your-key-here"

# Test
darkcoder
> Test YARAify connection

# Done!
```

---

## ✨ **Success!**

You're now ready to use YARAify with DarkCoder for:

- ✅ Professional YARA rule scanning
- ✅ Malware threat intelligence
- ✅ YARA rule validation
- ✅ Community-powered detection

**Happy malware hunting!** 🎯🔒
