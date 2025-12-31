# 🐦 Cuckoo Sandbox Integration Guide

Complete guide for integrating Cuckoo Sandbox malware analysis with DarkCoder.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Installation Methods](#installation-methods)
4. [Configuration](#configuration)
5. [Usage Examples](#usage-examples)
6. [Advanced Features](#advanced-features)
7. [Troubleshooting](#troubleshooting)
8. [Security Considerations](#security-considerations)

---

## Overview

Cuckoo Sandbox is an open-source automated malware analysis system. Integration with DarkCoder enables:

- ✅ **Automated malware analysis** - Submit files/URLs and get detailed reports
- ✅ **Behavioral analysis** - Process, network, registry, file system monitoring
- ✅ **Network capture** - Full packet capture and DNS analysis
- ✅ **Memory dumps** - Extract malware artifacts from memory
- ✅ **YARA matching** - Custom signature detection
- ✅ **IOC extraction** - Automatic indicators of compromise generation
- ✅ **Private analysis** - All data stays on your infrastructure

---

## Quick Start

### 1. Deploy Cuckoo Sandbox

```bash
# Navigate to docker directory
cd /home/littlekid/Projects/CLI/darkcoder/docker/cuckoo

# Start Cuckoo services
docker-compose up -d

# Wait for initialization (1-2 minutes)
docker logs -f cuckoo-sandbox

# Verify API is running
curl http://localhost:8090/cuckoo/status
```

### 2. Configure DarkCoder

**Option A: Environment Variables**

```bash
export CUCKOO_API_URL="http://localhost:8090"
export CUCKOO_API_TOKEN="your-secure-token"
```

**Option B: Settings File** (`~/.qwen/settings.json`)

```json
{
  "advanced": {
    "cuckooApiUrl": "http://localhost:8090",
    "cuckooApiToken": "your-secure-token"
  }
}
```

### 3. Test Integration

```bash
darkcoder
> Check Cuckoo status
```

Expected output:

```
✅ Cuckoo Sandbox Status
Status: Online
API URL: http://localhost:8090
```

---

## Installation Methods

### Method 1: Docker (Recommended)

**Pros:**

- ✅ Easy setup
- ✅ Isolated environment
- ✅ Quick deployment

**Cons:**

- ⚠️ Limited to Docker-based VMs
- ⚠️ May have performance overhead

**Setup:**

```bash
cd docker/cuckoo
docker-compose up -d
```

---

### Method 2: Native Installation

**Pros:**

- ✅ Better performance
- ✅ Full VirtualBox/KVM support
- ✅ More configuration options

**Cons:**

- ⚠️ Complex setup
- ⚠️ Requires manual configuration

**Setup:**

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip virtualbox mongodb postgresql

# Create Cuckoo user
sudo adduser --disabled-password --gecos "" cuckoo
sudo usermod -a -G vboxusers cuckoo

# Install Cuckoo
sudo -u cuckoo -i
pip3 install cuckoo

# Initialize Cuckoo
cuckoo init
cuckoo community

# Configure
nano ~/.cuckoo/conf/cuckoo.conf
nano ~/.cuckoo/conf/virtualbox.conf

# Start services
cuckoo -d
cuckoo web runserver 0.0.0.0:8000
cuckoo api --host 0.0.0.0 --port 8090
```

---

### Method 3: Cloud/Remote Cuckoo

**For remote Cuckoo instances:**

```bash
# Configure remote Cuckoo URL
export CUCKOO_API_URL="https://cuckoo.example.com"
export CUCKOO_API_TOKEN="your-remote-token"
```

---

## Configuration

### Docker Configuration

Edit [`docker/cuckoo/docker-compose.yml`](../docker/cuckoo/docker-compose.yml):

```yaml
environment:
  - CUCKOO_API_TOKEN=your-secure-token-here # Change this!
```

**Generate secure token:**

```bash
openssl rand -hex 32
```

### DarkCoder Configuration

**~/.qwen/settings.json**

```json
{
  "advanced": {
    "cuckooApiUrl": "http://localhost:8090",
    "cuckooApiToken": "abc123...",
    "cuckooDefaultTimeout": 120,
    "cuckooDefaultPriority": 2
  }
}
```

### Analysis VM Setup

For best results, configure Windows VMs:

1. **Create Windows VM in VirtualBox**

   ```bash
   VBoxManage createvm --name "cuckoo-win10" --register
   VBoxManage modifyvm "cuckoo-win10" --memory 2048 --vram 128
   ```

2. **Install Cuckoo Agent**
   - Download agent.py from Cuckoo
   - Configure to run on startup
   - Snapshot VM as "clean state"

3. **Configure in Cuckoo**
   Edit `~/.cuckoo/conf/virtualbox.conf`:
   ```ini
   [cuckoo-win10]
   label = Windows 10
   platform = windows
   ip = 192.168.56.101
   ```

---

## Usage Examples

### Example 1: Analyze Suspicious File

```bash
darkcoder
> Analyze this suspicious file with Cuckoo: /path/to/malware.exe
```

**DarkCoder will:**

1. ✅ Submit file to Cuckoo
2. ✅ Monitor analysis progress
3. ✅ Retrieve full report when complete
4. ✅ Provide threat assessment and IOCs

### Example 2: Check Malicious URL

```bash
> Submit this URL to Cuckoo for analysis: http://suspicious-site.com
```

### Example 3: Get Detailed Report

```bash
> Get full Cuckoo report for task ID 123
```

**Output includes:**

- 📊 Malware score (0-10)
- 🚨 Behavioral detections
- 🌐 Network activity (domains, IPs, HTTP requests)
- 📂 Dropped files
- 💻 Process behavior
- 🎯 Threat verdict

### Example 4: Advanced Analysis

```bash
> Analyze malware.dll with Cuckoo:
  - Use DLL analysis package
  - Enable memory dump
  - High priority
  - 180 second timeout
```

**Manual API Call:**

```json
{
  "operation": "submit_file",
  "filePath": "/path/to/malware.dll",
  "package": "dll",
  "memory": true,
  "priority": 3,
  "timeout": 180,
  "tags": "apt,targeted"
}
```

---

## Advanced Features

### Custom Analysis Packages

Cuckoo supports various file types:

| Package | File Types      | Description                       |
| ------- | --------------- | --------------------------------- |
| `exe`   | .exe, .scr      | Windows executables               |
| `dll`   | .dll            | DLL files (needs export function) |
| `pdf`   | .pdf            | PDF documents                     |
| `doc`   | .doc, .docx     | Microsoft Word documents          |
| `xls`   | .xls, .xlsx     | Microsoft Excel documents         |
| `ppt`   | .ppt, .pptx     | PowerPoint presentations          |
| `zip`   | .zip, .rar, .7z | Archives                          |
| `jar`   | .jar            | Java archives                     |
| `apk`   | .apk            | Android packages                  |

### Priority Levels

- **1 (Low)** - Background analysis
- **2 (Medium)** - Standard priority (default)
- **3 (High)** - Urgent analysis

### Memory Dumps

Enable with `memory: true`:

```json
{
  "operation": "submit_file",
  "filePath": "/samples/malware.exe",
  "memory": true
}
```

**Memory dump analysis provides:**

- Injected code detection
- Hidden processes
- Network connections
- Malware unpacking

### YARA Signatures

Add custom YARA rules:

```bash
# Add rule to Cuckoo
cat > ~/.cuckoo/yara/custom_rules.yar <<EOF
rule APT_Malware {
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
    condition:
        all of them
}
EOF

# Restart Cuckoo to load rules
docker-compose restart cuckoo
```

---

## Troubleshooting

### Issue: "Cuckoo is not responding"

**Check if Cuckoo is running:**

```bash
docker ps | grep cuckoo
```

**View logs:**

```bash
docker logs cuckoo-sandbox
```

**Restart:**

```bash
cd docker/cuckoo
docker-compose restart
```

---

### Issue: "No machines available"

**Check machine status:**

```bash
darkcoder
> List Cuckoo machines
```

**Or via curl:**

```bash
curl http://localhost:8090/machines/list
```

**Fix locked machines:**

```bash
docker exec -it cuckoo-sandbox cuckoo machine list
docker exec -it cuckoo-sandbox cuckoo machine unlock <machine-name>
```

---

### Issue: "Analysis taking too long"

**Check task status:**

```bash
> Get Cuckoo task status for task 123
```

**Increase timeout:**

```json
{
  "operation": "submit_file",
  "filePath": "/path/to/file",
  "timeout": 300
}
```

**Default timeout:** 120 seconds
**Maximum recommended:** 600 seconds

---

### Issue: "API authentication failed"

**Verify token:**

```bash
# Check token in docker-compose.yml
cat docker/cuckoo/docker-compose.yml | grep CUCKOO_API_TOKEN

# Update DarkCoder configuration
export CUCKOO_API_TOKEN="correct-token-here"
```

---

### Issue: "Out of storage space"

**Clean old analyses:**

```bash
docker exec -it cuckoo-sandbox cuckoo clean

# Or manually
docker exec -it cuckoo-sandbox rm -rf /cuckoo/storage/analyses/*
```

**Check storage:**

```bash
docker exec -it cuckoo-sandbox df -h
```

---

## Security Considerations

### 🔒 Network Isolation

**CRITICAL:** Cuckoo should run on an isolated network!

```
┌────────────────────────────────────┐
│  Internet                          │
└────────────────┬───────────────────┘
                 │
                 ↓ (Firewall)
┌────────────────────────────────────┐
│  DarkCoder Host                    │
│  - Can access internet             │
│  - Can access Cuckoo API           │
└────────────────┬───────────────────┘
                 │ (Isolated network)
                 ↓
┌────────────────────────────────────┐
│  Cuckoo Sandbox                    │
│  - NO direct internet access       │
│  - Analysis VMs ISOLATED           │
│  - Malware contained               │
└────────────────────────────────────┘
```

### Firewall Rules

```bash
# Allow DarkCoder → Cuckoo API
sudo iptables -A INPUT -p tcp --dport 8090 -s 192.168.1.0/24 -j ACCEPT

# Block Cuckoo → Internet (except for updates)
sudo iptables -A OUTPUT -o eth0 -m owner --uid-owner cuckoo -j DROP

# Block analysis VMs from escaping
sudo iptables -A FORWARD -s 192.168.56.0/24 -j DROP
```

### Data Retention

**Regularly clean sensitive data:**

```bash
# Clean analyses older than 7 days
docker exec -it cuckoo-sandbox find /cuckoo/storage/analyses \
  -type d -mtime +7 -exec rm -rf {} \;

# Or configure auto-cleanup
# Edit ~/.cuckoo/conf/cuckoo.conf:
[cuckoo]
delete_original = yes
delete_bin_copy = yes
```

### Access Control

**Restrict API access:**

```yaml
# docker-compose.yml
services:
  cuckoo:
    networks:
      cuckoo-net:
        ipv4_address: 172.20.0.10
    ports:
      - '127.0.0.1:8090:8090' # Only localhost!
```

**Use strong tokens:**

```bash
# Generate cryptographically secure token
openssl rand -base64 48
```

---

## Performance Tuning

### Multiple Analysis VMs

Configure multiple VMs for parallel analysis:

```ini
# ~/.cuckoo/conf/virtualbox.conf

[cuckoo-win10-1]
label = Windows 10 VM 1
platform = windows
ip = 192.168.56.101

[cuckoo-win10-2]
label = Windows 10 VM 2
platform = windows
ip = 192.168.56.102

[cuckoo-win10-3]
label = Windows 10 VM 3
platform = windows
ip = 192.168.56.103
```

### Resource Allocation

**Docker limits:**

```yaml
services:
  cuckoo:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
```

### Database Optimization

**PostgreSQL tuning:**

```bash
docker exec -it cuckoo-db psql -U cuckoo -c "VACUUM ANALYZE;"
```

---

## Integration with Other Tools

### Chain with VirusTotal

```bash
> First check this hash on VirusTotal, if unknown, submit to Cuckoo for analysis
```

### Export to MISP

```bash
> Analyze malware.exe with Cuckoo and export IOCs to MISP
```

### Generate YARA Rules

```bash
> Analyze this sample and generate YARA rules from dropped files
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      DarkCoder CLI                          │
│  ┌───────────────────────────────────────────────────────┐ │
│  │  CuckooSandboxTool                                    │ │
│  │  packages/core/src/tools/cuckoo-sandbox.ts           │ │
│  └────────────────────┬──────────────────────────────────┘ │
└───────────────────────┼────────────────────────────────────┘
                        │ HTTP REST API (Port 8090)
                        │
┌───────────────────────▼────────────────────────────────────┐
│              Cuckoo Sandbox Services                       │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  Cuckoo API Server                                   │ │
│  │  - Task management                                   │ │
│  │  - File upload                                       │ │
│  │  - Report generation                                 │ │
│  └───────────┬──────────────────────────────────────────┘ │
│              │                                             │
│  ┌───────────▼──────────────────────────────────────────┐ │
│  │  PostgreSQL Database                                 │ │
│  │  - Task metadata                                     │ │
│  │  - Machine status                                    │ │
│  └──────────────────────────────────────────────────────┘ │
│              │                                             │
│  ┌───────────▼──────────────────────────────────────────┐ │
│  │  MongoDB                                             │ │
│  │  - Analysis reports                                  │ │
│  │  - Behavioral data                                   │ │
│  └──────────────────────────────────────────────────────┘ │
│              │                                             │
│  ┌───────────▼──────────────────────────────────────────┐ │
│  │  Analysis Virtual Machines                           │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐             │ │
│  │  │Win 10 #1│  │Win 10 #2│  │Win 7    │             │ │
│  │  │192.56.101  │192.56.102  │192.56.103              │ │
│  │  └─────────┘  └─────────┘  └─────────┘             │ │
│  └──────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Resources

- **Official Docs:** https://cuckoo.readthedocs.io/
- **Docker Image:** https://hub.docker.com/r/blacktop/cuckoo
- **GitHub:** https://github.com/cuckoosandbox/cuckoo
- **Community:** https://cuckoosandbox.org/community

---

## Next Steps

1. ✅ Deploy Cuckoo Sandbox
2. ✅ Configure DarkCoder integration
3. ✅ Test with sample files
4. ✅ Set up analysis VMs
5. ✅ Configure network isolation
6. ✅ Integrate with threat intelligence workflow

**Ready to analyze malware securely!** 🐦🔒
