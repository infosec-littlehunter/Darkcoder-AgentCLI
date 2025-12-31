# 🛠️ Developer Setup Guide

Complete guide for setting up DarkCoder development environment. This guide helps you avoid common issues like missing tools, memory errors, and API problems.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Health Check](#quick-health-check)
3. [Memory Configuration](#memory-configuration)
4. [API Keys Setup](#api-keys-setup)
5. [Security Tools Installation](#security-tools-installation)
6. [Common Issues & Solutions](#common-issues--solutions)
7. [Platform-Specific Notes](#platform-specific-notes)

---

## Prerequisites

### Required Software

| Software | Minimum Version | Check Command    | Install                             |
| -------- | --------------- | ---------------- | ----------------------------------- |
| Node.js  | 20.0.0+         | `node --version` | [nodejs.org](https://nodejs.org/)   |
| npm      | 10.0.0+         | `npm --version`  | Comes with Node.js                  |
| Git      | 2.0+            | `git --version`  | [git-scm.com](https://git-scm.com/) |

### Recommended System Requirements

| Resource   | Minimum | Recommended |
| ---------- | ------- | ----------- |
| RAM        | 8 GB    | 16 GB       |
| Disk Space | 2 GB    | 5 GB        |
| CPU        | 2 cores | 4+ cores    |

---

## Quick Health Check

Run the diagnostic script to check your system:

```bash
# After cloning the repo
cd darkcoder
npm run doctor
```

Or manually check:

```bash
# Check Node.js version (must be 20+)
node --version

# Check available memory
node -e "console.log('Available heap:', Math.round(require('v8').getHeapStatistics().heap_size_limit / 1024 / 1024), 'MB')"

# Check if you can increase heap
node --max-old-space-size=8192 -e "console.log('8GB heap: OK')"
```

---

## Memory Configuration

### The Problem

DarkCoder processes large security data and AI responses. Without proper memory configuration, you'll see:

```
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory
```

### The Solution

#### Option 1: Environment Variable (Recommended)

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, or `~/.profile`):

```bash
# For bash/zsh
export NODE_OPTIONS="--max-old-space-size=8192"
```

Then reload:

```bash
source ~/.bashrc  # or ~/.zshrc
```

#### Option 2: Per-Command

```bash
NODE_OPTIONS="--max-old-space-size=8192" npm run build
NODE_OPTIONS="--max-old-space-size=8192" npm start
```

#### Option 3: npm config

```bash
npm config set node-options "--max-old-space-size=8192"
```

### Verify Memory Configuration

```bash
node -e "const v8 = require('v8'); console.log('Heap limit:', Math.round(v8.getHeapStatistics().heap_size_limit / 1024 / 1024), 'MB')"
```

Expected output: `Heap limit: 8192 MB` (or higher)

---

## Settings Configuration

### User Settings File

DarkCoder stores user preferences in `~/.qwen/settings.json`. This file is **NOT in Git** — each developer creates their own.

**Quick setup:**

```bash
# Create directory
mkdir -p ~/.qwen

# Copy example template
cp docs/examples/settings.example.json ~/.qwen/settings.json

# Edit with your preferences
nano ~/.qwen/settings.json
```

For detailed settings guide, see [SETTINGS_GUIDE.md](./SETTINGS_GUIDE.md).

---

## API Keys Setup

### Required API Keys

DarkCoder supports multiple AI providers. You need at least ONE:

| Provider   | Environment Variable | Get Key                                                               |
| ---------- | -------------------- | --------------------------------------------------------------------- |
| Anthropic  | `ANTHROPIC_API_KEY`  | [console.anthropic.com](https://console.anthropic.com/)               |
| OpenAI     | `OPENAI_API_KEY`     | [platform.openai.com](https://platform.openai.com/)                   |
| Google     | `GOOGLE_API_KEY`     | [aistudio.google.com](https://aistudio.google.com/)                   |
| Qwen       | `DASHSCOPE_API_KEY`  | [dashscope.console.aliyun.com](https://dashscope.console.aliyun.com/) |
| DeepSeek   | `DEEPSEEK_API_KEY`   | [platform.deepseek.com](https://platform.deepseek.com/)               |
| OpenRouter | `OPENROUTER_API_KEY` | [openrouter.ai](https://openrouter.ai/)                               |

### Optional Security Tool API Keys

For full security tool functionality:

| Tool       | Environment Variable                 | Get Key                                         |
| ---------- | ------------------------------------ | ----------------------------------------------- |
| Shodan     | `SHODAN_API_KEY`                     | [account.shodan.io](https://account.shodan.io/) |
| Censys     | `CENSYS_API_ID`, `CENSYS_API_SECRET` | [search.censys.io](https://search.censys.io/)   |
| VirusTotal | `VIRUSTOTAL_API_KEY`                 | [virustotal.com](https://www.virustotal.com/)   |
| URLScan    | `URLSCAN_API_KEY`                    | [urlscan.io](https://urlscan.io/)               |

### Setup Methods

#### Method 1: .env file (Development)

Create `.env` in project root:

```bash
# AI Provider (choose one or more)
ANTHROPIC_API_KEY=sk-ant-xxxxx
OPENAI_API_KEY=sk-xxxxx
GOOGLE_API_KEY=AIzaxxxxx

# Security Tools (optional)
SHODAN_API_KEY=xxxxx
VIRUSTOTAL_API_KEY=xxxxx
```

#### Method 2: Shell Export (Session)

```bash
export ANTHROPIC_API_KEY="sk-ant-xxxxx"
```

#### Method 3: System Environment (Persistent)

Add to `~/.bashrc` or `~/.zshrc`:

```bash
export ANTHROPIC_API_KEY="sk-ant-xxxxx"
```

---

## Security Tools Installation

DarkCoder integrates with many security tools. **These are OPTIONAL** - the CLI will gracefully handle missing tools.

### Tool Installation Matrix

| Tool      | Purpose               | Installation                                                            |
| --------- | --------------------- | ----------------------------------------------------------------------- |
| nuclei    | Vulnerability scanner | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| ffuf      | Web fuzzer            | `go install github.com/ffuf/ffuf/v2@latest`                             |
| nmap      | Network scanner       | `sudo apt install nmap` / `brew install nmap`                           |
| radare2   | Reverse engineering   | `sudo apt install radare2` / `brew install radare2`                     |
| rizin     | RE framework          | `sudo apt install rizin` / `brew install rizin`                         |
| binwalk   | Firmware analysis     | `sudo apt install binwalk` / `brew install binwalk`                     |
| strings   | Binary analysis       | Pre-installed on most systems                                           |
| file      | File type detection   | Pre-installed on most systems                                           |
| objdump   | Binary disassembly    | `sudo apt install binutils` / `brew install binutils`                   |
| ROPgadget | ROP chain finder      | `pip install ROPgadget`                                                 |

### Quick Install Scripts

#### Ubuntu/Debian

```bash
# Essential tools
sudo apt update
sudo apt install -y nmap radare2 binwalk binutils

# Go-based tools (requires Go 1.21+)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

# Python tools
pip install ROPgadget
```

#### macOS

```bash
# Using Homebrew
brew install nmap radare2 binwalk binutils go

# Go-based tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

# Python tools
pip3 install ROPgadget
```

#### Windows (WSL2 Recommended)

```bash
# In WSL2 Ubuntu
sudo apt update
sudo apt install -y nmap radare2 binwalk binutils
```

### Verify Tools

```bash
# Run the diagnostic script
npm run doctor

# Or check manually
which nuclei ffuf nmap radare2 binwalk
```

---

## Common Issues & Solutions

### Issue 1: Heap Out of Memory

**Symptoms:**

```
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory
```

**Solution:**

```bash
# Set Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=8192"

# Verify
node -e "console.log(require('v8').getHeapStatistics().heap_size_limit / 1024 / 1024, 'MB')"
```

---

### Issue 2: API Error 400 - Context Length Exceeded

**Symptoms:**

```
API Error: 400 - maximum context length is 131072 tokens
```

**Solution:**
This is handled automatically in v0.7.0+. If you still see this:

1. Use `/compress` command to compress conversation history
2. Use `/clear` to start fresh
3. Use `/stats` to check token usage

---

### Issue 3: Tool Not Found Warnings

**Symptoms:**

```
Warning: nuclei not found in PATH
Warning: ffuf not found in PATH
```

**Solution:**
These are **non-blocking warnings**. DarkCoder works without these tools, but with reduced functionality. Install tools as needed (see [Security Tools Installation](#security-tools-installation)).

---

### Issue 4: API Key Not Set

**Symptoms:**

```
Error: No API key found for provider
```

**Solution:**

```bash
# Check which keys are set
env | grep -E "(ANTHROPIC|OPENAI|GOOGLE|DEEPSEEK|DASHSCOPE)_API_KEY"

# Set at least one
export ANTHROPIC_API_KEY="your-key-here"
```

---

### Issue 5: Build Fails with TypeScript Errors

**Symptoms:**

```
error TS2307: Cannot find module
```

**Solution:**

```bash
# Clean and rebuild
npm run clean
npm install
npm run build
```

---

### Issue 6: Permission Denied on Scripts

**Symptoms:**

```
EACCES: permission denied, open '/path/to/file'
```

**Solution:**

```bash
chmod +x scripts/*.sh
```

---

### Issue 7: Rate Limiting

**Symptoms:**

```
Error: 429 Too Many Requests
```

**Solution:**

1. Wait a few minutes and retry
2. Consider using a different AI provider
3. Check your API tier/plan limits

---

## Platform-Specific Notes

### Linux

```bash
# Ensure you have build essentials
sudo apt install build-essential

# For native modules
sudo apt install python3 make g++
```

### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Windows

**Recommended:** Use WSL2 with Ubuntu

```powershell
# Install WSL2
wsl --install -d Ubuntu

# Then follow Linux instructions inside WSL2
```

**Native Windows (Limited Support):**

- Some security tools may not work
- Use Git Bash or PowerShell
- Node.js for Windows required

---

## Getting Help

1. **Run diagnostics:** `npm run doctor`
2. **Check logs:** Look in `~/.darkcoder/logs/`
3. **GitHub Issues:** [Report a bug](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
4. **Documentation:** See [docs/](./docs/) folder

---

## Quick Start Checklist

- [ ] Node.js 20+ installed
- [ ] Memory configured (`NODE_OPTIONS="--max-old-space-size=8192"`)
- [ ] At least one AI API key set
- [ ] `npm install` completed
- [ ] `npm run build` successful
- [ ] `npm run doctor` shows no critical errors

Once all checks pass, you're ready to develop! 🚀
