# DarkCoder CLI - Complete Setup & Usage Guide

<p align="center">
  <img src="https://img.shields.io/badge/DarkCoder-v0.6.0-red.svg" alt="version">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="license">
  <img src="https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg" alt="node version">
</p>

**DarkCoder** is a multi-provider AI-powered CLI designed for security researchers, penetration testers, and cybersecurity professionals. This guide covers everything from installation to advanced usage.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Authentication & Provider Setup](#authentication--provider-setup)
4. [API Keys Configuration](#api-keys-configuration)
5. [Basic Usage](#basic-usage)
6. [CLI Commands Reference](#cli-commands-reference)
7. [Security Tools](#security-tools)
8. [MCP Server Integration](#mcp-server-integration)
9. [Configuration Files](#configuration-files)
10. [Keyboard Shortcuts](#keyboard-shortcuts)
11. [Troubleshooting](#troubleshooting)
12. [Advanced Usage](#advanced-usage)

---

## System Requirements

| Component            | Requirement                                   |
| -------------------- | --------------------------------------------- |
| **Node.js**          | v20.0.0 or higher                             |
| **Operating System** | Linux, macOS, or Windows (WSL recommended)    |
| **RAM**              | 4GB minimum, 8GB recommended                  |
| **Disk Space**       | 500MB for installation                        |
| **Network**          | Internet connection required for AI providers |

### Verify Node.js Version

```bash
node --version
# Should output v20.x.x or higher
```

---

## Installation

### Method 1: Install from npm (Recommended)

```bash
# Install globally
npm install -g @darkcoder/darkcoder@latest

# Verify installation
darkcoder --version
```

### Method 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI/darkcoder

# Install dependencies
npm install

# Build the project
npm run build

# Install globally
npm install -g .

# Verify installation
darkcoder --version
```

### Method 3: Docker Installation

```bash
# Clone the repository first
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI/darkcoder

# Build the Docker image locally
docker build -t darkcoder:latest .

# Run interactively
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENAI_API_KEY="your_key" \
  darkcoder:latest

# Run with custom settings
docker run -it --rm \
  -v $(pwd):/workspace \
  -v ~/.qwen:/root/.qwen \
  darkcoder:latest

# (Optional) Tag and push to GitHub Container Registry
docker tag darkcoder:latest ghcr.io/infosec-littlehunter/darkcoder:latest
docker push ghcr.io/infosec-littlehunter/darkcoder:latest
```

### Method 4: Build from Makefile

```bash
cd darkcoder
make build
make install
```

---

## Authentication & Provider Setup

DarkCoder supports multiple AI providers. Choose one or configure multiple for flexibility.

### Option 1: OpenAI (GPT-4, GPT-3.5)

```bash
# Set environment variables
export OPENAI_API_KEY="sk-your-api-key-here"
export OPENAI_MODEL="gpt-4"  # Optional, defaults to gpt-4

# Or use .env file in your project
echo 'OPENAI_API_KEY=sk-your-api-key-here' >> .env
echo 'OPENAI_MODEL=gpt-4' >> .env
```

### Option 2: Qwen/DashScope (Alibaba Cloud)

```bash
# For DashScope API
export DASHSCOPE_API_KEY="sk-your-dashscope-key"

# Or configure in settings.json
```

### Option 3: DeepSeek

```bash
export OPENAI_API_KEY="your-deepseek-key"
export OPENAI_BASE_URL="https://api.deepseek.com/v1"
export OPENAI_MODEL="deepseek-chat"
```

### Option 4: Anthropic (Claude)

```bash
export ANTHROPIC_API_KEY="your-anthropic-key"
export OPENAI_BASE_URL="https://api.anthropic.com/v1"
export OPENAI_MODEL="claude-3-opus-20240229"
```

### Option 5: Local LLM (Ollama, LM Studio)

```bash
# For Ollama
export OPENAI_BASE_URL="http://localhost:11434/v1"
export OPENAI_API_KEY="ollama"  # Any non-empty string
export OPENAI_MODEL="llama3.1"

# For LM Studio
export OPENAI_BASE_URL="http://localhost:1234/v1"
export OPENAI_API_KEY="lm-studio"
export OPENAI_MODEL="local-model"
```

### Provider Configuration via Settings File

Create or edit `~/.qwen/settings.json`:

```json
{
  "security": {
    "auth": {
      "selectedType": "openai",
      "apiKey": "$OPENAI_API_KEY"
    }
  },
  "model": {
    "name": "gpt-4",
    "generationConfig": {
      "baseUrl": "https://api.openai.com/v1"
    }
  }
}
```

---

## API Keys Configuration

DarkCoder integrates with multiple security platforms. Configure API keys for full functionality.

### Environment Variables Method

Add to your shell profile (`~/.bashrc`, `~/.zshrc`):

```bash
# AI Provider
export OPENAI_API_KEY="your_openai_key"

# Security Tools
export SHODAN_API_KEY="your_shodan_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
export URLSCAN_API_KEY="your_urlscan_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"

# Bug Bounty Platforms
export HACKERONE_API_USERNAME="your_h1_username"
export HACKERONE_API_TOKEN="your_h1_token"
export BUGCROWD_API_TOKEN="your_bugcrowd_token"
export INTIGRITI_API_TOKEN="your_intigriti_token"
export IMMUNEFI_API_TOKEN="your_immunefi_token"

# Web Search
export TAVILY_API_KEY="your_tavily_key"
export GOOGLE_API_KEY="your_google_key"
export GOOGLE_CSE_ID="your_cse_id"
```

### Settings File Method

Create `~/.qwen/settings.json`:

```json
{
  "advanced": {
    "shodanApiKey": "your_shodan_key",
    "censysApiId": "your_censys_id",
    "censysApiSecret": "your_censys_secret",
    "urlscanApiKey": "your_urlscan_key",
    "virusTotalApiKey": "your_virustotal_key",
    "hackeroneUsername": "your_h1_username",
    "hackeroneToken": "your_h1_token"
  }
}
```

### Using the Built-in API Key Manager

```bash
darkcoder

# Then use natural language:
darkcoder> Set my Shodan API key to abc123xyz
darkcoder> Check API key status
darkcoder> List all configured API keys
```

Or use JSON format:

```json
{ "operation": "set", "tool": "shodan", "apiKey": "your_key" }
{ "operation": "set", "tool": "censys", "apiId": "id", "apiSecret": "secret" }
{ "operation": "status" }
```

### API Key Sources

Get API keys from these providers:

| Tool           | Get API Key                                |
| -------------- | ------------------------------------------ |
| **Shodan**     | https://account.shodan.io/                 |
| **Censys**     | https://search.censys.io/account/api       |
| **URLScan**    | https://urlscan.io/user/profile/           |
| **VirusTotal** | https://www.virustotal.com/gui/user/apikey |
| **HackerOne**  | https://hackerone.com/settings/api_token   |
| **Bugcrowd**   | https://bugcrowd.com/settings/api          |
| **Tavily**     | https://app.tavily.com/home                |

---

## Basic Usage

### Starting DarkCoder

```bash
# Interactive mode (recommended)
darkcoder

# With initial prompt
darkcoder "Scan 8.8.8.8 with Shodan"

# Non-interactive mode (single task)
darkcoder -p "Find subdomains for example.com"

# With specific working directory
darkcoder -d /path/to/project

# Debug mode
darkcoder --debug

# With JSON output
darkcoder --json -p "List CVEs for Apache 2.4"
```

### Interactive Session Examples

```bash
darkcoder

# You'll see:
# 🔒 DarkCoder v0.4.0 - AI Security Operations Agent
# Type your request or use /help for commands

darkcoder> Perform reconnaissance on target.com

darkcoder> Find open ports on 192.168.1.0/24

darkcoder> Search for SQL injection vulnerabilities in this code
# Then paste or reference your code

darkcoder> Generate a Python reverse shell

darkcoder> Find bug bounty programs for crypto companies
```

### Piping Input

```bash
# Pipe file content
cat suspicious_file.log | darkcoder "Analyze this log for IOCs"

# Pipe command output
nmap -sV 192.168.1.1 | darkcoder "Summarize these scan results"

# From clipboard (Linux)
xclip -selection clipboard -o | darkcoder "Explain this code"
```

---

## CLI Commands Reference

### Slash Commands (`/`)

| Command              | Description                          |
| -------------------- | ------------------------------------ |
| `/help` or `/?`      | Display help information             |
| `/clear` or `/reset` | Clear conversation and start fresh   |
| `/model`             | Switch AI model for current session  |
| `/provider`          | Switch AI provider                   |
| `/mcp`               | List MCP servers and tools           |
| `/mcp desc`          | Show detailed MCP tool descriptions  |
| `/memory show`       | Display loaded context memory        |
| `/memory add <text>` | Add to AI's memory                   |
| `/memory refresh`    | Reload context files                 |
| `/settings`          | Open settings editor                 |
| `/summary`           | Generate project summary             |
| `/compress`          | Compress chat context to save tokens |
| `/copy`              | Copy last output to clipboard        |
| `/restore`           | Restore files to checkpoint          |
| `/extensions`        | List active extensions               |
| `/bug`               | File a bug report                    |

### At Commands (`@`)

| Command        | Description                    |
| -------------- | ------------------------------ |
| `@file.txt`    | Include file content in prompt |
| `@folder/`     | Include folder contents        |
| `@*.py`        | Include all Python files       |
| `@https://url` | Fetch and include URL content  |

### Bang Commands (`!`)

| Command         | Description                    |
| --------------- | ------------------------------ |
| `!ls`           | Execute shell command directly |
| `!pwd`          | Show current directory         |
| `!cat file.txt` | Display file contents          |

---

## Security Tools

### Shodan Integration

```bash
# Host lookup
darkcoder> Check Shodan info for 8.8.8.8

# Search query
darkcoder> Search Shodan for Apache servers in Germany

# JSON format
{ "tool": "shodan", "searchType": "host", "ip": "8.8.8.8", "history": true }
{ "tool": "shodan", "searchType": "search", "query": "apache country:DE" }
```

### Censys Integration

```bash
# Host search
darkcoder> Find hosts with open port 3389 on Censys

# Certificate search
darkcoder> Search Censys for certificates with "admin" in title

# JSON format
{ "tool": "censys", "searchType": "hosts", "query": "services.port: 3389" }
{ "tool": "censys", "searchType": "certificates", "query": "parsed.subject.common_name: admin" }
```

### URLScan Integration

```bash
# Scan a URL
darkcoder> Scan https://suspicious-site.com with URLScan

# Search existing scans
darkcoder> Search URLScan for scans of example.com

# JSON format
{ "tool": "urlscan", "searchType": "scan", "url": "https://example.com", "visibility": "public" }
{ "tool": "urlscan", "searchType": "search", "query": "domain:example.com" }
```

### Wayback Machine

```bash
# Find historical URLs
darkcoder> Get Wayback URLs for target.com

# Find JavaScript files
darkcoder> Find archived JS files for example.com

# JSON format
{ "tool": "wayback_machine", "target": "example.com", "searchType": "urls", "filter": "js" }
```

### CVE & Security Intelligence

```bash
# CVE lookup
darkcoder> Get details for CVE-2024-1234

# Exploit search
darkcoder> Find exploits for Apache Log4j

# JSON format
{ "tool": "security_intel", "searchType": "cve", "cveId": "CVE-2024-1234" }
{ "tool": "security_intel", "searchType": "exploit", "query": "log4j" }
```

### Bug Bounty Platform Integration

```bash
# Search programs
darkcoder> Find bug bounty programs for blockchain

# Platform-specific search
darkcoder> Search HackerOne for programs with crypto scope

# JSON format
{ "tool": "bug_bounty", "operation": "search", "query": "blockchain", "platform": "immunefi" }
{ "tool": "bug_bounty", "operation": "platforms", "platform": "hackerone" }
```

---

## MCP Server Integration

### What is MCP?

Model Context Protocol (MCP) allows DarkCoder to connect to external tools and services, extending its capabilities beyond built-in features.

### Configuring MCP Servers

Add to `~/.qwen/settings.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/home/user/projects"
      ],
      "trust": true
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "$GITHUB_TOKEN"
      }
    },
    "custom-security": {
      "command": "python",
      "args": ["./my-security-mcp/server.py"],
      "cwd": "/home/user/tools",
      "timeout": 60000
    }
  }
}
```

### SSE Transport (Remote Servers)

```json
{
  "mcpServers": {
    "remote-tools": {
      "url": "https://mcp.example.com/sse",
      "transport": "sse",
      "headers": {
        "Authorization": "Bearer $MCP_TOKEN"
      }
    }
  }
}
```

### HTTP Transport with OAuth

```json
{
  "mcpServers": {
    "oauth-server": {
      "url": "https://secure-mcp.example.com",
      "transport": "http",
      "authorizationToken": "$OAUTH_TOKEN"
    }
  }
}
```

### Managing MCP Servers

```bash
# List all MCP servers
darkcoder> /mcp

# Show tool descriptions
darkcoder> /mcp desc

# Show tool schemas
darkcoder> /mcp schema
```

---

## Configuration Files

### Directory Structure

```
~/.qwen/
├── settings.json          # User settings
├── PROJECT_SUMMARY.md     # Generated summaries
└── memory/               # Saved memories

./project/
├── .qwen/
│   ├── settings.json     # Project settings (overrides user)
│   └── QWEN.md          # Project context file
├── QWEN.md              # Alternative context location
└── .env                 # Environment variables
```

### Complete settings.json Example

```json
{
  "general": {
    "vimMode": false,
    "preferredEditor": "code",
    "checkpointing": {
      "enabled": true
    }
  },
  "ui": {
    "theme": "dark",
    "hideBanner": false,
    "hideTips": false
  },
  "output": {
    "format": "text"
  },
  "security": {
    "auth": {
      "selectedType": "openai",
      "apiKey": "$OPENAI_API_KEY"
    }
  },
  "model": {
    "name": "gpt-4",
    "generationConfig": {
      "baseUrl": "https://api.openai.com/v1",
      "temperature": 0.7,
      "maxOutputTokens": 8192
    }
  },
  "advanced": {
    "shodanApiKey": "$SHODAN_API_KEY",
    "censysApiId": "$CENSYS_API_ID",
    "censysApiSecret": "$CENSYS_API_SECRET",
    "urlscanApiKey": "$URLSCAN_API_KEY"
  },
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
      "trust": true
    }
  },
  "mcp": {
    "allowed": [],
    "excluded": []
  }
}
```

### Context Files (QWEN.md)

Create a `QWEN.md` in your project root to provide persistent context:

```markdown
# Project Context

## Overview

This is a security testing project for ACME Corp.

## Scope

- Target: \*.acme.com
- Excluded: api.acme.com, admin.acme.com

## Notes

- Always use passive reconnaissance first
- Document all findings in ./reports/

## Custom Commands

- Run `make scan` to start automated scanning
```

---

## Keyboard Shortcuts

| Shortcut  | Action                          |
| --------- | ------------------------------- |
| `Ctrl+C`  | Cancel current operation        |
| `Ctrl+D`  | Exit DarkCoder                  |
| `Ctrl+L`  | Clear screen (same as `/clear`) |
| `Ctrl+T`  | Toggle MCP tool descriptions    |
| `Ctrl+R`  | Search command history          |
| `Tab`     | Auto-complete commands          |
| `↑` / `↓` | Navigate command history        |
| `Ctrl+A`  | Move to beginning of line       |
| `Ctrl+E`  | Move to end of line             |

---

## Troubleshooting

### Common Issues

#### "API key not found" Error

```bash
# Check if key is set
echo $OPENAI_API_KEY

# Verify in DarkCoder
darkcoder
> Check API key status

# Reset and reconfigure
export OPENAI_API_KEY="your_key"
```

#### "Connection refused" for AI Provider

```bash
# Test API endpoint
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  https://api.openai.com/v1/models

# For custom endpoints
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  $OPENAI_BASE_URL/models
```

#### MCP Server Not Connecting

```bash
# Check if command exists
which npx

# Test MCP server manually
npx -y @modelcontextprotocol/server-filesystem /tmp

# Check logs
darkcoder --debug
> /mcp
```

#### Tool Execution Failures

```bash
# Run with debug mode
darkcoder --debug

# Check tool-specific API
curl "https://api.shodan.io/api-info?key=$SHODAN_API_KEY"
```

#### Installation Issues

```bash
# Clear npm cache
npm cache clean --force

# Remove and reinstall
npm uninstall -g @darkcoder/darkcoder
npm install -g @darkcoder/darkcoder@latest

# Check Node.js version
node --version  # Must be >= 20.0.0
```

### Debug Mode

```bash
# Enable full debug output
darkcoder --debug

# Debug specific components
DEBUG=darkcoder:* darkcoder

# Save debug logs
darkcoder --debug 2>&1 | tee debug.log
```

---

## Advanced Usage

### Non-Interactive Scripting

```bash
#!/bin/bash
# security-scan.sh

TARGET="$1"

# Subdomain enumeration
darkcoder -p "Find all subdomains for $TARGET using passive methods" --json > subdomains.json

# Port scanning
darkcoder -p "Scan top 1000 ports on $TARGET" --json > ports.json

# Technology detection
darkcoder -p "Identify technologies used by $TARGET" --json > tech.json
```

### Automation with JSON Output

```bash
# Get structured output
darkcoder --json -p "Search Shodan for port:22 country:US" | jq '.results[]'

# Parse and process
darkcoder --json -p "Get CVE details for CVE-2024-1234" | \
  jq -r '.cvss_score, .description'
```

### Multi-Directory Projects

```bash
# Add multiple directories
darkcoder
> /directory add ../other-project,/home/user/shared-libs

# Show all directories
> /directory show
```

### Session Checkpointing

```bash
# Enable checkpointing
darkcoder --checkpointing

# Or in settings.json
{
  "general": {
    "checkpointing": {
      "enabled": true
    }
  }
}

# Restore to checkpoint
> /restore
```

### Custom Tool Development

Create custom tools via MCP:

```python
# my_security_tool.py
from mcp.server import Server
from mcp.types import Tool

app = Server("my-security-tools")

@app.tool()
async def custom_scanner(target: str, port_range: str = "1-1000"):
    """Custom network scanner with advanced features"""
    # Your implementation
    return {"results": scan_results}

if __name__ == "__main__":
    app.run()
```

Register in settings:

```json
{
  "mcpServers": {
    "my-tools": {
      "command": "python",
      "args": ["my_security_tool.py"]
    }
  }
}
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                    DarkCoder Quick Reference                │
├─────────────────────────────────────────────────────────────┤
│ START:     darkcoder                                        │
│ WITH TASK: darkcoder "your task here"                      │
│ DEBUG:     darkcoder --debug                               │
│ JSON OUT:  darkcoder --json -p "task"                      │
├─────────────────────────────────────────────────────────────┤
│ COMMANDS:  /help  /clear  /model  /mcp  /settings          │
│ INCLUDE:   @file.txt  @folder/  @https://url               │
│ SHELL:     !command                                         │
├─────────────────────────────────────────────────────────────┤
│ SHORTCUTS: Ctrl+C=Cancel  Ctrl+L=Clear  Ctrl+D=Exit        │
├─────────────────────────────────────────────────────────────┤
│ CONFIG:    ~/.qwen/settings.json                           │
│ PROJECT:   ./.qwen/settings.json                           │
│ CONTEXT:   ./QWEN.md                                       │
├─────────────────────────────────────────────────────────────┤
│ SECURITY TOOLS:                                             │
│   shodan, censys, urlscan, wayback_machine                 │
│   security_intel, bug_bounty, api_key_manager              │
└─────────────────────────────────────────────────────────────┘
```

---

## Getting Help

- **Documentation**: [docs/](./docs/)
- **Issues**: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
- **In-CLI Help**: Type `/help` in DarkCoder

---

<p align="center">
  <strong>DarkCoder</strong> - AI-Powered Security Operations<br>
  <sub>Built for security professionals who demand results</sub>
</p>
