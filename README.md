# DarkCoder: AI Security Operations Agent

<p align="center">
  <img src="docs/assets/DarkcoderV1.png" alt="DarkCoder Logo" width="600">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.7.0-blue.svg" alt="version">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="license">
  <img src="https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg" alt="node version">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20WSL-blue.svg" alt="platform">
  <img src="https://img.shields.io/badge/AI_Models-29+-purple.svg" alt="AI models">
  <img src="https://img.shields.io/badge/Security_Tools-58+-red.svg" alt="Security tools">
  <img src="https://img.shields.io/badge/CVE_Intelligence-Live-red.svg" alt="CVE intelligence">
  <img src="https://img.shields.io/badge/Memory_Safe-5_Layer_Defense-green.svg" alt="Memory safe">
</p>

---

**DarkCoder** is a multi-provider AI assistant built for security researchers, penetration testers, and cybersecurity professionals. It combines advanced AI capabilities with specialized security tools for offensive and defensive operations.

> ⚡ **No lock-in. No limits. No corporate constraints.**

## 📋 Table of Contents

- [Why DarkCoder?](#-why-darkcoder)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#️-configuration)
- [Usage Examples](#-usage-examples)
- [Tools Reference](#-tool-reference)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Documentation](#-documentation)
- [License & Disclaimer](#-license--disclaimer)

---

## 🎯 Why DarkCoder?

- **🔒 Security-First Design**: Built from the ground up for cybersecurity operations with specialized tools and workflows
- **🌐 Multi-Provider Support**: Works with OpenAI, Qwen, DashScope, and other AI providers - no vendor lock-in
- **🛠️ Integrated Security Tools**: Built-in Shodan, Censys, URLScan, VirusTotal, bug bounty platforms, and OSINT tools
- **🎯 Predictive Security Operations**: Advanced scenario prediction and autonomous execution capabilities
- **🔧 Extensible Architecture**: Custom tools via MCP (Model Context Protocol) and plugin system
- **💻 Terminal-First Workflow**: Designed for security professionals who live in the terminal

---

## ✨ Features

### 🤖 **Multi-Provider AI Support (29+ Models)**

- **Anthropic Claude**: Claude Sonnet 4.5, Claude 3.5 Haiku, Claude 3.5 Sonnet, Claude 3 Opus
- **OpenAI ChatGPT**: GPT-4o, GPT-4o Mini, o1, o1-mini, o1-pro, o3, o3-mini
- **Qwen Models**: Qwen3-Coder-Plus, Qwen3-Plus, Qwen3-Max, Qwen3-VL-Max (Vision)
- **Google Gemini**: Gemini 2.5 Pro, Gemini 2.5 Flash, Gemini 2.0 Flash
- **DeepSeek**: DeepSeek V3, DeepSeek R1, DeepSeek Coder
- **OpenRouter**: Access 100+ models via single API

### 💰 **Real-Time Cost Tracking**

- Per-session and cumulative cost tracking
- Automatic pricing calculation based on token usage
- Support for all model pricing tiers
- Cost comparison tools for model selection

### 🔒 **Memory Safety & Performance**

- **Multi-Layer Defense System**: Prevents JavaScript heap overflow with 5-tier protection
  - Per-tool input limits (15-50 items based on data complexity)
  - CVE intelligence output constraints (100KB max)
  - Set-based O(1) deduplication (vs O(n²) array operations)
  - Absolute safety limits enforced across all security tools
  - Output truncation as final safeguard
- **Optimized Algorithms**:
  - Early break conditions in all loops
  - Bounded iteration with pre-slicing
  - Memory markers on critical operations
  - No unbounded array growth
- **Production-Ready**: Tested with Node.js --max-old-space-size=8192 memory limits

### 🔍 **OSINT & Reconnaissance**

- **Shodan Integration**: Host discovery, service enumeration, vulnerability scanning
  - **NEW**: Auto-detects software products from services → generates CVE intelligence
  - Memory-optimized product extraction (max 20 products per scan)
- **Censys Integration**: Certificate transparency, asset discovery, attack surface mapping
  - **NEW**: Extracts software versions from service data → correlates with known CVEs
  - Set-based deduplication for efficient processing
- **URLScan.io**: Website analysis, screenshot capture, threat intelligence
- **Wayback Machine**: Historical data, endpoint discovery, subdomain enumeration
- **Security RAG**: Context-aware security knowledge base with MITRE ATT&CK integration

### 🌐 **Web Security Analysis**

- **Web-Tech Detection**: Technology stack fingerprinting (no API required)
  - **NEW**: Version-aware CVE recommendations for web servers, frameworks, CMS
  - Filters critical categories: web-server, framework, cms, programming-language
  - Memory-optimized with max 15 products per scan
- **SSL/TLS Scanner**: Security assessment using testssl.sh
  - **NEW**: Maps vulnerabilities (POODLE, BEAST, DROWN, Heartbleed) → related CVEs
  - Automatic exploit availability checking
  - Memory-limited vulnerability tracking (max 20 per scan)

### 🐛 **Bug Bounty & Platform Integration**

- **HackerOne**: Program search, scope analysis, report templates
- **Bugcrowd**: Platform statistics, program discovery, bounty tracking
- **Intigriti**: European program access, GDPR-compliant workflows
- **Immunefi**: Web3/DeFi security programs, high-value bounty discovery
- **YesWeHack & Synack**: Additional platform support for comprehensive coverage

### 🔐 **Security Intelligence**

- **CVE Lookup**: Real-time vulnerability information with CVSS scoring
- **Exploit Search**: Public exploit/PoC discovery across multiple repositories
- **Threat Intel**: IOC analysis, campaign tracking, actor profiling
- **VirusTotal**: File/URL/domain analysis, malware intelligence
- **AI/LLM Security**: Advanced prompt injection detection, jailbreak prevention, multi-modal attack defense (2025)
  - Modern prompt injection patterns (60-85% success rate mitigation)
  - Sophisticated jailbreaking techniques and countermeasures
  - Multi-modal attack detection (image, audio, document-based)
  - Agent & tool manipulation protection
  - See [AI/LLM Security Guide](docs/AI_LLM_SECURITY_2025.md) for comprehensive defense strategies

### 🆕 **Live Vulnerability Intelligence System** (New!)

- **Real-Time CVE Integration**: Automatically cross-references scan results with live vulnerability databases
  - NVD (National Vulnerability Database)
  - Exploit-DB (20,000+ exploits)
  - VirusTotal threat intelligence
  - Shodan vulnerability data
  - CISA KEV (Known Exploited Vulnerabilities) catalog
  - YARAify malware signatures
- **Enhanced Security Tools with CVE Intelligence**:
  - **Nuclei**: Extracts CVE IDs from 10,000+ scan templates + auto-generates live CVE checks
  - **Shodan**: Maps exposed services → software products → known vulnerabilities
  - **Censys**: Analyzes certificates and services → extracts software versions → CVE correlation
  - **Web-Tech**: Detects web technologies → checks for version-specific vulnerabilities
  - **SSL Scanner**: Maps TLS/SSL weaknesses → related CVE exploits (POODLE, Heartbleed, etc.)
  - **Reverse Engineering**: Integrates 6 live intelligence operations for binary analysis
- **Memory-Optimized Design**: Multi-layer defense system prevents heap overflow
  - Per-tool input limits (15-50 products)
  - Output size constraints (100KB max)
  - Set-based O(1) deduplication
  - Absolute safety limits across all operations
- **Automated Recommendations**: AI generates targeted security commands based on:
  - LLM training data vs current vulnerability landscape comparison
  - Discovered software versions and CVE correlation
  - Live exploit availability and proof-of-concept links
  - Vendor security advisories and patch information

### 🦠 **Malware Analysis**

- **Reverse Engineering Tool**: Comprehensive binary analysis toolkit (20,000+ lines)
  - **NEW**: 6 live intelligence operations integrated:
    - `check_cves`: Query live CVE databases for vulnerabilities
    - `check_exploits`: Search Exploit-DB for proof-of-concepts
    - `threat_intel`: VirusTotal + Shodan threat intelligence
    - `check_yara_rules`: YARAify malware signature matching
    - `vendor_advisories`: Vendor security bulletins
    - `recent_attacks`: CISA KEV catalog of exploited vulnerabilities
  - Manual analysis emphasis with automated intelligence support
  - Memory-safe processing with absolute limits
- **Cuckoo Sandbox**: Automated dynamic malware analysis (self-hosted)
  - File and URL submission
  - Behavioral analysis (process, network, registry, file system)
  - Memory dumps and YARA signature matching
  - Full PCAP network capture
  - Detailed analysis reports with IOC extraction
- **VirusTotal**: Multi-AV scanning (70+ engines)
  - File, URL, domain, and IP analysis
  - Hash reputation lookup
  - Behavioral analysis reports
- **YARAify**: YARA-based malware scanning
  - File submission for YARA rule matching
  - Hash lookup with known malware families
  - YARA rule search across malware database
  - Task status monitoring

### 🛡️ **Defensive Security**

- **SOC Operations**: Log analysis, incident response automation
- **Threat Hunting**: Behavioral analytics, anomaly detection
- **MITRE ATT&CK Mapping**: TTP correlation, attack pattern analysis
- **Security RAG**: Knowledge base for security frameworks and best practices

### ⚡ **AI-Powered Workflows**

- **Predictive Execution**: Think 3+ steps ahead with scenario planning
- **Autonomous Operations**: Complete task execution without constant supervision
- **Multi-Model Support**: Switch between AI providers based on task requirements
- **Tool Orchestration**: Coordinate multiple security tools for complex operations
- **Edit Request with Feedback**: Redirect AI operations mid-execution with custom guidance

---

## 🚀 Quick Start

### Option 1: Docker (Fastest - Recommended)

```bash
# Clone and build
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
docker build -t darkcoder .

# Run with OpenRouter (supports 100+ models including free ones)
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY="your_openrouter_key" \
  darkcoder --model google/gemini-2.0-flash-exp:free

# Run with OpenAI
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENAI_API_KEY="your_openai_key" \
  darkcoder --model gpt-4o

# Run with Anthropic Claude (via OpenRouter)
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY="your_openrouter_key" \
  darkcoder --model anthropic/claude-sonnet-4-20250514
```

### Option 2: Build from Source

#### With Node.js (Standard)

```bash
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
npm install
npm run build
cd packages/cli
npm link  # Makes 'darkcoder' command available globally from the CLI workspace
darkcoder --version
```

#### With Bun (3-4x Faster Startup) ⚡

For improved performance, use [Bun](https://bun.sh) instead of Node.js:

```bash
# Install Bun (if not installed)
curl -fsSL https://bun.sh/install | bash

# Clone and build
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
bun install              # 10-20x faster than npm install
bun run build:bun        # 2x faster build
cd packages/cli
npm link
darkcoder --version
```

**Performance gains with Bun:**

- CLI startup: **3-4x faster** (~150ms vs ~500ms)
- Build time: **2x faster** (~8s vs ~15s)
- Memory usage: **25-30% lower**
- I/O operations: **10-30% faster**

See [docs/BUN_SETUP.md](docs/BUN_SETUP.md) for detailed Bun setup and usage.

#### Windows + Bun (Install Flow)

On Windows, avoid bundling during `bun install` due to OS file locking. Use one of these flows:

```bash
# Recommended on Windows
npm install
bun run build:bun

# Or with Bun, skip lifecycle scripts
bun install --ignore-scripts
bun run build:bun
```

Bundling is not run during install. When you need a bundle:

```bash
npm run bundle    # Node
bun run bundle    # Bun
```

Why: Windows may lock `node_modules` while lifecycle scripts run, causing esbuild errors. We’ve limited `prepare` to `husky` only and moved bundling to explicit commands. See troubleshooting: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md#windows--bun-installation).

### Free Models (No Cost!)

Get an API key from [OpenRouter](https://openrouter.ai) and use these free models:

| Model                  | Features                   | Command                                                   |
| ---------------------- | -------------------------- | --------------------------------------------------------- |
| **Gemini 2.0 Flash**   | 1M context, tool support   | `--model google/gemini-2.0-flash-exp:free`                |
| **Qwen 2.5 72B**       | 32K context, tool support  | `--model qwen/qwen-2.5-72b-instruct:free`                 |
| **Llama 3.3 70B**      | 128K context, tool support | `--model meta-llama/llama-3.3-70b-instruct:free`          |
| **Olmo 3.1 32B Think** | Reasoning model, chat only | `--model allenai/olmo-3.1-32b-think:free --disable-tools` |

> **Note:** Some free models don't support tool calling. Use `--disable-tools` flag for chat-only mode.

For detailed setup instructions, see the [Installation](#-installation) section below.

---

## 🚀 Installation

### Prerequisites

- **Docker**: Recommended for quick setup
- **Node.js**: v20.0.0 or higher (for source builds)
- **npm**: v10.0.0 or higher (for source builds)

> Note for Windows users
>
> When using Bun for builds, avoid bundling during `bun install` due to Windows file locking. Use one of these flows:
>
> ```bash
> # Recommended on Windows
> npm install
> bun run build:bun
>
> # Or with Bun, skip lifecycle scripts
> bun install --ignore-scripts
> bun run build:bun
> ```
>
> Bundling is explicit (not run during install):
>
> ```bash
> npm run bundle    # Node
> bun run bundle    # Bun
> ```
>
> See troubleshooting: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md#windows--bun-installation).

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# Build the Docker image
docker build -t darkcoder .

# Run with OpenRouter (100+ models, including free options)
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY="your_key" \
  darkcoder --model google/gemini-2.0-flash-exp:free

# Run with OpenAI
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENAI_API_KEY="your_key" \
  darkcoder --model gpt-4o

# Run with Anthropic Claude (via OpenRouter)
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY="your_key" \
  darkcoder --model anthropic/claude-sonnet-4-20250514

# Run with DeepSeek
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENAI_API_KEY="your_deepseek_key" \
  -e OPENAI_BASE_URL="https://api.deepseek.com/v1" \
  darkcoder --model deepseek-chat

# Run with Local Ollama
docker run -it --rm \
  -v $(pwd):/workspace \
  --network host \
  -e OPENAI_BASE_URL="http://localhost:11434/v1" \
  -e OPENAI_API_KEY="ollama" \
  darkcoder --model llama3.1
```

### Option 2: Build from Source

```bash
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
npm install
npm run build
npm link  # Makes 'darkcoder' command available globally
```

### Memory Configuration Options

DarkCoder provides three memory profiles to match your system resources:

#### Low Memory Systems (4GB RAM)

For systems with limited memory or when running alongside other applications:

```bash
# Build with low memory
NODE_OPTIONS="--max-old-space-size=4096" npm run build

# Run with low memory profile
npm run start:lowmem
# or
NODE_OPTIONS="--max-old-space-size=4096" darkcoder
```

**Recommended for:**

- Systems with 4-8GB RAM
- Virtual machines with memory limits
- Running multiple applications simultaneously
- Basic security scanning and analysis

#### Standard Memory (8GB - Default)

Balanced configuration for most use cases:

```bash
# Build (default)
npm run build

# Run (default)
npm start
# or
darkcoder
```

**Recommended for:**

- Systems with 8-16GB RAM
- General security operations
- Most scanning and analysis tasks
- Standard CVE intelligence operations

#### High Memory Systems (16GB RAM)

For intensive operations and large-scale security analysis:

```bash
# Build with high memory
NODE_OPTIONS="--max-old-space-size=16384" npm run build

# Run with high memory profile
npm run start:highmem
# or
NODE_OPTIONS="--max-old-space-size=16384" darkcoder
```

**Recommended for:**

- Systems with 16GB+ RAM
- Large-scale vulnerability scanning
- Processing extensive CVE datasets
- Multiple concurrent security tool operations
- Heavy OSINT and data correlation tasks

#### Monitoring Memory Usage

Check current memory allocation:

```bash
# Check Node.js heap limit
node -e "console.log('Heap limit:', Math.round(require('v8').getHeapStatistics().heap_size_limit / 1024 / 1024), 'MB')"

# Monitor during build
npm run build  # Shows memory stats during build

# Monitor during runtime
darkcoder --help  # Memory stats shown in debug mode
```

#### Troubleshooting Memory Issues

If you encounter `JavaScript heap out of memory` errors:

1. **Increase heap size**:

   ```bash
   export NODE_OPTIONS="--max-old-space-size=8192"
   ```

2. **Use memory-optimized build**:

   ```bash
   npm run build  # Uses build-with-memory-management.js
   ```

3. **Monitor and adjust**:
   ```bash
   # Check available system memory
   free -h  # Linux
   vm_stat  # macOS
   ```

For detailed memory troubleshooting, see [docs/DEVELOPER_SETUP.md](docs/DEVELOPER_SETUP.md#memory-configuration).

### Verify Installation

```bash
darkcoder --version
darkcoder --help
```

---

## ⚙️ Configuration

### 1. API Keys Configuration

DarkCoder checks for API keys in this priority order:

1. **Environment variables** (highest priority)
2. **Settings file** (`~/.qwen/settings.json`)
3. **API Key Manager** (via tool operations)
4. **Runtime parameters** (lowest priority)

#### Using Environment Variables (Recommended)

```bash
# Shodan
export SHODAN_API_KEY="your_shodan_key"

# Censys
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"

# URLScan
export URLSCAN_API_KEY="your_urlscan_key"

# VirusTotal
export VIRUSTOTAL_API_KEY="your_virustotal_key"

# YARAify (Optional - works without API key for basic lookups)
export YARAIFY_API_KEY="your_yaraify_key"

# Cuckoo Sandbox (Self-hosted)
export CUCKOO_API_URL="http://localhost:8090"
export CUCKOO_API_TOKEN="your_cuckoo_token"

# Bug Bounty Platforms
export HACKERONE_API_USERNAME="your_username"
export HACKERONE_API_TOKEN="your_token"
export BUGCROWD_API_TOKEN="your_bugcrowd_token"
```

#### Using Settings File

Create or edit `~/.qwen/settings.json`:

```json
{
  "advanced": {
    "shodanApiKey": "your_shodan_key",
    "censysApiId": "your_censys_id",
    "censysApiSecret": "your_censys_secret",
    "urlscanApiKey": "your_urlscan_key",
    "virusTotalApiKey": "your_virustotal_key",
    "yaraifyApiKey": "your_yaraify_key",
    "cuckooApiUrl": "http://localhost:8090",
    "cuckooApiToken": "your_cuckoo_token"
  }
}
```

#### Using API Key Manager

```json
{ "operation": "status" }
{ "operation": "set", "tool": "shodan", "apiKey": "your_key" }
{ "operation": "set", "tool": "censys", "apiId": "your_id", "apiSecret": "your_secret" }
```

### 2. AI Provider Configuration

DarkCoder supports **29+ AI models** across multiple providers. Configure your preferred model:

#### Option A: Environment Variables (Quickest)

```bash
# OpenRouter (Recommended - access 100+ models with one API key)
export OPENROUTER_API_KEY="sk-or-..."

# OpenAI / ChatGPT
export OPENAI_API_KEY="sk-..."

# Qwen / DashScope
export DASHSCOPE_API_KEY="sk-..."

# Google Gemini
export GOOGLE_API_KEY="AIza..."
```

#### Option B: Settings File (`~/.qwen/settings.json`)

```json
{
  "model": {
    "name": "google/gemini-2.0-flash-exp:free",
    "disableTools": false
  }
}
```

#### Option C: Command Line (Per-Session)

```bash
# Use specific model
darkcoder --model gpt-4o "Scan target for vulnerabilities"
darkcoder --model anthropic/claude-sonnet-4-20250514 "Analyze this code"

# Use free model with tool support
darkcoder --model google/gemini-2.0-flash-exp:free "Review this code"

# Use model without tool support (chat-only mode)
darkcoder --model allenai/olmo-3.1-32b-think:free --disable-tools
```

#### Supported AI Providers

| Provider       | Models                                           | API Key Variable                     | Tool Support |
| -------------- | ------------------------------------------------ | ------------------------------------ | ------------ |
| **OpenRouter** | 100+ models (Claude, GPT, Llama, Gemini, etc.)   | `OPENROUTER_API_KEY`                 | Most models  |
| Anthropic      | Claude Sonnet 4.5, 3.5 Sonnet, 3 Opus, 3.5 Haiku | Via OpenRouter                       | ✅ Yes       |
| OpenAI         | GPT-4o, GPT-4, o1, o1-mini, o3, o3-mini          | `OPENAI_API_KEY`                     | ✅ Yes       |
| DeepSeek       | DeepSeek-V3, DeepSeek-Coder, DeepSeek-R1         | `OPENAI_API_KEY` + `OPENAI_BASE_URL` | ✅ Yes       |
| Qwen           | Qwen3-Coder-Plus, Qwen3-Plus, Qwen3-Max          | `DASHSCOPE_API_KEY`                  | ✅ Yes       |
| Google         | Gemini 2.5 Pro, Gemini 2.0 Flash                 | `GOOGLE_API_KEY`                     | ✅ Yes       |
| Local          | Ollama, LM Studio (any OpenAI-compatible)        | `OPENAI_BASE_URL`                    | Varies       |

#### Free Models on OpenRouter

| Model                                    | Context     | Tool Support | Usage                                   |
| ---------------------------------------- | ----------- | ------------ | --------------------------------------- |
| `google/gemini-2.0-flash-exp:free`       | 1M tokens   | ✅ Yes       | Best free option with full capabilities |
| `qwen/qwen-2.5-72b-instruct:free`        | 32K tokens  | ✅ Yes       | Good for coding tasks                   |
| `meta-llama/llama-3.3-70b-instruct:free` | 128K tokens | ✅ Yes       | Open source, strong performance         |
| `allenai/olmo-3.1-32b-think:free`        | 32K tokens  | ❌ No        | Use with `--disable-tools`              |

#### The `--disable-tools` Flag

Some models (especially free/open-source ones) don't support function/tool calling. Use the `--disable-tools` flag to run in chat-only mode:

```bash
darkcoder --model allenai/olmo-3.1-32b-think:free --disable-tools
```

**With tools disabled:**

- ✅ Chat and conversation works
- ✅ Ask questions, get explanations
- ❌ No file editing
- ❌ No command execution
- ❌ No code search or security tools
  | Custom | Any OpenAI-compatible API (Ollama, LM Studio, etc.) | `OPENAI_BASE_URL` |

#### DeepSeek Models

```bash
export OPENAI_API_KEY="your_deepseek_api_key"
export OPENAI_BASE_URL="https://api.deepseek.com/v1"
darkcoder -m deepseek-chat "Your prompt"        # DeepSeek-V3
darkcoder -m deepseek-coder "Your prompt"       # Code-specialized
darkcoder -m deepseek-reasoner "Your prompt"    # DeepSeek-R1 reasoning
```

#### Local Models (Ollama, LM Studio)

```bash
# For Ollama
export OPENAI_BASE_URL="http://localhost:11434/v1"
export OPENAI_API_KEY="ollama"  # Any non-empty string works
darkcoder -m llama3.1 "Your prompt"

# For LM Studio
export OPENAI_BASE_URL="http://localhost:1234/v1"
export OPENAI_API_KEY="lm-studio"
darkcoder -m local-model "Your prompt"
```

---

## 🦠 Cuckoo Sandbox Setup & Integration

Cuckoo Sandbox provides automated dynamic malware analysis with behavioral monitoring, network capture, and IOC extraction. DarkCoder integrates seamlessly with self-hosted Cuckoo instances.

### Quick Setup (Docker - Recommended)

**1. Deploy Cuckoo Sandbox:**

```bash
# Navigate to docker directory
cd /path/to/darkcoder/docker/cuckoo

# Start Cuckoo services
docker-compose up -d

# Wait for initialization (1-2 minutes)
docker logs -f cuckoo-sandbox

# Verify API is running
curl http://localhost:8090/cuckoo/status
```

**2. Configure DarkCoder:**

Add to environment variables:

```bash
export CUCKOO_API_URL="http://localhost:8090"
export CUCKOO_API_TOKEN="your-secure-token"
```

Or add to `~/.qwen/settings.json`:

```json
{
  "advanced": {
    "cuckooApiUrl": "http://localhost:8090",
    "cuckooApiToken": "your-secure-token"
  }
}
```

**3. Test Integration:**

```bash
darkcoder
> Check Cuckoo status
```

Expected output:

```
✅ Cuckoo Sandbox Status
Status: Online
API URL: http://localhost:8090
Available Machines: 2
Pending Tasks: 0
```

### Installation Methods

#### Method 1: Docker (Recommended)

**Pros:**

- ✅ Easy setup (5-10 minutes)
- ✅ Isolated environment
- ✅ Pre-configured VMs
- ✅ Quick updates

**Setup:**

```bash
# Clone or use provided docker-compose.yml
git clone https://github.com/blacktop/docker-cuckoo.git
cd docker-cuckoo

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f
```

**Configuration:**

- Default API endpoint: `http://localhost:8090`
- Default web UI: `http://localhost:8080`
- Default token: Set in `docker-compose.yml`

#### Method 2: Manual Installation (Ubuntu/Debian)

**Pros:**

- ✅ Full control
- ✅ Custom VM configurations
- ✅ Better performance

**Setup:**

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev libffi-dev libssl-dev \
    postgresql postgresql-contrib libpq-dev virtualbox tcpdump apparmor-utils

# Create Cuckoo user
sudo adduser cuckoo
sudo usermod -a -G vboxusers cuckoo

# Install Cuckoo
sudo pip3 install -U cuckoo

# Initialize Cuckoo
cuckoo init
cuckoo community
```

**Configure API:**

Edit `~/.cuckoo/conf/cuckoo.conf`:

```ini
[cuckoo]
api = yes

[resultserver]
ip = 192.168.56.1
port = 2042
```

Edit `~/.cuckoo/conf/reporting.conf`:

```ini
[mongodb]
enabled = yes
host = 127.0.0.1
port = 27017
```

**Start Cuckoo:**

```bash
# Terminal 1: Main instance
cuckoo

# Terminal 2: Web interface
cuckoo web runserver 0.0.0.0:8080

# Terminal 3: API server
cuckoo api --host 0.0.0.0 --port 8090
```

### Setting Up Analysis VMs

**1. Create Windows VM in VirtualBox:**

```bash
# Download Windows 10 ISO
# Create VM with:
# - 2GB RAM
# - 50GB disk
# - Host-only adapter (vboxnet0)
# - NAT adapter
```

**2. Install Guest Tools:**

Inside Windows VM:

- Install Python 3.7+
- Install Office (for document analysis)
- Install Adobe Reader
- Disable Windows Defender
- Disable Windows Firewall
- Disable UAC

**3. Take Snapshot:**

```bash
VBoxManage snapshot "Win10-Cuckoo" take "clean"
```

**4. Configure Cuckoo:**

Edit `~/.cuckoo/conf/virtualbox.conf`:

```ini
[Win10-Cuckoo]
label = Win10-Cuckoo
platform = windows
ip = 192.168.56.101
snapshot = clean
```

### Usage Examples

#### Submit File for Analysis

```bash
darkcoder "Submit /tmp/suspicious.exe to Cuckoo Sandbox"
```

Or use JSON:

```json
{
  "tool": "cuckoo_sandbox",
  "operation": "submit_file",
  "filePath": "/tmp/suspicious.exe",
  "timeout": 120
}
```

#### Submit URL for Analysis

```json
{
  "tool": "cuckoo_sandbox",
  "operation": "submit_url",
  "url": "https://suspicious-site.com/download.exe"
}
```

#### Get Analysis Report

```json
{
  "tool": "cuckoo_sandbox",
  "operation": "get_report",
  "taskId": 123
}
```

#### Check Sandbox Status

```json
{
  "tool": "cuckoo_sandbox",
  "operation": "status"
}
```

### Troubleshooting

**Issue: "Connection refused" Error**

Solutions:

- Verify Cuckoo is running: `curl http://localhost:8090/cuckoo/status`
- Check Docker containers: `docker ps | grep cuckoo`
- Review logs: `docker logs cuckoo-sandbox`

**Issue: VMs Not Starting**

Solutions:

- Verify VirtualBox is installed: `vboxmanage --version`
- Check VM snapshot exists: `VBoxManage snapshot "Win10-Cuckoo" list`
- Ensure vboxnet0 is configured: `VBoxManage list hostonlyifs`

**Issue: Analysis Takes Too Long**

Solutions:

- Increase timeout: `"timeout": 300` (5 minutes)
- Check VM resources (RAM, CPU)
- Reduce analysis depth in Cuckoo config

**Issue: Network Capture Empty**

Solutions:

- Verify tcpdump permissions: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump`
- Check resultserver IP matches host-only adapter
- Ensure VM routing is configured

### Advanced Configuration

**Enable YARA Scanning:**

Edit `~/.cuckoo/conf/processing.conf`:

```ini
[yara]
enabled = yes
rules = /path/to/yara/rules
```

**Memory Dump Analysis:**

Edit `~/.cuckoo/conf/memory.conf`:

```ini
[basic]
enabled = yes

[volatility]
enabled = yes
```

**Custom Reporting:**

```ini
[moloch]
enabled = yes
host = 127.0.0.1
```

### Security Considerations

⚠️ **Important Security Warnings:**

- Run Cuckoo on **isolated network** or dedicated VLAN
- Never connect analysis VMs to production networks
- Use **disposable VMs** for untrusted malware
- Regularly update guest OS and analysis tools
- Monitor Cuckoo host for suspicious activity
- Use strong authentication for API access
- Restrict API access with firewall rules

**Network Isolation:**

```bash
# Create isolated network
sudo iptables -A FORWARD -i vboxnet0 -o eth0 -j DROP
sudo iptables -A FORWARD -i vboxnet0 -o lo -j ACCEPT
```

### Complete Documentation

For comprehensive setup and advanced features, see:

- **[Cuckoo Integration Guide](docs/tools/CUCKOO_INTEGRATION_GUIDE.md)** - Complete setup documentation
- **[Official Cuckoo Docs](https://cuckoo.readthedocs.io/)** - Cuckoo Sandbox documentation

---

## 📖 Usage Examples

### Basic Commands

```bash
# Start interactive session
darkcoder

# Run with a specific task
darkcoder "Scan 8.8.8.8 with Shodan"

# Non-interactive mode
darkcoder -p "Search for Apache servers in the US"

# Enable debug mode
darkcoder --debug

# Install shell completions (bash, zsh, fish)
darkcoder completion --install
```

### Security Tool Examples

#### Shodan Host Reconnaissance

```json
{
  "tool": "shodan",
  "searchType": "host",
  "ip": "8.8.8.8",
  "history": true
}
```

#### Censys Certificate Search

```json
{
  "tool": "censys",
  "searchType": "certificates",
  "query": "services.port: 443 and services.http.response.html_title: admin"
}
```

#### URLScan Website Analysis

```json
{
  "tool": "urlscan",
  "searchType": "scan",
  "url": "https://example.com",
  "visibility": "public"
}
```

#### Bug Bounty Program Search

```json
{
  "tool": "bug_bounty",
  "operation": "search",
  "query": "crypto",
  "platform": "immunefi",
  "limit": 10
}
```

### Reverse Engineering

DarkCoder includes helper workflows for reverse engineering using radare2/rizin, Ghidra headless, binwalk, strings, objdump, and rabin2. It also reduces false positives with explicit verification prompts.

#### Detect Available Tools

Get a report of installed tools and suggested improvements. This helps DarkCoder tailor analysis to your environment.

```json
{
  "tool": "reverse_engineering",
  "operation": "detect_tools",
  "targetPath": "/path/to/binary"
}
```

The output includes:

- Detected tools and versions (radare2/rizin, Ghidra, binwalk, strings, objdump, rabin2)
- Capabilities (which workflows are enabled)
- Recommendations (e.g., install `rabin2` for richer ELF introspection)

#### Relocation Handling (radare2/rizin)

DarkCoder automatically applies `-e bin.relocs.apply=true` when invoking radare2/rizin, preventing warnings like:

> WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true`

This ensures more accurate disassembly and analysis. If you run radare2/rizin manually, include the same flag for parity with DarkCoder’s results.

#### CVE Lookup

```json
{
  "tool": "security_intel",
  "searchType": "cve",
  "cveId": "CVE-2024-1234"
}
```

#### Wayback Machine Historical Analysis

```json
{
  "tool": "wayback_machine",
  "target": "example.com",
  "searchType": "urls",
  "matchType": "domain",
  "filter": "js"
}
```

#### Cuckoo Sandbox Malware Analysis

```json
{
  "tool": "cuckoo_sandbox",
  "operation": "submit_file",
  "filePath": "/path/to/suspicious_file.exe",
  "timeout": 120,
  "priority": 2,
  "memory": true
}
```

```json
{
  "tool": "cuckoo_sandbox",
  "operation": "submit_url",
  "url": "http://suspicious-site.com/malware",
  "timeout": 60
}
```

```json
{
  "tool": "cuckoo_sandbox",
  "operation": "get_report",
  "taskId": 123
}
```

#### VirusTotal File/URL Analysis

```json
{
  "tool": "virustotal",
  "operation": "scan_file",
  "filePath": "/path/to/file.exe"
}
```

```json
{
  "tool": "virustotal",
  "operation": "scan_url",
  "url": "https://suspicious-url.com"
}
```

```json
{
  "tool": "virustotal",
  "operation": "lookup_hash",
  "hash": "44d88612fea8a8f36de82e1278abb02f"
}
```

#### YARAify Malware Scanning

```json
{
  "tool": "yaraify",
  "operation": "scan_file",
  "filePath": "/path/to/suspicious.bin"
}
```

```json
{
  "tool": "yaraify",
  "operation": "lookup_hash",
  "hash": "sha256_hash_here"
}
```

```json
{
  "tool": "yaraify",
  "operation": "search_yara",
  "yaraRule": "rule_name"
}
```

### Real-World Security Workflows

#### 1. Attack Surface Discovery

**Goal**: Find all subdomains and exposed services for a target domain

```bash
darkcoder "Find all subdomains and exposed services for acme.com"
```

**What DarkCoder does**:

1. Uses Wayback Machine for historical subdomain discovery
2. Queries Censys for certificate transparency data
3. Scans discovered hosts with Shodan
4. Analyzes results and prioritizes vulnerabilities

#### 2. Bug Bounty Program Reconnaissance

**Goal**: Identify high-value Web3/DeFi security programs

```bash
darkcoder "Find bug bounty programs with Web3/DeFi focus and minimum $50k bounties"
```

**What DarkCoder does**:

1. Searches across integrated bug bounty platforms (HackerOne, Bugcrowd, Immunefi, etc.)
2. Filters for Web3/DeFi programs
3. Analyzes scope and bounty amounts
4. Provides actionable recommendations with detailed scope analysis

#### 3. Incident Response Automation

**Goal**: Analyze suspicious activity and map to attack patterns

```bash
darkcoder "Analyze this PowerShell activity: <paste_log> and determine if it's malicious"
```

**What DarkCoder does**:

1. Parses alert data and extracts IOCs (IP addresses, domains, hashes)
2. Queries threat intelligence sources (VirusTotal, CVE databases)
3. Maps to MITRE ATT&CK techniques
4. Recommends containment and eradication steps

#### 4. Vulnerability Research

**Goal**: Research a specific CVE and find proof-of-concept exploits

```bash
darkcoder "Research CVE-2024-1234 and find available PoCs or exploits"
```

**What DarkCoder does**:

1. Looks up CVE details and CVSS score
2. Searches for public exploits and PoCs
3. Identifies affected systems using Shodan
4. Provides remediation guidance

#### 5. Malware Analysis Workflow

**Goal**: Analyze a suspicious file for malware indicators

```bash
darkcoder "Analyze this suspicious file /path/to/file.exe for malware"
```

**What DarkCoder does**:

1. Calculates file hashes (MD5, SHA1, SHA256)
2. Checks VirusTotal for known detections across 70+ AV engines
3. Submits to YARAify for YARA signature matching
4. (Optional) Submits to Cuckoo Sandbox for dynamic behavioral analysis
5. Extracts IOCs (IPs, domains, file paths, registry keys)
6. Generates comprehensive threat report with MITRE ATT&CK mapping

**Example with Cuckoo Sandbox:**

```bash
darkcoder "Submit /tmp/malware.exe to Cuckoo Sandbox and wait for the analysis report"
```

**What DarkCoder does**:

1. Submits file to Cuckoo Sandbox API
2. Monitors task status until completion
3. Retrieves full behavioral analysis report including:
   - Process tree and API calls
   - Network traffic and DNS queries
   - File system changes
   - Registry modifications
   - Memory analysis results
   - YARA matches and signatures

#### 6. CVE Intelligence Integration Workflow (New!)

**Goal**: Scan target and automatically correlate with latest vulnerability intelligence

```bash
darkcoder "Scan 192.168.1.1 with Nuclei and provide CVE intelligence"
```

**What DarkCoder does**:

1. Runs Nuclei vulnerability scanner with 10,000+ templates
2. Extracts CVE IDs from scan results (e.g., CVE-2024-1234)
3. Cross-references with live vulnerability databases:
   - NVD for detailed CVE information and CVSS scores
   - Exploit-DB for proof-of-concept exploits
   - VirusTotal for threat intelligence
   - CISA KEV for known exploited vulnerabilities
4. Generates comparison table: LLM training data vs current intelligence
5. Provides targeted security commands based on findings

**Example with Shodan Service Analysis:**

```bash
darkcoder "Analyze exposed services on 8.8.8.8 and check for vulnerabilities"
```

**What DarkCoder does**:

1. Queries Shodan for service enumeration
2. Extracts software products and versions (e.g., "Apache 2.4.41")
3. Maps products to known CVEs using live databases
4. Provides actionable intelligence:
   - CVE lookup commands: `darkcoder "Search CVE for Apache 2.4.41"`
   - Exploit availability: `searchsploit Apache 2.4.41`
   - Vendor advisories and patch information
   - Risk assessment based on CVSS scores

**Memory Safety Features:**

All CVE intelligence operations include automatic protection:

- Max 15-50 products per scan (depending on data complexity)
- Output size limited to 100KB
- Set-based deduplication (O(1) performance)
- Early termination on excessive results
- Graceful degradation with truncation warnings

**Supported Tools with CVE Intelligence:**

| Tool               | CVE Intelligence Feature                              | Memory Limit    |
| ------------------ | ----------------------------------------------------- | --------------- |
| `nuclei`           | Extracts CVE IDs from templates + live cross-ref      | 30 products     |
| `shodan`           | Maps services → software → CVEs                       | 20 products     |
| `censys`           | Analyzes certificates/services → version → CVEs       | 20 products     |
| `web-tech`         | Detects web stack → version-specific vulnerabilities  | 15 products     |
| `ssl-scanner`      | TLS vulnerabilities → related CVE exploits            | 20 vulns        |
| `reverse_engineer` | 6 live intelligence ops (CVE, exploits, threat intel) | Absolute limits |

- File system changes
- Registry modifications
- Memory analysis results
- YARA matches and signatures

---

## 📊 Tool Reference

### Security Intelligence Tools

| Tool              | Description                     | Use Case                                 |
| ----------------- | ------------------------------- | ---------------------------------------- |
| `shodan`          | Internet device search          | Host discovery, port scanning            |
| `censys`          | Host & certificate search       | SSL cert enumeration, asset discovery    |
| `nuclei`          | Vulnerability scanner           | CVE scanning, misconfiguration detection |
| `urlscan`         | Website scanning                | URL analysis, screenshot capture         |
| `wayback_machine` | Historical website data         | Subdomain discovery, endpoint finding    |
| `security_intel`  | CVE & exploit database          | Vulnerability research, PoC hunting      |
| `bug_bounty`      | Bug bounty platform integration | Program discovery, scope analysis        |
| `api_key_manager` | API key management              | Configuration management                 |

### Malware Analysis Tools

| Tool             | Description                | Use Case                             |
| ---------------- | -------------------------- | ------------------------------------ |
| `cuckoo_sandbox` | Automated malware analysis | Dynamic analysis, behavioral reports |
| `virustotal`     | Multi-AV file/URL scanning | Malware detection, hash reputation   |
| `yaraify`        | YARA rule scanning         | Signature matching, malware hunting  |

### Utility & File Tools

| Tool         | Description           | Use Case                    |
| ------------ | --------------------- | --------------------------- |
| `edit`       | File editing          | Creating/modifying files    |
| `shell`      | Command execution     | Running system commands     |
| `grep`       | Pattern searching     | Searching file contents     |
| `glob`       | File pattern matching | Finding files with patterns |
| `read_file`  | File reading          | Viewing file contents       |
| `write_file` | File writing          | Writing output to files     |

| `task` | Sub-agent delegation | Complex task automation |

---

## 🛠️ Development

### Project Structure

```
darkcoder/
├── packages/
│   ├── cli/              # Command-line interface
│   ├── core/            # Core functionality and tools
│   ├── sdk-typescript/  # TypeScript SDK
│   └── vscode-ide-companion/ # VSCode extension
├── docs/                # Documentation
├── scripts/            # Build and utility scripts
├── integration-tests/  # Test suite
└── patches/            # Dependency patches
```

### Building from Source

```bash
# Clone repository
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# Install dependencies
npm install

# Build project
npm run build

# Run tests
npm test

# Install globally
npm install -g .
```

### Creating Custom Tools

DarkCoder supports custom tools via the Model Context Protocol (MCP). Here's how to create one:

```typescript
// packages/core/src/tools/my-tool.ts
import { BaseDeclarativeTool, Kind } from './tools.js';

export class MySecurityTool extends BaseDeclarativeTool {
  constructor() {
    super(
      'my_tool',
      'My Security Tool',
      'Description of my custom security tool',
      Kind.Fetch,
      {
        properties: {
          target: { type: 'string', description: 'Target to analyze' },
        },
        required: ['target'],
      },
    );
  }
}
```

---

## 🐛 Troubleshooting

### Quick Health Check

Run the diagnostic tool to identify issues:

```bash
npm run doctor
```

This checks:

- ✅ Node.js version and memory configuration
- ✅ API keys (AI providers and security tools)
- ✅ Security tool availability
- ✅ Build status and dependencies

### 📚 Comprehensive Guides

| Issue Type              | Guide                                                                          |
| ----------------------- | ------------------------------------------------------------------------------ |
| **New Developer Setup** | [docs/DEVELOPER_SETUP.md](docs/DEVELOPER_SETUP.md)                             |
| **All Troubleshooting** | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)                             |
| **Memory Management**   | [docs/development/MEMORY_MANAGEMENT.md](docs/development/MEMORY_MANAGEMENT.md) |
| **Project Structure**   | [docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md)                         |

### Common Issues & Solutions

#### "API key not found" Error

**Symptoms**: Tool fails with "API key not found" message

**Solutions**:

- Verify key is set: `{ "operation": "status" }`
- Check environment variables are properly exported: `echo $SHODAN_API_KEY`
- Ensure settings.json exists at `~/.qwen/settings.json`
- Verify API key is valid on the provider's website

#### Tool Execution Failures

**Symptoms**: Tools timeout, network errors, or invalid responses

**Solutions**:

- Run with debug flag: `darkcoder --debug`
- Check network connectivity to API endpoints
- Verify API key permissions and quotas
- Check rate limiting on the API provider

#### CLI Command Not Found

**Symptoms**: `darkcoder: command not found` after installation

**Solutions**:

```bash
# If installed from source, run npm link again
cd AssistanceAntiCyber-Darkcoder-CLI
npm run build
npm link

# Check if darkcoder is linked
which darkcoder

# If not found, check npm global bin is in PATH
npm bin -g
echo $PATH

# If npm bin not in PATH, add it to your shell profile (~/.bashrc or ~/.zshrc)
export PATH="$(npm bin -g):$PATH"

# Alternative: Run directly without linking
node packages/cli/dist/index.js
```

**Note**: DarkCoder is not published to npm. Install from source or use Docker.

#### Build Issues

**Symptoms**: Compilation errors during `npm run build`

**Solutions**:

- Ensure Node.js >= 20.0.0: `node --version`
- Clean and reinstall: `rm -rf node_modules && npm install`
- Check TypeScript errors: `npm run build 2>&1 | head -50`
- Clear npm cache: `npm cache clean --force`

#### Memory Issues (Heap Out of Memory)

**Symptoms**: `FATAL ERROR: Allocation failed - JavaScript heap out of memory`

**Solutions**:

```bash
# Default 8GB memory limit (recommended for most systems)
npm start

# High memory mode for intensive operations (16GB)
npm run start:highmem

# Low memory mode for constrained systems (4GB)
npm run start:lowmem

# Or manually set memory limit
NODE_OPTIONS='--max-old-space-size=16384' darkcoder
```

**Prevention**:

- Restart the CLI periodically during long sessions
- Avoid processing very large files (>50MB) in a single operation
- Close unused terminal windows
- Ensure your system has at least 8GB RAM available

#### Installation Issues with Dependencies

**Symptoms**: Native module compilation failures, permission errors

**Solutions**:

```bash
# Clean reinstall
rm -rf node_modules package-lock.json
npm cache clean --force
npm install

# If still failing, check system dependencies
# macOS: brew install python3
# Ubuntu: sudo apt-get install python3 build-essential
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
darkcoder --debug

# Or set environment variable
DEBUG=darkcoder:* darkcoder
```

Debug mode provides detailed logs for:

- Tool execution and API calls
- Configuration loading
- Error traces
- Performance metrics

### Getting Help

1. Check the documentation: [docs/](docs/)
2. Search existing issues: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
3. Open a new issue with:
   - Detailed error message and logs
   - Steps to reproduce
   - Node.js and npm versions
   - Operating system

---

## 🤝 Contributing

We welcome contributions from the security community! Here's how you can help:

### 🚀 Quick Start for Contributors

New to the project? Check out our [Quick Start Guide for Contributors](QUICK_START_CONTRIBUTORS.md) for a 5-minute setup!

### Reporting Issues

1. Check existing issues before creating new ones
2. Include detailed reproduction steps
3. Provide relevant logs and configuration details
4. Specify your Node.js version and OS

### Feature Requests

1. Describe the security use case
2. Explain how it benefits the community
3. Provide examples or mockups if applicable
4. Consider implementing it yourself!

### Code Contributions

**See detailed guidelines**: [CONTRIBUTING.md](CONTRIBUTING.md)

**Key areas for contribution**:

- 🔧 New security tool integrations
- 🐛 Bug fixes and improvements
- 📚 Documentation enhancements
- ✅ Test coverage improvements
- 🎨 UI/UX enhancements

**Important for security tools**:

- Must follow memory safety patterns (see CONTRIBUTING.md)
- Include CVE intelligence integration where applicable
- Add comprehensive tests
- Document API requirements

**Release Notes**: See [CHANGELOG.md](CHANGELOG.md) for current history; archived v0.7.0 details at [docs/archive/RELEASE_NOTES_v0.7.0.md](docs/archive/RELEASE_NOTES_v0.7.0.md).

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Ensure all tests pass: `npm test`
5. Commit with clear messages
6. Submit a pull request

### Security Researchers

Found a vulnerability? Please report it responsibly via:

- GitHub Security Advisory
- Email: dara.daranaki@gmail.com
- Do not open public issues for security vulnerabilities

---

## 📚 Documentation

- **[Full Documentation](docs/index.md)** - Complete user guide and API reference
- **[Shell Completions](docs/SHELL_COMPLETIONS.md)** - Tab completion for bash, zsh, fish
- **[Typo Detection](docs/TYPO_DETECTION.md)** - "Did you mean?" command suggestions
- **[Tool Documentation](docs/tools/)** - Detailed tool usage and examples
- **[Development Guide](docs/development/)** - Building and extending DarkCoder
- **[Security RAG](docs/tools/SECURITY_RAG.md)** - Security knowledge base integration
- **[Bug Bounty Guide](docs/tools/BUG_BOUNTY.md)** - Bug bounty platform integration
- **[Setup Guide](docs/DARKCODER_SETUP_GUIDE.md)** - Step-by-step setup instructions
- **[Multi-Provider System](docs/MULTI_PROVIDER_SYSTEM.md)** - AI provider configuration

---

## 📄 License & Disclaimer

### License

DarkCoder is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for full details.

### Disclaimer

**DarkCoder is a tool for authorized security testing and research only.**

Users are responsible for:

- ✅ Complying with all applicable laws and regulations
- ✅ Obtaining proper authorization before testing any systems
- ✅ Respecting terms of service of integrated platforms
- ✅ Using API keys and tools responsibly
- ✅ Reporting security vulnerabilities responsibly

**The developers assume no liability for misuse or illegal use of this tool.**

---

## 🙏 Acknowledgments

- Built upon [Qwen Code](https://github.com/QwenLM/qwen-code) and [Gemini CLI](https://github.com/google-gemini/gemini-cli)
- Security tools integration inspired by the open-source security community
- Contributors and testers who help improve DarkCoder

---

<p align="center">
  <strong>DarkCoder</strong> - Empowering security researchers with AI-driven tools<br>
  <sub>Because the best defense is a good offense</sub>
</p>

<p align="center">
  <a href="https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI">GitHub</a> •
  <a href="docs/index.md">Docs</a> •
  <a href="https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues">Issues</a> •
  <a href="https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions">Discussions</a>
</p>
# Darkcoder-AgentCLI
