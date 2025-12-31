# DarkCoder Documentation

DarkCoder is a multi-provider AI assistant built for security researchers, penetration testers, and cybersecurity professionals. It combines advanced AI capabilities with specialized security tools for offensive and defensive operations.

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Clone and build
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
docker build -t darkcoder .

# Run with free model
docker run -it --rm \
  -v $(pwd):/workspace \
  -e OPENROUTER_API_KEY="your_key" \
  darkcoder --model google/gemini-2.0-flash-exp:free
```

### From Source

```bash
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
npm install
npm run build
npm link
darkcoder --version
```

## 🎯 Why DarkCoder?

- **🔒 Security-First**: Built for cybersecurity with specialized tools and workflows
- **🌐 Multi-Provider**: Works with OpenRouter, OpenAI, Qwen, Google, and more
- **🆓 Free Models**: Use Gemini, Llama, Qwen free tiers via OpenRouter
- **🛠️ 58+ Security Tools**: Shodan, Censys, VirusTotal, bug bounty platforms, OSINT
- **💻 Terminal-First**: Designed for security professionals who live in the terminal

## 📚 Documentation

### Getting Started

- [Installation Guide](./DEVELOPER_SETUP.md)
- [Quick Start](./QUICK_START_CONTRIBUTORS.md)
- [Troubleshooting](./TROUBLESHOOTING.md)

### AI Providers

- [Provider Overview](./providers/index.md)
- [OpenRouter Setup](./providers/openrouter.md) - Recommended for free models
- [Model Comparison](./providers/index.md#quick-comparison)

### Features

- [Parallel Execution](./features/PARALLEL_EXECUTION_QUICK_START.md)
- [Cost Tracking](./features/COST_TRACKING_GUIDE.md)
- [Checkpointing](./features/checkpointing.md)
- [Sandbox Mode](./features/sandbox.md)

### Security Tools

- [Tools Overview](./tools/index.md)
- [Bug Bounty Integration](./tools/BUG_BOUNTY.md)
- [Reverse Engineering](./tools/CTF_REVERSE_ENGINEERING_GUIDE.md)
- [OSINT Tools](./tools/SECURITY_RAG.md)

### Development

- [Architecture](./development/architecture.md)
- [Memory Management](./development/MEMORY_MANAGEMENT.md)
- [Contributing](../CONTRIBUTING.md)

# Example commands

> Explain this codebase structure
> Help me refactor this function
> Generate unit tests for this module

````

### Session Management

Control your token usage with configurable session limits to optimize costs and performance.

#### Configure Session Token Limit

Create or edit `.qwen/settings.json` in your home directory:

```json
{
  "sessionTokenLimit": 32000
}
````

#### Session Commands

- **`/compress`** - Compress conversation history to continue within token limits
- **`/clear`** (aliases: `/reset`, `/new`) - Clear conversation history, start a fresh session, and free up context
- **`/stats`** - Check current token usage and limits

> 📝 **Note**: Session token limit applies to a single conversation, not cumulative API calls.

### Vision Model Configuration

Qwen Code includes intelligent vision model auto-switching that detects images in your input and can automatically switch to vision-capable models for multimodal analysis. **This feature is enabled by default** - when you include images in your queries, you'll see a dialog asking how you'd like to handle the vision model switch.

#### Skip the Switch Dialog (Optional)

If you don't want to see the interactive dialog each time, configure the default behavior in your `.qwen/settings.json`:

```json
{
  "experimental": {
    "vlmSwitchMode": "once"
  }
}
```

**Available modes:**

- **`"once"`** - Switch to vision model for this query only, then revert
- **`"session"`** - Switch to vision model for the entire session
- **`"persist"`** - Continue with current model (no switching)
- **Not set** - Show interactive dialog each time (default)

#### Command Line Override

You can also set the behavior via command line:

```bash
# Switch once per query
qwen --vlm-switch-mode once

# Switch for entire session
qwen --vlm-switch-mode session

# Never switch automatically
qwen --vlm-switch-mode persist
```

#### Disable Vision Models (Optional)

To completely disable vision model support, add to your `.qwen/settings.json`:

```json
{
  "experimental": {
    "visionModelPreview": false
  }
}
```

> 💡 **Tip**: In YOLO mode (`--yolo`), vision switching happens automatically without prompts when images are detected.

### Authorization

Choose your preferred authentication method based on your needs:

#### 1. Qwen OAuth (🚀 Recommended - Start in 30 seconds)

The easiest way to get started - completely free with generous quotas:

```bash
# Just run this command and follow the browser authentication
qwen
```

**What happens:**

1. **Instant Setup**: CLI opens your browser automatically
2. **One-Click Login**: Authenticate with your qwen.ai account
3. **Automatic Management**: Credentials cached locally for future use
4. **No Configuration**: Zero setup required - just start coding!

**Free Tier Benefits:**

- ✅ **2,000 requests/day** (no token counting needed)
- ✅ **60 requests/minute** rate limit
- ✅ **Automatic credential refresh**
- ✅ **Zero cost** for individual users
- ℹ️ **Note**: Model fallback may occur to maintain service quality

#### 2. OpenAI-Compatible API

Use API keys for OpenAI or other compatible providers:

**Configuration Methods:**

1. **Environment Variables**

   ```bash
   export OPENAI_API_KEY="your_api_key_here"
   export OPENAI_BASE_URL="your_api_endpoint"
   export OPENAI_MODEL="your_model_choice"
   ```

2. **Project `.env` File**
   Create a `.env` file in your project root:
   ```env
   OPENAI_API_KEY=your_api_key_here
   OPENAI_BASE_URL=your_api_endpoint
   OPENAI_MODEL=your_model_choice
   ```

**API Provider Options**

> ⚠️ **Regional Notice:**
>
> - **Mainland China**: Use Alibaba Cloud Bailian or ModelScope
> - **International**: Use Alibaba Cloud ModelStudio or OpenRouter

<details>
<summary><b>🇨🇳 For Users in Mainland China</b></summary>

**Option 1: Alibaba Cloud Bailian** ([Apply for API Key](https://bailian.console.aliyun.com/))

```bash
export OPENAI_API_KEY="your_api_key_here"
export OPENAI_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
export OPENAI_MODEL="qwen3-coder-plus"
```

**Option 2: ModelScope (Free Tier)** ([Apply for API Key](https://modelscope.cn/docs/model-service/API-Inference/intro))

- ✅ **2,000 free API calls per day**
- ⚠️ Connect your Aliyun account to avoid authentication errors

```bash
export OPENAI_API_KEY="your_api_key_here"
export OPENAI_BASE_URL="https://api-inference.modelscope.cn/v1"
export OPENAI_MODEL="Qwen/Qwen3-Coder-480B-A35B-Instruct"
```

</details>

<details>
<summary><b>🌍 For International Users</b></summary>

**Option 1: Alibaba Cloud ModelStudio** ([Apply for API Key](https://modelstudio.console.alibabacloud.com/))

```bash
export OPENAI_API_KEY="your_api_key_here"
export OPENAI_BASE_URL="https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
export OPENAI_MODEL="qwen3-coder-plus"
```

**Option 2: OpenRouter (Free Tier Available)** ([Apply for API Key](https://openrouter.ai/))

```bash
export OPENAI_API_KEY="your_api_key_here"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
export OPENAI_MODEL="qwen/qwen3-coder:free"
```

</details>

## Usage Examples

### 🔍 Explore Codebases

```bash
cd your-project/
qwen

# Architecture analysis
> Describe the main pieces of this system's architecture
> What are the key dependencies and how do they interact?
> Find all API endpoints and their authentication methods
```

### 💻 Code Development

```bash
# Refactoring
> Refactor this function to improve readability and performance
> Convert this class to use dependency injection
> Split this large module into smaller, focused components

# Code generation
> Create a REST API endpoint for user management
> Generate unit tests for the authentication module
> Add error handling to all database operations
```

### 🔄 Automate Workflows

```bash
# Git automation
> Analyze git commits from the last 7 days, grouped by feature
> Create a changelog from recent commits
> Find all TODO comments and create GitHub issues

# File operations
> Convert all images in this directory to PNG format
> Rename all test files to follow the *.test.ts pattern
> Find and remove all console.log statements
```

### 🐛 Debugging & Analysis

```bash
# Performance analysis
> Identify performance bottlenecks in this React component
> Find all N+1 query problems in the codebase

# Security audit
> Check for potential SQL injection vulnerabilities
> Find all hardcoded credentials or API keys
```

## Popular Tasks

### 📚 Understand New Codebases

```text
> What are the core business logic components?
> What security mechanisms are in place?
> How does the data flow through the system?
> What are the main design patterns used?
> Generate a dependency graph for this module
```

### 🔨 Code Refactoring & Optimization

```text
> What parts of this module can be optimized?
> Help me refactor this class to follow SOLID principles
> Add proper error handling and logging
> Convert callbacks to async/await pattern
> Implement caching for expensive operations
```

### 📝 Documentation & Testing

```text
> Generate comprehensive JSDoc comments for all public APIs
> Write unit tests with edge cases for this component
> Create API documentation in OpenAPI format
> Add inline comments explaining complex algorithms
> Generate a README for this module
```

### 🚀 Development Acceleration

```text
> Set up a new Express server with authentication
> Create a React component with TypeScript and tests
> Implement a rate limiter middleware
> Add database migrations for new schema
> Configure CI/CD pipeline for this project
```

## Commands & Shortcuts

### Session Commands

- `/help` - Display available commands
- `/clear` (aliases: `/reset`, `/new`) - Clear conversation history and start a fresh session
- `/compress` - Compress history to save tokens
- `/stats` - Show current session information
- `/exit` or `/quit` - Exit Qwen Code

### Keyboard Shortcuts

- `Ctrl+C` - Cancel current operation
- `Ctrl+D` - Exit (on empty line)
- `Up/Down` - Navigate command history

## Advanced Features

### 🎯 CTF & Reverse Engineering

DarkCoder includes comprehensive tooling for CTF challenges and reverse engineering:

- **[CTF Quick Wins](./CTF_QUICK_WINS.md)** - Common CTF patterns and quick solve strategies
- **[CTF Crypto Guide](./CTF_CRYPTO_GUIDE.md)** - Cryptography challenges and techniques
- **[CTF Reverse Engineering Guide](./CTF_REVERSE_ENGINEERING_GUIDE.md)** - Binary analysis and exploitation
- **[LLM-Friendly Cracking Workflow](./LLM_FRIENDLY_CRACKING_WORKFLOW.md)** - AI-assisted password cracking
- **[Binary Patching Guide](./tools/BINARY_PATCHING_GUIDE.md)** - Modifying binaries for analysis
- **[Modern Malware Evasion Detection](./tools/MODERN_MALWARE_EVASION_DETECTION.md)** - Anti-debugging and evasion techniques
- **[Packer Detection Enhancement](./tools/PACKER_DETECTION_ENHANCEMENT.md)** - Identifying packed executables

### 🤖 AI/LLM Security

Comprehensive guide to modern AI security threats and defenses (Updated December 2025):

- **[AI/LLM Security 2025](./AI_LLM_SECURITY_2025.md)** - Modern prompt injection, jailbreaking, and defense techniques
  - Advanced prompt injection (multi-turn, cross-context, multi-modal)
  - Sophisticated jailbreaking methods beyond DAN
  - Multi-modal attacks (image, audio, document-based)
  - Agent & tool manipulation exploits
  - Defense-in-depth strategies and detection patterns
  - Red teaming playbooks and testing frameworks

### 🧠 Memory Management & Performance

Optimize your workflows with advanced memory management:

- **🚨 [Memory Management Issues and Fixes](./MEMORY_MANAGEMENT_ISSUES_AND_FIXES.md)** - **CRITICAL** timer-based memory leaks and solutions
- **[Memory Management Guide](./MEMORY_MANAGEMENT.md)** - Complete guide to memory configuration
- **[Memory Quick Reference](./MEMORY_QUICK_REFERENCE.md)** - Fast lookup for memory settings
- **[Permanent Memory Configuration](./PERMANENT_MEMORY_CONFIGURATION.md)** - Persistent memory setup
- **[Top 10 Scripts with Memory Management](./TOP_10_SCRIPTS_WITH_MEMORY_MANAGEMENT.md)** - Examples and best practices

### ⚡ Parallel Execution

Accelerate security operations with parallel tool execution:

- **[Parallel Execution Quick Start](./PARALLEL_EXECUTION_QUICK_START.md)** - Get started in minutes
- **[Parallel Tool Execution](./PARALLEL_TOOL_EXECUTION.md)** - Architecture and usage
- **[AI-Driven Parallel Execution](./AI_DRIVEN_PARALLEL_EXECUTION.md)** - Intelligent task distribution
- **[Parallel Execution Integration](./PARALLEL_EXECUTION_INTEGRATION.md)** - Integration guide

### 🔍 Vulnerability Scanning

- **[Nuclei Integration Guide](./NUCLEI_INTEGRATION_GUIDE.md)** - Template-based vulnerability scanning with 10,000+ templates
- **[FFUF Integration Guide](./FFUF_INTEGRATION_GUIDE.md)** - Fast web fuzzing integration

### 🛠️ CLI Enhancements

- **[Shell Completions](./SHELL_COMPLETIONS.md)** - Tab completion for bash, zsh, fish
- **[Typo Detection](./TYPO_DETECTION.md)** - "Did you mean?" command suggestions
- **[Completion and Typo Features](./cli/COMPLETION_AND_TYPO_FEATURES.md)** - Combined CLI improvements
