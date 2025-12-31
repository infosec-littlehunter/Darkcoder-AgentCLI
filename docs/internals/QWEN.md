# DarkCoder: AI Security Operations Agent - Project Context

This document provides comprehensive context about the DarkCoder project for AI assistants and developers. Use this as a reference for understanding the project structure, build processes, and development conventions.

## 🎯 Project Overview

**DarkCoder** is a multi-provider AI assistant built for security researchers, penetration testers, and cybersecurity professionals. It combines advanced AI capabilities with specialized security tools for offensive and defensive operations.

### Key Features:

- **Multi-Provider AI Support**: Works with OpenAI, Qwen, DashScope, Claude, Gemini, DeepSeek, and OpenRouter (29+ models)
- **Integrated Security Tools**: Built-in Shodan, Censys, URLScan, VirusTotal, bug bounty platforms, and OSINT tools
- **Live Vulnerability Intelligence**: Real-time CVE correlation across all security tools
- **Memory-Safe Processing**: Multi-layer defense system with O(1) deduplication and bounded iteration
- **Predictive Security Operations**: Advanced scenario prediction and autonomous execution capabilities
- **Terminal-First Workflow**: Designed for security professionals who live in the terminal

### Core Philosophy:

- **No lock-in**: Support for multiple AI providers
- **No limits**: Full access to underlying security tools
- **No corporate constraints**: Open architecture with extensible plugin system

## 🏗️ Technology Stack

- **Runtime**: Node.js >=20.0.0 (primary), Bun (alternative)
- **Package Manager**: npm (primary), Bun (optional)
- **Language**: TypeScript with strict configuration
- **Build System**: esbuild for bundling, TypeScript for compilation
- **Testing**: Vitest for unit tests, integration tests
- **Linting**: ESLint with custom security rules
- **Formatting**: Prettier
- **UI Framework**: Ink (React for terminal interfaces)
- **Package Management**: npm workspaces (monorepo)
- **Containerization**: Docker for sandbox environments

## 📁 Project Structure

```
darkcoder/
├── 📄 Root Configuration Files
├── 📂 packages/           # Core monorepo packages
│   ├── cli/              # Main CLI application
│   ├── core/             # Core business logic and AI integration
│   ├── sdk-typescript/   # TypeScript SDK for programmatic access
│   ├── vscode-ide-companion/ # VS Code extension
│   └── test-utils/       # Shared testing utilities
├── 📂 docs/              # Comprehensive documentation
├── 📂 scripts/           # Build & utility scripts
├── 📂 integration-tests/ # E2E integration tests
├── 📂 eslint-rules/      # Custom ESLint rules
├── 📂 patches/           # Package patches
└── 📂 .github/           # GitHub Actions workflows
```

### Key Directories:

| Directory                        | Purpose                                                    |
| -------------------------------- | ---------------------------------------------------------- |
| `packages/cli/`                  | Main CLI application with terminal UI (Ink/React)          |
| `packages/core/`                 | Core AI client, security tools, and business logic         |
| `packages/sdk-typescript/`       | TypeScript SDK for programmatic access                     |
| `packages/vscode-ide-companion/` | VS Code extension for IDE integration                      |
| `packages/test-utils/`           | Shared testing utilities                                   |
| `docs/`                          | Comprehensive documentation (usage, development, features) |
| `scripts/`                       | Build scripts, memory management, and utilities            |
| `integration-tests/`             | End-to-end integration tests                               |
| `eslint-rules/`                  | Custom ESLint rules for security code                      |

## 🚀 Building and Running

### Prerequisites:

- Node.js >=20.0.0
- npm >=10.0.0 OR Bun >=1.1.0
- Git

### Installation:

```bash
# Clone the repository
git clone <repository-url>
cd AssistanceAntiCyber-Darkcoder-CLI

# Install dependencies
npm install

# Or with Bun
bun install
```

### Building the Project:

```bash
# Build all packages (recommended)
npm run build

# Build with memory management optimizations
npm run build:managed

# Build for production with safety limits
npm run build:safe

# Build using Bun
bun run build:bun

# Build everything including sandbox and VS Code companion
npm run build:all
```

### Running the CLI:

```bash
# Start the CLI (Node.js)
npm run start

# Start with Bun
bun run start:bun

# Start with low memory (4GB)
npm run start:lowmem

# Start with high memory (16GB)
npm run start:highmem

# Debug mode with inspector
npm run debug
```

### Using the Global CLI:

After building, you can run the CLI directly:

```bash
node dist/cli.js
```

Or install globally:

```bash
npm link
darkcoder
```

### Testing:

```bash
# Run all tests
npm run test

# Run integration tests (no sandbox)
npm run test:integration:sandbox:none

# Run integration tests with Docker sandbox
npm run test:integration:sandbox:docker

# Run terminal benchmark tests
npm run test:terminal-bench

# Run CI test suite
npm run test:ci
```

### Development Workflow:

```bash
# Pre-flight check (format, lint, build, test)
npm run preflight

# Lint code
npm run lint

# Format code
npm run format

# Type checking
npm run typecheck

# Clean generated files
npm run clean
```

## 📝 Development Conventions

### Code Style:

- **TypeScript**: Strict mode enabled with no implicit any/returns/this
- **Imports**: ES modules (`import/export`) only
- **Naming**: CamelCase for variables/functions, PascalCase for classes/interfaces
- **Error Handling**: Use typed errors with proper error propagation
- **Memory Safety**: Implement bounded iteration, early breaks, and set-based deduplication

### Security Tool Development:

- All security tools must implement memory limits (15-50 items based on complexity)
- Use O(1) set operations instead of O(n²) array operations
- Implement early break conditions in all loops
- Enforce output size constraints (100KB max for CVE intelligence)
- Include proper error handling for API failures

### Testing Requirements:

- Unit tests for all core functionality
- Integration tests for security tools
- Memory safety tests for bounded operations
- E2E tests for CLI workflows

### Git Commit Conventions:

- Follow conventional commits format
- Include relevant issue/PR references
- Scope commits to specific packages when possible

## 📦 Available Scripts (package.json)

### Build Scripts:

| Script          | Purpose                                     |
| --------------- | ------------------------------------------- |
| `build`         | Build main project with memory management   |
| `build:bun`     | Build using Bun runtime                     |
| `build:managed` | Build with memory management optimizations  |
| `build:safe`    | Build with higher memory limits for safety  |
| `build:all`     | Build everything (main + sandbox + VS Code) |
| `build:sandbox` | Build Docker sandbox image                  |
| `build:vscode`  | Build VS Code companion extension           |
| `bundle`        | Generate bundle with assets                 |

### Development Scripts:

| Script          | Purpose                                                |
| --------------- | ------------------------------------------------------ |
| `start`         | Start CLI with standard memory (8GB)                   |
| `start:bun`     | Start CLI using Bun                                    |
| `start:lowmem`  | Start with 4GB memory limit                            |
| `start:highmem` | Start with 16GB memory limit                           |
| `debug`         | Start with debug inspector                             |
| `test`          | Run test suite across all packages                     |
| `test:ci`       | Run CI test suite                                      |
| `lint`          | Lint code with ESLint                                  |
| `format`        | Format code with Prettier                              |
| `typecheck`     | Type check across all packages                         |
| `preflight`     | Full check (clean, install, format, lint, build, test) |

### Utility Scripts:

| Script       | Purpose                            |
| ------------ | ---------------------------------- |
| `clean`      | Remove generated files             |
| `doctor`     | Diagnostic check for setup issues  |
| `telemetry`  | Telemetry utilities                |
| `generate`   | Generate git commit info           |
| `check-i18n` | Check internationalization strings |

## ⚙️ Key Configuration Files

### TypeScript (`tsconfig.json`):

- Strict mode enabled with all strict flags
- ES2022 target with NodeNext module resolution
- Declaration files enabled
- Composite and incremental builds

### ESLint (`eslint.config.js`):

- Custom security-focused rules
- TypeScript-aware linting
- React hooks and JSX runtime rules
- Import ordering and no-default-export warnings
- No `require()` statements (ES modules only)

### Prettier (`.prettierrc.json`):

- 2-space indentation
- Single quotes
- Trailing commas
- 80 character print width

### Bun Configuration (`bunfig.toml`):

- Bun-specific settings
- Optimized for memory and speed

### Makefile:

- Convenient aliases for common commands
- `make install`, `make build`, `make test`, etc.

## 📦 Workspace Packages

### `packages/cli/` - Main CLI Application

**Entry Point**: `src/index.ts`
**Bin Command**: `darkcoder`

**Key Subdirectories**:

- `src/commands/` - CLI command handlers
- `src/config/` - Configuration management
- `src/ui/` - Terminal UI components (Ink/React)
- `src/utils/` - CLI-specific utilities
- `src/acp-integration/` - ACP protocol integration

**Dependencies**: `@darkcoder/darkcoder-core`, Ink, React, yargs, various security tool integrations.

### `packages/core/` - Core Business Logic

**Entry Point**: `src/index.ts`

**Key Subdirectories**:

- `src/core/` - Core AI client & orchestration (client.ts, turn.ts, tokenLimits.ts)
- `src/tools/` - Security tool implementations (50+ tools: shodan.ts, censys.ts, nuclei.ts, ffuf.ts, etc.)
- `src/services/` - Business logic services (chatCompressionService.ts, etc.)
- `src/config/` - Configuration handling
- `src/utils/` - Shared utilities

**Dependencies**: Multiple AI provider SDKs (OpenAI, Google GenAI, etc.), MCP SDK, OpenTelemetry, security libraries.

### `packages/sdk-typescript/` - TypeScript SDK

**Entry Point**: `src/index.ts`

Provides programmatic access to DarkCoder functionality for integration into other applications.

### `packages/vscode-ide-companion/` - VS Code Extension

**Entry Point**: `src/extension.ts`

VS Code extension that integrates DarkCoder into the IDE for security code analysis and assistance.

### `packages/test-utils/` - Shared Testing Utilities

**Entry Point**: `src/index.ts`

Shared test helpers, mocks, and utilities used across all packages.

## 🔌 MCP Tool Integration

DarkCoder connects to external **Model Context Protocol (MCP)** servers for tool access, enabling users to leverage professional security tools without local installation.

### Core MCP Servers:

1. **Kali Linux MCP Server** (`kali_mcp`)
   - Provides access to 30+ security tools (nmap, metasploit, sqlmap, burpsuite, etc.)
   - Tools run in isolated Kali Linux environment
   - Available via `kali_mcp` tool category

2. **Browser MCP Server** (`browsermcp`, `chrome-mcp-stdio`)
   - Browser automation for web security testing
   - Navigation, screenshot, form filling, network capture
   - Available via `browsermcp` and `chrome-mcp-stdio` tool categories

3. **Burp Suite MCP Server** (`burpsuite`)
   - Professional web vulnerability testing
   - Proxy history, repeater, intruder, decoder
   - Available via `burpsuite` tool category

### Available Security Tools (via MCP):

- **Network Scanning**: nmap, masscan, naabu
- **Web Scanning**: nikto, dirb, gobuster, ffuf, nuclei
- **Exploitation**: metasploit, sqlmap, commix, ssrfmap, ghauri
- **Reconnaissance**: subfinder, amass, assetfinder, httpx, gau, waybackurls
- **Password Attacks**: hydra, john
- **Web Security**: dalfox, jwt_tool, graphqlmap, wpscan
- **Enumeration**: enum4linux, paramspider, kiterunner

### Usage Pattern:

When assisting with security operations, leverage the appropriate MCP tools directly rather than suggesting manual tool installation. The AI has direct access to execute these tools via the MCP servers.

## 🛡️ Memory Safety Guidelines

DarkCoder implements a **multi-layer defense system** to prevent JavaScript heap overflow:

### 1. Per-Tool Input Limits

- **Shodan/Censys**: Max 20 products per scan
- **Web-Tech Detection**: Max 15 products per scan
- **SSL Scanner**: Max 20 vulnerabilities per scan
- **CVE Intelligence**: Max 100KB output size

### 2. Algorithm Optimizations

- **Set-based deduplication**: O(1) operations instead of O(n²) array filtering
- **Early break conditions**: Exit loops when limit reached
- **Bounded iteration**: Pre-slice arrays before iteration
- **Memory markers**: Track memory usage in critical operations

### 3. Output Constraints

- All security tools enforce maximum output sizes
- CVE intelligence limited to 100KB per response
- Automatic truncation when limits exceeded

### 4. Production Memory Limits

- Default: `--max-old-space-size=8192` (8GB)
- Low memory: `--max-old-space-size=4096` (4GB)
- High memory: `--max-old-space-size=16384` (16GB)

## 🔧 Development Setup

### IDE Configuration

- VS Code recommended with extensions:
  - TypeScript
  - ESLint
  - Prettier
  - EditorConfig

### Environment Variables

Copy `.env.example` to `.env` and configure:

- AI provider API keys (OpenAI, Qwen, DashScope, etc.)
- Security tool API keys (Shodan, Censys, VirusTotal, etc.)
- Optional: Docker/Podman configuration for sandbox

### Debugging

```bash
# Start with debug inspector
npm run debug

# Attach debugger on port 9229
# Use Chrome DevTools or VS Code debugger
```

### Sandbox Development

The project includes a sandbox for secure execution:

```bash
# Build sandbox image
npm run build:sandbox

# Run integration tests with sandbox
npm run test:integration:sandbox:docker
```

## 📚 Additional Resources

### Documentation

- `README.md` - Main project documentation (1771 lines)
- `docs/` - Comprehensive guides and references
- `CONTRIBUTING.md` - Contribution guidelines
- `CHANGELOG.md` - Version history

### Key Documentation Files:

- `docs/PROJECT_STRUCTURE.md` - Detailed project structure
- `docs/DEVELOPER_SETUP.md` - Development environment setup
- `docs/MEMORY_MANAGEMENT.md` - Memory safety implementation
- `docs/AI_LLM_SECURITY_2025.md` - AI/LLM security defenses
- `expert-ai-system-prompt.md` - Full AI persona and operating directives (9232 lines)

### Security Tools Integration:

- **Shodan**: Host discovery, service enumeration, CVE correlation
- **Censys**: Certificate transparency, asset discovery
- **URLScan.io**: Website analysis, threat intelligence
- **Wayback Machine**: Historical data, endpoint discovery
- **VirusTotal**: File/URL/domain analysis, malware intelligence
- **Bug Bounty Platforms**: HackerOne, Bugcrowd, Intigriti, Immunefi

### AI Provider Support:

- **OpenAI**: GPT-4o, GPT-4o Mini, o1, o3 series
- **Anthropic Claude**: Claude Sonnet 4.5, Claude 3.5 Haiku/Sonnet, Claude 3 Opus
- **Qwen**: Qwen3-Coder-Plus, Qwen3-Plus, Qwen3-Max, Qwen3-VL-Max
- **Google Gemini**: Gemini 2.5 Pro, Gemini 2.5 Flash, Gemini 2.0 Flash
- **DeepSeek**: DeepSeek V3, DeepSeek R1, DeepSeek Coder
- **OpenRouter**: Access to 100+ models via single API

## 🚨 Troubleshooting

### Common Issues:

1. **Memory Heap Overflow**
   - Use `npm run start:highmem` for 16GB limit
   - Check tool input limits are being enforced
   - Verify set-based deduplication is used

2. **Build Failures**
   - Run `npm run clean` then rebuild
   - Ensure Node.js >=20.0.0
   - Check TypeScript compiler errors

3. **API Key Issues**
   - Verify `.env` file is properly configured
   - Check API key permissions and quotas
   - Use `npm run doctor` for diagnostic checks

4. **Sandbox Problems**
   - Ensure Docker/Podman is installed and running
   - Check sandbox image builds correctly
   - Verify container permissions

### Diagnostic Commands:

```bash
# Run project doctor
npm run doctor

# Check build status
node scripts/check-build-status.js

# Verify dependencies
npm ls --depth=0
```

## 🤝 Contributing

See `CONTRIBUTING.md` for detailed guidelines:

1. **Fork and clone** the repository
2. **Create a branch** for your feature/fix
3. **Follow coding conventions** and memory safety guidelines
4. **Write tests** for new functionality
5. **Run pre-flight checks**: `npm run preflight`
6. **Submit pull request** with clear description

### Code Review Checklist:

- [ ] Memory safety limits implemented
- [ ] TypeScript strict mode compliance
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No security tool API keys exposed

## 📄 License

Apache 2.0 License - See `LICENSE` file for details.

---

_This document was generated based on analysis of the DarkCoder codebase. Last updated: December 29, 2025._
