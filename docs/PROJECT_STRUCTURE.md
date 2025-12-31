# DarkCoder Project Structure

A comprehensive guide to the DarkCoder codebase for developers and contributors.

## 📁 Repository Overview

```
darkcoder/
├── 📄 Root Configuration Files
├── 📂 packages/           # Core monorepo packages
├── 📂 docs/               # Documentation
├── 📂 scripts/            # Build & utility scripts
├── 📂 integration-tests/  # E2E integration tests
├── 📂 eslint-rules/       # Custom ESLint rules
└── 📂 patches/            # Package patches
```

---

## 📄 Root Files

| File                         | Purpose                                 |
| ---------------------------- | --------------------------------------- |
| `README.md`                  | Main project documentation              |
| `CHANGELOG.md`               | Version history and changes             |
| `CONTRIBUTING.md`            | Contribution guidelines                 |
| `LICENSE`                    | Apache 2.0 license                      |
| `CLAUDE.md`                  | AI assistant guidance (Claude Code)     |
| `expert-ai-system-prompt.md` | DarkCoder AI personality & capabilities |
| `package.json`               | Monorepo package manager config         |
| `tsconfig.json`              | TypeScript configuration                |
| `vitest.config.ts`           | Test framework configuration            |
| `eslint.config.js`           | Linting configuration                   |
| `esbuild.config.js`          | Build bundler configuration             |
| `Dockerfile`                 | Container build configuration           |
| `Makefile`                   | Build automation commands               |

---

## 📂 packages/ - Core Monorepo

### packages/cli/

**The main CLI application**

```
packages/cli/
├── src/
│   ├── commands/          # CLI command handlers
│   ├── config/            # Configuration management
│   ├── ui/                # Terminal UI components (Ink/React)
│   │   ├── components/    # Reusable UI components
│   │   └── hooks/         # React hooks for state management
│   ├── utils/             # CLI-specific utilities
│   └── acp-integration/   # ACP protocol integration
├── package.json
└── tsconfig.json
```

### packages/core/

**Core business logic and AI integration**

```
packages/core/
├── src/
│   ├── core/              # Core AI client & orchestration
│   │   ├── client.ts      # Main AI API client
│   │   ├── turn.ts        # Conversation turn handling
│   │   └── tokenLimits.ts # Token management
│   ├── tools/             # Security tool implementations
│   │   ├── shodan.ts      # Shodan API integration
│   │   ├── censys.ts      # Censys search
│   │   ├── nuclei.ts      # Nuclei scanner
│   │   ├── ffuf.ts        # FFUF fuzzer

│   │   └── ...            # 50+ security tools
│   ├── services/          # Business logic services
│   │   └── chatCompressionService.ts  # Context compression
│   ├── config/            # Configuration handling
│   └── utils/             # Shared utilities
├── package.json
└── tsconfig.json
```

### packages/sdk-typescript/

**TypeScript SDK for programmatic access**

```
packages/sdk-typescript/
├── src/                   # SDK source code
├── test/                  # SDK unit tests
├── package.json
└── tsconfig.json
```

### packages/vscode-ide-companion/

**VS Code extension for IDE integration**

```
packages/vscode-ide-companion/
├── src/                   # Extension source
├── package.json           # VS Code extension manifest
└── tsconfig.json
```

### packages/test-utils/

**Shared testing utilities**

```
packages/test-utils/
├── src/                   # Test helpers
└── package.json
```

---

## 📂 docs/ - Documentation

```
docs/
├── index.md               # Main documentation entry
├── sidebar.json           # Navigation structure
├── PROJECT_STRUCTURE.md   # This file
├── QUICK_START_CONTRIBUTORS.md  # Contributor quick start
├── archive/               # Archived docs (legacy release notes, etc.)
│   └── RELEASE_NOTES_v0.7.0.md
│
├── cli/                   # CLI usage documentation
├── core/                  # Core library documentation
├── development/           # Development guides
│   ├── ARCHITECTURE.md
│   ├── DEBUGGING_GUIDE.md
│   └── MEMORY_MANAGEMENT.md
├── features/              # Feature documentation
│   ├── PARALLEL_EXECUTION.md
│   ├── COST_TRACKING_GUIDE.md
│   └── AI_DRIVEN_PARALLEL_EXECUTION.md
├── tools/                 # Security tool guides
│   ├── CTF_CRYPTO_GUIDE.md
│   ├── CTF_REVERSE_ENGINEERING_GUIDE.md
│   ├── NUCLEI_INTEGRATION_GUIDE.md
│   └── SHODAN_INTEGRATION_GUIDE.md
├── extensions/            # Extension documentation
│   ├── QWEN.md
│   └── qwen-extension.json
├── ide-integration/       # IDE integration guides
├── examples/              # Usage examples
├── assets/                # Images and media
│   └── DarkcoderV1.png    # Project logo
├── mermaid/               # Architecture diagrams
└── support/               # Troubleshooting guides
```

---

## 📂 scripts/ - Build & Utilities

```
scripts/
├── build-with-memory-management.js  # Main build script with memory monitoring
├── build.js               # Legacy build script
├── build-with-memory-management.js  # Memory-safe build
├── setup-coverage-dirs.js # Test coverage setup
├── setup-memory.sh        # Memory configuration
├── test-memory-leak.js    # Memory leak detection
├── start.js               # Development start script
└── tests/                 # Script tests
```

---

## 📂 integration-tests/

End-to-end integration tests for the CLI and core packages.

```
integration-tests/
├── *.test.ts              # Integration test files
├── vitest.config.ts       # Test configuration
├── globalSetup.ts         # Test setup
├── sdk-typescript/        # SDK-specific tests
└── terminal-bench/        # Terminal benchmarks
```

---

## 🔧 Development Workflow

### Build Commands

```bash
# Build everything
npm run build

# Build specific package
npm run build --workspace=packages/cli
npm run build --workspace=packages/core

# Clean build
npm run clean && npm run build
```

### Testing

```bash
# Run all tests
npm test

# Run specific test file
npx vitest run path/to/test.ts

# Run tests with coverage
npm run test:coverage
```

### Development

```bash
# Start development mode
npm run dev

# Lint code
npm run lint

# Format code
npm run format
```

---

## 🏗️ Architecture Highlights

### Monorepo Structure

- **npm workspaces** for package management
- **Shared TypeScript configuration** via root `tsconfig.json`
- **Cross-package imports** properly configured

### AI Integration

- **Multi-provider support**: Anthropic, OpenAI, Qwen, Gemini, DeepSeek, OpenRouter
- **29+ models** supported
- **Context compression** for long conversations
- **Token management** with safety limits

### Security Tools

- **50+ security tools** integrated
- **MCP (Model Context Protocol)** for tool extensibility
- **Live CVE intelligence** integration

### Memory Safety

- **8GB heap allocation** with monitoring
- **Auto-GC** at 90% threshold
- **5-layer defense** against memory issues

---

## 📚 Further Reading

- [CLAUDE.md](../CLAUDE.md) - AI assistant guidance
- [CONTRIBUTING.md](../CONTRIBUTING.md) - How to contribute
- [docs/development/](./development/) - Development guides
- [docs/tools/](./tools/) - Security tool documentation
