# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DarkCoder is a multi-provider AI assistant for security researchers built on the Qwen Code/Gemini CLI foundation. It's a monorepo project that combines advanced AI capabilities with specialized security tools for offensive and defensive security operations.

**Key Characteristics:**

- Monorepo using npm workspaces
- TypeScript codebase with strict typing
- Node.js ≥20.0.0 required
- Module system: ESM (ES2022 target, NodeNext module resolution)
- Primary entry point: CLI tool that can run interactively or non-interactively
- Supports 29+ AI models across multiple providers (Anthropic, OpenAI, Qwen, Google Gemini, DeepSeek, OpenRouter)

## Development Commands

### Building

```bash
# Build all packages (requires Node.js with --max-old-space-size=8192)
npm run build

# Build specific packages
npm run build --workspace=packages/cli
npm run build --workspace=packages/core

# Build VSCode extension
npm run build:vscode

# Build sandbox image
npm run build:sandbox

# Clean build artifacts
npm run clean
```

### Testing

```bash
# Run all tests across workspaces
npm test

# Run tests in CI mode (includes script tests)
npm run test:ci

# Run specific test file
npx vitest run path/to/test.ts

# Test specific package
npx vitest run packages/cli
npx vitest run packages/core

# Watch mode for development
npx vitest watch

# Run integration tests (different sandbox modes)
npm run test:integration:sandbox:none           # No sandbox
npm run test:integration:sandbox:docker         # Docker sandbox
npm run test:integration:all                    # All sandbox modes

# Run tests with debugging
DEBUG=1 npm test
```

### Linting & Formatting

```bash
# Lint all packages
npm run lint

# Lint with auto-fix
npm run lint:fix

# Lint for CI (zero warnings)
npm run lint:ci

# Format code
npm run format

# Type checking
npm run typecheck
```

### Running the CLI

```bash
# Start CLI in development mode
npm start

# Debug mode with inspector
npm run debug

# Build and start
npm run build-and-start

# Run directly from dist
node dist/cli.js

# Shell completions (bash, zsh, fish)
node dist/cli.js completion --install
```

### Other Commands

```bash
# Generate git commit info
npm run generate

# Run preflight checks (full validation)
npm run preflight

# Check internationalization
npm run check-i18n

# Pre-commit hooks
npm run pre-commit
```

## Architecture

### Package Structure

**Monorepo Layout:**

```
packages/
├── cli/                    # Main CLI application (user-facing)
│   ├── src/ui/            # React-based UI (using Ink)
│   ├── src/commands/      # CLI command handlers
│   ├── src/config/        # CLI configuration
│   └── src/nonInteractive/# Non-interactive mode logic
├── core/                   # Core functionality (the engine)
│   ├── src/core/          # Client, content generation, tool scheduling
│   ├── src/tools/         # All security and utility tools
│   ├── src/services/      # File system, git, shell execution
│   ├── src/config/        # Configuration management
│   ├── src/subagents/     # Subagent system
│   ├── src/mcp/           # Model Context Protocol integration
│   └── src/utils/         # Shared utilities
├── sdk-typescript/         # TypeScript SDK for programmatic access
├── test-utils/            # Shared test utilities
└── vscode-ide-companion/  # VSCode extension
```

### Core Architecture Concepts

**1. Content Generation Pipeline:**

- `ContentGenerator` (core): Interface for AI model interaction
- `BaseLlmClient` → `GeminiClient`: Client implementations for different providers
- `ContentGeneratorConfig`: Handles authentication and model configuration
- Multi-provider support through abstraction layer (OpenAI, Qwen, DashScope, Gemini)

**2. Tool System:**

- Base classes: `BaseDeclarativeTool`, `BaseToolInvocation`
- `ToolRegistry`: Manages available tools
- `CoreToolScheduler`: Orchestrates tool execution, validation, and confirmation
- Two tool types:
  - **Security Tools**: Shodan, Censys, VirusTotal, YARAify, Hybrid Analysis, Bug Bounty platforms, etc.
  - **Utility Tools**: Edit, Shell, Grep, Glob, Read/Write files, Web fetch, Task (subagents)
- All tools in `packages/core/src/tools/`

**3. Tool Execution Flow:**

```
User Request → ContentGenerator → Tool Call Request
              ↓
CoreToolScheduler → Tool Validation → Confirmation (if needed)
              ↓
Tool Execution (with AbortSignal support) → Result → Response to User
```

- Tools support graceful cancellation via AbortSignal
- Tool validation happens in `tool-validation.ts` before execution
- Confirmation dialogs managed by `ShellConfirmationDialog` and `ToolConfirmationMessage` components
- **Edit Request with Feedback**: Users can redirect AI operations mid-confirmation by selecting "Edit request" and providing guidance. The feedback is sent to the AI which continues with the new instructions.

**4. Configuration System:**

- Primary config location: `~/.qwen/settings.json`
- Environment variables override settings file
- API keys managed via `api-key-manager.ts` tool
- Multi-provider auth handled in `contentGenerator.ts`

**5. Service Layer:**

- `FileSystemService`: File operations abstraction
- `FileDiscoveryService`: Fast file searching (uses `fdir`)
- `GitService`: Git operations
- `ShellExecutionService`: Terminal/shell command execution

**6. Subagent System:**

- Located in `packages/core/src/subagents/`
- Autonomous agents for specialized tasks
- Examples: explore, plan, code-reviewer, etc.

**7. MCP (Model Context Protocol):**

- Integration in `packages/core/src/mcp/`
- Allows custom tool extensions
- OAuth support for MCP servers

### Security Tool Architecture

All security tools follow the `BaseDeclarativeTool` pattern:

```typescript
class SecurityTool extends BaseDeclarativeTool {
  constructor() {
    super(name, title, description, kind, schema);
  }

  async execute(params, signal, updateOutput) {
    // 1. Get API key from config/env
    // 2. Make API request
    // 3. Format and return results
  }
}
```

**Key Security Tools:**

- `shodan.ts`: Internet-wide scanning and host enumeration
- `censys.ts`: Certificate transparency and asset discovery
- `nuclei.ts`: Template-based vulnerability scanner (10,000+ CVE templates)
- `ffuf.ts`: Fast web fuzzer integration
- `virustotal.ts`: Multi-AV malware scanning (70+ engines)
- `yaraify.ts`: YARA-based malware detection
- `cuckoo-sandbox.ts`: Dynamic malware analysis
- `bug-bounty.ts`: Platform integration (HackerOne, Bugcrowd, Immunefi, etc.)
- `security-intel.ts`: CVE lookup and exploit search
- `urlscan.ts`: URL/website analysis
- `wayback-machine.ts`: Historical data and endpoint discovery
- `seclists.ts`: SecLists wordlist integration
- `ssl-scanner.ts`: SSL/TLS security scanning
- `web-recon-methodology.ts`: Structured web reconnaissance workflows

### Data Flow

**Interactive Mode:**

```
User Input (CLI) → UI Layer (Ink/React) → Core Client
                                            ↓
                                    ContentGenerator
                                            ↓
                                    AI Model Provider
                                            ↓
                                    Tool Execution
                                            ↓
                                    UI Display
```

**Non-Interactive Mode:**

```
CLI Args → NonInteractiveCli → Core Client → Tool Execution → JSON/Text Output
```

## CLI Features

### Shell Completions

- Bash, Zsh, and Fish shell completion support
- Install via: `darkcoder completion --install`
- Provides intelligent suggestions for commands, options, and model names
- Implementation: [packages/cli/src/commands/completion.ts](packages/cli/src/commands/completion.ts)

### Typo Detection

- Automatic "did you mean?" suggestions for mistyped commands
- Uses Levenshtein distance algorithm for similarity matching
- Implementation: [packages/cli/src/utils/typoSuggestions.ts](packages/cli/src/utils/typoSuggestions.ts)

## Important Implementation Patterns

### Adding a New Security Tool

1. Create tool file in `packages/core/src/tools/your-tool.ts`
2. Extend `BaseDeclarativeTool` and implement:
   - Constructor with schema definition
   - `execute()` method for API interaction
3. Handle API keys via environment variables or settings
4. Add tool to `tool-registry.ts`
5. Export from `packages/core/src/index.ts`
6. Write tests in `your-tool.test.ts`
7. Update documentation in `docs/tools/`

### API Key Management

API keys are loaded with this priority:

1. Environment variables (highest)
2. Settings file (`~/.qwen/settings.json`)
3. API Key Manager tool operations
4. Runtime parameters (lowest)

Access pattern in tools:

```typescript
const apiKey = process.env.SHODAN_API_KEY ||
               config.advanced?.shodanApiKey;
if (!apiKey) throw new ToolError(...);
```

### Error Handling in Tools

Use `ToolError` from `tool-error.ts`:

```typescript
import { ToolError, ToolErrorType } from './tool-error.js';

throw new ToolError('Error message', ToolErrorType.ExecutionError, {
  details: '...',
});
```

### Testing Patterns

- Unit tests: Use Vitest, place alongside source files
- Integration tests: Located in `/integration-tests/`
- Mock AI responses: Use MSW (Mock Service Worker) patterns from `packages/core/src/__mocks__/`
- Test utilities: `@darkcoder/darkcoder-test-utils` package

### Build System

**esbuild-based:**

- Entry point: `esbuild.config.js` (root)
- Individual package builds: `scripts/build_package.js`
- Bundle includes polyfills and shims from `scripts/esbuild-shims.js`
- Handles `.node` native modules
- VSCode extension has separate build: `scripts/build_vscode_companion.js`

## Configuration Files

- `tsconfig.json`: Root TypeScript config (composite project)
- `vitest.config.ts`: Test configuration (multi-project setup)
- `package.json`: Workspace configuration
- `.husky/`: Git hooks (pre-commit, etc.)
- `eslint.config.js`: Linting rules
- `.prettierrc`: Code formatting

## Critical Notes

### ⚠️ Module Resolution (MOST IMPORTANT)

- **ALWAYS use `.js` extensions in imports** even for `.ts` files (NodeNext resolution requirement)
- Example: `import { foo } from './bar.js'` even though the actual file is `bar.ts`
- Forgetting this will cause build failures

### Memory Management

- Build commands use `NODE_OPTIONS='--max-old-space-size=8192'` due to large codebase
- Start script uses `NODE_OPTIONS='--no-deprecation'`

### TypeScript Configuration

- **Very strict compiler options** enabled (noImplicitAny, strictNullChecks, etc.)
- **ESM-only**: No CommonJS support
- Target: ES2022, Module: NodeNext
- `verbatimModuleSyntax: true` enforces explicit type imports

### Testing Security Tools

- Security tools with API keys should be tested using environment variables
- Integration tests support different sandbox modes via `GEMINI_SANDBOX` env var
- Some tests require actual API keys (mark as skip if not available)

### Workspace Dependencies

- Internal dependencies use `file:` protocol: `"@darkcoder/darkcoder-core": "file:../core"`
- Changes to core package require rebuilding dependent packages

### Shell Integration

- CLI supports shell completions for bash, zsh, and fish (`completion` command)
- Typo detection provides "did you mean?" suggestions for mistyped commands

## Special Directories

- `patches/`: Contains `patch-package` patches for npm dependencies
- `scripts/`: Build automation and utility scripts
- `vendor/`: Vendored dependencies (if any)
- `.claude/`: Claude Code configuration
- `docs/`: Extensive documentation (guides, tools, examples)

## Documentation References

- [README.md](README.md): Main project documentation
- [docs/](docs/): Comprehensive documentation
  - [SHELL_COMPLETIONS.md](docs/SHELL_COMPLETIONS.md): Shell completion setup
  - [TYPO_DETECTION.md](docs/TYPO_DETECTION.md): Command typo suggestions
  - [AI_DRIVEN_PARALLEL_EXECUTION.md](docs/AI_DRIVEN_PARALLEL_EXECUTION.md): **AI-driven parallel execution (recommended)**
  - [PARALLEL_EXECUTION_ISSUES_AND_FIXES.md](docs/PARALLEL_EXECUTION_ISSUES_AND_FIXES.md): **Critical fixes for file conflicts & error handling**
  - [PARALLEL_EXECUTION_INTEGRATION.md](docs/PARALLEL_EXECUTION_INTEGRATION.md): **Integration guide with code examples**
  - [PARALLEL_TOOL_EXECUTION.md](docs/PARALLEL_TOOL_EXECUTION.md): System-driven parallel execution (alternative)
  - [PARALLEL_EXECUTION_QUICK_START.md](docs/PARALLEL_EXECUTION_QUICK_START.md): User guide for parallel execution
  - [NUCLEI_INTEGRATION_GUIDE.md](docs/NUCLEI_INTEGRATION_GUIDE.md): Nuclei scanner integration
  - [FFUF_INTEGRATION_GUIDE.md](docs/FFUF_INTEGRATION_GUIDE.md): ffuf fuzzer integration
  - [DARKCODER_SETUP_GUIDE.md](docs/DARKCODER_SETUP_GUIDE.md): Setup instructions
  - [MULTI_PROVIDER_SYSTEM.md](docs/MULTI_PROVIDER_SYSTEM.md): AI provider configuration
  - [COST_TRACKING_GUIDE.md](docs/COST_TRACKING_GUIDE.md): Cost tracking features
  - Tool-specific guides (CUCKOO_INTEGRATION_GUIDE.md, YARAIFY_INTEGRATION_GUIDE.md)

## Debugging Tips

- Use `DEBUG=1` environment variable for verbose logging
- Inspector debugging: `npm run debug` (opens Node.js inspector)
- CLI debug mode: `darkcoder --debug`
- Test debugging: Add `--inspect-brk` to vitest commands

## Build Output

- Compiled JavaScript: `packages/*/dist/`
- Root bundle: `dist/cli.js` (entry point)
- VSCode extension: `packages/vscode-ide-companion/dist/`
- Source maps enabled for all builds
