# Contributing to DarkCoder

Thank you for your interest in contributing to DarkCoder! This document provides guidelines and instructions for contributing to the project across all platforms (Windows, macOS, Linux).

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct. By participating in this project, you agree to abide by its terms.

## Quick Start for Contributors

**New to the project?** Follow these steps to get started:

1. **Read the Setup Guides**:
   - [SETUP.md](./SETUP.md) - First-time setup (5 min) - **Includes Windows instructions!**
   - [BUILD.md](./BUILD.md) - Building troubleshooting
   - [ARCHITECTURE.md](./ARCHITECTURE.md) - Project structure

2. **Clone and Setup**:

   **On Windows:**

   ```bash
   git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
   cd AssistanceAntiCyber-Darkcoder-CLI
   npm install && npm run build
   ```

   **On macOS/Linux:**

   ```bash
   git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
   cd AssistanceAntiCyber-Darkcoder-CLI
   make setup  # or npm install && npm run build
   ```

3. **Verify Installation**:

   ```bash
   npm run doctor
   npm start --help
   ```

4. **Make Your Changes**:

   **On Windows:**

   ```bash
   git checkout -b feature/your-feature-name
   # Make changes and test
   npm run lint:fix && npm test
   git commit -m "feat: description"
   git push origin feature/your-feature-name
   ```

   **On macOS/Linux:**

   ```bash
   git checkout -b feature/your-feature-name
   # Make changes and test
   make lint-fix && make test
   git commit -m "feat: description"
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** with details about your changes

## Getting Started

### Prerequisites

- **Node.js** v20.0.0 or higher
- **npm** v10.0.0 or higher
- **Git**
- Optional: At least one AI provider API key (OpenAI, Anthropic, etc.)

### Development Setup

**Option A: Using npm (All Platforms, Recommended for Windows)**

```bash
# Clone the repository
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# Install and build
npm install && npm run build

# Verify
npm run doctor
```

**Option B: Using Makefile (macOS/Linux only)**

```bash
# Clone
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# One-command setup
make setup
```

**Windows Users**: Use Option A above. See [SETUP.md](./SETUP.md#windows-setup) for Windows-specific instructions.

For detailed setup instructions with troubleshooting, see [SETUP.md](./SETUP.md).

## Development Workflow

### Create a Branch

```bash
git checkout -b feature/your-feature-name
# or for bug fixes:
git checkout -b fix/your-bug-fix-name
# or for documentation:
git checkout -b docs/update-feature-docs
```

### Available Commands

**All Platforms (npm):**

```bash
npm run build      # Build
npm test           # Test
npm run lint       # Lint
npm run lint:fix   # Fix linting issues
npm run format     # Format code
npm start          # Run CLI
npm run doctor     # Health check
```

**macOS/Linux (make):**

```bash
make build         # Build
make test          # Test
make lint          # Lint
make lint-fix      # Fix linting issues
make format        # Format code
make start         # Run CLI
make doctor        # Health check
```

See [QUICKREF.md](./QUICKREF.md) for all available commands.

### Code Quality

#### All Platforms:

```bash
# Check code style
npm run lint

# Fix code style automatically
npm run lint:fix

# Format code
npm run format
```

Pre-commit hooks will automatically run formatting and linting when you commit.

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run specific test file
npm test -- path/to/test.ts

# Run with coverage
npm test -- --coverage
```

### Writing Tests

- Place test files alongside source files with `.test.ts` suffix
- Use Vitest for unit tests
- Aim for good coverage of critical functionality
- For security tools, ensure memory safety tests are included

## Commit Guidelines

Follow conventional commit format:

```
type(scope): description

body (optional)

footer (optional)
```

**Types:**

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (no logic changes)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test-related changes
- `chore`: Build, dependencies, or tooling changes

**Examples:**

```
feat(shodan): Add support for host history
fix(api-keys): Resolve undefined key error
docs: Update installation instructions
```

## Pull Request Process

1. **Create Feature Branch**

   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make Changes and Commit**
   - Keep commits atomic and well-described
   - Follow commit guidelines above

3. **Push to Your Fork**

   ```bash
   git push origin feature/my-feature
   ```

4. **Create Pull Request**
   - Use a clear title describing the changes
   - Reference related issues: `Fixes #123`
   - Provide detailed description of changes
   - Include testing instructions if applicable

5. **Address Review Comments**
   - Push new commits addressing feedback
   - Don't force push unless requested

6. **Merge**
   - Project maintainers will merge your PR once approved

## Package Structure

```
darkcoder/
├── packages/              # Monorepo packages
│   ├── cli/              # Main CLI application
│   ├── core/             # Core functionality and tools
│   ├── sdk-typescript/   # TypeScript SDK for programmatic use
│   ├── test-utils/       # Shared testing utilities
│   └── vscode-ide-companion/  # VS Code extension
├── docs/                 # Comprehensive documentation
├── scripts/              # Build and utility scripts
├── integration-tests/    # End-to-end integration tests
├── BUILD.md              # Build and compilation guide
├── SETUP.md              # First-time setup guide
├── ARCHITECTURE.md       # Project structure and design
└── Makefile              # Quick command reference
```

**For detailed project structure**, see [ARCHITECTURE.md](./ARCHITECTURE.md)

## Adding New Security Tools

To add a new security tool integration:

1. **Create Tool File**: `packages/core/src/tools/[tool-name].ts`
2. **Implement Tool Interface**: Extend `BaseDeclarativeTool` or `BaseTool`
3. **Add Memory Safety**: Follow memory optimization guidelines below
4. **Include Tests**: Create `packages/core/src/tools/[tool-name].test.ts`
5. **Update Documentation**: Add to `docs/tools/[tool-name].md`
6. **Export**: Add to `packages/core/src/tools/index.ts`

### Memory Safety Requirements (CRITICAL)

All new security tools MUST implement memory safety patterns to prevent heap overflow:

#### 1. Set Absolute Limits

```typescript
// 🔒 MEMORY OPTIMIZATION: Define maximum items
const MAX_PRODUCTS = 20; // Adjust based on data complexity
const MAX_OUTPUT_LENGTH = 100000; // 100KB max output
```

#### 2. Use Set-Based Deduplication (O(1) vs O(n²))

```typescript
// ❌ WRONG: O(n²) complexity
const products = [];
for (const item of items) {
  if (!products.find((p) => p.name === item.name)) {
    products.push(item);
  }
}

// ✅ CORRECT: O(1) with Set
const MAX_PRODUCTS = 20;
const seenProducts = new Set<string>();
const products = [];

for (const item of items) {
  if (products.length >= MAX_PRODUCTS) break; // Early termination

  const key = `${item.name}:${item.version}`;
  if (!seenProducts.has(key)) {
    seenProducts.add(key);
    products.push(item);
  }
}
```

#### 3. Early Break Conditions

```typescript
// Always break loops when limit reached
for (const item of items) {
  if (results.length >= MAX_ITEMS) break;
  // Process item
}
```

#### 4. Pre-Slice Large Arrays

```typescript
// Limit iterations upfront
const itemsToProcess = largeArray.slice(0, MAX_ITEMS_TO_PROCESS);
for (const item of itemsToProcess) {
  // Process safely
}
```

#### 5. CVE Intelligence Integration

If your tool detects software products, integrate with the CVE intelligence helper:

```typescript
import { formatCVEIntelligenceSection } from './cve-intelligence-helper.js';

// Extract products from your tool's output
const products = extractProducts(scanResults); // Your implementation

// Add CVE intelligence section (automatically memory-safe)
const cveIntelligence = formatCVEIntelligenceSection(
  products,
  'your-tool-name',
);

// Append to tool output
return originalOutput + '\n\n' + cveIntelligence;
```

The CVE helper automatically enforces:

- Input validation and limits
- Output size constraints (100KB max)
- Absolute maximum of 50 products
- Graceful truncation with warnings

### Security Tool Testing Requirements

1. **Unit Tests**: Test core functionality and edge cases
2. **Memory Safety Tests**: Verify limits are enforced
3. **API Mocking**: Use mock responses to avoid rate limits
4. **Error Handling**: Test failure modes (network errors, invalid API keys)
5. **CVE Intelligence**: If integrated, test with sample products

Example test structure:

```typescript
describe('MySecurityTool', () => {
  test('enforces max items limit', () => {
    const largeInput = generateLargeDataset(1000);
    const result = processTool(largeInput);
    expect(result.items.length).toBeLessThanOrEqual(MAX_ITEMS);
  });

  test('uses set-based deduplication', () => {
    const duplicateInput = generateDuplicates(100);
    const result = processTool(duplicateInput);
    expect(result.items).toHaveNoDuplicates();
  });
});
```

## Adding New Features

### API Endpoints

- Add to `packages/core/src/` with proper TypeScript types
- Include comprehensive tests
- Update relevant documentation

### CLI Commands

- Add command handler to `packages/cli/src/`
- Include help text and usage examples
- Test with `npm start`

### Bug Reports

Include:

- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Node version, etc.)
- Screenshots if applicable

### Feature Requests

Include:

- Use case and motivation
- Proposed solution
- Alternative approaches
- Examples of similar features

## Documentation

- Keep README.md up-to-date
- Document complex functionality with comments
- Update CHANGELOG.md for significant changes
- Add examples for new features

## Releasing

Only maintainers can publish releases. We follow semantic versioning:

- MAJOR: Breaking changes
- MINOR: New features
- PATCH: Bug fixes

## Questions?

- Check existing issues and discussions
- Open a new discussion for questions
- Read the documentation in `/docs`

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

## Attribution

Thank you for contributing to DarkCoder! Contributors will be recognized in the project.

---

**Happy contributing! 🎉**
