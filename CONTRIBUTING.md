# Contributing to DarkCoder

Thank you for your interest in contributing to DarkCoder! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct. By participating in this project, you agree to abide by its terms.

## Getting Started

### Prerequisites

- Node.js v20.0.0 or higher
- npm 10.0.0 or higher
- Git
- At least one AI provider API key (OpenAI, Anthropic, etc.)

### Development Setup

1. **Fork and Clone**

   ```bash
   git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
   cd AssistanceAntiCyber-Darkcoder-CLI/darkcoder
   ```

2. **Install Dependencies**

   ```bash
   npm install
   ```

3. **Configure Settings**

   Create `~/.qwen/settings.json` with your preferences:

   ```bash
   mkdir -p ~/.qwen
   cp docs/examples/settings.example.json ~/.qwen/settings.json
   nano ~/.qwen/settings.json
   ```

   See [SETTINGS_GUIDE.md](./docs/SETTINGS_GUIDE.md) for details.

4. **Set Up API Keys**

   ```bash
   # Add to ~/.bashrc, ~/.zshrc, or equivalent
   export OPENAI_API_KEY="sk-proj-xxxxx"
   # OR choose another provider (ANTHROPIC_API_KEY, GOOGLE_API_KEY, etc.)
   ```

5. **Build the Project**

   ```bash
   npm run build
   ```

6. **Start Development**
   ```bash
   npm start
   ```

## Development Workflow

### Create a Branch

```bash
git checkout -b feature/your-feature-name
# or for bug fixes:
git checkout -b fix/your-bug-fix-name
```

### Code Style

We use ESLint and Prettier for code style. Before committing:

```bash
# Run linting
npm run lint

# Format code
npm run format

# Or let pre-commit hooks handle it
git add .
git commit -m "your message"
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run specific test file
npm test -- path/to/test.ts
```

### Writing Tests

- Place test files alongside source files with `.test.ts` suffix
- Use Vitest for unit tests
- Aim for good coverage of critical functionality

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
├── packages/
│   ├── cli/                 # Main CLI package
│   ├── core/               # Core functionality
│   ├── sdk-typescript/     # TypeScript SDK
│   ├── test-utils/         # Testing utilities
│   └── vscode-ide-companion/  # VS Code extension
├── docs/                   # Documentation
├── scripts/                # Build and utility scripts
└── integration-tests/      # Integration tests
```

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
