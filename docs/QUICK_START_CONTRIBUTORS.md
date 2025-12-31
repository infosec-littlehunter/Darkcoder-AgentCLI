# 🎯 Quick Start Guide for GitHub Contributors

## Overview

DarkCoder is an **AI Security Operations Agent** with:

- Live CVE intelligence integration
- Memory-safe processing (5-layer defense)
- 58+ security tools
- 29+ AI model support

**Latest Version**: 0.7.0

---

## 🚀 Quick Setup (5 Minutes)

### 1. Fork & Clone

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI/darkcoder
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Build

```bash
npm run build
```

**Build time**: ~30-60 seconds  
**Memory usage**: ~500MB peak

### 4. Link & Test

```bash
npm link
darkcoder --version  # Should show: 0.7.0
darkcoder "Hello, DarkCoder!"
```

---

## 📁 Project Structure

```
darkcoder/
├── packages/
│   ├── cli/              # 🖥️  Command-line interface
│   ├── core/            # 🔧 Core functionality (security tools here!)
│   ├── sdk-typescript/  # 📦 TypeScript SDK
│   └── vscode-ide-companion/  # 🎨 VS Code extension
├── docs/                # 📚 Documentation
├── scripts/            # 🛠️  Build scripts
└── integration-tests/  # ✅ Test suite
```

**Key directories for contributors**:

- `packages/core/src/tools/` - Security tool implementations
- `docs/tools/` - Tool documentation
- `integration-tests/` - Integration tests

---

## 🎯 Common Contribution Areas

### 1. Add a New Security Tool

**Location**: `packages/core/src/tools/your-tool.ts`

**Template**:

```typescript
import { BaseDeclarativeTool, Kind } from './tools.js';

export class YourSecurityTool extends BaseDeclarativeTool {
  constructor() {
    super(
      'your_tool',
      'Your Tool Name',
      'Description of what your tool does',
      Kind.Fetch,
      {
        properties: {
          target: { type: 'string', description: 'Target to analyze' },
        },
        required: ['target'],
      },
    );
  }

  // 🔒 MEMORY OPTIMIZATION: Always set limits
  private readonly MAX_RESULTS = 20;

  async execute(params: ToolParams): Promise<ToolResult> {
    // Your implementation here
    // MUST include memory safety patterns (see CONTRIBUTING.md)
  }
}
```

**Required**:

- ✅ Memory safety limits (MAX_ITEMS constants)
- ✅ Set-based deduplication (O(1) not O(n²))
- ✅ Tests in `your-tool.test.ts`
- ✅ Documentation in `docs/tools/your-tool.md`

### 2. Improve Documentation

**Easy wins**:

- Fix typos in README.md
- Add examples to `docs/examples/`
- Improve tool descriptions
- Add screenshots/demos

**Process**:

1. Edit markdown files
2. Preview locally
3. Submit PR

### 3. Fix Bugs

**Check**: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)

**Process**:

1. Comment on issue you want to fix
2. Create branch: `fix/issue-123`
3. Fix + add test
4. Submit PR with "Fixes #123"

### 4. Add Tests

**Location**: `packages/core/src/tools/*.test.ts`

**Example**:

```typescript
describe('YourTool', () => {
  test('enforces memory limits', () => {
    const largeInput = generateData(1000);
    const result = yourTool.execute(largeInput);
    expect(result.items.length).toBeLessThanOrEqual(20);
  });
});
```

---

## 📝 Commit Guidelines

**Format**: `type(scope): description`

**Types**:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (no logic change)
- `refactor`: Code refactoring
- `test`: Test-related
- `chore`: Build/dependencies

**Examples**:

```bash
git commit -m "feat(shodan): Add CVE intelligence integration"
git commit -m "fix(nuclei): Prevent heap overflow on large scans"
git commit -m "docs: Update installation instructions"
```

---

## ✅ Pre-Commit Checklist

Before pushing:

- [ ] Code builds: `npm run build`
- [ ] Tests pass: `npm test`
- [ ] Linting passes: `npm run lint`
- [ ] No TypeScript errors
- [ ] Memory limits set (if adding security tool)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if significant)

---

## 🔒 Memory Safety Requirements

**CRITICAL for security tools**:

### ❌ WRONG (O(n²) - causes heap overflow)

```typescript
for (const item of items) {
  if (!results.find((r) => r.id === item.id)) {
    results.push(item);
  }
}
```

### ✅ CORRECT (O(1) - memory safe)

```typescript
const MAX_RESULTS = 20;
const seen = new Set<string>();

for (const item of items) {
  if (results.length >= MAX_RESULTS) break;

  if (!seen.has(item.id)) {
    seen.add(item.id);
    results.push(item);
  }
}
```

**Why?**:

- Prevents JavaScript heap out of memory errors
- O(1) Set lookups vs O(n) array.find()
- Explicit limits prevent unbounded growth

**See**: [CONTRIBUTING.md](CONTRIBUTING.md) section "Memory Safety Requirements"

---

## 🧪 Testing Your Changes

### Unit Tests

```bash
npm test
```

### Integration Tests

```bash
npm run test:integration:sandbox:none
```

### Manual Testing

```bash
npm link
darkcoder "Test your feature"
```

---

## 📤 Submitting Pull Request

### 1. Create Branch

```bash
git checkout -b feature/my-awesome-feature
```

### 2. Make Changes & Commit

```bash
git add .
git commit -m "feat(tool): Add awesome feature"
```

### 3. Push to Fork

```bash
git push origin feature/my-awesome-feature
```

### 4. Open PR on GitHub

- Clear title: "Add CVE intelligence to Shodan tool"
- Description: What, why, how
- Reference issues: "Fixes #123"
- Screenshots/examples if applicable

### 5. Address Review Comments

- Push new commits
- Don't force push (unless requested)

---

## 💡 Tips for Success

### Good First Issues

Look for labels:

- `good first issue`
- `documentation`
- `help wanted`

### Communication

- Ask questions in PR/issue comments
- Be patient (maintainers are volunteers)
- Be respectful and constructive

### Quality Over Quantity

- One well-tested feature > five broken features
- Good documentation = happy users
- Memory safety is non-negotiable

---

## 📚 Resources

### Documentation

- [README.md](README.md) - Main documentation
- [CONTRIBUTING.md](CONTRIBUTING.md) - Detailed guidelines
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [docs/](docs/) - Tool-specific docs

### Examples

- `docs/examples/` - Usage examples
- `integration-tests/` - Test examples
- `packages/core/src/tools/` - Tool implementations

### Support

- **Issues**: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions)

---

## 🎉 Welcome!

Thank you for contributing to DarkCoder! Every contribution makes the security community stronger.

**Questions?** Open a discussion or comment on an issue.

**Ready to code?** Check out [good first issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and dive in!

---

**Happy hacking! 🔐**
