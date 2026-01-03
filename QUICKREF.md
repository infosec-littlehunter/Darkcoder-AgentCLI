# Quick Reference Guide

Fast lookup for common tasks and commands.

## Setup & Installation

**Windows:**

```cmd
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
npm install && npm run build
npm run doctor
```

**macOS/Linux:**

```bash
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
make setup

# Or step by step
npm install
npm run build
npm run doctor  # Verify everything works
```

## Daily Development

**Windows (npm):**

```cmd
npm start
npm run build
npm test
npm run lint
npm run lint:fix
npm run format
```

**macOS/Linux (make or npm):**

```bash
npm start        # Same on all platforms
make help        # macOS/Linux only

# Common tasks
make build       # Build project
make test        # Run tests
make lint        # Check code style
make lint-fix    # Fix code style
make format      # Format with prettier

# Or use npm on all platforms
npm run build
npm test
npm run lint
npm run lint:fix
npm run format
```

## Troubleshooting

**Windows:**

```cmd
npm run doctor                                          # Run diagnostic
npm config set node-options "--max-old-space-size=8192"  # Memory config
```

**macOS/Linux:**

```bash
npm run doctor                  # Run diagnostic
NODE_OPTIONS="--max-old-space-size=8192" npm run build
npm config set node-options "--max-old-space-size=8192"
```

Help resources:

```bash
cat TROUBLESHOOTING.md   # Common issues
cat BUILD.md             # Build errors
cat SETUP.md             # Setup problems
```

## Git Workflow

**Windows:**

```cmd
git checkout -b feature/your-feature-name
# ... edit files ...
npm run lint:fix && npm test
git add .
git commit -m "feat: description"
git push origin feature/your-feature-name
```

**macOS/Linux:**

```bash
git checkout -b feature/your-feature-name
# ... edit files ...
make lint-fix && make test   # or: npm run lint:fix && npm test
git add .
git commit -m "feat: description"
git push origin feature/your-feature-name
```

## Useful Files

| File                                        | Purpose                             |
| ------------------------------------------- | ----------------------------------- |
| [SETUP.md](../SETUP.md)                     | First-time setup (read this first!) |
| [BUILD.md](../BUILD.md)                     | Build troubleshooting               |
| [CONTRIBUTING.md](../CONTRIBUTING.md)       | Contribution guidelines             |
| [ARCHITECTURE.md](../ARCHITECTURE.md)       | Project structure                   |
| [DEPENDENCIES.md](../DEPENDENCIES.md)       | Dependency information              |
| [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) | Common issues                       |
| [Makefile](../Makefile)                     | Command reference (macOS/Linux)     |

## System Requirements

- **Node.js**: v20 or higher
- **npm**: v10 or higher
- **RAM**: 8GB minimum (16GB recommended)
- **Disk**: 2GB+ free space

## Environment Setup

**Windows (PowerShell as Admin):**

```cmd
[Environment]::SetEnvironmentVariable("NODE_OPTIONS", "--max-old-space-size=8192", "User")
```

Or use npm config:

```cmd
npm config set node-options "--max-old-space-size=8192"
```

**macOS/Linux:**

```bash
echo 'export NODE_OPTIONS="--max-old-space-size=8192"' >> ~/.bashrc
source ~/.bashrc
```

Or use npm config:
npm config set node-options "--max-old-space-size=8192"

````

## Testing

```bash
make test                      # Run all tests
npm test -- --watch           # Watch mode
npm test -- path/to/test.ts   # Specific test
npm test -- --coverage        # With coverage
````

## Code Quality

```bash
make lint                  # Check for issues
make lint-fix              # Fix automatically
make format                # Format code
make preflight             # Full checks (lint + test + build)
```

## Package Management

```bash
# Add dependency to main project
npm install package-name

# Add to specific package
npm install --workspace=packages/cli package-name

# Check for vulnerabilities
npm audit

# Update dependencies
npm update
npm outdated  # See what's available
```

## Performance Tuning

```bash
# Fast build for development
npm run build:managed

# Memory-optimized build
NODE_OPTIONS="--max-old-space-size=4096" npm run build

# Low memory
NODE_OPTIONS="--max-old-space-size=2048" npm run build

# High memory
NODE_OPTIONS="--max-old-space-size=16384" npm run build
```

## Cleaning Up

```bash
# Remove build artifacts
npm run clean

# Remove everything (careful!)
npm run clean
rm -rf node_modules package-lock.json
npm install
```

## Helpful npm Scripts

```bash
npm start              # Start CLI
npm run build          # Build project
npm test               # Run tests
npm run lint           # Lint code
npm run format         # Format code
npm run typecheck      # Check types
npm run doctor         # Run diagnostics
npm run preflight      # Full checks
npm run clean          # Clean artifacts
```

## VS Code Setup

**Recommended Extensions:**

- ESLint
- Prettier
- TypeScript Vue (if working with Vue)

**VS Code Settings** (`.vscode/settings.json`):

```json
{
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

## Getting Help

1. **Check documentation**: [SETUP.md](../SETUP.md), [BUILD.md](../BUILD.md)
2. **Run diagnostic**: `npm run doctor`
3. **Search issues**: https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues
4. **Read troubleshooting**: [TROUBLESHOOTING.md](../TROUBLESHOOTING.md)
5. **Ask in discussions**: https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions

## Monorepo Commands

```bash
# Build all packages
npm run build:packages

# Build specific package
npm run build -w packages/cli

# Run tests in all packages
npm test --workspaces

# Install in specific package
npm install --workspace=packages/cli package-name
```

## One-Liner Commands

```bash
# Full setup
git clone [repo] && cd AssistanceAntiCyber-Darkcoder-CLI && make setup

# Quick health check
npm run doctor

# Fix all issues
npm run format && npm run lint:fix

# Run everything
npm run preflight

# Deep clean and reinstall
npm run clean && rm -rf node_modules && npm install && npm run build
```

---

**Pro Tip**: Bookmark [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) - you'll need it! 😉
