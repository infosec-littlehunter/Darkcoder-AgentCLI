# Dependencies Guide

Overview of key dependencies and their purpose in DarkCoder.

## Core Runtime Dependencies

### Runtime Execution

- **node**: v20.0.0+
- **npm**: v10.0.0+

### Primary Dependencies

| Package      | Version | Purpose        |
| ------------ | ------- | -------------- |
| `simple-git` | ^3.28.0 | Git operations |
| `punycode`   | ^2.3.1  | IDN encoding   |

## Development Dependencies

### Build & Compilation

- **`esbuild`** (^0.25.0) - Fast TypeScript/JavaScript bundler
- **`tsx`** (^4.20.3) - TypeScript executor for scripts

### Language & Type Checking

- **`typescript`** - Language compiler
- **`typescript-eslint`** (^8.30.1) - TypeScript linting

### Code Quality

- **`eslint`** (^9.24.0) - Code linting
- **`prettier`** (^3.5.3) - Code formatting
- **`eslint-config-prettier`** (^10.1.2) - ESLint/Prettier integration

### Testing

- **`vitest`** (^3.2.4) - Fast unit testing framework
- **`@vitest/coverage-v8`** (^3.1.1) - Code coverage
- **`msw`** (^2.10.4) - Mock service worker for API mocking

### Environment & Build

- **`cross-env`** (^7.0.3) - Cross-platform environment variables
- **`rimraf`** (^6.0.1) - Cross-platform file deletion
- **`glob`** (^11.0.0) - File pattern matching

### Utilities

- **`yargs`** (^17.7.2) - CLI argument parsing
- **`semver`** (^7.7.2) - Semantic versioning
- **`patch-package`** (^8.0.1) - Patch application for dependencies

## Optional Dependencies

These provide system-level functionality when available:

- `@lydell/node-pty-*` (1.1.0) - Terminal emulation (platform-specific)
- `node-pty` (^1.0.0) - Fallback terminal emulation

**Note**: These are optional; the project functions without them on systems that support alternative terminal access.

## Security & Vulnerability Management

### CVE Intelligence Integration

- Integrates with multiple vulnerability databases:
  - NVD (National Vulnerability Database)
  - Exploit-DB
  - VirusTotal
  - Shodan
  - CISA KEV
  - VulnDB

### Dependency Updates

- Regular vulnerability scanning
- Automatic security updates where possible
- Manual review of breaking changes

## Dependency Auditing

### Check for Vulnerabilities

```bash
# Audit dependencies for known vulnerabilities
npm audit

# Fix vulnerabilities automatically (when possible)
npm audit fix

# Detailed audit report
npm audit --json | jq '.vulnerabilities'
```

### Review Locked Versions

```bash
# List all dependencies with versions
npm list

# Check for outdated packages
npm outdated
```

## Monorepo Workspaces

The project uses npm workspaces for package management:

```bash
# Install all workspace dependencies
npm install

# Install in specific workspace
npm install --workspace=packages/cli

# Run command in all workspaces
npm run build --workspaces

# List workspace dependencies
npm ls --workspaces
```

## Patched Dependencies

Some dependencies are patched for compatibility. Patches are stored in `/patches`:

```bash
# View applied patches
git ls-files patches/

# Apply patches (automatic during npm install)
npm install
```

## Adding New Dependencies

### For Main Project

```bash
# Add to root
npm install package-name

# Add as dev dependency
npm install --save-dev package-name
```

### For Specific Workspace

```bash
# Add to workspace
npm install --workspace=packages/cli package-name

# Add as dev dependency to workspace
npm install --save-dev --workspace=packages/cli package-name
```

### Guidelines

1. Check for security vulnerabilities before adding
2. Prefer packages with minimal dependencies
3. Consider bundle size impact
4. Ensure compatibility with Node.js v20+
5. Document the reason for adding in PR

## Dependency Conflicts

### Common Issues

**Issue**: `peer dependency missing` warning

```bash
# Check what's missing
npm ls --all

# Fix peer dependencies
npm install --legacy-peer-deps  # Last resort only
```

**Issue**: Multiple versions of same package

```bash
# Visualize dependency tree
npm ls package-name

# Deduplicate
npm dedupe
```

## Security Best Practices

### Before Using New Packages

1. Check GitHub repository: https://github.com/search?q=package-name
2. Review issue tracker for security concerns
3. Check npm security audit: `npm view package-name --json | jq '.vulnerabilities'`
4. Verify maintenance status

### Lockfile Management

- Commit `package-lock.json` to version control
- Use `npm ci` in CI/CD environments (not `npm install`)
- Review lockfile changes in PRs

## Performance Optimization

### Bundle Size

- Monitor bundle size with each release
- Tree-shake unused code in builds
- Prefer `@types/*` packages over bundled types

### Memory Management

- Set `NODE_OPTIONS="--max-old-space-size=8192"` in `.npmrc`
- Use memory-efficient build strategies
- Monitor heap usage during builds

## Updating Dependencies

### Safe Updates

```bash
# Update patch versions (recommended)
npm update

# Update to latest (review changes)
npm outdated  # See what's available
npm update package-name
```

### Major Version Updates

```bash
# Check for breaking changes
npm view package-name versions

# Review changelog before updating
# Update specific package
npm install package-name@latest

# Run full test suite
npm run preflight
```

## CI/CD Considerations

For reproducible builds:

```bash
# Use ci instead of install in CI environments
npm ci

# Verify lockfile integrity
npm ci --verify-integrity

# Run full preflight checks
npm run preflight
```

## Getting Help

- **Package documentation**: Visit package's npm page
- **Security advisories**: https://www.npmjs.com/advisories
- **Dependency issues**: Check project issues tracker
- **Breaking changes**: Review package CHANGELOG.md

---

For detailed setup, see [SETUP.md](./SETUP.md) or [BUILD.md](./BUILD.md)
