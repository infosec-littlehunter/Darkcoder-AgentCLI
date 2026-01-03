# Build & Compilation Guide for DarkCoder

Complete guide for building DarkCoder across different machines and environments.

## Quick Start

```bash
# Clone repository
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# Install dependencies
npm install

# Build the project
npm run build

# Verify installation
npm start
```

## Prerequisites

### Required

- **Node.js**: v20.0.0 or higher
  - Check: `node --version`
  - Download: https://nodejs.org/

- **npm**: v10.0.0 or higher
  - Comes with Node.js
  - Update: `npm install -g npm@latest`

- **Git**: v2.0 or higher
  - Check: `git --version`
  - Download: https://git-scm.com/

### Recommended System Resources

| Resource   | Minimum | Recommended |
| ---------- | ------- | ----------- |
| RAM        | 8 GB    | 16+ GB      |
| Disk Space | 2 GB    | 5+ GB       |
| CPU        | 2 cores | 4+ cores    |

## Build Commands

### Standard Build

```bash
npm run build
```

**Best for**: Most developers and CI/CD pipelines

### Memory-Optimized Builds

For machines with limited memory:

```bash
# Low memory machines (4GB heap)
npm run build:managed

# High memory machines (16GB heap)
npm run build:safe
```

### Build with Bun (Optional - Faster)

```bash
# Requires bun: https://bun.sh/docs/installation
npm run build:bun
```

### Build Specific Packages

```bash
# Build all workspace packages
npm run build:packages

# Build CLI only
npm run build -w packages/cli

# Build core only
npm run build -w packages/core

# Build VS Code companion
npm run build:vscode
```

### Full Build (All Artifacts)

```bash
# Includes CLI, sandbox, and VS Code extension
npm run build:all
```

## Memory Configuration

### Problem

DarkCoder may encounter heap overflow on machines with limited memory:

```
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory
```

### Recommended Settings

| System     | NODE_OPTIONS                |
| ---------- | --------------------------- |
| 4 GB RAM   | `--max-old-space-size=2048` |
| 8 GB RAM   | `--max-old-space-size=4096` |
| 16+ GB RAM | `--max-old-space-size=8192` |

### Solution - Windows

**Option 1: Persistent Configuration (Recommended)**

```cmd
npm config set node-options "--max-old-space-size=8192"
```

Verify it was set:

```cmd
npm config get node-options
```

**Option 2: Environment Variable (Permanent)**

```cmd
# PowerShell (Admin)
[Environment]::SetEnvironmentVariable("NODE_OPTIONS", "--max-old-space-size=8192", "User")

# Command Prompt (Admin)
setx NODE_OPTIONS "--max-old-space-size=8192"
```

After setting, restart your terminal and PowerShell.

**Option 3: Per-Command (Temporary)**

```cmd
# PowerShell
$env:NODE_OPTIONS="--max-old-space-size=8192"; npm run build

# Command Prompt
set NODE_OPTIONS=--max-old-space-size=8192 && npm run build
```

### Solution - macOS/Linux

**Option 1: Environment Variable (Recommended)**

Add to `~/.bashrc`, `~/.zshrc`, or `~/.profile`:

```bash
export NODE_OPTIONS="--max-old-space-size=8192"
```

Reload shell:

```bash
source ~/.bashrc  # or ~/.zshrc or ~/.profile
```

**Option 2: Per-Command**

```bash
NODE_OPTIONS="--max-old-space-size=8192" npm run build
NODE_OPTIONS="--max-old-space-size=8192" npm start
```

**Option 3: npm Config**

```bash
npm config set node-options "--max-old-space-size=8192"
```

## Troubleshooting

### Issue: Heap Out of Memory

**Error**: `JavaScript heap out of memory`

**Solution**:

1. Increase heap size: `NODE_OPTIONS="--max-old-space-size=8192"`
2. Free up system memory (close other applications)
3. Run: `npm run clean && npm install && npm run build`

### Issue: Module Not Found

**Error**: `Cannot find module '@darkcoder/...'`

**Solution**:

1. Install all dependencies: `npm install`
2. Rebuild packages: `npm run build:packages`
3. Clear cache: `npm cache clean --force`

### Issue: TypeScript Errors

**Error**: `error TS...` during build

**Solution**:

1. Run type checking: `npm run typecheck`
2. Check tsconfig.json is valid
3. Update TypeScript: `npm install typescript@latest`

### Issue: Port Already in Use

**Error**: `EADDRINUSE: address already in use :::3000`

**Solution - Windows**:

```cmd
# PowerShell - Find process using port 3000
Get-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess

# Kill the process (replace PID with actual process ID)
Stop-Process -Id <PID> -Force

# Or use a different port
$env:PORT="3001"; npm start
```

**Solution - macOS/Linux**:

```bash
# Find process using port 3000
lsof -i :3000

# Kill the process
kill -9 <PID>

# Or use a different port
PORT=3001 npm start
```

### Issue: Build Hangs or Freezes

**Error**: Process hangs with no output

**Solution - Windows**:

1. Check available disk space: `Get-Volume` (PowerShell)
2. Task Manager → check CPU/Memory usage
3. Try: `npm run clean && npm install && npm run build`
4. Increase memory limit (see Memory Configuration section)

**Solution - macOS/Linux**:

1. Check available disk space: `df -h`
2. Increase timeout: `npm config set fetch-timeout 120000`
3. Use verbose mode: `npm run build -- --verbose`
4. Try clean build: `npm run clean && npm install && npm run build`

### Issue: Permission Denied

**Error**: `EACCES: permission denied`

**Solution - Windows**:

Run terminal as Administrator, or configure npm to not require sudo:

```cmd
npm config set prefix "C:\Users\%USERNAME%\AppData\Roaming\npm"
```

**Solution - macOS/Linux**:

```bash
# Fix npm permissions
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
export PATH=~/.npm-global/bin:$PATH

# Or use sudo (not recommended)
sudo npm install
```

## Platform-Specific Notes

### macOS

```bash
# Install Xcode Command Line Tools if needed
xcode-select --install

# Use Homebrew for Node.js (recommended)
brew install node@20
```

### Linux

```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Fedora/RHEL
sudo dnf install nodejs

# Arch
sudo pacman -S nodejs npm
```

### Windows

1. Download Node.js from https://nodejs.org/
2. Run installer (includes npm)
3. Open new terminal and verify: `node --version`

## Development Build

For faster iteration during development:

```bash
# Watch mode for changes
npm run dev

# Or with TypeScript watching
npm run typecheck -- --watch
```

## Testing After Build

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run specific test file
npm test -- path/to/test.ts

# Run integration tests
npm run test:integration:sandbox:none
```

## Verification Steps

After successful build, verify:

1. **Binary exists**:

   ```bash
   test -f dist/cli.js && echo "✓ CLI built" || echo "✗ CLI missing"
   ```

2. **Dependencies installed**:

   ```bash
   npm list | head -20
   ```

3. **No errors**:

   ```bash
   npm run lint
   npm run typecheck
   ```

4. **Run CLI**:
   ```bash
   npm start --help
   ```

## Cleaning Build Artifacts

```bash
# Remove all generated files
npm run clean

# Remove node_modules and lock file
rm -rf node_modules package-lock.json
npm install

# Full reset
npm run clean && rm -rf node_modules && npm install
```

## CI/CD Build

For automated builds (GitHub Actions, etc.):

```bash
# Use consistent environment
npm ci  # Instead of npm install

# Run full checks
npm run preflight

# Build
npm run build

# Test
npm run test:ci

# Lint
npm run lint:ci
```

## Getting Help

- **Documentation**: See [docs/](./docs/)
- **Issues**: Report at https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues
- **Discussions**: Ask at https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions
- **Developer Setup**: See [docs/DEVELOPER_SETUP.md](./docs/DEVELOPER_SETUP.md)
