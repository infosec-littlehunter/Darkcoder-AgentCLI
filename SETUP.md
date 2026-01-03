# Project Setup Guide

Complete step-by-step guide for setting up DarkCoder for development on Windows, macOS, and Linux.

## Platform-Specific Notes

**Windows Users**: Use `npm run` commands instead of `make` commands (Makefiles don't work on Windows by default). See [Windows Setup](#windows-setup) below.

## Table of Contents

1. [One-Time Setup](#one-time-setup)
2. [Platform-Specific Setup](#platform-specific-setup)
3. [Verify Installation](#verify-installation)
4. [IDE Setup](#ide-setup)
5. [Configuration](#configuration)
6. [Troubleshooting](#troubleshooting)

## One-Time Setup

### Step 1: System Prerequisites

Ensure you have the required software installed:

```bash
# Check Node.js version (requires >= 20.0.0)
node --version

# Check npm version (requires >= 10.0.0)
npm --version

# Check git version
git --version
```

If any are missing, install them:

- **Node.js**: https://nodejs.org/ (choose LTS v20 or later)
- **npm**: Comes with Node.js (update with `npm install -g npm@latest`)
- **Git**: https://git-scm.com/

### Step 2: Clone Repository

```bash
# Clone the repository
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# Or if you forked it
git clone https://github.com/YOUR_USERNAME/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
```

### Step 3: Install Dependencies

```bash
# Install all dependencies
npm install

# This may take 2-5 minutes depending on internet speed
```

### Step 4: Build the Project

```bash
# Build the main project
npm run build

# If you encounter memory errors, try:
NODE_OPTIONS="--max-old-space-size=8192" npm run build
```

### Step 5: Verify Installation

```bash
# Run the diagnostic script
npm run doctor

# Or manually verify
npm start --help
```

## Platform-Specific Setup

### Windows Setup

Windows requires some additional configuration:

#### Option 1: Using npm (Recommended)

All commands work with `npm run`:

```bash
npm run build       # Build
npm run test        # Test
npm start           # Run CLI
npm run lint        # Lint
npm run format      # Format code
```

#### Option 2: Memory Configuration

Windows doesn't support shell profile variables the same way. Use npm config instead:

```cmd
# Set permanent memory for all npm commands
npm config set node-options "--max-old-space-size=8192"

# Or set for single command
set NODE_OPTIONS=--max-old-space-size=8192
npm run build
```

#### Option 3: Using make (Advanced - requires GNU Make)

If you want to use `make` commands on Windows:

1. Install [GNU Make for Windows](https://gnuwin32.sourceforge.net/packages/make.htm)
2. Add to PATH
3. Then use `make build`, `make test`, etc.

#### Windows Terminal Recommendation

Use [Windows Terminal](https://apps.microsoft.com/detail/9N0DX20HK701) for a better command-line experience.

### macOS Setup

```bash
# Install Xcode Command Line Tools if needed
xcode-select --install

# Use Homebrew for Node.js (recommended)
brew install node@20
```

All npm commands work normally:

```bash
npm run build
npm run test
npm start
```

Optionally configure memory for your shell:

```bash
echo 'export NODE_OPTIONS="--max-old-space-size=8192"' >> ~/.zshrc
source ~/.zshrc
```

### Linux Setup

Linux distributions vary. Common options:

**Ubuntu/Debian:**

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**Fedora/RHEL:**

```bash
sudo dnf install nodejs
```

**Arch:**

```bash
sudo pacman -S nodejs npm
```

Configure memory (optional):

```bash
echo 'export NODE_OPTIONS="--max-old-space-size=8192"' >> ~/.bashrc
source ~/.bashrc
```

## Verify Installation

### Quick Health Check

Run all checks at once:

```bash
npm run preflight
```

This runs:

- Dependency check
- Code formatting
- Linting
- Type checking
- Tests
- Build

### Individual Checks

```bash
# Check Node/npm versions
node --version && npm --version

# Verify dependencies
npm list 2>/dev/null | head -20

# Check TypeScript compilation
npm run typecheck

# Run linter
npm run lint

# Run tests
npm test
```

## IDE Setup

### VS Code (Recommended - All Platforms)

1. **Install Extensions**:
   - ESLint: `dbaeumer.vscode-eslint`
   - Prettier: `esbenp.prettier-vscode`
   - TypeScript Vue: `Vue.vscode-typescript-vue-plugin`

2. **VS Code Settings** (`.vscode/settings.json`):

   ```json
   {
     "editor.defaultFormatter": "esbenp.prettier-vscode",
     "editor.formatOnSave": true,
     "editor.codeActionsOnSave": {
       "source.fixAll.eslint": true
     },
     "search.exclude": {
       "**/node_modules": true,
       "dist": true,
       "build": true
     }
   }
   ```

3. **Run in Terminal**:
   ```bash
   npm start
   ```

### WebStorm / IntelliJ IDEA (All Platforms)

1. Open project folder
2. Enable ESLint in Settings → Languages & Frameworks → JavaScript → ESLint
3. Enable Prettier in Settings → Languages & Frameworks → JavaScript → Prettier

## Configuration

### Environment Variables

Create `.env.local` in project root:

```bash
# AI Provider APIs (choose at least one)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=ant-...
GOOGLE_API_KEY=AIzaSy...

# Optional: Security APIs
VIRUSTOTAL_API_KEY=...
SHODAN_API_KEY=...

# Optional: Memory configuration
NODE_OPTIONS="--max-old-space-size=8192"
```

### Memory Configuration

**For macOS/Linux**, add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
# For 8GB+ systems
export NODE_OPTIONS="--max-old-space-size=8192"

# Or for 4GB systems
export NODE_OPTIONS="--max-old-space-size=2048"
```

Apply immediately:

```bash
source ~/.bashrc  # or ~/.zshrc
```

## Troubleshooting

### npm install fails

**Issue**: Installation stops with errors

**Solutions**:

```bash
# Clear npm cache
npm cache clean --force

# Delete lock files
rm -rf node_modules package-lock.json

# Retry with verbose output
npm install --verbose

# Or use ci instead of install
npm ci
```

### Build fails with memory error

**Issue**: `FATAL ERROR: Reached heap limit Allocation failed`

**Solution**:

```bash
# Set heap size before building
NODE_OPTIONS="--max-old-space-size=8192" npm run build

# Or update npm config permanently
npm config set node-options "--max-old-space-size=8192"
```

### Port 3000 already in use

**Issue**: `EADDRINUSE: address already in use :::3000`

**Solution**:

```bash
# Use a different port
PORT=3001 npm start

# Or find and kill the process using port 3000
lsof -i :3000
kill -9 <PID>
```

### ESLint errors after install

**Issue**: ESLint can't find configuration

**Solution**:

```bash
# Reinstall eslint
npm install eslint@latest

# Clear eslint cache
npx eslint --reset-cache

# Run lint to verify
npm run lint
```

### TypeScript errors in editor

**Issue**: Red squiggles appear but `npm run typecheck` passes

**Solution**:

1. Reload VS Code: `Ctrl+Shift+P` → "Reload Window"
2. Select TypeScript version: `Ctrl+Shift+P` → "TypeScript: Select TypeScript Version"
3. Choose "Use Workspace Version"

### Build hangs indefinitely

**Issue**: `npm run build` hangs with no output for >10 minutes

**Solution**:

```bash
# Kill the process
Ctrl+C

# Clean everything
npm run clean

# Verify disk space
df -h

# Increase timeout
npm config set fetch-timeout 120000

# Retry build with verbose output
npm run build 2>&1 | tee build.log
```

## Next Steps

After setup completes successfully:

1. **Read Documentation**:
   - [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines
   - [BUILD.md](./BUILD.md) - Build guide
   - [docs/README.md](./docs/README.md) - Full documentation

2. **Start Development**:

   ```bash
   npm start
   ```

3. **Create a feature branch**:

   ```bash
   git checkout -b feature/my-feature
   ```

4. **Make changes and test**:

   ```bash
   npm test
   npm run lint
   ```

5. **Commit and push**:
   ```bash
   git add .
   git commit -m "feat: add my feature"
   git push origin feature/my-feature
   ```

## Getting Help

- **Issues**: https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues
- **Discussions**: https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions
- **Developer Docs**: [docs/DEVELOPER_SETUP.md](./docs/DEVELOPER_SETUP.md)
