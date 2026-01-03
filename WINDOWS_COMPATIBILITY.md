# Windows Compatibility Guide

This document describes the cross-platform compatibility improvements made to support Windows, macOS, and Linux developers equally.

## Overview

DarkCoder now has full Windows support with JavaScript-based equivalents for all shell scripts, making the project truly cross-platform compatible.

## What Was Changed

### 1. Shell Scripts Converted to JavaScript

Three bash shell scripts were converted to cross-platform JavaScript equivalents:

| Original Script             | JavaScript Replacement      | npm Script               | Purpose                         |
| --------------------------- | --------------------------- | ------------------------ | ------------------------------- |
| `scripts/setup-settings.sh` | `scripts/setup-settings.js` | `npm run setup:settings` | Configure ~/.qwen/settings.json |
| `scripts/setup-memory.sh`   | `scripts/setup-memory.js`   | `npm run setup:memory`   | Configure NODE_OPTIONS memory   |
| `scripts/create_alias.sh`   | `scripts/create-alias.js`   | `npm run setup:alias`    | Create CLI command aliases      |

**Why**: Bash shell scripts cannot run on Windows without additional tools (WSL, Git Bash, etc.). JavaScript scripts run on any platform with Node.js.

### 2. New npm Scripts Added

Three new npm scripts were added to [package.json](./package.json):

```json
"setup:settings": "node scripts/setup-settings.js",
"setup:memory": "node scripts/setup-memory.js",
"setup:alias": "node scripts/create-alias.js"
```

These scripts use Node.js built-in modules to detect the operating system and provide appropriate guidance.

### 3. Documentation Updated for Cross-Platform

All documentation has been updated with Windows-specific guidance:

| File                                       | Changes                                                                                                            |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| [CONTRIBUTING.md](./CONTRIBUTING.md)       | Added Windows vs macOS/Linux command examples in Quick Start, Development Setup, and Development Workflow sections |
| [SETUP.md](./SETUP.md)                     | Added Windows Setup, macOS Setup, and Linux Setup sections with platform-specific instructions                     |
| [BUILD.md](./BUILD.md)                     | Added Windows memory configuration (npm config, setx, Environment Variables) and Windows troubleshooting           |
| [QUICKREF.md](./QUICKREF.md)               | Separated commands by platform (Windows uses npm, macOS/Linux use make or npm)                                     |
| [GETTING_STARTED.md](./GETTING_STARTED.md) | Added Windows-specific navigation and command alternatives                                                         |

## Using on Windows

### Option 1: npm Commands (Recommended)

All commands work with npm on Windows:

```cmd
npm install         # Install dependencies
npm run build       # Build
npm test            # Test
npm start           # Run CLI
npm run lint        # Lint
npm run lint:fix    # Fix linting issues
npm run format      # Format code
npm run doctor      # Health check
```

### Option 2: Windows Terminal with PowerShell

Use [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) with PowerShell for better command-line experience.

### Option 3: Make (Advanced)

If you want to use `make` commands:

1. Install [GNU Make for Windows](https://gnuwin32.sourceforge.net/packages/make.htm)
2. Add to PATH
3. Use `make build`, `make test`, etc.

## Memory Configuration on Windows

### Problem

On Windows, heap overflow errors may occur if Node.js doesn't have enough memory allocated:

```
FATAL ERROR: Reached heap limit - JavaScript heap out of memory
```

### Solution 1: npm Config (Permanent)

```cmd
npm config set node-options "--max-old-space-size=8192"
```

Verify:

```cmd
npm config get node-options
```

### Solution 2: Environment Variable (PowerShell)

```powershell
# As Administrator
[Environment]::SetEnvironmentVariable("NODE_OPTIONS", "--max-old-space-size=8192", "User")
```

Then restart your terminal.

### Solution 3: Command Prefix (Temporary)

```powershell
$env:NODE_OPTIONS="--max-old-space-size=8192"; npm run build
```

### Recommended Values

- 4 GB RAM: `--max-old-space-size=2048`
- 8 GB RAM: `--max-old-space-size=4096`
- 16+ GB RAM: `--max-old-space-size=8192`

## How the JavaScript Scripts Work

### setup-settings.js

Configures the settings file at `~/.qwen/settings.json`:

**Windows**: Provides instructions for manual configuration
**macOS/Linux**: Automatically sets up the settings file

Usage: `npm run setup:settings`

### setup-memory.js

Configures Node.js memory allocation via NODE_OPTIONS environment variable:

**Windows Options**:

- Use `npm config` (recommended)
- Use `setx` to set persistent environment variables
- Use PowerShell environment variable

**macOS/Linux**:

- Appends to shell configuration files (.bashrc, .zshrc)

Usage: `npm run setup:memory`

### create-alias.js

Creates a shortcut to run DarkCoder CLI easily:

**Windows**:

- Shows instructions for `doskey` (command-line aliases)
- Shows how to create batch files

**macOS/Linux**:

- Adds alias to .bashrc or .zshrc

Usage: `npm run setup:alias`

## Testing Cross-Platform Compatibility

### Windows (PowerShell)

```powershell
# Clone and setup
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# Install and build
npm install
npm run build

# Run tests
npm test

# Verify
npm run doctor
```

### macOS/Linux

```bash
# Clone and setup
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI

# Using make
make setup
make test

# Or using npm
npm install && npm run build && npm test
npm run doctor
```

## Troubleshooting

### Issue: npm commands don't work

**Solution**:

- Ensure Node.js v20+ is installed: `node --version`
- Update npm: `npm install -g npm@latest`
- Clear npm cache: `npm cache clean --force`

### Issue: Heap out of memory on Windows

**Solution**:

- Set memory limit (see Memory Configuration section above)
- Close other applications to free up RAM
- Try building with `npm run clean && npm install && npm run build`

### Issue: Long paths on Windows (exceeds 260 characters)

**Solution**:

- Use a shorter project path (avoid deep nested folders)
- Or enable long paths in Windows: See [docs/windows-long-paths.md](./docs/windows-long-paths.md)

### Issue: File permissions error (EACCES)

**Windows Solution**:

- Run terminal as Administrator
- Or configure npm: `npm config set prefix "C:\Users\%USERNAME%\AppData\Roaming\npm"`

## Key Improvements

✅ **Windows Support**: All shell scripts converted to cross-platform JavaScript  
✅ **Documentation**: All guides updated with Windows-specific instructions  
✅ **Memory Configuration**: Clear Windows-specific memory setup guides  
✅ **npm Scripts**: Easy command access on all platforms  
✅ **No Dependencies**: JavaScript scripts use only Node.js built-ins  
✅ **Graceful Fallbacks**: Windows provides clear guidance when features need manual setup

## Still Using Makefile?

The Makefile is still available for macOS/Linux developers who prefer it. Windows developers should use `npm run` commands instead.

To see all available commands on any platform:

```bash
# View help
npm run help

# Or on macOS/Linux with make
make help
```

## References

- [SETUP.md](./SETUP.md) - Complete setup guide with platform-specific sections
- [BUILD.md](./BUILD.md) - Build troubleshooting with Windows-specific solutions
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Developer workflow with cross-platform examples
- [QUICKREF.md](./QUICKREF.md) - Quick command reference for all platforms
- [GETTING_STARTED.md](./GETTING_STARTED.md) - Navigation guide with platform awareness

## Questions?

For Windows-specific issues:

1. Check [BUILD.md](./BUILD.md#troubleshooting) for troubleshooting steps
2. Check [SETUP.md](./SETUP.md#windows-setup) for setup-specific help
3. Open an issue on [GitHub](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
