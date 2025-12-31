# 🔧 DarkCoder Troubleshooting Guide

Quick solutions for common issues developers encounter.

---

## Quick Diagnostic

```bash
# Run the automated health check
npm run doctor
```

---

## Memory Issues

### Symptom: JavaScript Heap Out of Memory

```
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory
<--- Last few GCs --->
[12345:0x...]    12345 ms: Mark-sweep 2048.0 (2051.2) -> 2047.9 (2051.2) MB
```

### Solutions

#### Solution 1: Set NODE_OPTIONS (Recommended)

```bash
# Add to ~/.bashrc or ~/.zshrc
export NODE_OPTIONS="--max-old-space-size=8192"

# Reload shell
source ~/.bashrc
```

#### Solution 2: Use Memory-Safe Scripts

```bash
# Use pre-configured memory-safe commands
npm run start          # 8GB heap (default)
npm run start:highmem  # 16GB heap (for heavy operations)
npm run start:lowmem   # 4GB heap (low memory systems)

npm run build:safe     # 16GB heap for build
npm run build:managed  # 8GB heap with GC monitoring
```

#### Solution 3: Per-Session Fix

```bash
# Set for current session only
NODE_OPTIONS="--max-old-space-size=8192" npm run build
```

#### Verify Fix

```bash
node -e "console.log('Heap:', Math.round(require('v8').getHeapStatistics().heap_size_limit/1024/1024), 'MB')"
# Should show: Heap: 8192 MB
```

---

## API Issues

### Symptom: Context Length Exceeded (Error 400)

```
API Error: 400 - maximum context length is 131072 tokens. However, you requested 135000 tokens
```

### Solutions

1. **Compress conversation** (in DarkCoder):

   ```
   /compress
   ```

2. **Clear and start fresh**:

   ```
   /clear
   ```

3. **Check token usage**:

   ```
   /stats
   ```

4. **Use a model with larger context** (if available):
   ```
   /model claude-3-opus
   ```

---

### Symptom: Rate Limiting (Error 429)

```
Error: 429 Too Many Requests
Rate limit exceeded. Please retry after X seconds.
```

### Solutions

1. **Wait and retry** - Most rate limits reset within 60 seconds

2. **Switch AI provider** temporarily:

   ```bash
   # Set a different provider
   export ANTHROPIC_API_KEY="your-key"  # Switch to Anthropic
   export OPENAI_API_KEY="your-key"     # Or OpenAI
   ```

3. **Check your API tier** - Free tiers have lower limits

4. **Use exponential backoff** - DarkCoder handles this automatically in v0.7.0+

---

### Symptom: API Key Not Found

```
Error: No API key configured for provider 'anthropic'
```

### Solutions

1. **Check which keys are set**:

   ```bash
   env | grep -E "API_KEY|API_SECRET"
   ```

2. **Set at least one AI provider key**:

   ```bash
   # Choose one (or more)
   export ANTHROPIC_API_KEY="sk-ant-..."
   export OPENAI_API_KEY="sk-..."
   export GOOGLE_API_KEY="AIza..."
   ```

3. **Use .env file** (development):
   ```bash
   # Create .env in project root
   echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env
   ```

---

## Tool Issues

### Symptom: Security Tool Not Found

```
Warning: nuclei not found. Some features will be disabled.
Warning: ffuf not found in PATH
```

### Solutions

This is a **non-blocking warning**. DarkCoder works without external tools, but with reduced functionality.

#### Install Missing Tools

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y nmap radare2 binwalk

# macOS
brew install nmap radare2 binwalk

# Go-based tools (requires Go 1.21+)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

# Python tools
pip install ROPgadget
```

#### Verify Installation

```bash
npm run doctor
```

#### If You Don't Need These Tools

The warnings can be safely ignored if you don't need:

- **nuclei**: Vulnerability scanning
- **ffuf**: Web fuzzing
- **nmap**: Network scanning

---

## Windows + Bun Installation

### Symptom: Hundreds of esbuild errors during `bun install`

```
✘ [ERROR] Cannot read directory "node_modules": The process cannot access the file because it is being used by another process.
... 500+ similar errors
```

### Cause

On Windows, `bun install` runs lifecycle scripts (`prepare`/`postinstall`) while maintaining file handles on `node_modules`. If those scripts bundle with esbuild concurrently, Windows file locking causes failures.

### Fixes

1. Use npm for install (recommended on Windows):

```bash
npm install
bun run build:bun
```

2. Or skip lifecycle scripts with Bun:

```bash
bun install --ignore-scripts
bun run build:bun
```

3. We avoid bundling during install:

- `prepare` now runs `husky` only
- `postinstall` prints a message and does not bundle
- Run bundling explicitly when needed:

```bash
npm run bundle    # Node
bun run bundle    # Bun
```

### Notes

- This is Windows-specific; macOS/Linux usually don’t exhibit the same locking.
- VS Code extension packaging still uses Node and is unaffected.
- **radare2/rizin**: Reverse engineering

---

## Build Issues

### Symptom: TypeScript Compilation Errors

```
error TS2307: Cannot find module '@darkcoder/core'
error TS2345: Argument of type 'X' is not assignable to parameter of type 'Y'
```

### Solutions

1. **Clean rebuild**:

   ```bash
   npm run clean
   npm install
   npm run build
   ```

2. **Clear npm cache**:

   ```bash
   npm cache clean --force
   rm -rf node_modules
   npm install
   ```

3. **Check Node.js version**:
   ```bash
   node --version  # Must be 20+
   ```

---

### Symptom: ESLint Errors During Commit

```
✖ eslint --fix --max-warnings 0:
error  Reaching to "../config/config.js" is not allowed
```

### Solutions

1. **For organization/doc changes only** (skip lint):

   ```bash
   git commit --no-verify -m "your message"
   ```

2. **Fix lint issues** (for code changes):
   ```bash
   npm run lint:fix
   ```

---

### Symptom: Permission Denied

```
EACCES: permission denied, open '/path/to/file'
EPERM: operation not permitted
```

### Solutions

1. **Fix npm permissions** (Linux/macOS):

   ```bash
   sudo chown -R $(whoami) ~/.npm
   sudo chown -R $(whoami) ~/.config
   ```

2. **Fix file/directory permissions**:

   ```bash
   # Make shell scripts executable (if any exist)
   chmod +x scripts/*.sh 2>/dev/null || true

   # Fix ownership of project directory
   sudo chown -R $(whoami) .
   ```

3. **Build uses Node.js scripts** (not shell scripts):
   ```bash
   # The build system uses JavaScript, not bash
   npm run build  # Calls scripts/build-with-memory-management.js
   ```

---

## Network Issues

### Symptom: ECONNREFUSED / ETIMEDOUT

```
Error: connect ECONNREFUSED 127.0.0.1:3000
Error: connect ETIMEDOUT api.anthropic.com
```

### Solutions

1. **Check internet connection**:

   ```bash
   curl -I https://api.anthropic.com
   ```

2. **Check proxy settings**:

   ```bash
   echo $HTTP_PROXY $HTTPS_PROXY
   ```

3. **Corporate firewall?** Try:
   ```bash
   export HTTPS_PROXY="http://your-proxy:port"
   ```

---

### Symptom: SSL Certificate Errors

```
Error: unable to verify the first certificate
UNABLE_TO_GET_ISSUER_CERT_LOCALLY
```

### Solutions

1. **Update CA certificates**:

   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install ca-certificates

   # macOS
   brew install ca-certificates
   ```

2. **Temporary workaround** (not recommended for production):
   ```bash
   export NODE_TLS_REJECT_UNAUTHORIZED=0
   ```

---

## Platform-Specific Issues

### Windows

#### WSL2 Recommended

Native Windows has limited tool support. Use WSL2:

```powershell
# Install WSL2
wsl --install -d Ubuntu

# Then work inside WSL2
wsl
```

#### Path Issues

If tools aren't found:

```bash
# Add Go binaries to PATH
export PATH="$PATH:$(go env GOPATH)/bin"
```

### macOS

#### Xcode Command Line Tools

```bash
xcode-select --install
```

#### Homebrew Issues

```bash
# Update Homebrew
brew update && brew upgrade

# Fix permissions
sudo chown -R $(whoami) $(brew --prefix)/*
```

### Linux

#### Build Dependencies

```bash
# Ubuntu/Debian
sudo apt install build-essential python3 make g++

# Fedora/RHEL
sudo dnf groupinstall "Development Tools"
```

---

## Getting Help

1. **Run diagnostics first**:

   ```bash
   npm run doctor
   ```

2. **Check existing issues**: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)

3. **Gather debug info**:

   ```bash
   # System info
   uname -a
   node --version
   npm --version

   # Memory info
   node -e "console.log(require('v8').getHeapStatistics())"

   # Environment
   env | grep -E "(NODE|API_KEY|PATH)" | head -20
   ```

4. **Open a new issue** with:
   - Error message (full output)
   - Steps to reproduce
   - Output of `npm run doctor`
   - OS and Node.js version
