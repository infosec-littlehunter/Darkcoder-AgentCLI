# Common Issues & Troubleshooting

Quick solutions to the most common problems when setting up and developing DarkCoder.

## Installation Issues

### npm install fails

**Error**: `ERR! code E403` or `ERR! 403 Forbidden`

**Causes**:

- Authentication issues with npm registry
- Network connectivity problems
- Rate limiting

**Solutions**:

```bash
# Clear npm cache
npm cache clean --force

# Retry installation
npm install

# Or use a different registry
npm install --registry https://registry.npmjs.org

# Check if npm is authenticated
npm whoami
```

### Node version mismatch

**Error**: `npm ERR! The engine "node" is incompatible with this module`

**Solution**:

```bash
# Check installed Node version
node --version

# Must be v20 or higher
# Download from https://nodejs.org/

# Or use nvm (Node Version Manager)
nvm install 20
nvm use 20
```

### Permission denied errors

**Error**: `EACCES: permission denied, access 'xxx'`

**Solution** (macOS/Linux):

```bash
# Fix npm permissions permanently
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'

# Add to PATH in ~/.bashrc or ~/.zshrc
export PATH=~/.npm-global/bin:$PATH

# Reload shell
source ~/.bashrc  # or ~/.zshrc
```

## Build Issues

### Memory errors during build

**Error**: `FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory`

**Solution**:

```bash
# Increase heap size permanently
echo 'export NODE_OPTIONS="--max-old-space-size=8192"' >> ~/.bashrc
source ~/.bashrc

# Or set for current session only
NODE_OPTIONS="--max-old-space-size=8192" npm run build
```

For systems with limited memory:

```bash
# Lower memory machines (4GB heap)
NODE_OPTIONS="--max-old-space-size=2048" npm run build

# Medium memory machines (6GB heap)
NODE_OPTIONS="--max-old-space-size=4096" npm run build
```

### Build hangs indefinitely

**Symptom**: `npm run build` hangs with no output for >10 minutes

**Solutions**:

```bash
# Option 1: Kill and retry with verbose output
Ctrl+C
npm run build 2>&1 | tee build.log

# Option 2: Clean and rebuild
npm run clean
npm install
npm run build

# Option 3: Check disk space
df -h
# Need at least 2GB free space

# Option 4: Increase timeout
npm config set fetch-timeout 120000
npm run build
```

### TypeScript errors

**Error**: `error TS...` during build

**Solutions**:

```bash
# Run type checking separately
npm run typecheck

# Fix common issues
npm run lint:fix

# Ensure TypeScript is up to date
npm install typescript@latest

# Clear tsbuildinfo cache
npm run clean
npm run build
```

## Runtime Issues

### Port already in use

**Error**: `EADDRINUSE: address already in use :::3000`

**Solution**:

```bash
# Find process using port 3000
lsof -i :3000

# Kill the process
kill -9 <PID>

# Or use a different port
PORT=3001 npm start
```

### Module not found

**Error**: `Cannot find module '@darkcoder/...'`

**Solutions**:

```bash
# Install all dependencies
npm install

# Rebuild monorepo packages
npm run build:packages

# Clear npm cache
npm cache clean --force

# Reinstall everything
rm -rf node_modules package-lock.json
npm install
```

### CLI not working after install

**Error**: `darkcoder: command not found` or other execution issues

**Solutions**:

```bash
# Verify build output exists
test -f dist/cli.js && echo "✓ Built" || echo "✗ Not built"

# Run via npm
npm start --help

# Check if globally installed
npm list -g @darkcoder/darkcoder

# If trying to use binary, ensure dist/ is built
npm run build
```

## Development Issues

### ESLint errors

**Error**: ESLint fails with configuration errors

**Solutions**:

```bash
# Clear eslint cache
npx eslint --reset-cache

# Reinstall eslint
npm install eslint@latest

# Check configuration
npm run lint -- --debug

# Fix all fixable issues
npm run lint:fix
```

### Prettier conflicts with ESLint

**Error**: Code fails ESLint after running Prettier or vice versa

**Solution**:

```bash
# Run in correct order (prettier first, then eslint)
npm run format    # Prettier
npm run lint:fix  # ESLint

# Or use the preflight check
npm run preflight
```

### Tests fail with strange errors

**Error**: Tests fail intermittently or with memory errors

**Solutions**:

```bash
# Run with increased memory
NODE_OPTIONS="--max-old-space-size=4096" npm test

# Run tests serially (slower but more reliable)
npm test -- --run

# Run specific test file
npm test -- path/to/test.ts

# Clear test cache
npm test -- --clearCache
```

## Git Issues

### Husky pre-commit hooks failing

**Error**: Commit fails with linting errors

**Solution**:

```bash
# Fix all issues automatically
npm run format && npm run lint:fix

# Then commit
git add .
git commit -m "fix: formatting and linting"

# Or bypass hooks (not recommended)
git commit --no-verify
```

### Merge conflicts in lock file

**Error**: Conflicts in package-lock.json after merge/pull

**Solution**:

```bash
# Resolve conflicts by removing lock file and reinstalling
rm package-lock.json
npm install

# Commit the new lock file
git add package-lock.json
git commit -m "chore: update lock file"
```

## Platform-Specific Issues

### macOS

**Issue**: Xcode command line tools missing

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Or use Homebrew
brew install node@20
```

### Windows (WSL2)

**Issue**: npm commands fail with ENOENT errors

```bash
# Use npm ci instead of npm install
npm ci

# Ensure autocrlf is set correctly
git config core.autocrlf true
```

### Linux

**Issue**: Permission errors on /usr/local

```bash
# Fix permissions
sudo chown -R $USER /usr/local/bin
sudo chown -R $USER /usr/local/lib

# Or use nvm to avoid sudo
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 20
```

## Getting Help

If your issue isn't listed:

1. **Check existing issues**: https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues
2. **Search documentation**: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
3. **Run diagnostic**: `npm run doctor`
4. **Collect info for issue report**:
   ```bash
   node --version
   npm --version
   npm list | head -30
   npm run doctor
   ```
5. **Create an issue**: https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues/new

## Related Guides

- [SETUP.md](./SETUP.md) - First-time setup
- [BUILD.md](./BUILD.md) - Build troubleshooting
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Project structure
- [DEPENDENCIES.md](./DEPENDENCIES.md) - Dependency information
- [docs/TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md) - Advanced troubleshooting
