# 🚀 Quick Start for New Contributors

Welcome to DarkCoder! This guide gets you up and running in 5 minutes.

---

## ⚡ 5-Minute Setup

### 1. Clone & Install (2 minutes)

```bash
# Clone the repository
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI/darkcoder

# Install dependencies
npm install
```

### 2. Configure Settings (2 minutes)

```bash
# Run the setup script (interactive)
bash scripts/setup-settings.sh

# Or manual setup
mkdir -p ~/.qwen
cp docs/examples/settings.example.json ~/.qwen/settings.json
nano ~/.qwen/settings.json
```

### 3. Set API Key (1 minute)

Choose **one** AI provider:

```bash
# OpenAI (recommended for starting)
export OPENAI_API_KEY="sk-proj-xxxxx"

# OR Anthropic
export ANTHROPIC_API_KEY="sk-ant-xxxxx"

# OR Google Gemini
export GOOGLE_API_KEY="AIza-xxxxx"

# Make it permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export OPENAI_API_KEY="sk-proj-xxxxx"' >> ~/.bashrc
source ~/.bashrc
```

### 4. Verify Setup

```bash
# Run diagnostic
npm run doctor

# You should see:
# ✓ Node.js version OK
# ✓ Settings file valid
# ✓ API key detected
# ✓ Memory configured
```

### 5. Start Developing

```bash
# Build
npm run build

# Start interactive CLI
npm start
```

---

## 📁 Project Structure Overview

```
darkcoder/
├── packages/
│   ├── cli/              ← Terminal UI (React + Ink)
│   ├── core/             ← AI logic & 50+ security tools
│   ├── sdk-typescript/   ← TypeScript SDK
│   └── vscode-ide-companion/  ← VS Code extension
│
├── docs/
│   ├── SETTINGS_GUIDE.md       ← Detailed settings reference
│   ├── DEVELOPER_SETUP.md      ← Full development guide
│   ├── PROJECT_STRUCTURE.md    ← Codebase walkthrough
│   └── examples/
│       └── settings.example.json  ← Settings template
│
└── scripts/
    └── setup-settings.sh       ← Interactive setup script
```

---

## 🎯 Common Tasks

### I want to...

#### Run the CLI

```bash
npm start
```

#### Run tests

```bash
npm test                    # All tests
npm test -- path/to/test   # Specific test
npm test -- --watch        # Watch mode
```

#### Build for production

```bash
npm run build
```

#### Check for errors

```bash
npm run lint
npm run typecheck
```

#### Format code

```bash
npm run format
```

#### Run diagnostics

```bash
npm run doctor
```

---

## 🔑 Understanding Settings & API Keys

### What's `~/.qwen/settings.json`?

It's your **personal configuration file** (not in Git):

- Stores your preferences (theme, language, tools)
- NOT shared with the team
- Created when you first run DarkCoder

Example structure:

```json
{
  "ui": { "theme": "dark" },
  "security": { "auth": { "selectedType": "use-openai" } },
  "model": { "provider": "openai" }
}
```

### What are API keys?

API keys are **credentials** you need to use AI providers:

- **OpenAI**: `sk-proj-xxxxx` → [Get it](https://platform.openai.com/)
- **Anthropic**: `sk-ant-xxxxx` → [Get it](https://console.anthropic.com/)
- **Google Gemini**: `AIza-xxxxx` → [Get it](https://aistudio.google.com/)
- **Qwen**: From Aliyun → [Get it](https://dashscope.console.aliyun.com/)

### Where do API keys go?

**Option 1: Environment Variable** (recommended for development)

```bash
export OPENAI_API_KEY="sk-proj-xxxxx"
```

**Option 2: .env file** (in project root, don't commit!)

```bash
OPENAI_API_KEY=sk-proj-xxxxx
```

**Option 3: System-wide** (add to `~/.bashrc` or `~/.zshrc`)

```bash
echo 'export OPENAI_API_KEY="sk-proj-xxxxx"' >> ~/.bashrc
```

---

## 🛠️ Memory Management

DarkCoder processes large amounts of data. On first run, you might see:

```
FATAL ERROR: JavaScript heap out of memory
```

**Fix it:**

```bash
# One-time setup
export NODE_OPTIONS="--max-old-space-size=8192"

# Or permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export NODE_OPTIONS="--max-old-space-size=8192"' >> ~/.bashrc
source ~/.bashrc

# Verify
node -e "console.log(require('v8').getHeapStatistics().heap_size_limit / 1024 / 1024, 'MB')"
```

---

## ✅ Troubleshooting

### "Settings file not found"

```bash
# Create it
bash scripts/setup-settings.sh
```

### "API key not found"

```bash
# Check if set
echo $OPENAI_API_KEY

# If empty, set it
export OPENAI_API_KEY="your-key-here"
```

### "Out of memory" during build

```bash
export NODE_OPTIONS="--max-old-space-size=8192"
npm run build
```

### "Module not found" error

```bash
# Clean and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Tests failing

```bash
# Run diagnostics first
npm run doctor

# Then check specific test
npm test -- path/to/test.ts
```

---

## 📚 Learn More

| Topic                      | File                                                                             |
| -------------------------- | -------------------------------------------------------------------------------- |
| **Settings Configuration** | [docs/SETTINGS_GUIDE.md](./docs/SETTINGS_GUIDE.md)                               |
| **Full Setup Guide**       | [docs/DEVELOPER_SETUP.md](./docs/DEVELOPER_SETUP.md)                             |
| **Project Structure**      | [docs/PROJECT_STRUCTURE.md](./docs/PROJECT_STRUCTURE.md)                         |
| **Contributing Rules**     | [CONTRIBUTING.md](./CONTRIBUTING.md)                                             |
| **Architecture**           | [docs/development/architecture.md](./docs/development/architecture.md)           |
| **Memory Management**      | [docs/development/MEMORY_MANAGEMENT.md](./docs/development/MEMORY_MANAGEMENT.md) |

---

## 🤝 Making Your First Contribution

1. **Create a feature branch**

   ```bash
   git checkout -b feature/my-awesome-feature
   ```

2. **Make changes and test**

   ```bash
   npm run lint
   npm test
   ```

3. **Commit with clear message**

   ```bash
   git add .
   git commit -m "feat: add awesome feature"
   ```

4. **Push and create PR**

   ```bash
   git push origin feature/my-awesome-feature
   ```

5. **Follow PR checklist** in GitHub

---

## 🆘 Getting Help

- **Documentation**: Check [docs/](./docs/) folder
- **Issues**: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions)

---

## ✨ You're All Set!

You now have:

- ✅ DarkCoder running locally
- ✅ Settings configured (`~/.qwen/settings.json`)
- ✅ API key ready
- ✅ Development environment ready

**Next:** Check out [CONTRIBUTING.md](./CONTRIBUTING.md) to get started with your first PR! 🚀
