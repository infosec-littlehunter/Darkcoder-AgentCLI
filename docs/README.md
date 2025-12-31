# 📖 Documentation Index

Welcome to DarkCoder documentation! This is your starting point for learning about the project.

---

## 🎯 Quick Navigation

### For New Contributors

- **[QUICK_START_NEW_CONTRIBUTORS.md](./QUICK_START_NEW_CONTRIBUTORS.md)** ← Start here! (5-minute setup)
- **[SETTINGS_GUIDE.md](./SETTINGS_GUIDE.md)** - How to configure `~/.qwen/settings.json`
- **[DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md)** - Complete development environment setup

### For Understanding the Project

- **[PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md)** - Codebase architecture & folder layout
- **[development/architecture.md](./development/architecture.md)** - System design & interaction flow
- **[development/MEMORY_MANAGEMENT.md](./development/MEMORY_MANAGEMENT.md)** - Memory optimization details

### For Using DarkCoder

- **[cli/](./cli/)** - Command-line interface documentation
- **[core/](./core/)** - Core library & API reference
- **[features/](./features/)** - Feature guides (cost tracking, parallel execution, etc.)
- **[tools/](./tools/)** - Security tool integration guides

### For IDE Integration

- **[ide-integration/](./ide-integration/)** - VS Code extension setup & usage

### For Tool-Specific Guides

- **[tools/SHODAN_INTEGRATION_GUIDE.md](./tools/SHODAN_INTEGRATION_GUIDE.md)** - Shodan API integration
- **[tools/NUCLEI_INTEGRATION_GUIDE.md](./tools/NUCLEI_INTEGRATION_GUIDE.md)** - Nuclei scanner setup
- **[tools/CUCKOO_INTEGRATION_GUIDE.md](./tools/CUCKOO_INTEGRATION_GUIDE.md)** - Cuckoo sandbox setup
- **[tools/CTF_REVERSE_ENGINEERING_GUIDE.md](./tools/CTF_REVERSE_ENGINEERING_GUIDE.md)** - RE tools guide

### For Troubleshooting

- **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** - Common issues & solutions
- **[development/DEBUGGING_GUIDE.md](./development/DEBUGGING_GUIDE.md)** - Debugging techniques

---

## 📋 Documentation Structure

```
docs/
├── 📄 Main Guides
│   ├── QUICK_START_NEW_CONTRIBUTORS.md    ← Start here!
│   ├── SETTINGS_GUIDE.md                  ← Settings configuration
│   ├── DEVELOPER_SETUP.md                 ← Full setup guide
│   ├── PROJECT_STRUCTURE.md               ← Codebase layout
│   └── TROUBLESHOOTING.md                 ← Common issues
│
├── 📂 development/
│   ├── architecture.md                    ← System design
│   ├── deployment.md                      ← Deployment info
│   ├── MEMORY_MANAGEMENT.md               ← Memory optimization
│   ├── DEBUGGING_GUIDE.md                 ← Debugging tips
│   └── HEAP_OOM_FIX_SUMMARY.md           ← Memory fix guide
│
├── 📂 cli/
│   ├── index.md                          ← CLI overview
│   ├── commands/                         ← Command docs
│   └── configuration.md                  ← Config guide
│
├── 📂 core/
│   ├── index.md                          ← Core library
│   ├── tools/                            ← Tool docs
│   └── services/                         ← Service docs
│
├── 📂 features/
│   ├── COST_TRACKING_GUIDE.md           ← Cost tracking
│   ├── PARALLEL_EXECUTION.md            ← Parallel execution
│   └── AI_DRIVEN_PARALLEL_EXECUTION.md  ← AI-driven parallel
│
├── 📂 tools/
│   ├── SHODAN_INTEGRATION_GUIDE.md      ← Shodan setup
│   ├── NUCLEI_INTEGRATION_GUIDE.md      ← Nuclei setup
│   ├── CUCKOO_INTEGRATION_GUIDE.md      ← Cuckoo setup
│   ├── CTF_REVERSE_ENGINEERING_GUIDE.md ← RE tools
│   ├── CTF_CRYPTO_GUIDE.md              ← Crypto tools
│   └── tool-validation.md               ← Tool validation
│
├── 📂 ide-integration/
│   ├── vscode.md                        ← VS Code integration
│   └── configuration.md                 ← IDE config
│
├── 📂 providers/
│   └── [Provider-specific docs]         ← AI provider guides
│
├── 📂 examples/
│   └── settings.example.json            ← Settings template
│
└── 📂 archive/
    └── RELEASE_NOTES_v0.7.0.md          ← Release history
```

---

## 🚀 Getting Started (3 Steps)

### 1️⃣ Quick Setup (2 min)

Start with **[QUICK_START_NEW_CONTRIBUTORS.md](./QUICK_START_NEW_CONTRIBUTORS.md)**

```bash
bash scripts/setup-settings.sh
npm install && npm run build
npm start
```

### 2️⃣ Configure Settings (1 min)

See **[SETTINGS_GUIDE.md](./SETTINGS_GUIDE.md)**

```bash
nano ~/.qwen/settings.json
```

### 3️⃣ Set API Key (1 min)

```bash
export OPENAI_API_KEY="sk-proj-xxxxx"
npm start
```

---

## 📚 Learning Paths

### I'm a New Contributor

1. [QUICK_START_NEW_CONTRIBUTORS.md](./QUICK_START_NEW_CONTRIBUTORS.md) - Get running
2. [DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md) - Full setup
3. [PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md) - Understand codebase
4. [../CONTRIBUTING.md](../CONTRIBUTING.md) - Make a contribution

### I Want to Understand the Architecture

1. [development/architecture.md](./development/architecture.md) - System design
2. [PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md) - Code organization
3. [development/DEBUGGING_GUIDE.md](./development/DEBUGGING_GUIDE.md) - Debug techniques

### I Want to Add a Security Tool

1. [core/tools/](./core/tools/) - Tool docs
2. [tools/](./tools/) - Tool guides
3. See existing tool implementations in `packages/core/src/tools/`

### I'm Having Issues

1. [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common problems
2. [development/MEMORY_MANAGEMENT.md](./development/MEMORY_MANAGEMENT.md) - Memory issues
3. [development/DEBUGGING_GUIDE.md](./development/DEBUGGING_GUIDE.md) - Debugging

### I Want to Deploy DarkCoder

1. [development/deployment.md](./development/deployment.md) - Deployment guide
2. [BUN_SETUP.md](./BUN_SETUP.md) - Bun runtime setup
3. Check Docker configuration in project root

---

## 🔍 Key Concepts

### Settings & Configuration

- **User Settings**: `~/.qwen/settings.json` - Your personal config
- **Workspace Settings**: `.qwen/settings.json` - Project-specific config
- **System Settings**: System-wide config (optional)

See **[SETTINGS_GUIDE.md](./SETTINGS_GUIDE.md)** for details.

### API Keys & Authentication

- Multiple AI provider support
- Environment variable based
- See **[SETTINGS_GUIDE.md](./SETTINGS_GUIDE.md#-required-api-keys)** for setup

### Memory Management

- 5-tier defense system
- Auto-GC and monitoring
- See **[development/MEMORY_MANAGEMENT.md](./development/MEMORY_MANAGEMENT.md)** for details

### Tool Execution

- 50+ integrated security tools
- Approval workflow for safety
- See **[tools/](./tools/)** for tool-specific guides

---

## 📖 Documentation Standards

- **Markdown format** - All docs are `.md` files
- **Table of contents** - Each doc has a TOC
- **Code examples** - Practical, working examples
- **Search friendly** - Clear headers and keywords
- **Links** - Cross-references between docs

---

## 🔗 External Resources

- **Repository**: [GitHub](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI)
- **Issues**: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions)
- **License**: [Apache 2.0](../LICENSE)

---

## ✨ Quick Links

| Need            | File                                                                 |
| --------------- | -------------------------------------------------------------------- |
| Getting started | [QUICK_START_NEW_CONTRIBUTORS.md](./QUICK_START_NEW_CONTRIBUTORS.md) |
| Settings help   | [SETTINGS_GUIDE.md](./SETTINGS_GUIDE.md)                             |
| Setup guide     | [DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md)                           |
| Project layout  | [PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md)                       |
| Architecture    | [development/architecture.md](./development/architecture.md)         |
| Troubleshooting | [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)                           |
| Contributing    | [../CONTRIBUTING.md](../CONTRIBUTING.md)                             |

---

## 🎯 Next Steps

👉 **Start here**: [QUICK_START_NEW_CONTRIBUTORS.md](./QUICK_START_NEW_CONTRIBUTORS.md)

Questions? Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) or open an [issue](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues).
