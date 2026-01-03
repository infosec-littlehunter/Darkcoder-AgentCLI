# Getting Started with DarkCoder

Choose your path based on your needs:

> **Windows Users**: Use `npm run` commands instead of `make`. See [SETUP.md](./SETUP.md#windows-setup) for Windows-specific instructions.

## 🚀 I'm a New Developer

**Time needed**: 15 minutes

1. Read [SETUP.md](./SETUP.md) (5 min) - One-time setup guide
2. **Windows**: Run `npm install && npm run build` (5 min)  
   **macOS/Linux**: Run `make setup` (5 min)
3. Verify: `npm run doctor` (2 min) - Check everything works
4. Start: `npm start --help` (1 min) - See CLI help
5. Read [CONTRIBUTING.md](./CONTRIBUTING.md) - Understand workflow

**Next**: Follow [CONTRIBUTING.md](./CONTRIBUTING.md) to make your first contribution

## 🔨 I'm Setting Up a Development Environment

**Read in this order**:

1. [SETUP.md](./SETUP.md) - Initial setup (platform-specific)
2. [BUILD.md](./BUILD.md) - Build configuration and troubleshooting
3. [ARCHITECTURE.md](./ARCHITECTURE.md) - Project structure
4. [DEPENDENCIES.md](./DEPENDENCIES.md) - Dependency information

**Then start coding:**

```bash
npm start              # Run CLI (all platforms)
npm test               # Run tests (all platforms)

# For macOS/Linux:
make help              # See all commands
```

See [QUICKREF.md](./QUICKREF.md) for all available commands on your platform.

## 🐛 Something's Broken!

**Quick troubleshooting**:

1. Run: `npm run doctor` - Get diagnostic info
2. Check: [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues
3. Check: [BUILD.md](./BUILD.md) - Build-specific errors
4. Search: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
5. Ask: [GitHub Discussions](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/discussions)

## 📖 I Want to Understand the Project

**Reading path**:

1. [README.md](./README.md) - Project overview
2. [ARCHITECTURE.md](./ARCHITECTURE.md) - Structure and design
3. [docs/README.md](./docs/README.md) - Detailed documentation

## 🤝 I Want to Contribute

**Follow these steps**:

1. [SETUP.md](./SETUP.md) - Get your environment ready
2. [CONTRIBUTING.md](./CONTRIBUTING.md) - Understand contribution workflow
3. [ARCHITECTURE.md](./ARCHITECTURE.md) - Learn project structure
4. Make your changes and create a PR

## 📚 Quick Reference

**Need a command?** Check [QUICKREF.md](./QUICKREF.md)

**Need to build?** Check [BUILD.md](./BUILD.md)

**Something broken?** Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)

**Don't know where to look?** Run `npm run doctor`

## 📋 Documentation Index

### Getting Started

- [SETUP.md](./SETUP.md) - Initial setup (⭐ Start here!)
- [QUICKREF.md](./QUICKREF.md) - Command quick reference
- [CONTRIBUTING.md](./CONTRIBUTING.md) - How to contribute

### Development

- [BUILD.md](./BUILD.md) - Build guide and troubleshooting
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Project structure
- [DEPENDENCIES.md](./DEPENDENCIES.md) - Dependency documentation
- [Makefile](./Makefile) - Make command targets

### Troubleshooting

- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues
- [docs/TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md) - Advanced troubleshooting
- [docs/DEVELOPER_SETUP.md](./docs/DEVELOPER_SETUP.md) - Detailed setup guide

### Reference

- [README.md](./README.md) - Project overview
- [docs/README.md](./docs/README.md) - Full documentation
- [docs/PROJECT_CLEANUP_2025.md](./docs/PROJECT_CLEANUP_2025.md) - What was improved

## 🎯 By Use Case

| I want to...               | Read...                                    | Time   |
| -------------------------- | ------------------------------------------ | ------ |
| Set up the project         | [SETUP.md](./SETUP.md)                     | 15 min |
| Make my first contribution | [CONTRIBUTING.md](./CONTRIBUTING.md)       | 10 min |
| Fix a build error          | [BUILD.md](./BUILD.md)                     | 5 min  |
| Understand the structure   | [ARCHITECTURE.md](./ARCHITECTURE.md)       | 20 min |
| Learn about dependencies   | [DEPENDENCIES.md](./DEPENDENCIES.md)       | 10 min |
| Fix something broken       | [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) | 10 min |
| Find a command             | [QUICKREF.md](./QUICKREF.md)               | 2 min  |

## ⚡ Quick Commands

```bash
# First time? Run this
git clone https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI.git
cd AssistanceAntiCyber-Darkcoder-CLI
make setup

# Every day
npm start              # Run the CLI
npm test               # Run tests
make lint              # Check code quality

# Need help?
make help              # Show all commands
npm run doctor         # Run diagnostics
cat TROUBLESHOOTING.md # See common issues
```

## 🚀 Next Steps

1. **Choose your path above** (which section matches you?)
2. **Read the recommended documents** (in order)
3. **Run the setup commands** (usually `make setup`)
4. **Start contributing!** (follow CONTRIBUTING.md)

## 💬 Questions?

- **Setup issues?** → Check [SETUP.md](./SETUP.md)
- **Build problems?** → Check [BUILD.md](./BUILD.md)
- **Can't find something?** → Check [QUICKREF.md](./QUICKREF.md)
- **Still stuck?** → [Open an issue](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)

---

**Ready to get started?** Open [SETUP.md](./SETUP.md) now! 🎉
