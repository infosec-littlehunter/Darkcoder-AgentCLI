# 🔧 Settings Configuration Guide

This guide explains how to set up `~/.qwen/settings.json` when you first clone and run DarkCoder.

---

## 📍 Where is the Settings File?

The settings file is located in your **home directory** (not in the project):

```bash
# On macOS/Linux
~/.qwen/settings.json

# On Windows
C:\Users\<YourUsername>\AppData\Roaming\QwenCode\settings.json
```

**This file is NOT in Git** — each developer creates their own copy with their personal preferences and API keys.

---

## 🚀 Quick Setup

### Option 1: Auto-Create on First Run

When you run DarkCoder for the first time:

```bash
npm start
```

It will automatically create `~/.qwen/settings.json` with default settings if it doesn't exist.

### Option 2: Manual Setup

1. **Create the directory** (if it doesn't exist):

```bash
# macOS/Linux
mkdir -p ~/.qwen

# Windows (PowerShell)
New-Item -ItemType Directory -Force -Path "$env:APPDATA\QwenCode"
```

2. **Copy the example template**:

```bash
# From the repo root
cp docs/examples/settings.example.json ~/.qwen/settings.json
```

3. **Edit the file** with your preferences and API keys.

---

## 📋 Minimal Settings Template

Create `~/.qwen/settings.json` with at least:

```json
{
  "security": {
    "auth": {
      "selectedType": "use-openai"
    }
  },
  "model": {
    "provider": "openai"
  }
}
```

---

## 🔑 Complete Settings Example

Here's a more comprehensive example:

```json
{
  "$version": 2,
  "general": {
    "language": "auto",
    "vimMode": false,
    "checkpointing": {
      "enabled": true
    }
  },
  "ui": {
    "theme": "dark",
    "showMemoryUsage": true
  },
  "security": {
    "auth": {
      "selectedType": "use-openai"
    }
  },
  "model": {
    "provider": "openai",
    "chatCompression": "auto"
  },
  "context": {
    "fileName": "CONTEXT.md",
    "importFormat": "tree",
    "includeDirectories": [],
    "loadMemoryFromIncludeDirectories": false
  },
  "tools": {
    "autoAccept": false,
    "sandbox": false
  },
  "mcp": {
    "allowed": []
  },
  "advanced": {
    "autoConfigureMemory": true
  },
  "telemetry": {
    "enabled": false
  }
}
```

---

## 🔐 Required API Keys

You need **at least ONE** of these environment variables or settings:

| Provider          | Environment Variable | Setting Location                           |
| ----------------- | -------------------- | ------------------------------------------ |
| **OpenAI**        | `OPENAI_API_KEY`     | `security.auth.selectedType: "use-openai"` |
| **Anthropic**     | `ANTHROPIC_API_KEY`  | `security.auth.selectedType: "use-openai"` |
| **Google Gemini** | `GOOGLE_API_KEY`     | `security.auth.selectedType: "use-openai"` |
| **Qwen**          | `DASHSCOPE_API_KEY`  | `security.auth.selectedType: "qwen-oauth"` |
| **DeepSeek**      | `DEEPSEEK_API_KEY`   | `security.auth.selectedType: "use-openai"` |
| **OpenRouter**    | `OPENROUTER_API_KEY` | `security.auth.selectedType: "use-openai"` |

### Set via Environment Variables

```bash
# macOS/Linux - Add to ~/.bashrc or ~/.zshrc
export OPENAI_API_KEY="sk-proj-xxxxx"

# Windows PowerShell - Add to profile or set permanently
$env:OPENAI_API_KEY="sk-proj-xxxxx"
```

### Or Set in Settings File

```json
{
  "security": {
    "auth": {
      "selectedType": "use-openai"
    }
  }
}
```

Then set the environment variable with your actual API key.

---

## 🛠️ Settings Categories

### `general`

- `language` - UI language (auto, en, zh, etc.)
- `vimMode` - Enable vim keybindings
- `disableAutoUpdate` - Disable automatic updates
- `checkpointing` - Enable/disable session checkpointing

### `ui`

- `theme` - Color theme (light, dark, system-theme)
- `showMemoryUsage` - Display memory stats in footer
- `hideWindowTitle` - Hide window title bar

### `security`

- `auth.selectedType` - Authentication method (use-openai, qwen-oauth, etc.)
- `folderTrust` - Folder trust settings

### `model`

- `provider` - AI provider (openai, anthropic, gemini, etc.)
- `chatCompression` - Context compression (auto, none, aggressive)

### `context`

- `fileName` - Name of context/memory file
- `importFormat` - How to format memory (tree, flat)
- `includeDirectories` - Directories to search for memory
- `loadMemoryFromIncludeDirectories` - Auto-load memory from directories

### `tools`

- `autoAccept` - Auto-accept tool confirmations (⚠️ use with caution)
- `sandbox` - Enable sandboxed execution
- `useRipgrep` - Use ripgrep for file search

### `mcp`

- `allowed` - List of allowed MCP servers

### `advanced`

- `autoConfigureMemory` - Auto-set Node memory limits
- `maxOutputLines` - Max lines in tool output

### `telemetry`

- `enabled` - Send anonymous usage data

---

## ✅ Verification

After creating the settings file, verify it's working:

```bash
# Check if the file exists and is valid JSON
npm run doctor

# You should see: ✅ Settings file is valid
```

---

## 🔄 Update Settings

You can modify settings:

1. **Directly edit the file**:

   ```bash
   nano ~/.qwen/settings.json
   ```

2. **Via the CLI** (when running interactively):
   ```bash
   npm start
   # Then use the settings dialog in the UI
   ```

---

## 🐛 Troubleshooting

### ❌ "Settings file not found"

Create it manually:

```bash
mkdir -p ~/.qwen
cat > ~/.qwen/settings.json << 'EOF'
{
  "$version": 2,
  "security": {
    "auth": {
      "selectedType": "use-openai"
    }
  }
}
EOF
```

### ❌ "Invalid JSON"

Check for syntax errors:

```bash
# Validate JSON
python3 -m json.tool ~/.qwen/settings.json

# Or use jq
jq . ~/.qwen/settings.json
```

### ❌ "API key not found"

Make sure your environment variable is set:

```bash
# Check if set
echo $OPENAI_API_KEY

# Or add to shell profile
echo 'export OPENAI_API_KEY="sk-proj-xxxxx"' >> ~/.bashrc
source ~/.bashrc
```

---

## 📖 See Also

- [Developer Setup Guide](./DEVELOPER_SETUP.md)
- [Contributing Guide](../CONTRIBUTING.md)
- [Settings Schema Reference](./development/SETTINGS_SCHEMA.md)
