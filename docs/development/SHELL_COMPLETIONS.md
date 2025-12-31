# Shell Completions Guide

DarkCoder provides comprehensive shell completion support for Bash, Zsh, and Fish shells. This guide explains how to install and use shell completions.

## Quick Install

The easiest way to install completions is using the built-in completion command:

```bash
# Auto-detect your shell and install
darkcoder completion --install

# Specify shell explicitly
darkcoder completion bash --install
darkcoder completion zsh --install
darkcoder completion fish --install
```

After installation, **restart your shell** or source your shell's RC file:

```bash
# Bash
source ~/.bashrc

# Zsh
source ~/.zshrc

# Fish (no action needed - auto-loads)
```

## Manual Installation

If you prefer manual installation or need to customize the location:

### Bash

1. Generate the completion script:

```bash
darkcoder completion bash --output ~/.darkcoder-completion.bash
```

2. Add to your `~/.bashrc`:

```bash
echo "source ~/.darkcoder-completion.bash" >> ~/.bashrc
source ~/.bashrc
```

### Zsh

1. Create completions directory if it doesn't exist:

```bash
mkdir -p ~/.zsh/completions
```

2. Generate the completion script:

```bash
darkcoder completion zsh --output ~/.zsh/completions/_darkcoder
```

3. Add to your `~/.zshrc`:

```bash
cat << 'EOF' >> ~/.zshrc
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit
EOF
source ~/.zshrc
```

### Fish

1. Create completions directory if it doesn't exist:

```bash
mkdir -p ~/.config/fish/completions
```

2. Generate the completion script:

```bash
darkcoder completion fish --output ~/.config/fish/completions/darkcoder.fish
```

3. Fish will automatically load it (no shell restart needed)

## What's Included

Shell completions provide intelligent suggestions for:

### Commands

- `darkcoder` - Main command
- `darkcoder completion` - Completion management
- `darkcoder extensions` - Extension management
  - `list`, `install`, `uninstall`, `enable`, `disable`, `update`, `new`, `link`
- `darkcoder mcp` - MCP server management
  - `list`, `add`, `remove`

### Options and Flags

- `--help`, `-h` - Show help
- `--version`, `-v` - Show version
- `--debug`, `-d` - Debug mode
- `--model`, `-m` - AI model selection (with model suggestions)
- `--prompt`, `-p` - Non-interactive prompt
- `--approval-mode` - Approval mode (plan, default, auto-edit, yolo)
- `--sandbox` - Sandbox mode (docker, podman, false)
- `--input-format` - Input format (text, multimodal)
- `--output-format`, `-o` - Output format (text, json, stream-json)
- `--yolo` - Auto-approve all operations
- `--all-files` - Include all files in context
- `--continue` - Resume most recent session
- `--resume` - Resume specific session
- `--config` - Configuration file path
- `--proxy` - HTTP proxy URL
- `--telemetry` - Enable telemetry

### Smart Suggestions

Completions provide context-aware suggestions:

**Model names:**

```bash
darkcoder --model <TAB>
# Suggests: gpt-4o, gpt-4o-mini, claude-3-5-sonnet, claude-3-5-haiku,
#          qwen-coder-plus, gemini-2.0-flash-exp, deepseek-v3, deepseek-r1
```

**Approval modes:**

```bash
darkcoder --approval-mode <TAB>
# Suggests: plan, default, auto-edit, yolo
```

**Shell types:**

```bash
darkcoder completion <TAB>
# Suggests: bash, zsh, fish
```

## Features

### Bash Completions

- ✅ Command and subcommand completion
- ✅ Option and flag completion
- ✅ Contextual suggestions based on previous arguments
- ✅ File path completion for `--config`
- ✅ Model name suggestions

### Zsh Completions

- ✅ All Bash features plus:
- ✅ Rich descriptions for each option
- ✅ Grouped completions (commands vs options)
- ✅ Aliased option support (e.g., `-h` and `--help`)
- ✅ Advanced completion menu navigation

### Fish Completions

- ✅ All Zsh features plus:
- ✅ Real-time suggestions as you type
- ✅ Automatic completion loading
- ✅ No shell restart required
- ✅ Inline descriptions

## Troubleshooting

### Completions not working

**Bash:**

```bash
# Check if completion is loaded
complete -p darkcoder

# Manually reload
source ~/.darkcoder-completion.bash
```

**Zsh:**

```bash
# Check if completions directory is in fpath
echo $fpath | grep completions

# Rebuild completion cache
rm -f ~/.zcompdump && compinit
```

**Fish:**

```bash
# Check if completion file exists
ls ~/.config/fish/completions/darkcoder.fish

# Fish auto-loads, but you can reload config
source ~/.config/fish/config.fish
```

### Permission denied

If you get permission errors during installation:

```bash
# Bash
chmod +x ~/.darkcoder-completion.bash

# Zsh
chmod +x ~/.zsh/completions/_darkcoder

# Fish
chmod +x ~/.config/fish/completions/darkcoder.fish
```

### Completions outdated

Regenerate completions after updating DarkCoder:

```bash
darkcoder completion --install
```

## Advanced Usage

### Custom Installation Path

```bash
# Install to custom location
darkcoder completion bash --output /custom/path/darkcoder-completion.bash

# Then source it from your RC file
echo "source /custom/path/darkcoder-completion.bash" >> ~/.bashrc
```

### View Completion Script

To see the generated script without installing:

```bash
# Print to stdout
darkcoder completion bash
darkcoder completion zsh
darkcoder completion fish
```

### System-wide Installation

For system-wide completions (requires sudo):

**Bash:**

```bash
sudo darkcoder completion bash --output /etc/bash_completion.d/darkcoder
```

**Zsh:**

```bash
sudo darkcoder completion zsh --output /usr/share/zsh/site-functions/_darkcoder
```

**Fish:**

```bash
sudo darkcoder completion fish --output /usr/share/fish/vendor_completions.d/darkcoder.fish
```

## Uninstallation

To remove completions:

**Bash:**

```bash
rm ~/.darkcoder-completion.bash
# Remove the source line from ~/.bashrc
```

**Zsh:**

```bash
rm ~/.zsh/completions/_darkcoder
# Remove the fpath line from ~/.zshrc
rm -f ~/.zcompdump && compinit
```

**Fish:**

```bash
rm ~/.config/fish/completions/darkcoder.fish
```

## See Also

- [Typo Detection](./TYPO_DETECTION.md) - "Did you mean?" suggestions for commands
- [Command Reference](./cli/COMMANDS.md) - Complete command documentation
- [Configuration Guide](./DARKCODER_SETUP_GUIDE.md) - DarkCoder configuration
