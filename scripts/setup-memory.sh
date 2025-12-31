#!/bin/bash

# DarkCoder Memory Configuration Setup Script
# This script configures your environment for optimal memory management

set -e

SHELL_CONFIG=""
CURRENT_SHELL=$(basename "$SHELL")

echo "=================================="
echo "DarkCoder Memory Setup"
echo "=================================="
echo ""

# Detect shell configuration file
case "$CURRENT_SHELL" in
  bash)
    if [ -f "$HOME/.bashrc" ]; then
      SHELL_CONFIG="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
      SHELL_CONFIG="$HOME/.bash_profile"
    fi
    ;;
  zsh)
    SHELL_CONFIG="$HOME/.zshrc"
    ;;
  fish)
    SHELL_CONFIG="$HOME/.config/fish/config.fish"
    ;;
  *)
    echo "⚠️  Unknown shell: $CURRENT_SHELL"
    echo "Please manually add the following to your shell configuration:"
    echo ""
    echo 'export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"'
    echo ""
    exit 1
    ;;
esac

if [ -z "$SHELL_CONFIG" ]; then
  echo "❌ Could not find shell configuration file"
  exit 1
fi

echo "Detected shell: $CURRENT_SHELL"
echo "Configuration file: $SHELL_CONFIG"
echo ""

# Check if already configured
if grep -q "NODE_OPTIONS.*max-old-space-size" "$SHELL_CONFIG" 2>/dev/null; then
  echo "✅ Memory configuration already exists in $SHELL_CONFIG"
  echo ""
  echo "Current configuration:"
  grep "NODE_OPTIONS" "$SHELL_CONFIG"
  echo ""
  echo "To update, edit: $SHELL_CONFIG"
  exit 0
fi

# Add configuration
echo "Adding memory configuration..."
echo "" >> "$SHELL_CONFIG"
echo "# DarkCoder Memory Management Configuration" >> "$SHELL_CONFIG"
echo "# Increase Node.js heap limit to 8GB and enable manual garbage collection" >> "$SHELL_CONFIG"
echo 'export NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"' >> "$SHELL_CONFIG"
echo "" >> "$SHELL_CONFIG"

echo "✅ Successfully added memory configuration to $SHELL_CONFIG"
echo ""
echo "⚠️  IMPORTANT: Reload your shell to apply changes:"
echo ""
if [ "$CURRENT_SHELL" = "fish" ]; then
  echo "  source ~/.config/fish/config.fish"
else
  echo "  source $SHELL_CONFIG"
fi
echo ""
echo "Or restart your terminal."
echo ""
echo "=================================="
echo "Memory Configuration Details"
echo "=================================="
echo ""
echo "Heap Limit: 8GB (8192MB)"
echo "Garbage Collection: Manual (enabled)"
echo ""
echo "For systems with >16GB RAM, consider increasing to 16GB:"
echo '  export NODE_OPTIONS="--max-old-space-size=16384 --expose-gc"'
echo ""
echo "For systems with <8GB RAM, decrease to 4GB:"
echo '  export NODE_OPTIONS="--max-old-space-size=4096 --expose-gc"'
echo ""
