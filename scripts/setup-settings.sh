#!/bin/bash
# DarkCoder Settings Setup Script
# This script helps new contributors set up ~/.qwen/settings.json

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Settings paths
SETTINGS_DIR="$HOME/.qwen"
SETTINGS_FILE="$SETTINGS_DIR/settings.json"
EXAMPLE_FILE="$PROJECT_ROOT/docs/examples/settings.example.json"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       DarkCoder Settings Configuration Setup              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if settings directory exists
if [ ! -d "$SETTINGS_DIR" ]; then
    echo -e "${YELLOW}→${NC} Creating ~/.qwen directory..."
    mkdir -p "$SETTINGS_DIR"
    echo -e "${GREEN}✓${NC} Directory created"
else
    echo -e "${GREEN}✓${NC} Settings directory already exists"
fi

# Check if settings file exists
if [ -f "$SETTINGS_FILE" ]; then
    echo -e "${GREEN}✓${NC} Settings file already exists at $SETTINGS_FILE"
    echo ""
    echo "Do you want to:"
    echo "  1) Keep existing settings (no changes)"
    echo "  2) Restore from example template (overwrites current)"
    read -p "Choose [1-2]: " choice
    
    case "$choice" in
        2)
            echo -e "${YELLOW}→${NC} Restoring from template..."
            cp "$EXAMPLE_FILE" "$SETTINGS_FILE"
            echo -e "${GREEN}✓${NC} Settings restored from template"
            ;;
        *)
            echo -e "${GREEN}✓${NC} Keeping existing settings"
            ;;
    esac
else
    echo -e "${YELLOW}→${NC} Creating settings file from template..."
    cp "$EXAMPLE_FILE" "$SETTINGS_FILE"
    echo -e "${GREEN}✓${NC} Settings file created at $SETTINGS_FILE"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Next steps:"
echo ""
echo "1. ${YELLOW}Edit your settings:${NC}"
echo "   nano $SETTINGS_FILE"
echo ""
echo "2. ${YELLOW}Set up API keys (choose at least ONE):${NC}"
echo "   export OPENAI_API_KEY='sk-proj-xxxxx'           # OpenAI"
echo "   # OR"
echo "   export ANTHROPIC_API_KEY='sk-ant-xxxxx'        # Anthropic"
echo "   # OR"
echo "   export GOOGLE_API_KEY='AIza-xxxxx'             # Google Gemini"
echo "   # OR"
echo "   export DASHSCOPE_API_KEY='sk-xxxxx'            # Qwen (Aliyun)"
echo ""
echo "   Add to ~/.bashrc or ~/.zshrc to make it permanent:"
echo "   echo 'export OPENAI_API_KEY=\"sk-proj-xxxxx\"' >> ~/.bashrc"
echo "   source ~/.bashrc"
echo ""
echo "3. ${YELLOW}Verify configuration:${NC}"
echo "   npm run doctor"
echo ""
echo "4. ${YELLOW}Start developing:${NC}"
echo "   npm start"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "For detailed settings documentation:"
echo "  ${BLUE}docs/SETTINGS_GUIDE.md${NC}"
echo ""
echo "For development setup guide:"
echo "  ${BLUE}docs/DEVELOPER_SETUP.md${NC}"
echo ""
