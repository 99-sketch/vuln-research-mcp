#!/bin/bash
# ============================================
#  vuln-research-mcp v5.1 macOS Setup
#  自动检测并安装所需依赖
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "  vuln-research-mcp v5.1"
echo "  Cross-Platform Enterprise Security"
echo "  macOS Setup"
echo "========================================"
echo

# --- Homebrew Check ---
echo -e "${GREEN}[1/5]${NC} Checking Homebrew..."
if ! command -v brew &>/dev/null; then
    echo "  Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    echo "  Homebrew installed [OK]"
else
    echo "  Homebrew found [OK]"
fi
echo

# --- System Tools ---
echo -e "${GREEN}[2/5]${NC} Installing system tools via Homebrew..."
brew install nmap git curl wget python@3.12 2>/dev/null || true
echo "  System tools installed [OK]"
echo

# --- Python Check ---
echo -e "${GREEN}[3/5]${NC} Setting up Python..."
PYTHON=$(brew --prefix python@3.12)/bin/python3 2>/dev/null || python3
$PYTHON --version
$PYTHON -m pip install --upgrade pip -q
echo "  Python ready [OK]"
echo

# --- Core Install ---
echo -e "${GREEN}[4/5]${NC} Installing vuln-research-mcp..."
$PYTHON -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple vuln-research-mcp -q 2>/dev/null || \
$PYTHON -m pip install vuln-research-mcp -q
echo "  vuln-research-mcp installed [OK]"
echo

# --- Verify ---
echo -e "${GREEN}[5/5]${NC} Verifying installation..."
$PYTHON -m vuln_research_mcp --version
echo
echo "========================================"
echo "  Installation Complete!"
echo
echo "  Quick Start:"
echo "    python -m vuln_research_mcp --interactive"
echo
echo "  Documentation: docs/COMMUNITY.md"
echo "  GitHub: https://github.com/99-sketch/vuln-research-mcp"
echo "========================================"
