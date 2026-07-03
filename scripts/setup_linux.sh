#!/bin/bash
# ============================================
#  vuln-research-mcp v5.1 Linux Setup
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
echo "  Linux Setup"
echo "========================================"
echo

# --- Python Check ---
echo -e "${GREEN}[1/6]${NC} Checking Python..."
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}[ERROR]${NC} Python 3.10+ is required!"
    exit 1
fi
VER=$($PYTHON --version 2>&1)
echo "  $VER [OK]"
echo

# --- Pip Check ---
echo -e "${GREEN}[2/6]${NC} Upgrading pip..."
$PYTHON -m pip install --upgrade pip -q
echo "  pip upgraded [OK]"
echo

# --- System Tools ---
echo -e "${GREEN}[3/6]${NC} Installing system tools..."
if command -v apt &>/dev/null; then
    sudo apt update -qq
    sudo apt install -y -qq nmap git curl wget python3-pip python3-venv 2>/dev/null
    echo "  apt packages installed [OK]"
elif command -v yum &>/dev/null; then
    sudo yum install -y -q nmap git curl wget python3-pip 2>/dev/null
    echo "  yum packages installed [OK]"
elif command -v apk &>/dev/null; then
    sudo apk add --no-cache nmap git curl wget python3 py3-pip 2>/dev/null
    echo "  apk packages installed [OK]"
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm nmap git curl wget python-pip 2>/dev/null
    echo "  pacman packages installed [OK]"
else
    echo -e "${YELLOW}[WARN]${NC} Unknown package manager - install manually: nmap git curl"
fi
echo

# --- Go Tools (Optional) ---
echo -e "${GREEN}[4/6]${NC} Optional: Go-based tools..."
if command -v go &>/dev/null; then
    echo "  go found - installing tools..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && echo "  nuclei installed [OK]" || echo "  nuclei skipped"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && echo "  subfinder installed [OK]" || echo "  subfinder skipped"
else
    echo -e "${YELLOW}[WARN]${NC} go not found - skipping Go tools"
    echo "  Install Go: https://go.dev/dl/"
fi
echo

# --- Core Install ---
echo -e "${GREEN}[5/6]${NC} Installing vuln-research-mcp..."
$PYTHON -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple vuln-research-mcp -q 2>/dev/null || \
$PYTHON -m pip install -i https://mirrors.aliyun.com/pypi/simple/ vuln-research-mcp -q 2>/dev/null || \
$PYTHON -m pip install vuln-research-mcp -q
echo "  vuln-research-mcp installed [OK]"
echo

# --- Verify ---
echo -e "${GREEN}[6/6]${NC} Verifying installation..."
$PYTHON -m vuln_research_mcp --version
echo
echo "========================================"
echo "  Installation Complete!"
echo
echo "  Quick Start:"
echo "    python -m vuln_research_mcp --interactive"
echo
echo "  For production (systemd):"
echo "    docs/DEPLOYMENT.md"
echo
echo "  Documentation: docs/COMMUNITY.md"
echo "  GitHub: https://github.com/99-sketch/vuln-research-mcp"
echo "========================================"
