@echo off
REM ============================================
REM  vuln-research-mcp v5.1 Windows Setup
REM  自动检测并安装所需依赖
REM ============================================

echo ========================================
echo  vuln-research-mcp v5.1
echo  Cross-Platform Enterprise Security
echo  Windows Setup
echo ========================================
echo.

REM --- Python Check ---
echo [1/5] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.10+ is required!
    echo Download: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH"
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do echo   Python %%v [OK]
echo.

REM --- Pip Check ---
echo [2/5] Upgrading pip...
python -m pip install --upgrade pip -q
echo   pip upgraded [OK]
echo.

REM --- Install Core ---
echo [3/5] Installing vuln-research-mcp core...
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple vuln-research-mcp --quiet
if %errorlevel% neq 0 (
    echo [WARN] Tsinghua mirror failed, trying default...
    pip install vuln-research-mcp --quiet
)
echo   vuln-research-mcp installed [OK]
echo.

REM --- Optional Tools ---
echo [4/5] Installing optional tools...

REM Nmap
where nmap >nul 2>&1
if %errorlevel% neq 0 (
    echo   nmap not found - installing python-nmap...
    pip install python-nmap --quiet
    echo   python-nmap installed [OK]
) else (
    echo   nmap found [OK]
)

REM Git
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] git not found - some features limited
    echo   Download: https://git-scm.com/download/win
) else (
    echo   git found [OK]
)

REM curl
where curl >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] curl not found
) else (
    echo   curl found [OK]
)
echo.

REM --- Verify ---
echo [5/5] Verifying installation...
python -m vuln_research_mcp --version
if %errorlevel% neq 0 (
    echo [ERROR] Installation verification failed!
    pause
    exit /b 1
)
echo.

echo ========================================
echo  Installation Complete!
echo.
echo  Quick Start:
echo    python -m vuln_research_mcp --interactive
echo.
echo  Documentation: docs/COMMUNITY.md
echo  GitHub: https://github.com/99-sketch/vuln-research-mcp
echo ========================================
pause
