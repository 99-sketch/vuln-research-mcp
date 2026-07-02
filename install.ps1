# 快速安装脚本 for Windows PowerShell

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Vulnerability Research MCP Server" -ForegroundColor Cyan
Write-Host "快速安装脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 检查 Python 版本
Write-Host "[1/5] 检查 Python 版本..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python 未安装"
    }
    Write-Host "✅ $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "❌ Python 未安装或不在 PATH 中" -ForegroundColor Red
    Write-Host "请安装 Python 3.10+ 并确保添加到 PATH" -ForegroundColor Yellow
    exit 1
}

# 检查 pip
Write-Host ""
Write-Host "[2/5] 检查 pip..." -ForegroundColor Yellow
try {
    $pipVersion = pip --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "pip 未安装"
    }
    Write-Host "✅ $pipVersion" -ForegroundColor Green
}
catch {
    Write-Host "❌ pip 未安装" -ForegroundColor Red
    exit 1
}

# 安装依赖
Write-Host ""
Write-Host "[3/5] 安装依赖包..." -ForegroundColor Yellow
try {
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        throw "依赖安装失败"
    }
    Write-Host "✅ 依赖安装成功" -ForegroundColor Green
}
catch {
    Write-Host "❌ 依赖安装失败: $_" -ForegroundColor Red
    exit 1
}

# 运行测试
Write-Host ""
Write-Host "[4/5] 运行测试..." -ForegroundColor Yellow
try {
    Set-Location -Path ".\tests"
    python test_server.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️ 部分测试失败，但可以继续" -ForegroundColor Yellow
    }
    else {
        Write-Host "✅ 所有测试通过" -ForegroundColor Green
    }
    Set-Location -Path ".."
}
catch {
    Write-Host "⚠️ 测试运行失败: $_" -ForegroundColor Yellow
    Set-Location -Path ".."
}

# 生成 Claude Desktop 配置
Write-Host ""
Write-Host "[5/5] 生成 Claude Desktop 配置..." -ForegroundColor Yellow

$configDir = "$env:APPDATA\Claude"
$configFile = "$configDir\claude_desktop_config.json"

# 确保目录存在
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
}

# 读取现有配置或创建新配置
if (Test-Path $configFile) {
    $config = Get-Content $configFile -Raw | ConvertFrom-Json
}
else {
    $config = @{
        "mcpServers" = @{}
    }
}

# 添加 vuln-research 配置
$serverPath = Resolve-Path ".\src\server.py"
$config.mcpServers | Add-Member -NotePropertyName "vuln-research" -NotePropertyValue @{
    "command" = "python"
    "args" = @($serverPath.Path)
} -Force

# 保存配置
$config | ConvertTo-Json -Depth 10 | Set-Content $configFile

Write-Host "✅ 配置已生成: $configFile" -ForegroundColor Green
Write-Host ""
Write-Host "配置内容:" -ForegroundColor Cyan
Write-Host ($config | ConvertTo-Json -Depth 10) -ForegroundColor Gray

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ 安装完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "下一步:" -ForegroundColor Yellow
Write-Host "1. 重启 Claude Desktop" -ForegroundColor White
Write-Host "2. 在 Claude 中测试工具：'帮我搜索 Log4j 相关的 CVE'" -ForegroundColor White
Write-Host ""
Write-Host "手动配置路径:" -ForegroundColor Yellow
Write-Host "  $configFile" -ForegroundColor Gray
Write-Host ""
