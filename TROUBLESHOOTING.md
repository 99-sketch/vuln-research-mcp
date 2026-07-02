# 问题排查指南

> 常见问题、错误码对照表和调试技巧。

---

## 目录

- [常见问题（FAQ）](#常见问题faq)
- [错误代码对照表](#错误代码对照表)
- [调试技巧](#调试技巧)

---

## 常见问题（FAQ）

### 安装与配置

#### Q1：MCP 服务器无法启动

**症状**：Claude Desktop 中看不到工具图标，或报错 "MCP Server failed to start"

**排查步骤**：

```
Step 1: 检查 Python 版本
└─ python --version  # 需要 3.10+

Step 2: 确认依赖已安装
└─ pip list | Select-String "mcp|httpx|pydantic"  # Windows
└─ pip list | grep -E "mcp|httpx|pydantic"         # macOS/Linux

Step 3: 测试服务器是否能手动启动
└─ python src/server.py
   # 预期输出：Vulnerability Research MCP Server 启动中...
   # 如果报错，查看错误信息

Step 4: 检查配置文件路径
└─ 确认 claude_desktop_config.json 中的路径是绝对路径
└─ 确认路径中没有拼写错误
```

**Windows 特别提示**：路径分隔符要用 `\\` 而不是 `\`

```json
// ❌ 错误
"args": ["E:\path\server.py"]

// ✅ 正确
"args": ["E:\\path\\server.py"]
```

---

#### Q2：Claude Desktop 提示 "Tool not found"

**症状**：Claude 表示看不到 "search_cve" 等工具

**原因**：MCP 服务器没有正确注册工具。

**解决**：

1. 重启 Claude Desktop（完全退出，不仅仅是关闭窗口）
2. 打开 Developer Tools → Console，查看是否有 MCP 相关错误
3. 确认 `list_tools()` 方法返回了工具列表
4. 检查配置文件是否被正确加载

---

#### Q3：NVD API 调用失败

**症状**：`search_cve` 或 `get_cve_details` 调用返回错误

**常见原因**：

| 原因 | 解决方案 |
|------|----------|
| 网络不可达（无法连接 NVD） | 检查网络，尝试 ping `services.nvd.nist.gov` |
| 速率限制（HTTP 429） | 等待 1 分钟后再试，或配置 API Key |
| 防火墙/DNS 问题 | 检查 DNS 解析，考虑配置代理 |
| API 服务故障 | 访问 [NVD Status](https://nvd.nist.gov/status) 确认 |

**测试连接**：

```bash
# PowerShell
Invoke-RestMethod -Uri "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=test&resultsPerPage=1"
```

---

#### Q4：searchsploit 无法使用

**症状**：`search_exploit` 返回 "searchsploit 未安装" 或执行失败

**排查**：

```bash
# 检查是否已安装
searchsploit --version

# 如果未安装
sudo apt install exploitdb   # Kali/Debian
brew install exploitdb       # macOS

# 如果已安装但仍然失败，检查是否在 PATH 中
# 确认 searchsploit 命令可在终端中直接执行
```

**Windows 特别说明**：Windows 下 searchsploit 不直接支持，建议：
1. 使用 WSL 环境
2. 或手动克隆仓库在 WSL 中使用

---

#### Q5：Nuclei 模板搜索无结果

**症状**：`find_nuclei_template` 返回 "nuclei-templates 仓库未找到"

**解决**：

```bash
# 方式 1：使用 nuclei 自动下载
nuclei -update-templates

# 方式 2：手动克隆
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/.local/share/nuclei-templates
```

确认模板目录存在：

```bash
ls ~/.local/share/nuclei-templates/
```

---

### 使用问题

#### Q6：搜索结果过于宽泛或不准确

**原因**：搜索关键词过于简单。

**改进方法**：

```
❌ 宽泛：search_cve(keyword="Apache")
✅ 精确：search_cve(keyword="Apache HTTP Server", version="2.4.49", max_results=10)
✅ 精确：search_cve(keyword="WordPress Plugin WooCommerce", max_results=20)

❌ 过宽：search_exploit(query="RCE")
✅ 精确：search_exploit(query="WordPress RCE", type_filter="webapps")
```

---

#### Q7：CVSS 评分看起来很离谱

**原因**：当前实现为简化版本，精确度有限。

**验证方法**：

```
1. 记录你使用的所有参数
2. 打开官方计算器：https://www.first.org/cvss/calculator/3.1
3. 填入相同的参数
4. 对比结果
```

如果差异很大，可能是 scope（范围变化）处理不正确。

---

#### Q8：CWE 查询返回非内置提示

**症状**：`cwe_mapping` 返回 "需要查询 MITRE CWE 数据库"

**原因**：内置数据库只包含 5 个常见 CWE 条目。

**临时解决**：手动访问 MITRE 链接：

```
https://cwe.mitre.org/data/definitions/502.html
```

（将 `502` 替换为你的 CWE 编号）

---

#### Q9：工具调用超时

**症状**：MCP 客户端长时间无响应后报错。

| 工具 | 典型超时原因 | 预计耗时 |
|------|-------------|----------|
| `search_cve` | NVD API 响应慢 | 2-10 秒 |
| `get_cve_details` | NVD API 响应慢 | 2-10 秒 |
| `search_exploit` | searchsploit 搜索 | 1-5 秒 |
| `find_nuclei_template` | 遍历大量文件 | 5-30 秒 |

**建议**：Nuclei 模板搜索在仓库文件多时较慢，建议缩小 tags 范围。

---

#### Q10：Linux/macOS 下路径问题

**症状**：配置文件路径在 Windows 上正常，但转到 Linux 无法使用

**根本原因**：路径分隔符不同（Windows `\` vs Linux `/`）

**解决方案**：在不同操作系统上使用对应的路径格式：

| 操作系统 | 示例 |
|----------|------|
| Windows | `"C:\\Users\\me\\project\\src\\server.py"` |
| macOS | `"/Users/me/project/src/server.py"` |
| Linux | `"/home/me/project/src/server.py"` |

---

## 错误代码对照表

### HTTP 状态码参考

以下错误由 NVD API 返回，通过 httpx 传播：

| HTTP 状态码 | 含义 | 常见原因 | 处理建议 |
|-------------|------|----------|----------|
| 200 | OK | - | 正常 |
| 400 | Bad Request | 参数格式错误 | 检查 CVE 编号格式 |
| 403 | Forbidden | 请求被拒绝 | 检查是否需要 API Key |
| 404 | Not Found | CVE 不存在 / 路径错误 | 确认 CVE 编号正确 |
| 429 | Too Many Requests | 速率限制 | 等待 1 分钟后重试，配置 API Key |
| 500 | Server Error | NVD 服务端错误 | 稍后重试，检查 NVD Status |
| 503 | Service Unavailable | 服务不可用 | NVD 维护中，稍后重试 |

### Python 异常对照

| 异常类型 | 触发场景 | 处理方式 |
|----------|----------|----------|
| `httpx.ConnectError` | NVD 网络不可达 | 检查网络连接 |
| `httpx.TimeoutException` | NVD 请求超时（>30s） | 稍后重试 |
| `httpx.HTTPStatusError` | NVD 返回非 200 | 参见上方 HTTP 状态码 |
| `FileNotFoundError` | searchsploit 未安装 | 安装 searchsploit |
| `subprocess.TimeoutExpired` | searchsploit 超时 | 尝试简化查询 |
| `json.JSONDecodeError` | searchsploit 输出解析失败 | 返回原始文本输出 |
| `ValueError` | 未知工具名 | 检查工具名拼写 |
| `KeyError` | 缺少必填参数 | 检查参数列表 |

### 工具特有错误代码

| 工具 | 错误场景 | 响应中的字段 | 说明 |
|------|----------|-------------|------|
| `search_cve` | NVD API 错误 | 抛出 httpx 异常 | 异常未特殊处理 |
| `get_cve_details` | CVE 未找到 | `error` | CVE 编号无效或不存在 |
| `search_exploit` | searchsploit 未安装 | `error` + `installation` | 返回安装指引 |
| `search_exploit` | 执行失败 | `error` + `stderr` | searchsploit 异常 |
| `cwe_mapping` | 不支持的 CWE | `note` + `url` | 返回 MITRE 链接 |
| `find_nuclei_template` | 模板目录不存在 | `error` + `installation` | 返回下载指引 |

---

## 调试技巧

### 1. 启用详细日志

在配置中设置 `LOG_LEVEL=DEBUG`：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\server.py"],
      "env": {
        "LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

DEBUG 级别会输出：
- 每次工具调用的完整参数
- 与 NVD 的 HTTP 交互信息
- searchsploit 的子进程输出
- 模板搜索的遍历过程

### 2. 手动测试服务器

直接运行服务器，查看控制台输出：

```bash
# macOS / Linux
python src/server.py

# Windows PowerShell
python src\server.py
```

正常启动后，服务器会等待 MCP 客户端的 stdin/stdout 通信。此时可以：
- 观察是否有启动错误
- 在日志中查看工具调用详情
- 确认 NVD API 连接是否正常

### 3. 运行测试套件

```bash
cd tests
python test_server.py
```

测试套件会测试三个核心功能：
- `search_cve`（需要 NVD API 可访问）
- `get_cve_details`
- `cvss_calculator`

如果测试失败，根据错误信息定位问题。

### 4. 检查 NVD API 直接访问

用 curl 或 Invoke-RestMethod 直接测试 NVD API：

```powershell
# Windows PowerShell 测试 NVD
Invoke-RestMethod -Uri "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=test&resultsPerPage=1" -Method Get
```

```bash
# macOS / Linux
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=test&resultsPerPage=1" | jq '.totalResults'
```

### 5. 检查 searchsploit 独立运行

```bash
searchsploit --json "WordPress"
```

如果成功，返回 JSON。如果失败，检查安装状态。

### 6. 配置文件路径验证

确认配置文件语法正确：

```bash
# macOS/Linux
python -c "import json; json.load(open('/path/to/claude_desktop_config.json'))"

# Windows PowerShell
Get-Content "$env:APPDATA\Claude\claude_desktop_config.json" | ConvertFrom-Json
```

### 7. Windows 特有调试

```powershell
# 检查 Python 编码
python -c "import sys; print(sys.getdefaultencoding())"
# 应输出：utf-8

# 检查路径
Test-Path "E:\QClawCache\workspace-agent-c3e0083a\vuln-research-mcp\src\server.py"
# 应输出：True

# 检查依赖是否完整
pip show mcp httpx pydantic
```

### 8. 快速验证 checklist

```
□ Python 版本 >= 3.10
□ 所有依赖已安装 (pip list)
□ server.py 可独立启动 (python src/server.py)
□ claude_desktop_config.json 语法正确
□ 服务器路径是绝对路径
□ 路径分隔符正确 (Windows: \\, macOS/Linux: /)
□ Claude Desktop 已完全重启
□ NVD API 可访问
□ (可选) searchsploit 已安装
□ (可选) nuclei-templates 已下载
```
