# 与其他工具集成

> 将 Vulnerability Research MCP Server 与渗透测试工具链中的其他工具配合使用。

---

## 目录

- [与 Nuclei 集成](#与-nuclei-集成)
- [与 Burp Suite 集成](#与-burp-suite-集成)
- [与 Metasploit 集成](#与-metasploit-集成)
- [与其他 MCP 服务器集成](#与其他-mcp-服务器集成)
- [与 CI/CD 流水线集成](#与-cicd-流水线集成)
- [与报告生成工具集成](#与报告生成工具集成)

---

## 与 Nuclei 集成

### 工作流：CVE 发现 → 模板查找 → 扫描执行

完整的漏洞验证链路：

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
│ search_cve  │ ──→ │ find_nuclei_    │ ──→ │ Nuclei CLI   │
│ (发现漏洞)   │     │ template        │     │ (执行扫描)    │
│             │     │ (查找检测模板)   │     │              │
└─────────────┘     └─────────────────┘     └──────────────┘
```

### Step-by-Step 示例

```bash
# 1. 通过 MCP 搜索 CVE（在 Claude 中执行）
# 工具调用：search_cve(keyword="CVE-2024-XXXXX")

# 2. 获取对应的 Nuclei 模板路径
# 工具调用：find_nuclei_template(tags="cve-2024-xxxxx")

# 3. 手动执行 Nuclei 扫描
nuclei -t /path/to/template.yaml -u https://target.com
```

### Nuclei 自动扫描脚本

创建自动化扫描脚本：

```powershell
# run-nuclei.ps1
$CVE_ID = "CVE-2024-XXXXX"
$TARGET = "https://target.com"
$TEMPLATES_DIR = "$env:USERPROFILE\.local\share\nuclei-templates"

# 查找对应的模板
$templates = Get-ChildItem -Path $TEMPLATES_DIR -Recurse -Filter "*.yaml" | 
             Select-String -Pattern $CVE_ID -SimpleMatch | 
             ForEach-Object { $_.Path }

if ($templates) {
    Write-Host "找到 ${templates.Count} 个匹配模板"
    foreach ($t in $templates) {
        Write-Host "执行: nuclei -t $t -u $TARGET"
        nuclei -t $t -u $TARGET
    }
} else {
    Write-Host "未找到 $CVE_ID 的 Nuclei 模板"
}
```

---

## 与 Burp Suite 集成

### 工作流：Burp 捕获 → 漏洞查询 → 报告

```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│ Burp Suite     │ ──→ │ Claude MCP     │ ──→ │ 漏洞详细信息   │
│ (捕获请求)     │     │ (查询漏洞)     │     │ (用于报告)     │
└────────────────┘     └────────────────┘     └────────────────┘
```

### 使用场景

1. **Burp 中发现疑似漏洞** → 在 Claude 中查询 CVE
2. **确定漏洞库中的对应条目** → 获取 CVSS 评分
3. **写入渗透测试报告**

### 具体步骤

```text
# 场景：Burp Suite 拦截到 SQL 注入

# Step 1: 在 Claude 中查询
search_cve(keyword="SQL Injection", product="Target Product")

# Step 2: 获取详细利用信息
cwe_mapping(cwe_id="CWE-89")

# Step 3: 搜索可用 Exploit
search_exploit(query="Target Product SQL Injection")

# Step 4: 将结果填入 Burp 报告
```

---

## 与 Metasploit 集成

### 工作流：CVE 查询 → Exploit 搜索 → MSF 利用

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│ search_cve  │ ──→ │ search_exploit  │ ──→ │ Metasploit   │
│ (发现漏洞)   │     │ (搜索 PoC)      │     │ (执行利用)   │
└─────────────┘     └─────────────────┘     └─────────────┘
```

### MSF 模块搜索辅助

Metasploit 中的 exploit 模块名称可能与 CVE-ExploitDB ID 对应，可以通过以下方式配合使用：

```bash
# 在 msfconsole 中
msf6 > search cve:2024 type:exploit
msf6 > search CVE-2024-XXXXX
```

同时在本 MCP 服务器中查询：

```text
# 获取漏洞详情
get_cve_details(cve_id="CVE-2024-XXXXX")

# 获取 Exploit-DB 条目
search_exploit(query="CVE-2024-XXXXX")
```

---

## 与其他 MCP 服务器集成

### filesystem MCP 服务器

将漏洞数据导出到本地文件：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\vuln-research-mcp\\src\\server.py"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\reports"]
    }
  }
}
```

工作流：

```text
Claude：
1. search_cve(keyword="漏洞") → 获取数据
2. 使用 filesystem MCP 将数据保存到报告文件 → write_file("C:\\reports\\vuln-data.json", data)
```

### github MCP 服务器

将漏洞信息创建为 GitHub Issue：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\server.py"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

---

## 与 CI/CD 流水线集成

### 场景：自动检查依赖漏洞

将漏洞查询集成到 CI/CD 流程中，在构建时检查依赖安全状态：

```yaml
# .github/workflows/vuln-check.yml
name: Dependency Vulnerability Check
on:
  schedule:
    - cron: '0 6 * * 1'  # 每周一早上 6 点
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check Dependencies
        run: |
          # 读取项目的依赖列表
          # 通过 MCP 服务器逐个查询 CVE
          echo "需要 MCP 客户端支持"
```

### 集成步骤

1. 在 CI/CD 环境中安装 MCP 客户端
2. 配置 MCP 服务器连接
3. 扫描依赖文件中的版本信息
4. 对每个依赖调用 `search_cve` 检查已知漏洞
5. 汇总结果到 CI 报告

---

## 与报告生成工具集成

### 生成 Markdown 报告

自动生成漏洞研究报告：

```text
# Claude 工作流
1. search_cve(keyword="目标产品") → 获取漏洞列表
2. get_cve_details → 对高价值漏洞获取详情
3. cvss_calculator → 计算评分
4. cwe_mapping → 获取 CWE 分类
5. 使用 filesystem MCP 写入报告文件
```

### 报告模板

```markdown
# 漏洞评估报告

## 概述
- 目标产品：{product}
- 版本：{version}
- 评估日期：{date}

## 发现的漏洞

### {cve_id} - {severity} 严重等级
- CVSS 评分：{score}
- CWE 分类：{cwe_name}
- 描述：{description}
- 推荐修复：{fix_advice}
```

### 配合工具输出格式

直接从 JSON 输出提取数据填充报告：

```
{
  "vulnerability_list": [
    {"cve_id": "...", "cvss_score": 9.8, "severity": "CRITICAL"},
    {"cve_id": "...", "cvss_score": 7.5, "severity": "HIGH"}
  ]
}
→ 转换为报告表格
```

---

## 与 AI 安全助手配合

本 MCP 服务器可以作为 AI 安全助手的"漏洞数据库"插件，提供实时漏洞查询能力：

```
用户 → AI 安全助手 → MCP 服务器 → NVD/Exploit-DB
   ↑                                    |
    └──────────── 返回结果 ──────────────┘
```

支持此架构的工具包括：
- Claude Desktop（原生 MCP 支持）
- Continue.dev（VS Code / JetBrains 插件）
- Cursor IDE
- 自定义 MCP 客户端
