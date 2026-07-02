# Vulnerability Research MCP Server — 使用教程

> 一个为渗透测试专家设计的漏洞研究 MCP 服务器，整合 NVD、Exploit-DB、CWE、Nuclei 等多个漏洞数据源，提供统一的漏洞研究接口。

---

## 目录

- [快速开始（5 分钟上手）](#快速开始5-分钟上手)
- [工具详解](#工具详解)
- [常见使用场景](#常见使用场景)
- [最佳实践](#最佳实践)
- [项目结构](#项目结构)

---

## 快速开始（5 分钟上手）

### 前提条件

- Python 3.10+
- Claude Desktop（或其他 MCP 客户端）

### Step 1：安装依赖

```bash
cd vuln-research-mcp
pip install -r requirements.txt
```

### Step 2：配置 Claude Desktop

编辑 `claude_desktop_config.json`（位于 `%APPDATA%\Claude\`）：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": [
        "E:\\path\\to\\vuln-research-mcp\\src\\server.py"
      ]
    }
  }
}
```

> Windows 一键安装：右键 `install.ps1` → "使用 PowerShell 运行"

### Step 3：重启 Claude Desktop

重启后，在对话框中应该可以看到锤子图标（工具列表），说明连接成功。

### Step 4：第一次调用

```
你：帮我搜索一下 Log4j 相关的 CVE 漏洞
Claude：调用 search_cve 工具
结果：返回 CVE-2021-44228 等相关漏洞信息
```

---

## 工具详解

### 1. `search_cve` — 搜索 CVE 漏洞

通过 NVD API 按关键词、产品名称或版本搜索公开漏洞。

#### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `keyword` | string | ✅ | - | 搜索关键词，如 "Apache Log4j"、"WordPress" |
| `product` | string | ❌ | null | 产品名称过滤，如 "Apache HTTP Server" |
| `version` | string | ❌ | null | 产品版本过滤，如 "2.4.49" |
| `max_results` | number | ❌ | 10 | 最大返回结果数（1-100） |

#### 使用示例

```
你：搜索 Apache Tomcat 的漏洞，返回 5 个结果
→ 工具调用：search_cve(keyword="Apache Tomcat", max_results=5)
```

#### 响应格式

```json
{
  "total_results": 42,
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-XXXXX",
      "source_identifier": "nvd@nist.gov",
      "published": "2024-01-15T10:00:00.000",
      "last_modified": "2024-02-01T08:30:00.000",
      "status": "Analyzed",
      "description": "Apache Tomcat 中存在...",
      "cvss_score": 8.1,
      "severity": "HIGH",
      "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    }
  ]
}
```

#### 注意事项

- NVD API 有速率限制：**未提供 API Key 时每分钟 5 次请求**
- 生产环境建议注册 NVD API Key 提升至每分钟 50 次
- 设置 API Key：在配置中添加环境变量 `NVD_API_KEY`

---

### 2. `get_cve_details` — 获取 CVE 详细信息

查询单个 CVE 的完整信息，包括 CVSS 指标、漏洞分类、受影响的配置、引用链接等。

#### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `cve_id` | string | ✅ | CVE 编号，格式如 `CVE-2021-44228` |

#### 使用示例

```
你：查看 CVE-2021-44228 的详细信息
→ 工具调用：get_cve_details(cve_id="CVE-2021-44228")
```

#### 响应格式

```json
{
  "cve_id": "CVE-2021-44228",
  "source_identifier": "nvd@nist.gov",
  "published": "2021-12-10T10:15:00.000",
  "last_modified": "2023-08-08T15:05:00.000",
  "status": "Modified",
  "description": "Apache Log4j2 中存在 JNDI 注入漏洞...",
  "metrics": {
    "cvssMetricV31": [
      {
        "cvssData": {
          "baseScore": 9.8,
          "baseSeverity": "CRITICAL"
        }
      }
    ]
  },
  "weaknesses": [
    {
      "source": "nvd@nist.gov",
      "type": "Primary",
      "description": [{"value": "CWE-502"}]
    }
  ],
  "configurations": [
    {
      "nodes": [
        {"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}]}
      ]
    }
  ],
  "references": [
    "https://github.com/apache/logging-log4j2/pull/608",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
  ]
}
```

---

### 3. `search_exploit` — 搜索漏洞利用代码（PoC/EXP）

通过本地 `searchsploit` 工具在 Exploit-DB 中搜索已知漏洞利用代码。

#### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `query` | string | ✅ | - | 搜索关键词，如 "WordPress"、"RCE"、"SQL" |
| `type_filter` | string | ❌ | null | 利用类型过滤：`remote` / `webapps` / `local` / `dos` |

#### 前置条件

需要在本地安装 searchsploit：

```bash
# Kali/Debian
sudo apt install exploitdb

# 通用方法（手动克隆）
git clone https://github.com/offensive-security/exploitdb.git
cd exploitdb
./searchsploit -u
```

#### 使用示例

```
你：搜索 WordPress 的远程代码执行漏洞利用
→ 工具调用：search_exploit(query="WordPress RCE", type_filter="webapps")
```

#### 响应格式

```json
{
  "query": "WordPress RCE",
  "type_filter": "webapps",
  "total_results": 15,
  "exploits": [
    {
      "Title": "WordPress Plugin XYZ 1.0 - Remote Code Execution",
      "EDB-ID": "12345",
      "Date": "2024-01-15",
      "Author": "security-researcher",
      "Type": "webapps",
      "Platform": "PHP",
      "Path": "/usr/share/exploitdb/exploits/php/webapps/12345.php"
    }
  ],
  "source": "searchsploit"
}
```

#### 如果 searchsploit 未安装

工具会返回安装指引：

```json
{
  "error": "searchsploit 未安装",
  "installation": [
    "Kali/Debian: sudo apt install exploitdb",
    "通用方法: git clone https://github.com/offensive-security/exploitdb.git"
  ],
  "query": "WordPress RCE"
}
```

---

### 4. `cvss_calculator` — CVSS v3.1 评分计算

根据 CVSS v3.1 标准计算漏洞的基础评分和严重等级。

#### 参数

| 参数 | 类型 | 必填 | 取值范围 |
|------|------|------|----------|
| `attack_vector` | string | ✅ | `NETWORK` / `ADJACENT_NETWORK` / `LOCAL` / `PHYSICAL` |
| `attack_complexity` | string | ✅ | `LOW` / `HIGH` |
| `privileges_required` | string | ✅ | `NONE` / `LOW` / `HIGH` |
| `user_interaction` | string | ✅ | `NONE` / `REQUIRED` |
| `scope` | string | ✅ | `UNCHANGED` / `CHANGED` |
| `confidentiality` | string | ✅ | `NONE` / `LOW` / `HIGH` |
| `integrity` | string | ✅ | `NONE` / `LOW` / `HIGH` |
| `availability` | string | ✅ | `NONE` / `LOW` / `HIGH` |

#### 参数速查表：如何选择

| CVSS 指标 | 参数名 | LOW 时机 | HIGH/NONE 时机 |
|-----------|--------|----------|----------------|
| 攻击位置 | `attack_vector` | 本地物理接触 | 远程网络攻击 |
| 攻击难度 | `attack_complexity` | 有特殊条件 | 不需要特殊条件 |
| 权限要求 | `privileges_required` | 需要认证/高权限 | 无需任何权限 |
| 用户交互 | `user_interaction` | 需要用户点击/操作 | 完全自动化 |
| 影响范围 | `scope` | - | 影响不跨安全域 / 跨安全域 |
| 影响程度 | `confidentiality` / `integrity` / `availability` | 部分影响 | 完全无影响 / 完全泄露或破坏 |

#### 使用示例

```
你：计算一个远程无需认证的 RCE 漏洞评分
   攻击向量：网络（远程）
   攻击复杂度：低
   所需权限：无
   用户交互：无
   作用域：不变
   机密性：高
   完整性：高
   可用性：高
→ 工具调用：cvss_calculator(
    attack_vector="NETWORK",
    attack_complexity="LOW",
    privileges_required="NONE",
    user_interaction="NONE",
    scope="UNCHANGED",
    confidentiality="HIGH",
    integrity="HIGH",
    availability="HIGH"
  )
```

#### 响应格式

```json
{
  "base_score": 9.8,
  "severity": "CRITICAL",
  "vector": {
    "AV": "N",
    "AC": "L",
    "PR": "N",
    "UI": "N",
    "S": "U",
    "C": "H",
    "I": "H",
    "A": "H"
  },
  "note": "这是简化实现，完整实现请参考 CVSS v3.1 规范"
}
```

#### 严重等级对照

| 评分范围 | 等级 | 说明 |
|----------|------|------|
| 9.0 - 10.0 | CRITICAL | 紧急，建议立即修复 |
| 7.0 - 8.9 | HIGH | 高危，应尽快修复 |
| 4.0 - 6.9 | MEDIUM | 中危，按计划修复 |
| 0.1 - 3.9 | LOW | 低危，可暂缓 |
| 0.0 | NONE | 无风险 |

> **注意**：当前实现为简化版本，精确评分请参考 [CVSS v3.1 官方计算器](https://www.first.org/cvss/calculator/3.1)

---

### 5. `cwe_mapping` — 查询 CWE 弱分类

查询 MITRE CWE（Common Weakness Enumeration）弱分类信息。

#### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `cwe_id` | string | ✅ | CWE 编号，如 `CWE-79`、`CWE-89` |

#### 内置支持的 CWE

| CWE ID | 名称 | 类型 |
|--------|------|------|
| CWE-79 | Cross-site Scripting（跨站脚本） | Class |
| CWE-89 | SQL Injection（SQL 注入） | Class |
| CWE-287 | Improper Authentication（认证缺陷） | Class |
| CWE-352 | Cross-Site Request Forgery (CSRF) | Compound |
| CWE-434 | Unrestricted File Upload（文件上传漏洞） | Base |

#### 使用示例

```
你：查询 CWE-79 的详细信息
→ 工具调用：cwe_mapping(cwe_id="CWE-79")
```

#### 响应格式

```json
{
  "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "weakness_type": "Class",
  "status": "Incomplete",
  "description": "The software does not neutralize or incorrectly neutralizes user-controllable input..."
}
```

#### 查询不支持的 CWE

如果查询不在内置列表中的 CWE，工具会返回 MITRE 官方链接：

```json
{
  "note": "CWE-502 详细信息需要查询 MITRE CWE 数据库",
  "url": "https://cwe.mitre.org/data/definitions/502.html",
  "suggestion": "考虑下载完整 CWE 数据库: https://cwe.mitre.org/data/downloads.html"
}
```

---

### 6. `find_nuclei_template` — 查找 Nuclei 模板

在本地 Nuclei Templates 仓库中搜索匹配的漏洞检测模板。

#### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `tags` | string | ✅ | - | 标签关键词，逗号分隔，如 `cve,rce,wordpress` |
| `severity` | string | ❌ | null | 严重等级过滤：`info` / `low` / `medium` / `high` / `critical` |

#### 前置条件

需要先下载 Nuclei Templates：

```bash
# 方法 1：使用 nuclei 自带的更新
nuclei -update-templates

# 方法 2：手动 git clone
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/.local/share/nuclei-templates
```

#### 使用示例

```
你：查找 Wordpress 相关的 critical 级别 Nuclei 模板
→ 工具调用：find_nuclei_template(tags="wordpress,cve", severity="critical")
```

#### 响应格式

```json
{
  "tags": "wordpress,cve",
  "severity": "critical",
  "total_matched": 5,
  "templates": [
    "/home/user/.local/share/nuclei-templates/http/cves/2024/wp-xyz.yaml",
    "/home/user/.local/share/nuclei-templates/http/cves/2023/wp-abc.yaml"
  ],
  "search_dir": "/home/user/.local/share/nuclei-templates"
}
```

---

### 7. `scan_ports` — 端口扫描

> ⚠️ **注意**：此工具已声明但**尚未实现完整功能**。当前无法直接调用。

目标：集成 nmap 进行端口扫描，支持快速/全端口/隐蔽/版本检测四种模式。

---

### 8. `enumerate_subdomains` — 子域名枚举

> ⚠️ **注意**：此工具已声明但**尚未实现完整功能**。当前无法直接调用。

目标：集成 sublist3r 或 amass 进行子域名发现。

---

### 9. `check_http_headers` — HTTP 安全头检查

> ⚠️ **注意**：此工具已声明但**尚未实现完整功能**。当前无法直接调用。

目标：检查目标站点的 HTTP 安全响应头（HSTS、CSP、X-Frame-Options 等）。

---

### 10. `query_dns` — DNS 记录查询

> ⚠️ **注意**：此工具已声明但**尚未实现完整功能**。当前无法直接调用。

目标：查询 A、AAAA、MX、NS、TXT、CNAME 等 DNS 记录。

---

### 11. `geolocate_ip` — IP 地理位置查询

> ⚠️ **注意**：此工具已声明但**尚未实现完整功能**。当前无法直接调用。

目标：查询 IP 地址的地理位置信息。

---

## 常见使用场景

### 场景 1：漏洞信息收集 → 漏洞利用 → 报告

```
你：
1. 搜索 Apache Log4j 相关的 CVE
2. 获取 CVE-2021-44228 的详细信息
3. 查询对应的 CWE 分类 CWE-502
4. 搜索可用的 exploit
5. 查找对应的 Nuclei 模板
→ 完整漏洞研究流程
```

### 场景 2：新漏洞发现时的快速评估

```
你：发现一个 Web 应用疑似存在 SQL 注入漏洞
1. 搜索该应用相关 CVE
2. 查询 CWE-89 的详细定义
3. 搜索 SQL 注入的 exploit
→ 快速确认漏洞类型和历史案例
```

### 场景 3：渗透测试报告编写

```
你：在报告中需要描述漏洞严重程度
1. 使用 cvss_calculator 计算 CVSS 评分
2. 结合 CWE 信息描述漏洞类型
3. 引用 CVE 详情的参考文献
→ 生成完整的漏洞评估数据
```

### 场景 4：漏洞复现与验证

```
你：需要复现 CVE-2021-44228
1. get_cve_details → 了解漏洞机制
2. search_exploit → 获取 PoC
3. find_nuclei_template → 获取检测模板
4. 用 Nuclei 扫描目标确认是否存在
→ 完成漏洞验证闭环
```

---

## 最佳实践

### 1. 配合使用工具链

建议按以下顺序在工作流中调用工具：

```
漏洞发现阶段：
  search_cve → 搜索相关漏洞

漏洞分析阶段：
  get_cve_details → 获取完整详情
  cwe_mapping → 了解漏洞分类
  cvss_calculator → 评估严重程度

利用与检测阶段：
  search_exploit → 获取利用代码
  find_nuclei_template → 获取检测模板
```

### 2. NVD API 速率管理

- 未提供 API Key：每分钟 ≤5 次
- 提供 API Key：每分钟 ≤50 次
- **建议**：在 `claude_desktop_config.json` 中添加：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["...\\src\\server.py"],
      "env": {
        "NVD_API_KEY": "your-api-key-here",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

[申请 NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)

### 3. 参数优化

- **搜索 CVE 时**：组合 `keyword` + `product` + `version` 获得更精确的结果
- **搜索 Exploit 时**：先搜索宽泛关键词，再使用 `type_filter` 缩小范围
- **计算 CVSS 时**：参考 NVD 官方的 CVSS 向量，确保参数准确

### 4. 日志管理

服务器运行时会生成跨会话的审计日志：

- 日志文件：`mcp-audit.log`
- 日志级别：通过环境变量 `LOG_LEVEL` 控制（DEBUG / INFO / WARNING / ERROR）

### 5. 安全注意事项

- **只用于授权测试**：确保拥有目标系统的书面授权
- **隔离运行环境**：建议在虚拟机或容器中运行
- **不要以管理员权限运行**：使用普通用户身份启动
- **注意数据合规**：不要将漏洞数据用于非法目的

---

## 项目结构

```
vuln-research-mcp/
├── src/
│   └── server.py            # MCP 服务器主程序
├── tests/
│   └── test_server.py       # 自动化测试
├── docs/                    # 高级文档目录
│   ├── installation.md      # 详细安装指南
│   ├── configuration.md     # 配置说明
│   ├── advanced-usage.md    # 高级用法
│   └── integrations.md      # 工具集成
├── USAGE.md                 # 本文件 — 使用教程
├── EXAMPLES.md              # 使用示例集合
├── API_REFERENCE.md         # API 参考手册
├── TROUBLESHOOTING.md       # 问题排查指南
├── CONTRIBUTING.md          # 贡献指南
├── CHANGELOG.md             # 版本更新日志
├── README.md                # 项目介绍 README
├── install.ps1              # Windows 一键安装脚本
├── requirements.txt         # Python 依赖
└── claude_desktop_config_example.json  # 配置示例
```
