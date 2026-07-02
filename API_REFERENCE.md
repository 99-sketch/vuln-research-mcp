# API 参考手册

> 完整的工具 API 文档。每个工具的参数、响应格式、错误码全覆盖。

---

## 目录

- [工具总览](#工具总览)
- [search_cve](#1-search_cve)
- [get_cve_details](#2-get_cve_details)
- [search_exploit](#3-search_exploit)
- [cvss_calculator](#4-cvss_calculator)
- [cwe_mapping](#5-cwe_mapping)
- [find_nuclei_template](#6-find_nuclei_template)
- [预留工具说明](#预留工具说明)
- [错误代码参考](#错误代码参考)
- [全局错误处理](#全局错误处理)

---

## 工具总览

| # | 工具名 | 版本 | 数据源 | 实现状态 |
|---|--------|------|--------|----------|
| 1 | `search_cve` | v0.1.0 | NVD API v2.0 | ✅ 完整 |
| 2 | `get_cve_details` | v0.1.0 | NVD API v2.0 | ✅ 完整 |
| 3 | `search_exploit` | v0.1.0 | searchsploit | ✅ 完整（依赖本地工具） |
| 4 | `cvss_calculator` | v0.1.0 | 内置算法 | ✅ 完整（简化版） |
| 5 | `cwe_mapping` | v0.1.0 | 内置数据库 | ✅ 完整（有限条目） |
| 6 | `find_nuclei_template` | v0.1.0 | 本地仓库 | ✅ 完整（依赖本地仓库） |
| 7 | `scan_ports` | v0.1.0 | - | ⚠️ 声明未实现 |
| 8 | `enumerate_subdomains` | v0.1.0 | - | ⚠️ 声明未实现 |
| 9 | `check_http_headers` | v0.1.0 | - | ⚠️ 声明未实现 |
| 10 | `query_dns` | v0.1.0 | - | ⚠️ 声明未实现 |
| 11 | `geolocate_ip` | v0.1.0 | - | ⚠️ 声明未实现 |

---

## 1. search_cve

搜索 CVE 漏洞（按关键词、产品名称或版本）。

### 请求参数

```json
{
  "keyword": "string (必填)",
  "product": "string (可选)",
  "version": "string (可选)",
  "max_results": "number (可选，默认 10)"
}
```

#### 参数详细说明

| 字段 | 类型 | 必填 | 默认 | 约束 | 说明 |
|------|------|------|------|------|------|
| `keyword` | string | ✅ | - | 1-200 字符 | 搜索关键词，如产品名、漏洞类型、CVE ID 片段 |
| `product` | string | ❌ | null | 1-100 字符 | 产品名称过滤，配合 keyword 使用 |
| `version` | string | ❌ | null | 1-50 字符 | 产品版本过滤 |
| `max_results` | number | ❌ | 10 | 1-100 | 每次返回的最大结果数 |

### 响应格式

```json
{
  "total_results": "number",
  "vulnerabilities": [
    {
      "cve_id": "string",
      "source_identifier": "string",
      "published": "string (ISO 8601)",
      "last_modified": "string (ISO 8601)",
      "status": "string",
      "description": "string",
      "cvss_score": "number (nullable)",
      "severity": "string (nullable)",
      "vector_string": "string (nullable)"
    }
  ]
}
```

#### 响应字段说明

| 字段 | 类型 | 说明 | 可能值 |
|------|------|------|--------|
| `total_results` | number | NVD 数据库中匹配的总条数 | 0-100000+ |
| `vulnerabilities[]` | array | 漏洞列表（长度 ≤ max_results） | - |
| `cve_id` | string | CVE 编号 | `CVE-YYYY-NNNNN` |
| `source_identifier` | string | 数据来源标识 | `nvd@nist.gov` 等 |
| `published` | string | 发布日期 | ISO 8601 格式 |
| `last_modified` | string | 最后修改日期 | ISO 8601 格式 |
| `status` | string | 漏洞处理状态 | `Analyzed`, `Modified`, `Rejected`, `Awaiting Analysis` |
| `description` | string | 英文漏洞描述 | 文本 |
| `cvss_score` | number | CVSS v3.1 基础评分 | 0.0 - 10.0 |
| `severity` | string | 严重等级 | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `vector_string` | string | CVSS 向量字符串 | `CVSS:3.1/AV:N/AC:...` |

### 错误场景

| 场景 | HTTP 状态 | 处理方式 |
|------|-----------|----------|
| NVD API 不可达 | 500 | httpx 异常，返回错误信息 |
| 速率限制 | 429 | NVD 返回错误，httpx 抛出异常 |
| 无效参数 | - | 服务器内部校验异常 |
| 超时（>30s） | - | httpx 超时异常 |

### 调用示例

```python
# Python 直接调用
result = await search_cve(keyword="Linux Kernel", max_results=3)
print(f"结果数: {result['total_results']}")
for v in result['vulnerabilities']:
    print(f"  {v['cve_id']}: {v['cvss_score']} {v['severity']}")
```

---

## 2. get_cve_details

获取指定 CVE-ID 的完整详细信息。

### 请求参数

```json
{
  "cve_id": "string (必填)"
}
```

#### 参数详细说明

| 字段 | 类型 | 必填 | 格式 | 说明 |
|------|------|------|------|------|
| `cve_id` | string | ✅ | `CVE-YYYY-NNNNN` | 有效的 CVE 编号，大小写不敏感 |

### 响应格式

```json
{
  "cve_id": "string",
  "source_identifier": "string",
  "published": "string (ISO 8601)",
  "last_modified": "string (ISO 8601)",
  "status": "string",
  "description": "string",
  "metrics": "object (CVSS 指标详情)",
  "weaknesses": "array (CWE 列表)",
  "configurations": "array (CPE 匹配条件)",
  "references": "array (URL 列表)"
}
```

#### 响应字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `cve_id` | string | CVE 编号 |
| `source_identifier` | string | 数据来源 |
| `published` | string | 发布日期 |
| `last_modified` | string | 最后修改日期 |
| `status` | string | 状态：`Analyzed` / `Modified` / `Rejected` 等 |
| `description` | string | 漏洞描述文本 |
| `metrics` | object | CVSS v2/v3/v3.1 指标集合，可能包含多个版本 |
| `weaknesses` | array | CWE 弱分类列表 |
| `configurations` | array | 受影响的 CPE 配置条件 |
| `references` | string[] | 参考链接 URL 数组 |
| `error` | string（仅错误时） | 错误信息，如 `CVE CVE-XXXX-XXXXX 未找到` |

### 错误场景

| 场景 | 响应行为 |
|------|----------|
| CVE 编号不存在 | 返回 `{"error": "CVE CVE-XXXX-XXXXX 未找到"}` |
| CVE 格式无效 | server.py 不校验格式，直接转发给 NVD |
| 网络不可达 | httpx 异常 |

---

## 3. search_exploit

在 Exploit-DB 中搜索漏洞利用代码（需要本地 `searchsploit`）。

### 请求参数

```json
{
  "query": "string (必填)",
  "type_filter": "string (可选)"
}
```

#### 参数详细说明

| 字段 | 类型 | 必填 | 默认 | 可选值 | 说明 |
|------|------|------|------|--------|------|
| `query` | string | ✅ | - | 任意关键词 | 搜索关键词，如 `WordPress`、`RCE`、`CVE-2024` |
| `type_filter` | string | ❌ | null | `remote`, `webapps`, `local`, `dos` | 限制搜索的利用类型 |

### 响应格式

**成功响应（searchsploit 可用）：**

```json
{
  "query": "string",
  "type_filter": "string (或 null)",
  "total_results": "number",
  "exploits": [
    {
      "Title": "string",
      "EDB-ID": "string",
      "Date": "string",
      "Author": "string",
      "Type": "string",
      "Platform": "string",
      "Path": "string"
    }
  ],
  "source": "searchsploit"
}
```

**searchsploit 未安装：**

```json
{
  "error": "searchsploit 未安装",
  "installation": [
    "Kali/Debian: sudo apt install exploitdb",
    "通用方法: git clone https://github.com/offensive-security/exploitdb.git"
  ],
  "query": "string"
}
```

**searchsploit 执行失败：**

```json
{
  "error": "searchsploit 执行失败",
  "stderr": "string (错误输出)",
  "installation_hint": "sudo apt install exploitdb  # Kali/Debian"
}
```

### 前置条件

| 操作系统 | 安装命令 |
|----------|----------|
| Kali Linux | `sudo apt install exploitdb` |
| Ubuntu/Debian | `sudo apt install exploitdb` |
| macOS | `brew install exploitdb` |
| Windows | 手动克隆仓库：`git clone https://github.com/offensive-security/exploitdb.git` |

---

## 4. cvss_calculator

计算 CVSS v3.1 基础评分。

### 请求参数

```json
{
  "attack_vector": "enum (必填)",
  "attack_complexity": "enum (必填)",
  "privileges_required": "enum (必填)",
  "user_interaction": "enum (必填)",
  "scope": "enum (必填)",
  "confidentiality": "enum (必填)",
  "integrity": "enum (必填)",
  "availability": "enum (必填)"
}
```

#### 枚举值说明

| 参数 | 枚举值 | CVSS 缩写 | 说明 |
|------|--------|-----------|------|
| `attack_vector` | `NETWORK` / `ADJACENT_NETWORK` / `LOCAL` / `PHYSICAL` | AV | 攻击者所处位置 |
| `attack_complexity` | `LOW` / `HIGH` | AC | 攻击所需特殊条件 |
| `privileges_required` | `NONE` / `LOW` / `HIGH` | PR | 攻击前需要的认证级别 |
| `user_interaction` | `NONE` / `REQUIRED` | UI | 是否需要用户操作 |
| `scope` | `UNCHANGED` / `CHANGED` | S | 漏洞是否影响其他组件 |
| `confidentiality` | `NONE` / `LOW` / `HIGH` | C | 机密性影响程度 |
| `integrity` | `NONE` / `LOW` / `HIGH` | I | 完整性影响程度 |
| `availability` | `NONE` / `LOW` / `HIGH` | A | 可用性影响程度 |

### 响应格式

```json
{
  "base_score": "number (0.0 - 10.0)",
  "severity": "string (NONE/LOW/MEDIUM/HIGH/CRITICAL)",
  "vector": {
    "AV": "string",
    "AC": "string",
    "PR": "string",
    "UI": "string",
    "S": "string",
    "C": "string",
    "I": "string",
    "A": "string"
  },
  "note": "string (关于实现状态的说明)"
}
```

### 严重等级对照

| base_score 范围 | severity | 颜色标识 |
|----------------|----------|----------|
| 9.0 - 10.0 | `CRITICAL` | 🔴 红 |
| 7.0 - 8.9 | `HIGH` | 🟠 橙 |
| 4.0 - 6.9 | `MEDIUM` | 🟡 黄 |
| 0.1 - 3.9 | `LOW` | 🟢 绿 |
| 0.0 | `NONE` | ⚪ 灰 |

### 实现说明

> **当前实现为简化版本**，不完全符合 CVSS v3.1 规范。完整实现需要：
> - 正确处理 Scope Change 的 Impact 公式
> - 精确的 Exploitability 和 Impact 子评分
> - 支持 Temporal 和 Environmental 评分
>
> 建议参考 [CVSS v3.1 官方计算器](https://www.first.org/cvss/calculator/3.1) 获取精确评分。

---

## 5. cwe_mapping

查询 CWE 弱分类信息。

### 请求参数

```json
{
  "cwe_id": "string (必填)"
}
```

#### 参数说明

| 字段 | 类型 | 必填 | 格式 | 说明 |
|------|------|------|------|------|
| `cwe_id` | string | ✅ | `CWE-NNN` | CWE 编号，如 `CWE-79`、`CWE-89` |

### 响应格式

**内置条目（匹配成功）：**

```json
{
  "name": "string",
  "weakness_type": "string",
  "status": "string",
  "description": "string"
}
```

**非内置条目（未找到）：**

```json
{
  "note": "CWE-502 详细信息需要查询 MITRE CWE 数据库",
  "url": "https://cwe.mitre.org/data/definitions/502.html",
  "suggestion": "考虑下载完整 CWE 数据库: https://cwe.mitre.org/data/downloads.html"
}
```

### 内置 CWE 列表（可离线使用）

| CWE ID | 名称 | Type | Status |
|--------|------|------|--------|
| CWE-79 | Cross-site Scripting (XSS) | Class | Incomplete |
| CWE-89 | SQL Injection | Class | Draft |
| CWE-287 | Improper Authentication | Class | Draft |
| CWE-352 | Cross-Site Request Forgery (CSRF) | Compound | Incomplete |
| CWE-434 | Unrestricted File Upload with Dangerous Type | Base | Draft |

---

## 6. find_nuclei_template

在本地 Nuclei Templates 仓库中搜索检测模板。

### 请求参数

```json
{
  "tags": "string (必填)",
  "severity": "string (可选)"
}
```

#### 参数说明

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `tags` | string | ✅ | - | 标签关键词，逗号分隔，如 `cve,rce,wordpress` |
| `severity` | string | ❌ | null | 严重等级过滤：`info`, `low`, `medium`, `high`, `critical` |

### 响应格式

**本地仓库存在：**

```json
{
  "tags": "string",
  "severity": "string (或 null)",
  "total_matched": "number",
  "templates": ["/path/to/template1.yaml", "/path/to/template2.yaml"],
  "search_dir": "string"
}
```

**本地仓库不存在：**

```json
{
  "error": "nuclei-templates 仓库未找到",
  "installation": [
    "方法1: nuclei -update-templates",
    "方法2: git clone https://github.com/projectdiscovery/nuclei-templates.git ~/.local/share/nuclei-templates"
  ],
  "tags": "string",
  "severity": "string (或 null)"
}
```

### 搜索逻辑

- 遍历模板目录下所有 `.yaml` 文件
- 检查文件内容是否包含 `tags` 参数中的**所有**标签（AND 逻辑）
- 如果指定 `severity`，额外检查文件内容是否包含该严重等级
- 返回前 10 个匹配文件

---

## 预留工具说明

以下工具已在 `list_tools()` 中声明但**尚未实现**。调用会引发 `NameError`。

| 工具名 | 预期功能 | 计划集成 |
|--------|----------|---------|
| `scan_ports` | 端口扫描（nmap 集成） | 未来版本 |
| `enumerate_subdomains` | 子域名枚举 | 未来版本 |
| `check_http_headers` | HTTP 安全头检查 | 未来版本 |
| `query_dns` | DNS 记录查询 | 未来版本 |
| `geolocate_ip` | IP 地理定位 | 未来版本 |

---

## 错误代码参考

### 错误类型分类

| 类别 | 触发条件 | 表现 |
|------|----------|------|
| 参数错误 | 缺少必填参数、无效枚举值 | MCP 协议层返回错误 |
| 网络错误 | NVD API 不可达、超时、DNS 解析失败 | httpx 异常 → 服务器错误 |
| 外部工具错误 | searchsploit 未安装、模板目录不存在 | 工具返回错误响应 |
| 服务器内部错误 | 未知工具名、代码异常 | 服务器异常 |

### 典型错误响应

```json
// 错误示例 1：工具名不存在
{
  "type": "error",
  "content": [
    {
      "type": "text",
      "text": "未知工具: non_existent_tool"
    }
  ],
  "isError": true
}
```

```json
// 错误示例 2：NVD API 超时
// 服务器日志将显示：
// ERROR - 工具 search_cve 执行失败: ...
```

### NVD API 速率限制

| API Key 状态 | 每分钟请求数 | 每秒请求数 |
|-------------|-------------|-----------|
| 无 Key | 5 | 约 0.08 |
| 有 Key | 50 | 约 0.83 |

超限时 NVD API 返回 HTTP 429，httpx 抛出异常。

---

## 全局错误处理

服务器未实现自定义错误处理中间件。所有异常由 `call_tool()` 中的 try-except 捕获并重新抛出：

```
Exception → 日志记录 → raise → MCP 协议处理
```

建议后续开发添加：
1. 自定义异常类
2. 友好的错误消息格式化
3. 重试机制（特别是对网络错误）
4. 输入参数预校验
