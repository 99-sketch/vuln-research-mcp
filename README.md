# Vulnerability Research MCP Server

一个为渗透测试专家设计的漏洞研究 MCP 服务器。

整合多个漏洞数据源，提供统一的漏洞研究接口。

当前版本：**v0.1.1**

---

## 🚀 功能特性

### 核心工具（11个）

| 工具名称 | 功能 | 数据源 |
|---------|------|--------|
| `search_cve` | 搜索 CVE 漏洞 | NVD API |
| `get_cve_details` | 获取 CVE 详细信息 | NVD API |
| `search_exploit` | 搜索 PoC/EXP | Exploit-DB |
| `cvss_calculator` | CVSS v3.1 评分计算（符合 FIRST 规范） | CVSS 标准 |
| `cwe_mapping` | 查询 CWE 分类（本地 18 类常见漏洞） | MITRE CWE |
| `find_nuclei_template` | 查找 Nuclei 模板 | Nuclei Templates |
| `scan_ports` | 端口扫描（nmap） | 本地 nmap |
| `enumerate_subdomains` | 子域名枚举（sublist3r/amass） | 本地工具 |
| `check_http_headers` | HTTP 安全头检查 | 目标站点 |
| `query_dns` | DNS 记录查询 | DNS 服务器 |
| `geolocate_ip` | IP 地理位置查询 | ip-api.com |

---

## 📦 安装

### 1. 克隆仓库

```bash
git clone https://github.com/99-sketch/vuln-research-mcp.git
cd vuln-research-mcp
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置 Claude Desktop

编辑 `claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": [
        "C:\\path\\to\\vuln-research-mcp\\src\\server.py"
      ]
    }
  }
}
```

---

## 🔧 使用方法

### 示例 1：搜索 Log4j 漏洞

```
你：帮我搜索 Log4j 相关的 CVE
Claude：调用 search_cve 工具
参数：keyword="Apache Log4j"
结果：返回 CVE-2021-44228 等相关漏洞
```

### 示例 2：获取 CVE 详细信息

```
你：获取 CVE-2021-44228 的详细信息
Claude：调用 get_cve_details 工具
结果：返回 CVSS 9.8, 影响版本, 修复建议等
```

### 示例 3：计算 CVSS 评分（完整 vector 字符串）

```
你：计算 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H 的评分
Claude：调用 cvss_calculator 工具
结果：CVSS 10.0 (Critical)
```

### 示例 4：查询 CWE-89（SQL 注入）

```
你：什么是 CWE-89？
Claude：调用 cwe_mapping 工具
结果：返回 SQL Injection 定义、类型、描述
```

---

## 🛠️ 开发计划

### 当前状态（v0.1.1）

- ✅ 基础 MCP 服务器框架
- ✅ 11 个工具完整实现
- ✅ CVSS 严格按 FIRST v3.1 规范计算
- ✅ 自测脚本覆盖核心路径
- 🔄 计划：增加 Temporal/Environmental Score 计算
- 🔄 计划：集成更多公开情报源

---

## 📄 许可证

MIT

---

## 📮 问题反馈

如有问题，请提交 Issue 到 [99-sketch/vuln-research-mcp](https://github.com/99-sketch/vuln-research-mcp)
