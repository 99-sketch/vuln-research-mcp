# Vulnerability Research MCP Server

一个为渗透测试专家设计的漏洞研究 MCP 服务器。

整合多个漏洞数据源，提供统一的漏洞研究接口。

---

## 🚀 功能特性

### 核心工具（6个）

| 工具名称 | 功能 | 数据源 |
|---------|------|--------|
| `search_cve` | 搜索 CVE 漏洞 | NVD API |
| `get_cve_details` | 获取 CVE 详细信息 | NVD API |
| `search_exploit` | 搜索 PoC/EXP | Exploit-DB |
| `cvss_calculator` | CVSS v3.1 评分计算 | CVSS 标准 |
| `cwe_mapping` | 查询 CWE 分类 | MITRE CWE |
| `find_nuclei_template` | 查找 Nuclei 模板 | Nuclei Templates |

---

## 📦 安装

### 1. 克隆仓库

```bash
cd E:\QClawCache\workspace-agent-c3e0083a\vuln-research-mcp
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
        "E:\\QClawCache\\workspace-agent-c3e0083a\\vuln-research-mcp\\src\\server.py"
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

### 示例 3：计算 CVSS 评分

```
你：计算这个漏洞的 CVSS 评分：
- 攻击向量：网络
- 攻击复杂度：低
- 权限要求：无
- 用户交互：无
- 作用域：不变
- 机密性：高
- 完整性：高
- 可用性：高

Claude：调用 cvss_calculator 工具
结果：CVSS 9.8 (Critical)
```

---

## 🛠️ 开发计划

### 当前状态（v0.1.0）

- ✅ 基础 MCP 服务器框架
- ✅ `search_cve` 工具（完整实现）
- ✅ `get_cve_details` 工具（完整实现）
- ✅ `cvss_calculator` 工具（简化实现）
- ⚠️ `search_exploit` 工具（占位符，需要 Exploit-DB API）
- ⚠️ `cwe_mapping` 工具（简化实现，仅常见 CWE）
- ⚠️ `find_nuclei_template` 工具（占位符，需要本地仓库）

### 下一步

1. **集成 Exploit-DB API**
   - 使用官方 API 或本地 searchsploit
   - 支持按 CVE、关键词、类型搜索

2. **完善 CWE 数据库**
   - 下载 MITRE CWE 完整列表
   - 支持按 CWE-ID 查询详细信息

3. **集成 Nuclei Templates**
   - 自动克隆 nuclei-templates 仓库
   - 支持按标签、严重等级搜索

4. **添加更多数据源**
   - CISA KEV（已知利用漏洞目录）
   - GitHub Security Advisories
   - PyPI/npm 安全公告

---

## 🔒 安全注意事项

### ⚠️ 法律风险

1. **仅用于授权测试**
   - 本工具仅可用于获得书面授权的渗透测试
   - 未经授权使用可能违反法律

2. **数据使用合规**
   - NVD API 有速率限制（请遵守）
   - Exploit-DB 数据仅用于合法目的

### ✅ 安全开发建议

1. **输入验证**
   - 所有用户输入必须经过严格验证
   - 防止命令注入、路径遍历等攻击

2. **审计日志**
   - 所有工具调用都会记录到日志
   - 日志文件：`mcp-audit.log`

3. **权限控制**
   - 建议仅在隔离环境中运行
   - 不要以 root/管理员权限运行

---

## 📚 技术文档

### API 参考

#### `search_cve`

```python
参数:
  - keyword (str, 必需): 搜索关键词
  - product (str, 可选): 产品名称
  - version (str, 可选): 产品版本
  - max_results (int, 默认 10): 最大返回结果数

返回:
  {
    "total_results": int,
    "vulnerabilities": [
      {
        "cve_id": str,
        "published": str,
        "cvss_score": float,
        "severity": str,
        "description": str
      }
    ]
  }
```

#### `cvss_calculator`

```python
参数:
  - attack_vector (enum): NETWORK | ADJACENT_NETWORK | LOCAL | PHYSICAL
  - attack_complexity (enum): LOW | HIGH
  - privileges_required (enum): NONE | LOW | HIGH
  - user_interaction (enum): NONE | REQUIRED
  - scope (enum): UNCHANGED | CHANGED
  - confidentiality (enum): NONE | LOW | HIGH
  - integrity (enum): NONE | LOW | HIGH
  - availability (enum): NONE | LOW | HIGH

返回:
  {
    "base_score": float,
    "severity": str,
    "vector": dict
  }
```

---

## 🐛 问题排查

### 常见问题

1. **NVD API 调用失败**
   - 检查网络连接
   - 确认没有超过速率限制
   - 尝试使用 VPN

2. **MCP 服务器无法启动**
   - 检查 Python 版本（需要 3.10+）
   - 确认所有依赖已安装
   - 查看日志文件获取详细错误

3. **Claude Desktop 无法识别工具**
   - 检查配置文件路径
   - 重启 Claude Desktop
   - 查看 Developer Tools 控制台

---

## 📄 许可证

MIT License

---

## 👤 作者

渗透测试专家 Agent

---

## 🔗 相关资源

- [Model Context Protocol 官方文档](https://modelcontextprotocol.io)
- [NVD API 文档](https://nvd.nist.gov/developers/vulnerabilities)
- [CVSS v3.1 规范](https://www.first.org/cvss/v3.1/specification-document)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
