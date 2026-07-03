# Vulnerability Research MCP Server

一个为渗透测试专家设计的漏洞研究 MCP 服务器。

整合多个漏洞数据源，提供统一的漏洞研究接口。

当前版本：**v0.2.0**

---

## v0.2.0 重构亮点

- **模块化架构**：server.py 路由层 + tools/ 实现层 + validators/ 安全校验层
- **安全防护**：全参数输入校验、命令注入防护、SSRF 防护、路径遍历防护
- **在线降级**：search_exploit 和 find_nuclei_template 无本地工具时自动切换在线 API
- **54 项自测全部通过**

---

## 工具清单（11个）

| 工具 | 功能 | 可用性 | 数据源 |
|------|------|--------|--------|
| `search_cve` | 搜索 CVE 漏洞 | 开箱即用 | NVD API |
| `get_cve_details` | 获取 CVE 详细信息 | 开箱即用 | NVD API |
| `cvss_calculator` | CVSS v3.1 评分（FIRST 规范） | 开箱即用 | 内置算法 |
| `cwe_mapping` | 查询 CWE 分类（20 条） | 开箱即用 | 本地数据库 |
| `check_http_headers` | HTTP 安全头检查 | 开箱即用 | 目标站点 |
| `query_dns` | DNS 记录查询 | 开箱即用 | dnspython |
| `geolocate_ip` | IP 地理位置查询 | 开箱即用 | ip-api.com |
| `search_exploit` | 搜索 PoC/EXP | 在线优先 + 本地降级 | Exploit-DB API / searchsploit |
| `find_nuclei_template` | 查找 Nuclei 模板 | 在线优先 + 本地降级 | GitHub API / 本地模板 |
| `scan_ports` | 端口扫描 | 需安装 nmap | nmap |
| `enumerate_subdomains` | 子域名枚举 | 需安装 sublist3r/amass | sublist3r / amass |

---

## 架构

```
src/
  server.py              # 路由层：工具注册 + 调用分发 + 错误处理
  tools/
    cve_tools.py          # CVE 搜索与详情
    cvss_tool.py          # CVSS v3.1 评分计算
    cwe_tool.py           # CWE 漏洞类型查询
    exploit_tool.py       # Exploit-DB 搜索（在线优先 + 本地降级）
    nuclei_tool.py        # Nuclei 模板搜索（在线优先 + 本地降级）
    scan_tools.py         # 端口扫描 + 子域名枚举
    network_tools.py      # HTTP 安全头 + DNS + IP 地理定位
  validators/
    __init__.py           # 输入验证：IP/域名/URL/端口/CVE/CWE + 命令注入防护
```

---

## 安装

### 1. 克隆仓库

```bash
git clone https://github.com/99-sketch/vuln-research-mcp.git
cd vuln-research-mcp
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置 MCP 客户端

编辑 `claude_desktop_config.json`（或对应 MCP 客户端配置）：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["src/server.py"]
    }
  }
}
```

### 4. 可选：安装外部工具

```bash
# nmap（端口扫描）
# Windows: https://nmap.org/download.html
# Linux: sudo apt install nmap
# macOS: brew install nmap

# sublist3r（子域名枚举）
pip install sublist3r

# searchsploit（Exploit 搜索 - 可选，不装会自动用在线 API）
# Linux: sudo apt install exploitdb
```

---

## 安全特性

| 防护类型 | 实现方式 |
|---------|---------|
| 命令注入 | `sanitize_subprocess_arg()` 拒绝 shell 元字符 |
| 输入校验 | IP/域名/URL/端口/CVE-ID/CWE-ID 正则验证 |
| SSRF 防护 | `is_private_ip()` 检测内网地址，URL 限制 http/https |
| 路径遍历 | 域名验证拒绝 `../` 模式 |
| 错误脱敏 | 统一 ValueError 捕获，不泄露堆栈 |

---

## 开发

```bash
# 运行测试
python test_v02.py

# 构建
pip install build
python -m build
```

---

## License

MIT
