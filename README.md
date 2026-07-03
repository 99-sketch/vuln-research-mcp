# Vulnerability Research MCP Server

面向渗透测试专家的漏洞研究 MCP 服务器。整合多个漏洞数据源，提供统一的漏洞研究接口。

**v1.0.0** — 生产就绪版本。

---

## 审计修复清单（v1.0.0）

| 审计问题 | 修复 |
|---------|------|
| NVD API 无 Key 支持，5次/分钟限速 | 支持环境变量 `NVD_API_KEY`，有 Key 50次/30秒 |
| 无重试机制 | exponential backoff（1s→2s→4s），最多 3 次重试 |
| CWE 仅 18 条硬编码 | 扩展至 40 条 + MITRE 在线 fallback |
| subprocess 无版本检测 | nmap/searchsploit/sublist3r/amass 全部检测 `shutil.which()` + 版本 |
| 无异步并发控制 | NVD 请求经 semaphore 限流 + 时间窗口控制 |
| 测试覆盖 3/11 | 60 项 pytest 覆盖全部 11 个工具 |
| pyproject.toml 漏 dnspython | 已修复（v0.2.0 起） |
| .pypirc 暴露 | 已删除（v0.2.1 起） |
| 文档与代码不一致 | 重写，与实际完全一致 |

---

## 工具清单（11个）

| 工具 | 功能 | 可用性 | 数据源 |
|------|------|--------|--------|
| `search_cve` | 搜索 CVE 漏洞 | 开箱即用 | NVD API (带 Key + 限速 + 重试) |
| `get_cve_details` | 获取 CVE 详细信息 | 开箱即用 | NVD API (带 Key + 限速 + 重试) |
| `cvss_calculator` | CVSS v3.1 评分（FIRST 规范） | 开箱即用 | 内置算法 |
| `cwe_mapping` | 查询 CWE 分类 | 开箱即用 | 40 条本地 + MITRE 在线 fallback |
| `check_http_headers` | HTTP 安全头检查 | 开箱即用 | 目标站点 |
| `query_dns` | DNS 记录查询 | 开箱即用 | dnspython |
| `geolocate_ip` | IP 地理位置查询 | 开箱即用 | ip-api.com |
| `search_exploit` | 搜索 PoC/EXP | 在线优先 + 本地降级 | Exploit-DB API / searchsploit |
| `find_nuclei_template` | 查找 Nuclei 模板 | 在线优先 + 本地降级 | GitHub API / 本地模板 |
| `scan_ports` | 端口扫描 | 需安装 nmap | nmap (带版本检测) |
| `enumerate_subdomains` | 子域名枚举 | 需安装 sublist3r/amass | sublist3r / amass (带版本检测) |

---

## 架构

```
src/
  server.py              # 路由层：工具注册 + 调用分发 + 错误处理
  rate_limiter.py        # NVD API 速率限制 + 重试机制
  tools/
    cve_tools.py          # CVE 搜索与详情 (NVD API Key + 重试)
    cvss_tool.py          # CVSS v3.1 评分计算
    cwe_tool.py           # CWE 查询 (40 条 + MITRE fallback)
    exploit_tool.py       # Exploit-DB 搜索 (在线 + 本地降级 + 版本检测)
    nuclei_tool.py        # Nuclei 模板搜索 (在线 + 本地降级)
    scan_tools.py         # 端口扫描 + 子域名枚举 (版本检测)
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

### 3. 配置 NVD API Key（强烈推荐）

无 Key 限速 5 次/30 秒，有 Key 50 次/30 秒。

```bash
# Linux/macOS
export NVD_API_KEY="your-api-key-here"

# Windows PowerShell
$env:NVD_API_KEY = "your-api-key-here"
```

申请地址：https://nvd.nist.gov/developers/request-an-api-key

### 4. 配置 MCP 客户端

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["src/server.py"],
      "env": {
        "NVD_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### 5. 可选：安装外部工具

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
| 日志脱敏 | 工具调用日志不记录参数内容 |
| 速率限制 | NVD API semaphore + 时间窗口控制 |
| 重试机制 | exponential backoff（1s→2s→4s），最多 3 次 |

---

## 开发

```bash
# 运行测试
python -m pytest tests/ -v

# 快速自测
python test_v02.py

# 构建
pip install build
python -m build
```

---

## License

MIT
