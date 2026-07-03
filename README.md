# vuln-research-mcp

> 安全情报工作站 — Vulnerability Research MCP Server
> 
> 20 个工具 | 异步架构 | 熔断器 | 缓存 | CISA KEV | EPSS | 跨源搜索 | Docker

## 工具一览

| # | 工具 | 描述 | 依赖 |
|---|------|------|------|
| 1 | `search_cve` | 搜索 CVE 漏洞 (NVD API) | NVD API |
| 2 | `get_cve_details` | 获取 CVE 详细信息 | NVD API |
| 3 | `search_exploit` | 搜索 Exploit-DB (在线优先，本地降级) | Exploit-DB API / searchsploit |
| 4 | `cvss_calculator` | CVSS v3.1 评分计算 | 无 (离线) |
| 5 | `cwe_mapping` | 查询 CWE 信息 (40条本地 + MITRE fallback) | 无 (离线) / MITRE API |
| 6 | `find_nuclei_template` | 搜索 Nuclei 模板 | GitHub API |
| 7 | `scan_ports` | 端口扫描 (nmap，异步) | nmap |
| 8 | `enumerate_subdomains` | 子域名枚举 (sublist3r/amass) | sublist3r / amass |
| 9 | `check_http_headers` | HTTP 安全头检查 | 无 |
| 10 | `query_dns` | DNS 记录查询 | 无 |
| 11 | `geolocate_ip` | IP 地理定位 | ip-api.com |
| 12 | `search_poc_archive` | 搜索 PoC 档案库 (exploitarium) | git |
| 13 | `list_poc_archive` | 列出 PoC 档案库条目 | 无 |
| 14 | `clone_poc_archive` | 克隆 exploitarium 仓库 | git |
| 15 | `update_poc_archive` | 更新 PoC 档案库 | git |
| 16 | `check_kev` | 检查 CVE 是否在 CISA KEV 目录 | CISA API |
| 17 | `get_epss_score` | 获取 EPSS 评分 | EPSS API |
| 18 | `vulnerability_assess` | 综合风险评估 (CVSS + EPSS + KEV) | NVD + CISA + EPSS |
| 19 | `search_kev` | 搜索 CISA KEV 目录 | CISA API |
| 20 | `cross_source_search` | 跨源关联搜索 (CVE + Exploit + Nuclei) | NVD + Exploit-DB + GitHub |

## 快速开始

### 安装

```bash
# 从源码安装
git clone https://github.com/99-sketch/vuln-research-mcp.git
cd vuln-research-mcp
pip install -e .

# 或直接安装
pip install vuln-research-mcp
```

### 配置

```bash
# 创建配置文件
python -c "from src.core.config_manager import create_default_config; create_default_config()"

# 编辑 ~/.vuln-research-mcp/config.yaml
# 或使用环境变量
export NVD_API_KEY="your-api-key"    # 可选，提升 NVD 速率限制 5→50 req/30s
export LOG_LEVEL="INFO"              # DEBUG | INFO | WARNING | ERROR
export LOG_FORMAT="text"             # text | json
```

### MCP 客户端配置

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/vuln-research-mcp",
      "env": {
        "NVD_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Docker 部署

```bash
# 构建并运行
docker-compose up -d

# 或手动构建
docker build -t vuln-research-mcp .
docker run -i --rm -e NVD_API_KEY=your-key vuln-research-mcp
```

## 架构

```
src/
├── server.py              # MCP 路由层 (ToolRegistry 驱动)
├── core/                  # 基础设施
│   ├── async_subprocess.py    # 异步子进程 (不阻塞事件循环)
│   ├── circuit_breaker.py     # 熔断器 (CLOSED→OPEN→HALF_OPEN)
│   ├── cache_manager.py       # SQLite 持久缓存 (diskcache)
│   ├── health_check.py        # 启动自检 (不阻塞)
│   ├── config_manager.py      # YAML + 环境变量配置
│   ├── tool_registry.py       # 插件化工具注册表
│   └── structured_logger.py   # JSON/text 结构化日志
├── tools/                 # 工具实现
│   ├── cve_tools.py           # CVE 搜索 + 详情
│   ├── cvss_tool.py           # CVSS v3.1 计算
│   ├── cwe_tool.py            # CWE 映射 (40条 + MITRE)
│   ├── exploit_tool.py        # Exploit-DB 搜索
│   ├── nuclei_tool.py         # Nuclei 模板搜索
│   ├── scan_tools.py          # 端口扫描 + 子域名枚举
│   ├── network_tools.py       # HTTP头 + DNS + GeoIP
│   ├── poc_archive_tool.py    # PoC 档案库
│   ├── threat_intel_tool.py   # CISA KEV + EPSS + 综合评估
│   └── cross_search_tool.py   # 跨源关联搜索
├── validators/            # 输入校验 (防注入)
└── rate_limiter.py        # NVD API 速率控制
```

## 配置项

| 配置 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `api_keys.nvd` | `NVD_API_KEY` | `""` | NVD API Key |
| `server.log_level` | `LOG_LEVEL` | `INFO` | 日志级别 |
| `server.log_format` | `LOG_FORMAT` | `text` | 日志格式 |
| `cache.enabled` | `CACHE_ENABLED` | `true` | 缓存开关 |
| `cache.max_size_mb` | - | `200` | 缓存大小上限 |
| `tools.disabled` | - | `[]` | 禁用工具列表 |

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest tests/ -v

# 代码格式化
black src/ tests/
isort src/ tests/
```

## License

MIT
