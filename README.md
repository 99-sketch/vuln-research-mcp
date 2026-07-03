# vuln-research-mcp

<p align="center">
  <img src="https://img.shields.io/badge/version-5.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10_|_3.11_|_3.12-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/platform-Win_|_Linux_|_macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/tools-55-orange.svg" alt="Tools">
  <img src="https://img.shields.io/badge/fingerprints-898-brightgreen.svg" alt="Fingerprints">
  <img src="https://img.shields.io/badge/security-extreme-red.svg" alt="Security">
  <img src="https://img.shields.io/badge/cnvd-CNVD_ready-red.svg" alt="CNVD">
  <img src="https://img.shields.io/badge/tests-363%20passed-brightgreen.svg" alt="Tests">
</p>

> **跨平台企业级安全平台** — Vulnerability Research MCP Server v5.1 (Cross-Platform Enterprise Security)
>
> 55 个工具 | 7层纵深防御 | 898指纹库 | 跨平台(Win/Linux/Mac) | CNVD/CNNVD | 等保2.0 | 离线镜像 | SIEM

---

## 工具一览 (39 tools)

### v1.0 基础安全工具 (15)

| # | 工具 | 描述 | 依赖 |
|---|------|------|------|
| 1 | `search_cve` | 搜索 CVE 漏洞 | NVD API |
| 2 | `get_cve_details` | 获取 CVE 详细信息 | NVD API |
| 3 | `search_exploit` | 搜索 Exploit-DB (在线优先，本地降级) | Exploit-DB / searchsploit |
| 4 | `cvss_calculator` | CVSS v3.1 评分计算 | 无 (离线) |
| 5 | `cwe_mapping` | 查询 CWE 信息 (40条 + MITRE fallback) | 无 / MITRE API |
| 6 | `find_nuclei_template` | 搜索 Nuclei 模板 | GitHub API |
| 7 | `scan_ports` | 端口扫描 | nmap |
| 8 | `enumerate_subdomains` | 子域名枚举 | sublist3r / amass |
| 9 | `check_http_headers` | HTTP 安全头检查 | 无 |
| 10 | `query_dns` | DNS 记录查询 | 无 |
| 11 | `geolocate_ip` | IP 地理定位 | ip-api.com |
| 12 | `search_poc_archive` | 搜索 PoC 档案库 (exploitarium) | git |
| 13 | `list_poc_archive` | 列出 PoC 档案库条目 | 无 |
| 14 | `clone_poc_archive` | 克隆 exploitarium 仓库 | git |
| 15 | `update_poc_archive` | 更新 PoC 档案库 | git |

### v2.0 威胁情报工具 (5)

| # | 工具 | 描述 | 依赖 |
|---|------|------|------|
| 16 | `check_kev` | 检查 CISA KEV 已知利用漏洞 | CISA API |
| 17 | `get_epss_score` | 获取 EPSS 利用概率评分 | EPSS API |
| 18 | `vulnerability_assess` | 综合风险评估 (CVSS + EPSS + KEV) | NVD + CISA + EPSS |
| 19 | `search_kev` | 搜索 CISA KEV 目录 | CISA API |
| 20 | `cross_source_search` | 跨源关联搜索 (CVE + Exploit + Nuclei) | NVD + Exploit-DB + GitHub |

### v3.0 高级分析工具 (9)

| # | 工具 | 描述 | 依赖 |
|---|------|------|------|
| 21 | `cpe_lookup` | 产品指纹 → CPE 匹配 | 无 (离线) |
| 22 | `service_fingerprint` | Banner 文本 → 服务/版本提取 | 无 |
| 23 | `graph_traverse` | 知识图谱 BFS 遍历 (CVE→CWE→Exploit→Actor) | 无 |
| 24 | `graph_neighbors` | 查询知识图谱节点邻居 | 无 |
| 25 | `graph_search` | 搜索知识图谱节点 | 无 |
| 26 | `graph_stats` | 知识图谱统计信息 | 无 |
| 27 | `generate_report` | 多格式安全报告 (STIX 2.1/SARIF/Markdown/JSON) | 无 |
| 28 | `run_workflow` | 执行预设渗透测试工作流 | 无 |
| 29 | `list_workflows` | 列出所有可用工作流 | 无 |

### v4.0 基础设施工具 (10)

| # | 工具 | 描述 | 依赖 |
|---|------|------|------|
| 30 | `parse_nmap_xml` | 解析 Nmap XML → 结构化资产 + 入库 | nmap |
| 31 | `generate_nuclei_cmd` | 生成 Nuclei CLI 扫描命令 | nuclei |
| 32 | `search_metasploit` | 搜索 Metasploit 模块 | msfconsole |
| 33 | `search_sploit` | 搜索 Exploit-DB 本地 (searchsploit) | searchsploit |
| 34 | `attack_technique` | 获取 MITRE ATT&CK 技术详情 | 无 (离线) |
| 35 | `map_to_attack` | 发现 → MITRE ATT&CK 战术/技术/缓解映射 | 无 (离线) |
| 36 | `attack_navigator` | 生成 ATT&CK Navigator 层 JSON | 无 (离线) |
| 37 | `run_pipeline` | 执行 YAML 渗透测试管道 | 无 |
| 38 | `list_pipelines` | 列出所有可用 YAML 管道 | 无 |
| 39 | `pentest_report` | 生成专业渗透测试报告 (Markdown/JSON) | SQLite |

### 预设工作流 (4)

| 工作流 | 描述 |
|--------|------|
| `quick_assess` | 快速评估：CVE详情 + 风险评估 + KEV + EPSS + Exploit搜索 |
| `full_pentest_prep` | 完整渗透准备：DNS + 子域名 + 端口 + HTTP头 + GeoIP |
| `vuln_deep_dive` | 漏洞深挖：Nuclei模板 + CWE + PoC + 跨源搜索 |
| `tech_stack_audit` | 技术栈审计：CPE查找 + CVE搜索 + 风险分析 |

### YAML 管道 (3)

| 管道 | 文件 | 描述 |
|------|------|------|
| `full_recon` | `data/pipelines/full_recon.yaml` | 完整侦察：网络发现→指纹识别→漏洞分析→报告 |
| `vuln_deep_dive` | `data/pipelines/vuln_deep_dive.yaml` | CVE深度分析：情报→漏洞利用→威胁情报 |
| `tech_stack_audit` | `data/pipelines/tech_stack_audit.yaml` | 技术栈审计：CPE识别→漏洞匹配→风险分析→报告 |

---

## 架构

```
src/
├── server.py                  # MCP 路由层 + CLI 入口 (820 行)
│
├── core/                      # 基础设施层
│   ├── tool_registry.py           # 插件化工具注册表
│   ├── circuit_breaker.py         # 熔断器 (CLOSED→OPEN→HALF_OPEN)
│   ├── cache_manager.py           # SQLite 持久缓存 (diskcache)
│   ├── config_manager.py          # YAML + 环境变量配置
│   ├── health_check.py            # 启动自检 + 降级
│   ├── async_subprocess.py        # 异步子进程 (不阻塞事件循环)
│   ├── structured_logger.py       # JSON/text 结构化日志
│   ├── knowledge_graph.py         # 知识图谱 (BFS 遍历 + pickle 持久化)
│   └── session_state.py           # 多会话状态管理
│
├── bus/                       # v4.0 事件总线
│   └── event_bus.py               # Pub/Sub 消息骨干 (同步/异步 + 通配符)
│
├── db/                        # v4.0 持久层
│   ├── database.py                # SQLite WAL 模式 (7 表 + CRUD + 线程安全)
│   └── models.py                  # ORM 模型 (Project/Asset/Finding/Scan/...)
│
├── correlator/                # v4.0 关联引擎
│   └── engine.py                  # Banner→CPE→CVE 自动关联 (28产品 + 20+版本)
│
├── orchestrator/              # v4.0 管道编排
│   ├── pipeline.py                # YAML DAG 并行管道 ($context.* 变量 + 重试)
│   └── scheduler.py               # 进程内 cron 任务调度器
│
├── intel/                     # v4.0 威胁情报
│   └── attck.py                   # MITRE ATT&CK 映射 (CWE→Technique + Navigator)
│
├── reporting/                 # v4.0 报告
│   └── pentest_report.py          # 专业渗透测试报告 (Markdown/JSON)
│
├── gateway/                   # 网关层
│   ├── cli.py                     # Rich CLI 交互界面 (16 快捷命令)
│   └── rest_api.py                # FastAPI REST API (20+ 端点 + WebSocket + SSE)
│
├── workflow/                  # 工作流引擎
│   ├── engine.py                  # DAG 工作流 (并行 + 优雅降级)
│   ├── presets.py                 # 4 个预设工作流
│   └── export.py                  # STIX 2.1/SARIF/PDF 导出
│
├── plugins/                   # 插件系统
│   └── sdk.py                     # DataSourcePlugin SDK + 管理器
│
├── models/                    # 数据模型
│   └── vulnerability.py           # UnifiedVulnerability + STIX 2.1/SARIF 序列化
│
├── watchdog/                  # 监控
│   └── watcher.py                 # CISA KEV 轮询 + 规则告警
│
├── tools/                     # 工具实现 (14 个模块)
│   ├── cve_tools.py               # CVE 搜索 + 详情
│   ├── threat_intel_tool.py       # CISA KEV + EPSS + 综合评估
│   ├── cross_search_tool.py       # 跨源关联搜索
│   ├── exploit_tool.py            # Exploit-DB 搜索
│   ├── nuclei_tool.py             # Nuclei 模板搜索
│   ├── cvss_tool.py               # CVSS v3.1 计算器
│   ├── cwe_tool.py                # CWE 映射
│   ├── scan_tools.py              # 端口扫描 + 子域名
│   ├── network_tools.py           # HTTP头 + DNS + GeoIP
│   ├── poc_archive_tool.py        # PoC 档案库
│   ├── cpe_tool.py                # CPE 查找 + 服务指纹
│   ├── graph_tool.py              # 知识图谱查询
│   ├── report_tool.py             # 报告生成
│   └── scanner_tools.py           # Nmap XML + Nuclei + Metasploit + SearchSploit
│
├── security/                   # v4.1 安全加固模块
│   ├── input_sanitizer.py          # 输入净化 (命令注入/SSRF/路径遍历)
│   ├── target_policy.py            # 目标白名单 + 扫描策略
│   ├── audit.py                    # 不可篡改审计日志
│   ├── key_manager.py              # API Key 加密存储
│   └── tool_guard.py               # 工具 RBAC + 哈希校验 + 频率限制
│
├── validators/                # 输入校验
└── rate_limiter.py            # NVD API 速率控制
```

---

## v4.1 安全加固新特性

| 模块 | 功能 | 描述 |
|------|------|------|
| `Input Sanitizer` | 输入净化 | 命令注入/SSRF/路径遍历/XSS 模式检测，白名单字符验证 |
| `Target Policy` | 目标管控 | 白名单/黑名单网段、域名后缀限制、扫描次数上限 |
| `Audit Logger` | 审计日志 | SHA256 哈希链、JSONL 追加写入、参数自动脱敏 |
| `Key Manager` | 密钥安全 | 设备绑定加密存储、环境变量优先注入、内存缓存清除 |
| `Tool Guard` | 工具权限 | 5 级风险分类 (read_only→system)、频率限制、哈希校验 |
| `Log Redaction` | 日志脱敏 | 自动替换 API Key、Token、密码等敏感信息 |

> 📖 完整安全加固指南: [docs/SECURITY.md](docs/SECURITY.md) | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)（国内环境友好部署）

---

## 快速开始

### 安装

```bash
git clone https://github.com/99-sketch/vuln-research-mcp.git
cd vuln-research-mcp
pip install -e .
```

### 配置文件

```bash
# 创建默认配置
python -c "from src.core.config_manager import create_default_config; create_default_config()"

# 编辑 ~/.vuln-research-mcp/config.yaml
# 可选: 设置 NVD API Key 提升速率限制 (5 req/30s → 50 req/30s)
```

环境变量:

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `NVD_API_KEY` | `""` | NVD API Key (可选，提升速率) |
| `LOG_LEVEL` | `INFO` | 日志级别: DEBUG/INFO/WARNING/ERROR |
| `LOG_FORMAT` | `text` | 日志格式: text/json |
| `CACHE_ENABLED` | `true` | 缓存开关 |

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

### 快速部署

```bash
# 方式 1: pipx 独立安装（推荐个人使用）
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pipx
pipx install -e .

# 方式 2: 虚拟环境（推荐生产环境）
python3 -m venv venv && source venv/bin/activate
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .

# 方式 3: Windows 一键
python -m venv venv && .\venv\Scripts\activate
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
```

> 📖 完整部署指南（Supervisor/systemd/nssm/Windows 服务）: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

---

## CLI 交互模式

```bash
python -m src.server --interactive
```

支持的命令:

```
help             显示帮助
tools            列出所有 39 个工具
workflows        列出 4 个预设工作流
pipelines        列出 3 个 YAML 管道
graph            显示知识图谱统计
shortcuts        列出所有快捷命令
info <tool>      查看工具参数说明
exit / quit      退出
```

16 个快捷命令:

| 命令 | 等价调用 | 示例 |
|------|----------|------|
| `cve` | `tool search_cve` | `cve log4j` |
| `details` | `tool get_cve_details` | `details CVE-2021-44228` |
| `assess` | `tool vulnerability_assess` | `assess CVE-2021-44228` |
| `kev` | `tool check_kev` | `kev CVE-2021-44228` |
| `epss` | `tool get_epss_score` | `epss CVE-2021-44228` |
| `search` | `tool search_exploit` | `search apache` |
| `cwe` | `tool cwe_mapping` | `cwe CWE-79` |
| `exploit` | `tool search_exploit` | `exploit log4j` |
| `nuclei` | `tool find_nuclei_template` | `nuclei cve-2021-44228` |
| `dns` | `tool query_dns` | `dns example.com` |
| `ip` | `tool geolocate_ip` | `ip 8.8.8.8` |
| `headers` | `tool check_http_headers` | `headers https://example.com` |
| `ports` | `tool scan_ports` | `ports 192.168.1.1` |
| `subdom` | `tool enumerate_subdomains` | `subdom example.com` |
| `cpe` | `tool cpe_lookup` | `cpe apache` |
| `cross` | `tool cross_source_search` | `cross log4j` |
| `kevs` | `tool search_kev` | `kevs microsoft` |

直接调用任意工具:

```
tool search_cve keyword=log4j max_results=5
tool vulnerability_assess cve_id=CVE-2021-44228
tool scan_ports target=192.168.1.1 ports=1-1000 scan_type=quick
```

---

## YAML 管道模式

```bash
# 列出可用管道
python -m src.server --pipeline list

# 执行漏洞深挖管道
python -m src.server --pipeline vuln_deep_dive \
  --context '{"cve_id":"CVE-2021-44228"}'

# 执行完整侦察管道
python -m src.server --pipeline full_recon \
  --context '{"target":"example.com"}'

# 执行技术栈审计管道
python -m src.server --pipeline tech_stack_audit \
  --context '{"product":"apache","version":"2.4.49","cve_id":"CVE-2021-41773"}'
```

管道支持 `$context.*` 变量解析、DAG 并行步骤执行、自动重试和失败策略。

---

## REST API 模式

```bash
python -m src.server --api --api-port 8000
```

启动后访问:
- API 文档: http://localhost:8000/docs (Swagger UI)
- WebSocket: `ws://localhost:8000/api/ws`
- SSE 事件流: http://localhost:8000/api/events

核心端点:

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 健康检查 |
| `GET` | `/api/projects` | 列出项目 |
| `POST` | `/api/projects` | 创建项目 |
| `GET` | `/api/projects/{id}/assets` | 获取项目资产 |
| `GET` | `/api/projects/{id}/findings` | 获取项目发现 |
| `GET` | `/api/projects/{id}/report` | 生成项目渗透报告 |
| `POST` | `/api/correlate` | 单资产漏洞关联 |
| `POST` | `/api/correlate/batch` | 批量资产漏洞关联 |
| `GET` | `/api/attack/{id}` | 查询 ATT&CK 技术 |
| `POST` | `/api/attack/map` | 发现→ATT&CK 映射 |
| `GET` | `/api/pipelines` | 列出可用管道 |
| `POST` | `/api/pipeline/run` | 执行 YAML 管道 |
| `WS` | `/api/ws` | 实时事件推送 |

---

## 渗透测试报告

```bash
python -m src.server --interactive
> tool pentest_report project_id=1 format=markdown
```

生成的报告包含:
- 执行摘要 (严重性分布 + 风险可视化)
- 完整发现矩阵 (CVE/CWE/CVSS/EPSS/KEV)
- ATT&CK Navigator 层映射
- 修复路线图 (按优先级)
- 时间线事件记录

---

## 开发

```bash
pip install -e ".[dev]"
pytest tests/ -v
black src/ tests/
isort src/ tests/
```

---

## 协议

MIT License — 详见 [LICENSE](LICENSE)
