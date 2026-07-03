# Changelog

## v4.0.0 (2026-07-03) — 渗透测试工具链基础设施级组件

### 新增基础设施模块 (7)

- **EventBus** (`src/bus/`): 全局单例 Pub/Sub 消息骨干。支持同步/异步处理器、通配符订阅 (`vuln.*`)、事件历史记录、优先级级别
- **SQLite 持久层** (`src/db/`): WAL 模式数据库，7 张表 (projects, assets, scans, findings, evidences, timeline, reports)。外键约束、索引、线程安全连接、完整 CRUD
- **资产-漏洞关联引擎** (`src/correlator/`): Banner 正则解析 → CPE 产品匹配 → 本地已知漏洞表 (20+ 产品版本) → NVD API 查询。28 个产品 CPE 映射
- **YAML 管道编排器** (`src/orchestrator/`): DAG 并行管道执行，`$context.*` 变量解析，重试逻辑，on_failure 策略。3 个预设管道 (full_recon, vuln_deep_dive, tech_stack_audit)
- **任务调度器** (`src/orchestrator/`): 进程内 cron 风格调度，无外部依赖
- **MITRE ATT&CK 映射器** (`src/intel/`): 10 个核心技术 + CWE→Technique 映射 + 关键词检测 + ATT&CK Navigator 层 JSON 生成
- **专业渗透测试报告生成器** (`src/reporting/`): Markdown/JSON 格式，含执行摘要、发现矩阵、ATT&CK 映射、修复路线图、CVE 交叉引用

### 新增工具 (10)

- `parse_nmap_xml`: Nmap XML 解析 → 结构化 Asset 对象入库
- `generate_nuclei_cmd`: Nuclei CLI 扫描命令生成器
- `search_metasploit`: Metasploit 模块搜索
- `search_sploit`: searchsploit 本地 Exploit-DB 搜索
- `attack_technique`: MITRE ATT&CK 技术详情查询
- `map_to_attack`: 发现 → ATT&CK 战术/技术/缓解映射
- `attack_navigator`: ATT&CK Navigator 层 JSON 生成
- `run_pipeline`: YAML 管道执行
- `list_pipelines`: YAML 管道列表
- `pentest_report`: 专业渗透测试报告生成

### 新增功能

- REST API 网关 (`src/gateway/rest_api.py`): FastAPI 应用，20+ 端点 + WebSocket + SSE 事件流。可选依赖，优雅降级
- CLI 管道模式: `--pipeline` + `--context`
- CLI API 模式: `--api --api-port 8000`
- 3 个 YAML 管道定义 (`data/pipelines/`)
- 扫描器工具集成: Nmap XML 解析器、Nuclei 命令生成器、Metasploit/SearchSploit 封装
- `$context.*` 变量系统用于管道间状态传递

### 变更

- `server.py`: 工具数 29 → 39
- `pyproject.toml`: 新增依赖 `networkx>=3.0`, `rich>=13.0`, `fastapi>=0.100.0`, `uvicorn>=0.23.0`, `pydantic>=2.0`
- `.gitignore`: 新增 `data/*.db`, `reports/`, `*.spec`
- 版本号: 3.0.0 → 4.0.0

### 工具总数

39 工具 / 4 工作流 / 3 YAML 管道

---

## v3.0.0 (2026-07-03) — Knowledge Graph Edition

### 新增模块

- **知识图谱** (`src/core/knowledge_graph.py`): BFS 遍历、邻居查询、文本搜索、pickle 持久化
- **会话状态管理** (`src/core/session_state.py`): 多会话隔离 + TTL 过期
- **工作流引擎** (`src/workflow/`): DAG 并行执行 + 优雅降级。4 个预设工作流 (quick_assess, full_pentest_prep, vuln_deep_dive, tech_stack_audit)
- **报告导出** (`src/workflow/export.py`): STIX 2.1, SARIF, PDF 多格式
- **Rich CLI** (`src/gateway/cli.py`): 交互式命令行。16 个快捷命令，智能参数解析，Rich Table 渲染
- **Watchdog 监控** (`src/watchdog/`): CISA KEV 轮询 + 规则告警
- **插件 SDK** (`src/plugins/`): DataSourcePlugin 抽象基类 + 插件管理器
- **统一漏洞模型** (`src/models/vulnerability.py`): UnifiedVulnerability + STIX 2.1/SARIF 序列化

### 新增工具 (9)

- `cpe_lookup`: 产品指纹 → CPE 匹配
- `service_fingerprint`: Banner 文本 → 服务/版本提取
- `graph_traverse`: 知识图谱 BFS 遍历 (CVE→CWE→Exploit→Actor)
- `graph_neighbors`: 知识图谱节点邻居查询
- `graph_search`: 知识图谱文本搜索
- `graph_stats`: 知识图谱统计
- `generate_report`: 多格式安全报告 (STIX 2.1/SARIF/Markdown/JSON)
- `run_workflow`: 预设工作流执行
- `list_workflows`: 工作流列表

### 变更

- `server.py`: 工具数 20 → 29
- CLI 交互模式: 支持直接工具调用 + 快捷命令
- 版本号: 2.0.0 → 3.0.0

---

## v2.0.0 (2026-07-03) — Production Stable

### Breaking Changes
- 完全重构: server.py 拆分为路由层 + 7个工具模块 + validators + core/
- 配置系统: 支持 `~/.vuln-research-mcp/config.yaml` + 环境变量
- 依赖变更: 新增 `diskcache>=5.6.0`, `PyYAML>=6.0`

### New Features
- **异步子进程**: `asyncio.create_subprocess_exec` 替代 `subprocess.run()`，nmap/searchsploit/sublist3r/amass 不再阻塞 MCP 事件循环
- **熔断器**: NVD/CISA/EPSS/Exploit-DB/ip-api 连续失败后自动熔断，30-60秒后尝试恢复
- **持久缓存**: SQLite (diskcache) 缓存 NVD/CWE/DNS/GeoIP/EPSS/KEV 结果，重启不丢，按数据源分级 TTL
- **CISA KEV**: 检查 CVE 是否在已知利用目录中，支持关键词搜索
- **EPSS**: 获取漏洞被利用概率评分
- **综合风险评估**: 一次查询返回 CVSS + EPSS + KEV 三源情报 + 风险评分
- **跨源关联搜索**: 并行查询 CVE + Exploit-DB + Nuclei，按 CVE-ID 自动关联
- **工具注册表**: 插件化架构，加新工具只需新建模块 + register
- **结构化日志**: 支持 text 和 JSON 两种格式
- **启动健康检查**: 自检外部依赖，降级工具不崩溃
- **Docker 部署**: Kali Linux 基础镜像，预装 nmap/searchsploit/sublist3r/amass/nuclei
- **配置文件**: YAML + 环境变量 + 默认值三级优先级

### Improvements
- 输入校验层覆盖所有工具入口
- CVSS 3.1 完整算法 (FIRST 规范)
- CWE 本地数据库扩展至 40 条 + MITRE 在线 fallback
- NVD API Key 支持 (50 req/30s vs 5 req/30s)
- 速率限制 + 指数退避重试

### Tests
- 110 项 pytest 测试全部通过
- 覆盖: 输入验证(23) + CVSS(5) + CWE(7) + CVE(4) + DNS(3) + HTTP(4) + GeoIP(4) + Exploit(4) + Nuclei(3) + Scan(5) + Subdomain(4) + RateLimiter(2) + PoC(6) + AsyncSubprocess(3) + CircuitBreaker(6) + Cache(5) + HealthCheck(3) + Config(4) + Registry(4) + Logger(2) + KEV(3) + EPSS(2) + Assess(2) + CrossSearch(2)

## v1.1.0 (2026-07-03)
- 新增 PoC 档案库工具 (exploitarium 集成)
- 74 项测试通过

## v1.0.0 (2026-07-03)
- NVD API Key 支持
- 速率限制 + 重试
- CWE 40 条 + MITRE fallback
- subprocess 版本检测
- 68 项测试通过

## v0.2.1 (2026-07-03)
- 审计修复: .pypirc 移除, 文档精简, pydantic 依赖移除
- 55 项测试通过

## v0.2.0 (2026-07-03)
- 模块化拆分: server.py → 路由层 + 7个工具文件 + validators
- 离线工具降级
- 54 项测试通过

## v0.1.1 (2026-07-03)
- Bug 修复: CVSS 算法, CWE 库, NVD 超时

## v0.1.0 (2026-07-02)
- 初始发布: 11 个工具
