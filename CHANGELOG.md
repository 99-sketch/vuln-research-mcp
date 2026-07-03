# Changelog

## v4.5.0 (2026-07-03) — 国内环境友好部署

### Docker 移除

- **删除 docker-compose.yml**: Docker 在国内存在镜像拉取失败、网络不可达等问题，采用国内友好方案替代
- **DEPLOYMENT.md 全面重写**: 5 种国内可用部署方式（pipx/venv+Supervisor/venv+systemd/nssm/Conda），均附带清华/阿里/华为镜像加速配置
- **Supervisor 支持**: 新增 Supervisor 进程守护方案，Python 原生生态，国内服务器广泛使用
- **nssm Windows 服务**: 新增 Windows 原生服务部署，支持 GUI 和命令行两种模式 + 任务计划程序备选
- **国内镜像加速**: 新增 pip 镜像源配置指南（清华/阿里/华为云/豆瓣）、Git 克隆加速

### 文档更新

- **README.md**: Docker 部署替换为 pipx/venv 快速部署，更新版本号至 4.5.0
- **USER_GUIDE.md**: 第 7 节 Docker 部署替换为 Supervisor 部署教程
- **CHANGELOG.md**: 移除历史 Docker 引用

---

## v4.1.0 (2026-07-03) — 安全加固版本

### 新增安全模块 (5)

- **Input Sanitizer** (`src/security/input_sanitizer.py`): 命令注入/SSRF/路径遍历/XSS 模式检测，白名单字符验证，shell 元字符拦截，网络目标黑名单
- **Target Policy** (`src/security/target_policy.py`): 白名单/黑名单网段控制，域名后缀限制，扫描次数上限，冷却时间机制，企业级预设策略
- **Audit Logger** (`src/security/audit.py`): SHA256 哈希链审计日志，JSONL 追加写入，敏感参数自动脱敏，不可篡改事件记录
- **Key Manager** (`src/security/key_manager.py`): 设备绑定加密存储，PBKDF2 密钥派生，环境变量优先注入，内存缓存清除
- **Tool Guard** (`src/security/tool_guard.py`): 5 级风险分类 (read_only/network_info/active_scan/exploit/system)，频率限制，工具哈希防篡改校验，按等级过滤工具列表

### 安全漏洞修复 (P0)

- **search_metasploit 命令注入**: 添加 `sanitize_shell_query()` 输入净化，拒绝 shell 元字符
- **execute_scanner shell 注入**: 从 `create_subprocess_shell` 改为 `create_subprocess_exec(*args)` list-based 执行 + shlex 解析
- **日志敏感信息泄露**: 添加 `RedactionFilter` 自动脱敏 API Key/Token/密码等敏感字段

### 安全加固

- **MCP call_tool 安全层**: 集成 Tool Guard (权限检查) + Target Policy (目标白名单) + Audit Logger (调用审计)
- **REST API CORS 收紧**: 从 `allow_origins=["*"]` 改为仅允许 localhost，可通过 `CORS_ORIGINS` 环境变量配置
- **pyproject.toml 依赖锁定**: 所有依赖添加上限版本约束 (`<2.0`, `<1.0` 等)
- **配置新增 security 段**: `max_risk_level`、`audit_enabled`、`target_whitelist_enabled`、`log_redaction`、`require_approval_for_scans`
- **config.example.yaml 更新**: 添加完整安全配置示例和扫描策略参数

### 文档

- **docs/SECURITY.md**: 安全加固完整指南，包含分层架构、工具风险等级、场景化配置、已知风险与缓解
- **docs/DEPLOYMENT.md**: 生产部署指南，venv+Supervisor/systemd/pipx/nssm/Conda 五种国内友好部署方式，监控指标和备份恢复
- **docs/CONTRIBUTING.md**: 贡献指南，安全编码规范，新工具添加规范，安全漏洞披露流程

### 测试

- 新增 86 个安全模块测试 (`tests/test_security_*.py`)
- 全部 277 个已有测试无回归
- 总测试数: 363 (277 + 86)

### 版本更新

- `__version__` → 4.1.0
- `pyproject.toml` version → 4.1.0

---

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
- **虚拟环境部署**: 预装 nmap/searchsploit/sublist3r/amass/nuclei 外部依赖
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
