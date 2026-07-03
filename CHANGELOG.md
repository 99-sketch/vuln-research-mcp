# Changelog

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
