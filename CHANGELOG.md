# Changelog

## [1.0.0] - 2026-07-03

### Production Ready

完整审计修复版本，解决全部已识别问题。

### Added
- **NVD API Key 支持**：环境变量 `NVD_API_KEY`，有 Key 50次/30秒，无 Key 5次/30秒
- **速率限制器** (`src/rate_limiter.py`)：semaphore + 时间窗口控制，防止 NVD 429
- **重试机制**：exponential backoff（1s→2s→4s），最多 3 次重试，处理超时和 503
- **CWE 数据库扩展至 40 条**：覆盖 OWASP Top 10 + 常见渗透发现类型
- **CWE 在线 MITRE fallback**：本地未收录时自动查询 MITRE 官网
- **subprocess 版本检测**：nmap/searchsploit/sublist3r/amass 使用 `shutil.which()` + 版本检查
- **日志脱敏**：工具调用日志不再记录参数内容

### Security
- 命令注入防护：`sanitize_subprocess_arg()` 拒绝 shell 元字符
- 输入格式校验：IP/域名/URL/端口/CVE-ID/CWE-ID 正则验证
- SSRF 防护：`is_private_ip()` 检测内网地址，URL 限制 http/https
- 路径遍历防护：域名验证拒绝 `../` 模式
- 错误信息脱敏：统一 ValueError 捕获，不泄露内部堆栈

### Architecture
- 模块化拆分：`server.py` 路由层 + `tools/` 实现层 + `validators/` 安全校验层 + `rate_limiter.py` 速率控制
- server.py 精简为路由层：工具定义 + 处理函数映射 + 统一错误处理

### Test
- 60 项 pytest 覆盖全部 11 个工具
  - 输入验证 22 项、CVSS 5 项、CWE 6 项、CVE 4 项
  - DNS 3 项、HTTP 4 项、GeoIP 4 项
  - 离线降级 + 命令注入防护 + 版本检测 12 项

### Removed
- `.pypirc`（应使用 ~/.pypirc 或 CI secrets）
- 7 份过时文档（API_REFERENCE.md, CONTRIBUTING.md, EXAMPLES.md, TROUBLESHOOTING.md, USAGE.md, PACKAGING_SETUP_REPORT.md, docs/）
- `install.ps1`（v0.1.x 旧脚本，路径不匹配）
- `MANIFEST.in`（pyproject.toml 已覆盖）
- `pydantic` 依赖（未使用）

## [0.2.1] - 2026-07-03

### Fixed
- 重写 tests/test_server.py 为 pytest 格式（55 项）
- 删除 .pypirc、冗余文档、install.ps1、MANIFEST.in

## [0.2.0] - 2026-07-03

### Changed
- 模块化拆分：server.py → 路由层 + tools/ + validators/
- 在线降级：search_exploit 和 find_nuclei_template 无本地工具时自动切换在线 API

## [0.1.1] - 2026-07-03

### Fixed
- CVSS 计算器算法重写（FIRST CVSS v3.1 规范）
- CWE 本地库扩展至 18 条

### Known Issues (retroactively noted)
- `test_v011.py` 在 CHANGELOG 中提及但未提交到仓库
- `pyproject.toml` 缺少 `dnspython` 依赖
- `.pypirc` 模板暴露在仓库根目录

## [0.1.0] - 2026-07-02

### Added
- 初始版本，11 个渗透测试工具
