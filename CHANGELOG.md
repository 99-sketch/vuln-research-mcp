# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-07-03

### Architecture
- **模块化拆分**：`server.py` 从 43KB 单文件重构为路由层 + `tools/` 实现层 + `validators/` 安全校验层
  - `src/validators/__init__.py` - 输入验证（IP/域名/URL/端口/CVE/CWE 格式校验 + 命令注入防护）
  - `src/tools/cve_tools.py` - CVE 搜索与详情
  - `src/tools/cvss_tool.py` - CVSS v3.1 评分计算
  - `src/tools/cwe_tool.py` - CWE 漏洞类型查询
  - `src/tools/exploit_tool.py` - Exploit-DB 搜索（在线 API 优先 + 本地降级）
  - `src/tools/nuclei_tool.py` - Nuclei 模板搜索（在线 GitHub API 优先 + 本地降级）
  - `src/tools/scan_tools.py` - 端口扫描与子域名枚举
  - `src/tools/network_tools.py` - HTTP 安全头/DNS/IP 地理定位
- **server.py 精简为路由层**：工具定义 + 处理函数映射 + 统一错误处理

### Security
- **命令注入防护**：所有 subprocess 参数经过 `sanitize_subprocess_arg()` 净化，拒绝 shell 元字符
- **输入格式校验**：IP/域名/URL/端口/CVE-ID/CWE-ID 均有正则验证
- **SSRF 防护**：`is_private_ip()` 检测内网地址，URL 限制 http/https 协议
- **路径遍历防护**：域名验证拒绝 `../` 模式
- **错误信息脱敏**：统一 ValueError 捕获，不泄露内部堆栈

### Fixed
- **search_exploit 在线降级**：无 searchsploit 时自动切换到 Exploit-DB API
- **find_nuclei_template 在线降级**：无本地模板时自动切换到 GitHub API
- **sublist3r 路径跨平台**：`/tmp` 改为 `tempfile.gettempdir()`，Windows 兼容
- **CWE 库扩展至 20 条**：新增 CWE-22, CWE-94, CWE-125, CWE-119, CWE-200, CWE-306, CWE-311, CWE-319, CWE-327, CWE-352, CWE-434, CWE-502, CWE-522, CWE-798, CWE-862
- **pyproject.toml 依赖修复**：添加 `dnspython>=2.4.0`，移除未使用的 `pydantic`

### Cleanup
- 删除 .pypirc（应使用 ~/.pypirc 或 CI secrets）
- 删除 7 份过时文档（API_REFERENCE.md, CONTRIBUTING.md, EXAMPLES.md, TROUBLESHOOTING.md, USAGE.md, PACKAGING_SETUP_REPORT.md, docs/）
- 删除 install.ps1（v0.1.x 旧脚本，路径不匹配 v0.2.0 架构）
- 删除 MANIFEST.in（pyproject.toml 已覆盖）

### Test
- **pytest 测试套件**：`tests/test_server.py` 重写为 pytest 格式，覆盖 54 项测试
  - 输入验证 22 项、CVSS 5 项、CWE 5 项、CVE 4 项、DNS 3 项、HTTP 4 项、GeoIP 4 项、离线降级 6 项
- **快速自测脚本**：`test_v02.py` 保留在根目录，可直接 `python test_v02.py` 运行

### Known Issues
- v0.1.1 CHANGELOG 声称的 `test_v011.py` 未提交到仓库（已被 .gitignore 排除），此问题在 v0.2.0 修正
- 5 个工具仍需外部二进制（nmap/sublist3r/searchsploit），但已实现在线 API 降级

## [0.1.1] - 2026-07-03

### Fixed
- CVSS 计算器算法重写（FIRST CVSS v3.1 规范）
- CWE 本地库扩展至 18 条
- CVE 查询超时优化

### Known Issues (retroactively noted)
- `test_v011.py` 在 CHANGELOG 中提及但未提交到仓库（.gitignore 排除）
- `pyproject.toml` 缺少 `dnspython` 依赖
- `.pypirc` 模板暴露在仓库根目录

## [0.1.0] - 2026-07-02

### Added
- 初始版本，11 个渗透测试工具
