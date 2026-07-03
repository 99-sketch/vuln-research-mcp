# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2026-07-03

### Fixed
- **CVSS 计算器算法重写**：严格遵循 FIRST CVSS v3.1 规范计算 Base Score（含 Impact、Exploitability、Scope Changed 分支）
- **CVSS 支持完整 vector 字符串**：可解析 `CVSS:3.1/AV:N/AC:L/...` 并返回正确分数
- **CWE 本地库扩展**：新增 18 个常见 CWE 条目（含 Path Traversal、SSRF、Deserialization、Hard-coded Credentials 等）
- **CWE 输入校验**：对非标准格式和未收录 CWE 返回明确的错误/未找到提示
- **CVE 查询超时**：NVD API 超时从 30s 降至 10s，减少阻塞

### Added
- 自测脚本 `test_v011.py`（覆盖 CVSS 5 用例 + CWE 4 用例 + DNS + 工具降级）

## [0.1.0] - 2026-07-02

### Added
- 初始版本，包含 11 个渗透测试工具
- CVE 搜索/详情、Exploit-DB 搜索、CVSS 计算、CWE 映射、Nuclei 模板查找
- 端口扫描、子域名枚举、HTTP 安全头检查、DNS 查询、IP 地理定位
