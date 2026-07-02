# 版本更新日志

> 所有显著的项目变更均记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

---

## [0.1.0] — 2026-07-02

### 🎉 初始版本

Vulnerability Research MCP Server 的第一个公开发布版本。

### ✨ 新增功能

#### 核心工具（6 个）

| 工具 | 状态 | 说明 |
|------|------|------|
| `search_cve` | ✅ 完整 | 通过 NVD API 搜索 CVE 漏洞 |
| `get_cve_details` | ✅ 完整 | 获取单个 CVE 的完整详细信息 |
| `search_exploit` | ✅ 完整 | 通过 searchsploit 搜索 Exploit-DB |
| `cvss_calculator` | ⚠️ 简化 | CVSS v3.1 评分计算（简化版） |
| `cwe_mapping` | ⚠️ 有限 | CWE 弱分类查询（内置 5 条） |
| `find_nuclei_template` | ✅ 完整 | 搜索本地 Nuclei Templates |

#### 预留工具（5 个）

以下工具已声明但尚未实现：

| 工具 | 预期功能 | 当前状态 |
|------|----------|----------|
| `scan_ports` | 端口扫描 | ⏳ 预留 |
| `enumerate_subdomains` | 子域名枚举 | ⏳ 预留 |
| `check_http_headers` | HTTP 安全头检查 | ⏳ 预留 |
| `query_dns` | DNS 记录查询 | ⏳ 预留 |
| `geolocate_ip` | IP 地理位置查询 | ⏳ 预留 |

#### 项目工程化

- ✅ MCP（Model Context Protocol）服务器完整框架
- ✅ stdio 通信协议支持
- ✅ 完整的日志系统（支持多级别）
- ✅ Windows 一键安装脚本 `install.ps1`
- ✅ Claude Desktop 配置示例 `claude_desktop_config_example.json`
- ✅ 自动化测试套件 `tests/test_server.py`
- ✅ 完整的文档体系

### 🧪 测试覆盖

- `search_cve` — 基础搜索测试 ✅
- `get_cve_details` — 详情查询测试 ✅
- `cvss_calculator` — 评分计算测试 ✅

### 📖 文档

初始文档集：

| 文档 | 内容 |
|------|------|
| `README.md` | 项目概述、功能特性、快速使用 |
| `USAGE.md` | 完整使用教程、最佳实践 |
| `EXAMPLES.md` | 10 基础 + 5 高级 + 3 实战示例 |
| `API_REFERENCE.md` | 完整 API 参考手册 |
| `TROUBLESHOOTING.md` | FAQ、错误码、调试技巧 |
| `CONTRIBUTING.md` | 贡献指南、开发规范 |
| `CHANGELOG.md` | 本文件 |
| `docs/installation.md` | 详细安装指南 |
| `docs/configuration.md` | 配置说明 |
| `docs/advanced-usage.md` | 高级用法 |
| `docs/integrations.md` | 工具集成指南 |

### 🐛 已知问题

1. **CVSS 计算简化**：`cvss_calculator` 的计算逻辑是简化版本，与官方 CVSS v3.1 标准有偏差。精确评分请参考 [FIRST 官方计算器](https://www.first.org/cvss/calculator/3.1)
2. **CWE 条目有限**：`cwe_mapping` 仅内置 5 条常见 CWE，其余返回 MITRE 链接
3. **预留工具不可用**：`scan_ports`、`enumerate_subdomains`、`check_http_headers`、`query_dns`、`geolocate_ip` 已声明但未实现
4. **缺少缓存**：频繁查询同一 CVE 时仍会重复调用 NVD API
5. **缺少重试机制**：NVD API 暂时性失败不会自动重试

### 🔜 下一版本计划

- [ ] 集成 CISA KEV 数据源
- [ ] 实现预留的 5 个工具
- [ ] 完善 CVSS 计算（完整 v3.1 实现）
- [ ] 下载完整 CWE 数据库
- [ ] 添加请求缓存机制
- [ ] 支持 JSON 输出到文件
- [ ] 添加 NVD API 重试逻辑

---

## 版本格式

```
v{major}.{minor}.{patch}
```

| 版本位 | 说明 |
|--------|------|
| `major` | 不兼容的 API 变更 |
| `minor` | 向下兼容的功能新增 |
| `patch` | 向下兼容的问题修复 |

---

## 版本历史

| 版本 | 日期 | 类型 | 说明 |
|------|------|------|------|
| 0.1.0 | 2026-07-02 | 初始发布 | 第一个正式版本 |
