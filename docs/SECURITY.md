# Security Hardening Guide (安全加固指南)

> vuln-research-mcp v4.1 — Production Security Configuration

## 概述

vuln-research-mcp 是一个功能强大的渗透测试 MCP 服务器，但**默认配置面向个人安全研究**。
在生产环境中部署前，必须完成以下安全加固。

## 快速安全加固清单

### 最小权限原则

```bash
# 1. 创建专用低权限用户
sudo useradd -r -s /bin/false vulnmcp

# 2. 仅安装必要工具
# ❌ 不要在生产服务器上安装 metasploit
# ✅ 仅安装 nmap, searchsploit (只读模式)

# 3. 虚拟环境隔离部署（推荐）
python3 -m venv /opt/vulnmcp/venv
/opt/vulnmcp/venv/bin/pip install -e .
sudo chown -R vulnmcp:vulnmcp /opt/vulnmcp
```

### 配置文件安全

```yaml
# ~/.vuln-research-mcp/config.yaml
server:
  log_level: WARNING    # 生产环境用 WARNING，避免参数完整打印
  log_format: json      # 便于 SIEM 采集

api_keys:
  nvd: ""               # 留空！通过环境变量注入

security:
  max_risk_level: read_only      # 只允许情报查询
  audit_enabled: true
  log_redaction: true
  require_approval_for_scans: true

tools:
  disabled:
    - search_metasploit      # 禁用
    - clone_poc_archive       # 禁用
    - update_poc_archive      # 禁用
```

### 环境变量

```bash
# 敏感信息只通过环境变量传入，不写入配置文件
export NVD_API_KEY="your-key-here"
export CORS_ORIGINS="https://your-domain.com"
export LOG_LEVEL="WARNING"
```

## 分层安全架构 (v4.1)

```
┌──────────────────────────────────────────────┐
│  MCP / REST API / CLI 接入层                  │
│  ├─ Tool Guard: 工具风险等级检查              │
│  └─ Target Policy: 目标白名单/黑名单          │
├──────────────────────────────────────────────┤
│  安全中间件层                                 │
│  ├─ Input Sanitizer: 命令注入/SSRF/路径遍历   │
│  ├─ Audit Logger: 不可篡改操作审计             │
│  └─ Log Redaction: 日志敏感信息脱敏            │
├──────────────────────────────────────────────┤
│  工具执行层                                   │
│  ├─ 参数验证 → 格式化检查 → 注入模式扫描       │
│  ├─ 子进程安全执行 (list-based, no shell)      │
│  └─ 网络扫描限速 + 目标黑名单                  │
├──────────────────────────────────────────────┤
│  基础设施层                                   │
│  ├─ API 熔断器 (Circuit Breaker)              │
│  ├─ 频率限制 (Rate Limiter)                   │
│  ├─ 缓存层 (TTL Cache)                        │
│  └─ Secure Key Manager (加密存储)             │
└──────────────────────────────────────────────┘
```

## 工具风险等级

| 等级 | 说明 | 示例工具 | 建议场景 |
|------|------|----------|----------|
| `read_only` | 只读情报查询 | search_cve, get_cve_details, vulnerability_assess | 安全运营中心 |
| `network_info` | 网络信息收集 | query_dns, fetch_http_headers, geolocate_ip | 应急响应 |
| `active_scan` | 主动扫描 | scan_ports, enumerate_subdomains | 授权渗透测试 |
| `exploit` | 漏洞利用 | search_metasploit, search_exploit | 个人研究/靶场 |
| `system` | 系统操作 | clone_poc_archive, update_poc_archive | 开发者/全权限 |

## 场景化配置

### 场景 1：个人安全研究（推荐默认）

```yaml
security:
  max_risk_level: system
  target_whitelist_enabled: false
  audit_enabled: true
```

**额外建议：**
- 在隔离虚拟机中运行
- Claude Desktop 开启手动工具调用确认
- 禁止 AI 自动执行 `scan_ports`、`search_metasploit` 等高风险工具

### 场景 2：企业安全运营（只读情报）

```yaml
security:
  max_risk_level: network_info  # 或 read_only
  target_whitelist_enabled: true
  audit_enabled: true
  log_redaction: true
  require_approval_for_scans: true
tools:
  disabled:
    - search_metasploit
    - clone_poc_archive
    - update_poc_archive
    - search_exploit
```

### 场景 3：企业内部授权扫描

```yaml
security:
  max_risk_level: active_scan
  target_whitelist_enabled: true
  target_whitelist_file: /etc/vulnmcp/targets.json
  audit_enabled: true
```

**targets.json 示例：**
```json
{
  "whitelist_enabled": true,
  "whitelist_networks": ["10.0.0.0/8", "172.16.0.0/12"],
  "whitelist_domains": ["*.company.com"],
  "allow_private_ips": true,
  "allow_public_ips": false,
  "scan_limits": {
    "max_concurrent_scans": 3,
    "max_targets_per_scan": 50,
    "cooldown_seconds": 30
  }
}
```

## 已知风险与缓解

| 风险 | 严重度 | 缓解措施 |
|------|--------|----------|
| MCP 无内置认证 | 高 | 仅本地使用，配置文件权限 600 |
| 子进程命令注入 | 中 | v4.1 输入净化 + list-based subprocess |
| 日志泄露 API Key | 中 | v4.1 自动脱敏 + WARNING 级别 |
| 未授权扫描 | 高 | v4.1 目标白名单 + 工具等级控制 |
| 供应链投毒 | 中 | 锁定依赖版本 + 固定系统工具版本 |
| AI 自主批量扫描 | 高 | 工具等级控制 + require_approval |

## 审计日志

审计日志位置：`~/.vuln-research-mcp/audit/audit-YYYY-MM-DD.jsonl`

```json
{"timestamp": "2026-07-03T10:00:00.000Z", "event_type": "tool_call",
 "tool_name": "scan_ports", "parameters": {"target": "192.168.1.1"},
 "result": "denied", "reason": "目标不在白名单中",
 "metadata": {"hash": "abc123..."}}
```

特性：
- 追加写入，不可篡改
- 每行一个 JSON 事件
- SHA256 哈希链保证完整性
- 自动脱敏敏感参数

## 安全报告

发现安全漏洞请通过 GitHub Security Advisory 报告：
https://github.com/99-sketch/vuln-research-mcp/security/advisories/new

请勿在公开 Issue 中披露安全漏洞。
