# vuln-research-mcp 使用手册 & 教程

> v4.5.0 | 渗透测试工具链基础设施级组件 (国内环境友好)

---

## 目录

1. [快速入门](#1-快速入门)
2. [MCP 客户端集成](#2-mcp-客户端集成)
3. [CLI 交互模式教程](#3-cli-交互模式教程)
4. [YAML 管道教程](#4-yaml-管道教程)
5. [REST API 教程](#5-rest-api-教程)
6. [渗透测试场景实战](#6-渗透测试场景实战)
7. [生产部署](#7-生产部署)
8. [自定义管道](#8-自定义管道)
9. [常见问题](#9-常见问题)

---

## 1. 快速入门

### 环境要求

- Python 3.10+
- 可选外部工具: nmap, searchsploit, sublist3r, amass, nuclei, msfconsole

### 安装

```bash
git clone https://github.com/99-sketch/vuln-research-mcp.git
cd vuln-research-mcp
pip install -e .
```

### 验证安装

```bash
python -m src.server --version
# 输出: vuln-research-mcp v4.5.0
```

### 创建配置文件

```bash
python -c "from src.core.config_manager import create_default_config; create_default_config()"
```

配置文件位于 `~/.vuln-research-mcp/config.yaml`。主要配置项:

```yaml
api_keys:
  nvd: ""          # NVD API Key (可选，提升速率限制)

server:
  log_level: INFO
  log_format: text

cache:
  enabled: true
  max_size_mb: 200

tools:
  disabled: []     # 禁用的工具列表
```

---

## 2. MCP 客户端集成

vuln-research-mcp 的核心使用场景是作为 MCP (Model Context Protocol) 服务器，让 AI 助手直接调用安全工具。

### Claude Desktop 配置

编辑 Claude Desktop 配置文件:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/vuln-research-mcp",
      "env": {
        "NVD_API_KEY": "your-nvd-api-key"
      }
    }
  }
}
```

重启 Claude Desktop 后，你就可以直接对 AI 说:

- "帮我查一下 CVE-2021-44228 的详细信息"
- "评估一下 log4j 漏洞的风险"
- "搜索 apache 2.4.49 有什么已知漏洞"
- "检查 CVE-2021-44228 是否在 CISA KEV 目录里"
- "生成一份针对 example.com 的渗透测试准备报告"

### WorkBuddy / CodeBuddy 配置

在 MCP 设置中添加 STDIO 类型服务器:

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/vuln-research-mcp"
    }
  }
}
```

### 可用工具速查

| 使用场景 | 推荐工具 |
|----------|----------|
| 查漏洞 | `search_cve`, `get_cve_details` |
| 评估风险 | `vulnerability_assess` (一键 CVSS+EPSS+KEV) |
| 找利用代码 | `search_exploit`, `search_metasploit`, `search_sploit` |
| 威胁情报 | `check_kev`, `get_epss_score`, `search_kev` |
| 资产识别 | `scan_ports`, `query_dns`, `enumerate_subdomains` |
| 指纹识别 | `cpe_lookup`, `service_fingerprint`, `check_http_headers` |
| 漏洞扫描 | `find_nuclei_template`, `generate_nuclei_cmd` |
| 知识关联 | `graph_traverse`, `cross_source_search` |
| 报告输出 | `generate_report`, `pentest_report` |
| 自动化 | `run_workflow`, `run_pipeline` |

---

## 3. CLI 交互模式教程

### 启动交互模式

```bash
python -m src.server --interactive
```

你会看到一个 Rich 渲染的面板，里面是欢迎信息和命令提示。

### 教程 1: CVE 漏洞情报分析

这是最常见的使用场景——拿到一个 CVE 编号，快速了解它的全部信息。

```
vuln> cve log4j
```

这会搜索包含 "log4j" 的 CVE。假设你想深入了解 CVE-2021-44228 (Log4Shell):

```
vuln> details CVE-2021-44228
```

输出包含:
- CVE 描述
- CVSS 3.1 评分 (10.0 / CRITICAL)
- 受影响产品
- CWE 分类
- 发布时间和最后修改时间

```
vuln> assess CVE-2021-44228
```

综合评估输出:
```
risk_score: 2.0
risk_level: CRITICAL
cvss_score: 10.0
epss_score: 97.5%
in_kev: true
ransomware_known: true
kev_due_date: 2021-12-24
```

```
vuln> exploit log4j
vuln> nuclei cve-2021-44228
vuln> cross log4j
```

### 教程 2: 目标侦察

```bash
vuln> dns example.com
vuln> dns example.com MX      # 查邮件服务器
vuln> subdom example.com      # 子域名枚举
vuln> headers https://example.com
vuln> ip 8.8.8.8
vuln> ports 192.168.1.1 ports=1-100 scan_type=quick
```

### 教程 3: 直接工具调用

快捷命令不够灵活时，使用 `tool` 命令直接调用:

```
vuln> tool search_cve keyword=openssl version=1.1.1 max_results=20
vuln> tool cross_source_search keyword=apache max_results=30
vuln> tool query_dns domain=example.com record_type=ALL
vuln> tool scan_ports target=10.0.0.1 ports=80,443,8080 scan_type=version
```

### 教程 4: 查看工具参数

```
vuln> info search_cve
```
输出:
```
Tool: search_cve
Description: Search CVEs by product name, version, or keyword
Parameters:
  keyword (string, required): Search keyword
  product (string, optional): Product name
  version (string, optional): Product version
  max_results (number, optional, default=10): Max results
```

### 教程 5: 工作流

4 个预设工作流可以一次执行多个工具:

```
vuln> workflows              # 查看可用工作流
vuln> tool run_workflow workflow_name=quick_assess target=CVE-2021-44228
```

---

## 4. YAML 管道教程

管道比工作流更强大，支持 DAG 并行执行和变量传递。

### 列出可用管道

```bash
python -m src.server --pipeline list
```

### 教程: CVE 深度分析

```bash
python -m src.server \
  --pipeline vuln_deep_dive \
  --context '{"cve_id":"CVE-2021-44228"}'
```

这个管道会自动执行:
1. **CVE 情报获取** — get_cve_details
2. **风险评估** (并行) — vulnerability_assess
3. **漏洞利用研究** (并行 3 步):
   - search_exploit
   - find_nuclei_template
   - search_poc_archive
4. **威胁情报** (并行 3 步):
   - check_kev
   - get_epss_score
   - cross_source_search

### 教程: 完整侦察

```bash
python -m src.server \
  --pipeline full_recon \
  --context '{"target":"example.com"}'
```

### 教程: 技术栈审计

```bash
python -m src.server \
  --pipeline tech_stack_audit \
  --context '{"product":"apache","version":"2.4.49","cve_id":"CVE-2021-41773"}'
```

---

## 5. REST API 教程

### 启动 API 服务器

```bash
python -m src.server --api --api-port 8000
```

访问 Swagger 文档: http://localhost:8000/docs

### 创建项目和资产

```bash
# 创建项目
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"外部渗透测试 - example.com","description":"2026 Q3 常规测试"}'

# 导入 Nmap 结果
curl -X POST http://localhost:8000/api/correlate/batch \
  -H "Content-Type: application/json" \
  -d '{"project_id":1,"banners":["Apache/2.4.49","OpenSSH 7.4"]}'

# 生成渗透测试报告
curl http://localhost:8000/api/projects/1/report?format=markdown
```

### WebSocket 实时事件

```javascript
const ws = new WebSocket('ws://localhost:8000/api/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event:', data.type, data.data);
};
```

### 完整 REST API 端点

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 系统健康检查 |
| `GET` | `/api/projects` | 列出所有项目 |
| `POST` | `/api/projects` | 创建项目 |
| `GET` | `/api/projects/{id}` | 获取项目详情 |
| `DELETE` | `/api/projects/{id}` | 删除项目 |
| `GET` | `/api/projects/{id}/assets` | 获取项目资产 |
| `POST` | `/api/projects/{id}/assets` | 添加资产 |
| `GET` | `/api/projects/{id}/findings` | 获取项目发现 |
| `POST` | `/api/projects/{id}/findings` | 添加发现 |
| `GET` | `/api/projects/{id}/scans` | 获取扫描记录 |
| `GET` | `/api/projects/{id}/timeline` | 获取时间线 |
| `GET` | `/api/projects/{id}/report` | 生成渗透报告 |
| `POST` | `/api/correlate` | 单资产漏洞关联 |
| `POST` | `/api/correlate/batch` | 批量资产漏洞关联 |
| `GET` | `/api/attack/{technique_id}` | 查询 ATT&CK 技术 |
| `POST` | `/api/attack/map` | 发现→ATT&CK 映射 |
| `GET` | `/api/pipelines` | 列出 YAML 管道 |
| `POST` | `/api/pipeline/run` | 执行管道 |
| `WS` | `/api/ws` | WebSocket 实时事件 |
| `GET` | `/api/events` | SSE 事件流 |

---

## 6. 渗透测试场景实战

### 场景 1: 外部渗透测试准备

**目标**: 对 example.com 进行渗透测试前的信息收集。

```bash
# 步骤 1: DNS 信息收集
vuln> dns example.com
vuln> dns example.com MX
vuln> dns example.com NS

# 步骤 2: 子域名枚举
vuln> subdom example.com

# 步骤 3: 端口扫描
vuln> ports example.com scan_type=version

# 步骤 4: HTTP 安全头检查
vuln> headers https://example.com

# 步骤 5: 一键完成 (管道)
python -m src.server --pipeline full_recon --context '{"target":"example.com"}'
```

### 场景 2: 已知漏洞应急响应

**目标**: 团队发现 Log4Shell (CVE-2021-44228)，需要快速评估影响。

```bash
# 步骤 1: 获取漏洞详情
vuln> details CVE-2021-44228

# 步骤 2: 综合风险评估
vuln> assess CVE-2021-44228
# 输出: CVSS 10.0 / EPSS 97.5% / KEV=true / 勒索软件已知

# 步骤 3: 查找利用代码
vuln> exploit log4j
vuln> nuclei cve-2021-44228

# 步骤 4: CWE 关联
vuln> cwe CWE-502

# 步骤 5: ATT&CK 映射
vuln> tool map_to_attack title="Log4Shell" \
  description="Apache Log4j2 JNDI injection" \
  cwe_ids="CWE-502" \
  severity="critical"

# 步骤 6: 一键完成 (管道)
python -m src.server --pipeline vuln_deep_dive \
  --context '{"cve_id":"CVE-2021-44228"}'
```

### 场景 3: 技术栈审计

**目标**: 审计某 Web 应用的技术栈安全状况。

```bash
# 步骤 1: 产品指纹识别
vuln> cpe apache
vuln> cpe nginx
vuln> cpe tomcat

# 步骤 2: 搜索相关 CVE
vuln> tool search_cve keyword=apache product=apache version=2.4.49

# 步骤 3: 跨源搜索
vuln> cross "apache 2.4.49"

# 步骤 4: 一键完成 (管道)
python -m src.server --pipeline tech_stack_audit \
  --context '{"product":"apache","version":"2.4.49","cve_id":"CVE-2021-41773"}'
```

### 场景 4: 生成渗透测试报告

```bash
# 通过 CLI
vuln> tool pentest_report project_id=1 format=markdown

# 或通过 REST API
curl http://localhost:8000/api/projects/1/report?format=markdown \
  -o pentest_report.md
```

报告结构:
1. 执行摘要 (Executive Summary)
2. 风险可视化 (严重性分布)
3. 发现矩阵 (Finding Matrix)
4. 修复路线图 (Remediation Roadmap)
5. CVE 交叉引用
6. ATT&CK 映射附录
7. 时间线事件记录

---

## 7. 生产部署

> 🔧 国内环境专用 — 不使用 Docker，全部基于 Python 原生生态

### 个人开发机 (pipx)

```bash
# 安装 pipx（清华镜像）
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pipx
pipx ensurepath

# 安装项目
cd /path/to/vuln-research-mcp
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
```

### Linux 服务器 (Supervisor)

```bash
# 1. 克隆 + 安装
git clone https://github.com/99-sketch/vuln-research-mcp.git /opt/vulnmcp
cd /opt/vulnmcp
python3 -m venv venv
venv/bin/pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e . supervisor

# 2. 创建专用用户
sudo useradd -r -s /bin/false -d /opt/vulnmcp vulnmcp
sudo chown -R vulnmcp:vulnmcp /opt/vulnmcp

# 3. Supervisor 配置 (/etc/supervisor/conf.d/vulnmcp.conf)
sudo tee /etc/supervisor/conf.d/vulnmcp.conf << 'EOF'
[program:vulnmcp]
command=/opt/vulnmcp/venv/bin/python -m src.server
directory=/opt/vulnmcp
user=vulnmcp
autostart=true
autorestart=true
environment=NVD_API_KEY="",LOG_LEVEL="WARNING"
EOF

# 4. 启动
sudo supervisorctl reread && sudo supervisorctl update
sudo supervisorctl start vulnmcp
sudo supervisorctl status vulnmcp
```

### Linux 服务器 (systemd)

```bash
sudo tee /etc/systemd/system/vulnmcp.service << 'EOF'
[Unit]
Description=Vulnerability Research MCP Server
After=network.target

[Service]
Type=simple
User=vulnmcp
Environment=NVD_API_KEY=
Environment=LOG_LEVEL=WARNING
WorkingDirectory=/opt/vulnmcp
ExecStart=/opt/vulnmcp/venv/bin/python -m src.server
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnmcp
```

### Windows Server (nssm)

```powershell
# 1. 安装项目
cd C:\vulnmcp
python -m venv venv
.\venv\Scripts\pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .

# 2. 下载 nssm: https://nssm.cc/download

# 3. 安装服务
nssm install VulnMcp "C:\vulnmcp\venv\Scripts\python.exe" "-m" "src.server"
nssm set VulnMcp AppDirectory "C:\vulnmcp"
nssm set VulnMcp AppEnvironmentExtra "NVD_API_KEY=your-key"
nssm set VulnMcp Start SERVICE_AUTO_START
nssm start VulnMcp
```

> 📖 完整部署指南（健康检查/日志管理/备份恢复/故障排查）: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

---

## 8. 自定义管道

你可以在 `data/pipelines/` 下创建自己的 YAML 管道文件。

### 管道结构

```yaml
name: "自定义管道"
description: "管道描述"
version: "1.0"

stages:
  - name: "信息收集"
    steps:
      - name: "DNS 查询"
        tool: query_dns
        params:
          domain: "$context.target"
        timeout: 10

      - name: "HTTP 头检查"
        tool: check_http_headers
        params:
          url: "https://$context.target"
        timeout: 10
    on_failure: continue

  - name: "漏洞分析"
    depends_on: ["信息收集"]
    steps:
      - name: "搜索漏洞"
        tool: search_cve
        params:
          keyword: "$context.product $context.version"
          max_results: 10
        timeout: 20
        retry: 3
```

### 管道语法

- `$context.xxx`: 引用上下文变量
- `depends_on`: 阶段依赖，支持数组
- `retry`: 步骤最大重试次数
- `timeout`: 步骤超时时间 (秒)
- `on_failure`: 失败策略 (`continue` | `abort`)

---

## 9. 常见问题

### Q: NVD API 提示速率限制?

设置 NVD API Key 可以将速率从 5 req/30s 提升到 50 req/30s。

```bash
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

或写入 `~/.vuln-research-mcp/config.yaml` 的 `api_keys.nvd` 字段。

### Q: 某些工具显示 "降级运行"?

启动健康检查会自动检测外部依赖。缺失的工具会在结果中标注降级状态，不影响其他工具。

安装缺失的工具:

```bash
# Kali/Debian
apt-get install nmap exploitdb sublist3r amass nuclei

# macOS
brew install nmap exploitdb sublist3r amass nuclei
```

### Q: 数据存在哪里?

- **缓存**: `~/.vuln-research-mcp/cache/` (diskcache SQLite)
- **数据库**: `data/pentest.db` (SQLite WAL 模式)
- **配置**: `~/.vuln-research-mcp/config.yaml`
- **日志**: stdout (可重定向到文件)

### Q: 如何禁用特定工具?

在 `~/.vuln-research-mcp/config.yaml` 中设置:

```yaml
tools:
  disabled:
    - scan_ports
    - enumerate_subdomains
```

### Q: 管道执行失败怎么办?

管道支持自动重试和失败策略。查看日志输出中的 `stages[].steps[].error` 字段了解具体错误。

### Q: REST API 启动报错?

REST API 依赖 FastAPI。如果未安装:

```bash
pip install fastapi uvicorn
```

或者忽略 API 模式，使用 MCP STDIO 或 CLI 交互模式。
