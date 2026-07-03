# vuln-research-mcp 社区文档 v5.1

## 快速入门 (Quick Start)

### Windows
```powershell
# 1. 下载便携版 (推荐)
# 解压 vuln-research-mcp-v5.1.0-win64-portable.zip
# 双击 setup.bat 即可

# 2. 或 pip 安装
pip install vuln-research-mcp
python -m vuln_research_mcp --version
```

### Linux
```bash
# pip 安装 (推荐使用清华源)
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple vuln-research-mcp

# 系统工具 (可选, 增强功能)
sudo apt install nmap git curl

# 验证
python -m vuln_research_mcp --version
```

### macOS
```bash
# Homebrew + pip
brew install nmap git
pip install vuln-research-mcp

# 验证
python -m vuln_research_mcp --version
```

## 架构深度解析

```
┌─────────────────────────────────────────────────────┐
│                   Gateway Layer                      │
│  MCP stdio │ REST API │ WebSocket │ CLI (Rich)      │
├─────────────────────────────────────────────────────┤
│                Security Layer (7层)                  │
│  AST 级输入净化 → 数据清洗 → 内网全阻断 → 目标策略 │
│  → RBAC 守卫 → 人工审批 → 权限执行                  │
├─────────────────────────────────────────────────────┤
│                 Platform Layer                       │
│  Windows │ Linux │ macOS — 自动检测 + pip 降级方案  │
├─────────────────────────────────────────────────────┤
│  Intel Layer │ Correlator(898指纹) │ Graph(N4j+Nx)  │
│  CNVD/CNNVD │ CVE/KEV/EPSS/ATT&CK │ 合规(等保+CIS) │
├─────────────────────────────────────────────────────┤
│                 Data Layer                           │
│  SQLite(AES-256-GCM) │ EventBus │ Cache │ Pipeline  │
└─────────────────────────────────────────────────────┘
```

## 常见问题 FAQ (30+ 条)

### 安装

**Q: Windows 上 nmap 找不到?**
A: 使用 python-nmap (pip install python-nmap)，或在 https://nmap.org/download.html 下载安装后添加到 PATH。PowerShell 可用 `Test-NetConnection` 部分替代。

**Q: Linux 上用清华源安装报错?**
A: 尝试其他国内源:
```bash
# 阿里云
pip install -i https://mirrors.aliyun.com/pypi/simple/ vuln-research-mcp
# 华为云
pip install -i https://mirrors.huaweicloud.com/repository/pypi/simple vuln-research-mcp
```

**Q: macOS M1/M2 安装失败?**
A: 确保使用 ARM 原生 Python: `brew install python@3.12`，然后用 `pip3.12 install vuln-research-mcp`。

### 安全

**Q: 为什么启动报错 "禁止以 root 运行"?**
A: v5.1 默认禁止 root/Administrator 运行，防止 MCP 协议漏洞导致主机被完全接管。创建专用用户:
```bash
# Linux
sudo useradd -m vulnscan
sudo -u vulnscan python -m vuln_research_mcp
# Windows
net user vulnscan /add
runas /user:vulnscan cmd
```
测试环境设置: `set VULNRESEARCH_ALLOW_ROOT=1`

**Q: 能不能扫描内网?**
A: v5.1 默认阻断所有 RFC 1918 内网地址 (10/8, 172.16/12, 192.168/16)。需要内网扫描时在 config.yaml 配置:
```yaml
intranet_guard:
  whitelist_enabled: true
  whitelist_cidrs:
    - "10.0.1.0/24"
    - "192.168.1.0/24"
```

**Q: 如何避免命令注入?**
A: v5.1 使用 AST 级 Shell 解析 + 白名单校准，自动阻断所有危险字符和命令。无需手动处理，参数会被自动清洗。如果参数被"误杀"，请提交 Issue 并附参数样例。

### 功能

**Q: 离线模式怎么用?**
A: 首次先在线同步数据库:
```bash
python -m vuln_research_mcp --mirror-download
```
之后即可离线查询 NVD/KEV/EPSS/Exploit-DB/CWE 数据。

**Q: 知识图谱能识别哪些产品?**
A: v5.1 支持 898 个 banner 模式, 覆盖 550+ 产品: Web服务器(45) + 应用服务器(25) + 数据库(35) + 框架CMS(110) + DevOps(55) + 网络设备(40) + 安全工具(25) + IoT(45) + 云服务(30) + 语言运行时(20) + 邮件(18) + DNS(15) + 代理(18) + 监控(22) + 消息队列(15) + 存储(12) + 虚拟化(10) + 认证(10)。

**Q: 网卡支持吗?**
A: 支持。Netgear, Asus, TP-Link, D-Link, Linksys, MikroTik, Ubiquiti, Zyxel, DrayTek 等常见品牌都已内置指纹。

### 工具兼容

**Q: 哪些工具在 Windows 上不可用?**
A: msfconsole, searchsploit, amass, nuclei 等部分 Linux 原生工具在 Windows 上不可用。v5.1 提供自动降级方案:
- nmap → python-nmap 或 PowerShell Test-NetConnection
- nuclei → pip install nuclei (实验性)
- 不可用的工具会自动跳过, 不影响其他功能

**Q: fish shell 兼容吗?**
A: 兼容。所有子进程使用参数数组模式 (shell=False)，与 shell 类型无关。

### 性能

**Q: 启动很慢怎么办?**
A: 检查网络连接(NVD API 速率低)、关闭不需要的模块(config.yaml)、使用离线模式。

**Q: 内存占用大?**
A: 知识图谱 + 指纹库合计约 50MB。可在 config.yaml 降低缓存大小。

### 开发

**Q: 如何写插件?**
A: 实现 `src/plugins/sdk.py` 中的 DataSourcePlugin 接口，放在 plugins/ 目录下自动加载。

**Q: 如何调试?**
A: 设置 `LOG_LEVEL=DEBUG` 查看详细日志。使用 `--interactive` 模式交互调试。

**Q: 如何跑测试?**
A: `pytest tests/ -x -v` (不依赖磁盘缓存的测试约 362 个)。

## 故障排查 (Troubleshooting)

### 问题: 启动卡在 "初始化中..."
1. 检查网络: NVD API 连接超时可能阻塞 (>30s)
2. 使用镜像源: 设置 pip 镜像源
3. 查看日志: LOG_LEVEL=DEBUG

### 问题: 工具调用返回空
1. 检查 API Key 是否配置: config.yaml → api_keys
2. 检查网络: curl https://services.nvd.nist.gov
3. 检查断路器状态: tools list --show-breakers

### 问题: 内存溢出
1. 限制缓存大小: config.yaml → cache.max_size_mb
2. 限制知识图谱节点数: config.yaml → graph.max_nodes
3. 定期清理: python -m vuln_research_mcp --cleanup

### 问题: Windows 权限错误
1. 以普通用户运行 (不要右键"以管理员身份运行")
2. 检查杀毒软件是否拦截
3. 添加 VULNRESEARCH_ALLOW_ROOT=1 (不推荐)

## 社区贡献

### 提交 Issue
- Bug: 附日志 (LOG_LEVEL=DEBUG)、系统信息、重现步骤
- Feature: 附使用场景、期望接口
- 安全: 私密报告 TODO: 设置安全邮箱

### Pull Request
1. Fork 仓库
2. 创建 feature 分支: `git checkout -b feat/xxx`
3. 遵循安全编码规范: docs/CONTRIBUTING.md
4. 确保 import 正确 (绝对导入: `from src.xxx import yyy`)
5. 确保 `pytest tests/` 通过 (不依赖磁盘缓存)
6. 提交 PR 并说明改动

### 添加指纹
在 `src/correlator/fingerprints.json` 中按类别添加:
```json
"Web Servers": {
    "YourServer/1.2": "your_server_id"
}
```
CPE 映射在 `src/correlator/fingerprint_loader.py` 的 `_load_cpe_map()` 中添加。

## 视频演示脚本 (10分钟)

### 0:00-1:00 介绍
- 项目定位: 渗透测试基础设施组件
- v5.1 新特性: 跨平台 | 898 指纹 | AST 级防御 | 内网全阻断

### 1:00-3:00 快速安装
- Windows: pip install + 便携版解压
- Linux: apt + pip 三命令搞定
- macOS: brew + pip

### 3:00-5:00 基础功能演示
- `--version` 查看版本
- `--interactive` 交互模式
- `cve CVE-2021-44228` 查询 Log4Shell
- `assess CVE-2021-44228` 综合评估

### 5:00-7:00 安全特性演示
- 尝试扫描 192.168.1.1 被内网防护阻断
- 尝试注入 `test; rm -rf /` 被 AST 检测阻断
- Root 运行被权限检测阻断

### 7:00-9:00 高级功能
- 知识图谱指纹识别 (Banner → 产品识别)
- CNVD/CNNVD 中文漏洞库查询
- 离线镜像模式

### 9:00-10:00 Q&A / 结尾
- 社区贡献指南
- 路线图展望
