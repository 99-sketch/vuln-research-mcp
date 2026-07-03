# 生产部署指南 (Deployment Guide)

> vuln-research-mcp v4.5 — 国内环境友好部署

## 部署方式概览

| 方式 | 适用场景 | 难度 | 推荐度 |
|------|----------|------|:------:|
| pipx 独立安装 | 个人桌面/开发机 | ⭐ 简单 | ★★★★★ |
| venv + Supervisor | Linux 服务器 | ⭐⭐ 中等 | ★★★★★ |
| venv + systemd | Linux 服务器 | ⭐⭐ 中等 | ★★★★☆ |
| nssm Windows 服务 | Windows Server | ⭐⭐ 中等 | ★★★★☆ |
| Conda 环境 | 科学计算/数据团队 | ⭐⭐ 中等 | ★★★☆☆ |

---

## 方式 1：pipx 独立安装（推荐个人使用）

[pipx](https://pypa.github.io/pipx/) 是 Python 官方推荐的独立应用安装工具，自动创建隔离环境。

```bash
# 安装 pipx（使用清华镜像加速）
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pipx
pipx ensurepath

# 从 GitHub 安装
cd /path/to/vuln-research-mcp
pipx install -e .

# 或指定国内镜像加速
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .

# 验证
python -m src.server --version
```

---

## 方式 2：venv + Supervisor（推荐 Linux 生产环境）

Supervisor 是 Python 生态最成熟的进程管理工具，国内服务器广泛使用。

### 安装依赖

```bash
# 系统依赖
sudo apt update
sudo apt install python3.11 python3.11-venv supervisor git

# CentOS / RHEL
sudo yum install python3.11 python3.11-devel supervisor git
```

### 创建虚拟环境

```bash
# 克隆项目
git clone https://github.com/99-sketch/vuln-research-mcp.git /opt/vulnmcp
cd /opt/vulnmcp

# 创建虚拟环境
python3.11 -m venv venv
source venv/bin/activate

# 使用国内镜像安装依赖
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple supervisor

deactivate
```

### 创建专用用户

```bash
sudo useradd -r -s /bin/false -d /opt/vulnmcp vulnmcp
sudo chown -R vulnmcp:vulnmcp /opt/vulnmcp
```

### 配置文件

```bash
# 复制配置模板
sudo -u vulnmcp mkdir -p /opt/vulnmcp/data /opt/vulnmcp/audit
sudo -u vulnmcp cp config.example.yaml /opt/vulnmcp/config.yaml

# 编辑安全配置
sudo -u vulnmcp vim /opt/vulnmcp/config.yaml
```

### Supervisor 配置

```ini
# /etc/supervisor/conf.d/vulnmcp.conf
[program:vulnmcp]
command=/opt/vulnmcp/venv/bin/python -m src.server
directory=/opt/vulnmcp
user=vulnmcp
autostart=true
autorestart=true
startsecs=5
stopwaitsecs=10
redirect_stderr=true
stdout_logfile=/opt/vulnmcp/logs/supervisor.log
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=10
environment=NVD_API_KEY="your-key",LOG_LEVEL="WARNING",LOG_FORMAT="json"
```

```bash
# 创建日志目录
sudo -u vulnmcp mkdir -p /opt/vulnmcp/logs

# 重新加载并启动
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start vulnmcp

# 查看状态
sudo supervisorctl status vulnmcp
```

---

## 方式 3：venv + systemd（推荐 Linux 生产环境）

适合不需要 Supervisor 的场景，直接使用 systemd 管理。

```bash
# 创建 systemd 环境变量文件
sudo tee /etc/vulnmcp.env << 'EOF'
NVD_API_KEY=your-key-here
LOG_LEVEL=WARNING
LOG_FORMAT=json
EOF
sudo chmod 600 /etc/vulnmcp.env

# 创建 systemd 服务
sudo tee /etc/systemd/system/vulnmcp.service << 'EOF'
[Unit]
Description=Vulnerability Research MCP Server
After=network.target

[Service]
Type=simple
User=vulnmcp
Group=vulnmcp
EnvironmentFile=/etc/vulnmcp.env
WorkingDirectory=/opt/vulnmcp
ExecStart=/opt/vulnmcp/venv/bin/python -m src.server
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/vulnmcp/data /opt/vulnmcp/audit /opt/vulnmcp/logs
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vulnmcp
sudo systemctl start vulnmcp
sudo systemctl status vulnmcp
```

---

## 方式 4：Windows 服务部署（nssm）

[nssm](https://nssm.cc/) 是 Windows 最流行的服务包装器，轻量无依赖。

### 前置准备

```powershell
# 安装 Python 3.11+
# 下载地址: https://www.python.org/downloads/windows/
# 或华为云镜像: https://mirrors.huaweicloud.com/python/

# 安装 git
# 下载地址: https://git-scm.com/download/win
```

### 部署步骤

```powershell
# 1. 克隆项目
cd C:\
git clone https://github.com/99-sketch/vuln-research-mcp.git C:\vulnmcp
cd C:\vulnmcp

# 2. 创建虚拟环境
python -m venv venv
.\venv\Scripts\activate
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
deactivate

# 3. 配置
copy config.example.yaml config.yaml
notepad config.yaml

# 4. 下载 nssm (https://nssm.cc/download)
# 解压 nssm.exe 到 C:\vulnmcp\ 或 C:\Windows\System32\

# 5. 安装 Windows 服务
nssm install VulnMcp
# GUI 弹窗中设置:
#   Application Path: C:\vulnmcp\venv\Scripts\python.exe
#   Startup Directory: C:\vulnmcp
#   Arguments: -m src.server
#   Environment: NVD_API_KEY=your-key
#   Details → Startup type: Automatic
#   I/O → Redirect stdout/stderr

# 或命令行安装（无 GUI）
nssm install VulnMcp "C:\vulnmcp\venv\Scripts\python.exe" "-m" "src.server"
nssm set VulnMcp AppDirectory "C:\vulnmcp"
nssm set VulnMcp AppEnvironmentExtra "NVD_API_KEY=your-key"
nssm set VulnMcp Start SERVICE_AUTO_START

# 6. 启动服务
nssm start VulnMcp
nssm status VulnMcp
```

### 备选：Windows 任务计划程序

```powershell
# 使用任务计划程序开机自启
$Action = New-ScheduledTaskAction -Execute "C:\vulnmcp\venv\Scripts\python.exe" -Argument "-m src.server" -WorkingDirectory "C:\vulnmcp"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "VulnMcp" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
```

---

## 方式 5：Conda 环境部署

适合已使用 Conda 生态的团队。

```bash
# 安装 Miniconda
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
# 或清华镜像: https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/

bash Miniconda3-latest-Linux-x86_64.sh -b -p /opt/miniconda3

# 创建环境
conda create -n vulnmcp python=3.11 -y
conda activate vulnmcp

# 安装
cd /opt/vulnmcp
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .

# 配合 Supervisor/systemd 管理同上
```

---

## 国内镜像加速

### pip 镜像源

```bash
# 清华源（推荐）
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# 阿里源
pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/

# 华为云源
pip config set global.index-url https://mirrors.huaweicloud.com/repository/pypi/simple

# 豆瓣源
pip config set global.index-url https://pypi.douban.com/simple/
```

### Git 加速

```bash
# 使用 https 协议（避免 SSH 被墙）
git clone https://github.com/99-sketch/vuln-research-mcp.git

# 或使用 ghproxy 加速
git clone https://ghproxy.com/https://github.com/99-sketch/vuln-research-mcp.git
```

---

## 环境要求

### 系统依赖

| 工具 | 最低版本 | 用途 | 安全模式下必需？ |
|------|----------|------|:---:|
| Python | 3.10+ | 运行时 | ✅ |
| nmap | 7.80+ | 端口扫描 | ❌ |
| searchsploit | 5.0+ | Exploit 搜索 | ❌ |
| sublist3r | 1.1+ | 子域名枚举 | ❌ |
| amass | 3.0+ | 子域名枚举 | ❌ |
| msfconsole | 6.0+ | Metasploit 搜索 | ❌ |
| git | 2.30+ | PoC 仓库克隆 | ❌ |

> 💡 安全模式（`max_risk_level: read_only`）不需要任何外部工具，仅需 Python 运行时。

### Python 依赖（已锁定版本范围）

```
mcp>=1.0.0,<2.0
httpx>=0.27.0,<1.0
dnspython>=2.4.0,<3.0
diskcache>=5.6.0,<6.0
PyYAML>=6.0,<7.0
networkx>=3.0,<4.0
rich>=13.0,<14.0
fastapi>=0.100.0,<1.0
uvicorn>=0.23.0,<1.0
pydantic>=2.0,<3.0
```

---

## 健康检查

```bash
# 检查服务状态（REST API 模式）
curl http://localhost:8000/api/health

# CLI 模式健康检查
python -m src.server --version

# 预期响应
{
  "status": "ok",
  "version": "4.5.0",
  "tools": 39,
  "tools_available": ["search_cve", "..."],
  "circuit_breakers": {"nvd": "closed", "cisa": "closed"}
}
```

---

## 日志管理

### Supervisor 日志

```bash
# 查看实时日志
sudo supervisorctl tail -f vulnmcp

# 日志路径
/opt/vulnmcp/logs/supervisor.log
```

### systemd 日志

```bash
# 查看实时日志
sudo journalctl -u vulnmcp -f

# 最近 100 行
sudo journalctl -u vulnmcp -n 100
```

### 应用日志

```bash
# 审计日志
ls -la /opt/vulnmcp/audit/

# 数据目录
ls -la /opt/vulnmcp/data/
```

---

## 监控指标

关键监控点：
- `audit/` 目录 — 审计日志数量与大小
- 工具调用频率（通过结构化日志）
- API 熔断器状态（`all_breaker_status()`）
- NVD API 速率限制剩余次数
- 进程内存/CPU 使用率

---

## 备份与恢复

```bash
# 备份
tar -czf vulnmcp-backup-$(date +%Y%m%d).tar.gz \
  /opt/vulnmcp/data/ \
  /opt/vulnmcp/audit/ \
  /opt/vulnmcp/config.yaml \
  /opt/vulnmcp/logs/

# 恢复
sudo tar -xzf vulnmcp-backup-20260703.tar.gz -C /
sudo chown -R vulnmcp:vulnmcp /opt/vulnmcp
sudo supervisorctl restart vulnmcp
```

---

## 升级指南

```bash
# 1. 拉取最新代码
cd /opt/vulnmcp
sudo -u vulnmcp git pull origin main

# 2. 更新依赖
sudo -u vulnmcp venv/bin/pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .

# 3. 检查配置变更
diff config.example.yaml config.yaml

# 4. 重启服务
sudo supervisorctl restart vulnmcp
# 或
sudo systemctl restart vulnmcp
```

---

## 故障排查

### 无法连接 NVD API

```bash
# 检查网络连通性
curl -I https://services.nvd.nist.gov/rest/json/cves/2.0

# 设置代理（如需）
export HTTPS_PROXY=http://your-proxy:port
```

### 服务启动失败

```bash
# Supervisor
sudo supervisorctl tail -f vulnmcp stderr

# systemd
sudo journalctl -u vulnmcp -xe

# 手动测试
cd /opt/vulnmcp
sudo -u vulnmcp venv/bin/python -m src.server --version
```

### pip 安装超时

```bash
# 设置镜像源 + 延长超时
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --default-timeout=120 -e .
```
