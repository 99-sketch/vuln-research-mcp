# 生产部署指南 (Deployment Guide)

> vuln-research-mcp v4.1

## 部署方式

### 方式 1：Docker 部署（推荐）

```bash
# 构建镜像
docker build -t vuln-research-mcp:4.1 .

# 创建配置目录
mkdir -p ~/.vuln-research-mcp

# 运行（只读文件系统 + 网络隔离）
docker run -d --name vulnmcp \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100M \
  -v ~/.vuln-research-mcp/config.yaml:/app/config.yaml:ro \
  -v ~/.vuln-research-mcp/data:/app/data:rw \
  -v ~/.vuln-research-mcp/audit:/app/audit:rw \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  vuln-research-mcp:4.1

# 仅允许扫描特定内网网段
docker run -d --name vulnmcp \
  --network=vuln-net \
  --ip=10.0.0.100 \
  vuln-research-mcp:4.1
```

### 方式 2：虚拟环境部署

```bash
# 创建隔离虚拟环境
python3 -m venv /opt/vulnmcp/venv
source /opt/vulnmcp/venv/bin/activate

# 安装
pip install vuln-research-mcp==4.1.0

# 创建专用用户
sudo useradd -r -s /bin/false -d /opt/vulnmcp vulnmcp
sudo chown -R vulnmcp:vulnmcp /opt/vulnmcp

# 配置文件
sudo -u vulnmcp mkdir -p ~vulnmcp/.vuln-research-mcp
sudo -u vulnmcp cp config.example.yaml ~vulnmcp/.vuln-research-mcp/config.yaml
sudo -u vulnmcp chmod 600 ~vulnmcp/.vuln-research-mcp/config.yaml

# 环境变量
cat > /etc/systemd/system/vulnmcp.env << 'EOF'
NVD_API_KEY=your-key
LOG_LEVEL=WARNING
LOG_FORMAT=json
EOF

# Systemd 服务
sudo tee /etc/systemd/system/vulnmcp.service << 'EOF'
[Unit]
Description=Vulnerability Research MCP Server
After=network.target

[Service]
Type=simple
User=vulnmcp
Group=vulnmcp
EnvironmentFile=/etc/systemd/system/vulnmcp.env
WorkingDirectory=/opt/vulnmcp
ExecStart=/opt/vulnmcp/venv/bin/python -m src.server
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
ReadOnlyPaths=/
ReadWritePaths=/opt/vulnmcp/data
ReadWritePaths=/opt/vulnmcp/audit
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vulnmcp
sudo systemctl start vulnmcp
```

### 方式 3：Kubernetes 部署

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: vuln-tools

---
apiVersion: v1
kind: Secret
metadata:
  name: vulnmcp-secrets
  namespace: vuln-tools
type: Opaque
stringData:
  nvd-api-key: "your-key-here"

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulnmcp-config
  namespace: vuln-tools
data:
  config.yaml: |
    server:
      log_level: WARNING
      log_format: json
    security:
      max_risk_level: active_scan
      target_whitelist_enabled: true
      audit_enabled: true
      require_approval_for_scans: true
    rate_limit:
      nvd_requests_per_window: 50
      nvd_window_seconds: 30

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vuln-research-mcp
  namespace: vuln-tools
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vuln-research-mcp
  template:
    metadata:
      labels:
        app: vuln-research-mcp
    spec:
      serviceAccountName: vulnmcp
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        readOnlyRootFilesystem: true
      containers:
      - name: mcp-server
        image: vuln-research-mcp:4.1
        env:
        - name: NVD_API_KEY
          valueFrom:
            secretKeyRef:
              name: vulnmcp-secrets
              key: nvd-api-key
        - name: LOG_LEVEL
          value: "WARNING"
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
          readOnly: true
        - name: data
          mountPath: /app/data
        - name: tmp
          mountPath: /tmp
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "100m"
      volumes:
      - name: config
        configMap:
          name: vulnmcp-config
      - name: data
        emptyDir: {}
      - name: tmp
        emptyDir: {}
```

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

## 健康检查

```bash
# 检查服务状态
curl http://localhost:8000/api/health

# 预期响应
{
  "status": "ok",
  "version": "4.1.0",
  "tools": 38,
  "tools_available": ["search_cve", "..."],
  "circuit_breakers": {"nvd": "closed", "cisa": "closed"}
}
```

## 监控指标

关键监控点：
- `~/vuln-research-mcp/audit/` — 审计日志数量与大小
- 工具调用频率（通过 MCP 日志）
- API 熔断器状态（`all_breaker_status()`）
- NVD API 速率限制剩余次数

## 备份与恢复

```bash
# 备份数据
tar -czf vulnmcp-backup-$(date +%Y%m%d).tar.gz \
  ~/.vuln-research-mcp/data/ \
  ~/.vuln-research-mcp/audit/ \
  ~/.vuln-research-mcp/config.yaml

# 恢复
tar -xzf vulnmcp-backup-20260703.tar.gz -C ~/
```

## Windows 部署注意事项

Windows 环境下建议使用 WSL2 或 Docker Desktop：

```powershell
# WSL2 部署
wsl --install -d Ubuntu-22.04
wsl -d Ubuntu-22.04

# 进入 WSL 后按 Linux 方式部署
sudo apt update && sudo apt install python3-pip nmap
pip install vuln-research-mcp==4.1.0

# Docker Desktop 部署
docker pull 99-sketch/vuln-research-mcp:4.1
docker run -d -p 8000:8000 --name vulnmcp vuln-research-mcp:4.1
```

**原生 Windows 限制：**
- `searchsploit` 和 `msfconsole` 在 Windows 上不可用
- 建议使用 `tools.disabled` 禁用这些工具
- nmap 需要在 Windows 上单独安装并添加至 PATH
