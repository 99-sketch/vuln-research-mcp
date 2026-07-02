# 详细安装指南

> 从零开始，安装并运行 Vulnerability Research MCP Server。

---

## 目录

- [系统要求](#系统要求)
- [安装 Python](#安装-python)
- [克隆或获取项目](#克隆或获取项目)
- [安装依赖](#安装依赖)
- [配置 MCP 客户端](#配置-mcp-客户端)
- [验证安装](#验证安装)
- [一键安装脚本](#一键安装脚本-windows)
- [Docker 安装（可选）](#docker-安装可选)

---

## 系统要求

| 组件 | 最低要求 | 推荐 |
|------|----------|------|
| 操作系统 | Windows 10+ / macOS 12+ / Linux (x86_64) | Windows 11 / macOS 14+ / Ubuntu 22.04+ |
| Python | 3.10 | 3.11+ |
| pip | 21.0+ | 23.0+ |
| 磁盘空间 | 50 MB | 200 MB（含 Nuclei Templates） |
| 网络 | 可访问 api 服务 | 稳定互联网连接 |
| MCP 客户端 | Claude Desktop / 兼容客户端 | Claude Desktop 最新版 |

### 可选依赖

| 工具 | 用途 | 安装命令 |
|------|------|----------|
| searchsploit | Exploit-DB 搜索 | `sudo apt install exploitdb` |
| Nuclei | 模板管理 | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| nmap | 端口扫描（预留） | `sudo apt install nmap` |
| sublist3r | 子域名枚举（预留） | `pip install sublist3r` |
| amass | 子域名枚举（预留） | `go install -v github.com/owasp-amass/amass/v4/...@master` |

---

## 安装 Python

### Windows

1. 访问 [python.org/downloads](https://www.python.org/downloads/)
2. 下载 Python 3.10+ 版本
3. 安装时 **务必勾选** "Add Python to PATH"
4. 验证安装：

```powershell
python --version
pip --version
```

### macOS

```bash
# 使用 Homebrew
brew install python@3.11

# 验证
python3 --version
pip3 --version
```

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
python3 --version
pip3 --version
```

---

## 克隆或获取项目

```bash
# 方式 1：git clone（推荐）
git clone https://github.com/your-org/vuln-research-mcp.git
cd vuln-research-mcp

# 方式 2：直接下载 ZIP 压缩包
# 下载后解压并进入目录
```

### 项目目录结构

```
vuln-research-mcp/
├── src/
│   └── server.py
├── tests/
│   └── test_server.py
├── requirements.txt
├── install.ps1
└── claude_desktop_config_example.json
```

---

## 安装依赖

### 标准安装

```bash
cd vuln-research-mcp
pip install -r requirements.txt
```

### 使用虚拟环境（推荐）

```bash
# 创建虚拟环境
python -m venv venv

# 激活（Windows PowerShell）
.\venv\Scripts\Activate.ps1

# 激活（macOS/Linux）
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### requirements.txt 内容

```
mcp>=1.0.0
httpx>=0.27.0
pydantic>=2.0.0
```

### 手动安装特定版本

```bash
pip install mcp==1.0.0 httpx==0.27.0 pydantic==2.0.0
```

### 常见安装问题

**问题：pip 安装速度慢**

```bash
# 使用国内镜像源
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

**问题：权限不足**

```bash
# macOS/Linux 使用 --user
pip install --user -r requirements.txt

# Windows 使用管理员终端
# 右键 PowerShell → 以管理员身份运行
```

---

## 配置 MCP 客户端

### Claude Desktop

1. 找到配置文件位置：

| 操作系统 | 配置文件路径 |
|----------|-------------|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

2. 添加服务器配置：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": [
        "C:\\full\\path\\to\\vuln-research-mcp\\src\\server.py"
      ],
      "env": {
        "LOG_LEVEL": "INFO",
        "NVD_API_KEY": ""
      }
    }
  }
}
```

> 用实际路径替换 `C:\\full\\path\\to\\vuln-research-mcp\\src\\server.py`
>
> 路径分隔符：Windows 使用 `\\`，macOS/Linux 使用 `/`

3. 保存文件
4. 完全退出 Claude Desktop 并重新启动

### 其他 MCP 客户端

不同客户端配置方式不同，请参考对应平台的文档添加 stdio MCP 服务器，命令为：

```
python /path/to/vuln-research-mcp/src/server.py
```

---

## 验证安装

### 方法 1：运行测试脚本

```bash
cd vuln-research-mcp/tests
python test_server.py
```

预期输出：

```
🧪 Vulnerability Research MCP Server 测试套件
============================================================

测试 1: search_cve
============================================================
✅ 成功搜索 CVE
总结果数: ...
返回漏洞数: 5

测试 2: get_cve_details
============================================================
✅ 成功获取 CVE 详情
CVE ID: CVE-2021-44228

测试 3: cvss_calculator
============================================================
✅ 成功计算 CVSS 评分
基础评分: 9.8
严重等级: CRITICAL

============================================================
✅ 所有测试完成
```

### 方法 2：直接连接 MCP 客户端

在 Claude Desktop 中发送：

```
你现在有哪些工具可以使用？
```

如果看到锤子图标或工具列表中出现 `search_cve` 等工具，说明安装成功。

---

## 一键安装脚本（Windows）

项目提供 `install.ps1` 自动完成全部安装流程：

```powershell
# 进入项目目录
cd vuln-research-mcp

# 执行安装脚本
.\install.ps1
```

脚本自动完成：
1. ✅ 检查 Python 版本
2. ✅ 检查 pip
3. ✅ 安装依赖包
4. ✅ 运行测试
5. ✅ 生成 Claude Desktop 配置文件

---

## Docker 安装（可选）

虽然项目当前没有提供 Dockerfile，但可以手动创建：

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

CMD ["python", "src/server.py"]
```

构建并运行：

```bash
docker build -t vuln-research-mcp .
docker run -it --rm vuln-research-mcp
```

---

## 安装后下一步

安装完成后：

1. 熟悉 [USAGE.md](../USAGE.md) 中的快速开始
2. 查看 [EXAMPLES.md](../EXAMPLES.md) 学习各种使用方式
3. 需要调优配置请参考 [configuration.md](configuration.md)
4. 遇到问题请查阅 [TROUBLESHOOTING.md](../TROUBLESHOOTING.md)
