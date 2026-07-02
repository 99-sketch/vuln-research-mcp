# 配置说明

> 本文档详细说明 Vulnerability Research MCP Server 的所有配置项。

---

## 目录

- [MCP 客户端配置](#mcp-客户端配置)
- [环境变量](#环境变量)
- [NVD API Key 配置](#nvd-api-key-配置)
- [日志配置](#日志配置)
- [可选工具路径配置](#可选工具路径配置)
- [高级配置](#高级配置)
- [多客户端配置示例](#多客户端配置示例)

---

## MCP 客户端配置

### Claude Desktop 配置

配置文件位置：

| 操作系统 | 路径 |
|----------|------|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

基础配置模板：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": [
        "E:\\QClawCache\\workspace-agent-c3e0083a\\vuln-research-mcp\\src\\server.py"
      ]
    }
  }
}
```

### 配置项详解

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `mcpServers.{name}.command` | string | ✅ | 启动命令，固定为 `python` |
| `mcpServers.{name}.args` | array | ✅ | 参数数组，第一项为 server.py 的绝对路径 |
| `mcpServers.{name}.env` | object | ❌ | 环境变量字典 |
| `mcpServers.{name}.disabled` | boolean | ❌ | 设为 `true` 可禁用此服务器 |

---

## 环境变量

所有环境变量通过 `mcpServers.vuln-research.env` 配置：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\server.py"],
      "env": {
        "NVD_API_KEY": "your-api-key",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### 环境变量列表

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `NVD_API_KEY` | 空 | NVD API 密钥（建议设置，提升速率限制） |
| `LOG_LEVEL` | `INFO` | 日志级别：`DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `NUCLEI_TEMPLATES_DIR` | `~/.local/share/nuclei-templates` | Nuclei 模板目录路径 |

---

## NVD API Key 配置

### 为什么要配置 API Key？

| 状态 | 速率限制 | 适用场景 |
|------|----------|----------|
| 无 API Key | 每分钟 5 次 | 个人测试、简单查询 |
| 有 API Key | 每分钟 50 次 | 渗透测试、批量研究 |

### 申请 API Key

1. 访问 [NVD API Key 申请页面](https://nvd.nist.gov/developers/request-an-api-key)
2. 填写申请表单（电子邮箱、组织名称等）
3. 提交后通常数分钟内收到包含 API Key 的邮件

### 配置方式

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\server.py"],
      "env": {
        "NVD_API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      }
    }
  }
}
```

### 安全提醒

- **不要**将 API Key 提交到版本控制系统
- **不要**在公开场合分享 API Key
- 建议将 `claude_desktop_config.json` 加入 `.gitignore`

---

## 日志配置

### 日志级别

| 级别 | 用途 | 输出内容 |
|------|------|----------|
| `DEBUG` | 调试 | 所有详细信息，包括请求/响应数据 |
| `INFO` | 默认 | 工具调用开始/结束、关键事件 |
| `WARNING` | 警告 | 潜在问题但不影响运行 |
| `ERROR` | 错误 | 工具调用失败、异常信息 |

### 配置示例

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\server.py"],
      "env": {
        "LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

### 日志内容示例（INFO 级别）

```
2024-01-15 10:00:00,123 - INFO - Vulnerability Research MCP Server 启动中...
2024-01-15 10:00:05,456 - INFO - 工具调用: search_cve, 参数: {'keyword': 'Log4j', 'max_results': 5}
2024-01-15 10:00:07,890 - INFO - 工具 search_cve 执行成功
```

---

## 可选工具路径配置

对于依赖外部工具的功能，确保对应工具已在 `PATH` 中：

| 功能 | 依赖工具 | 验证命令 |
|------|----------|----------|
| `search_exploit` | `searchsploit` | `searchsploit --version` |
| `find_nuclei_template` | Nuclei Templates 目录 | `ls ~/.local/share/nuclei-templates/` |
| `scan_ports`（预留） | `nmap` | `nmap --version` |
| `enumerate_subdomains`（预留） | `sublist3r` / `amass` | `sublist3r --help` |

### 在 Windows 中添加工具到 PATH

```powershell
# 临时添加
$env:Path += ";C:\path\to\tool"

# 永久添加（系统级别）
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "User") + ";C:\path\to\tool",
    "User"
)
```

---

## 高级配置

### 自定义 Nuclei 模板目录

如果 Nuclei 模板不在默认路径，可以通过环境变量指定：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\server.py"],
      "env": {
        "NUCLEI_TEMPLATES_DIR": "E:\\tools\\nuclei-templates"
      }
    }
  }
}
```

> **注意**：当前代码尚未实现对此环境变量的读取，此配置为预留。

### 配置多个 MCP 服务器

可以与其他 MCP 服务器共存：

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["path\\to\\vuln-research-mcp\\src\\server.py"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\projects\\repos"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

---

## 多客户端配置示例

### Cursor IDE

```json
{
  "mcpServers": {
    "vuln-research": {
      "command": "python",
      "args": ["/Users/me/vuln-research-mcp/src/server.py"]
    }
  }
}
```

### Continue.dev

```json
{
  "experimental": {
    "mcpServers": {
      "vuln-research": {
        "command": "python",
        "args": ["/Users/me/vuln-research-mcp/src/server.py"]
      }
    }
  }
}
```

### 自定义脚本启动（调试用）

```bash
# Linux / macOS
export NVD_API_KEY="your-key"
export LOG_LEVEL="DEBUG"
python /path/to/vuln-research-mcp/src/server.py

# Windows PowerShell
$env:NVD_API_KEY = "your-key"
$env:LOG_LEVEL = "DEBUG"
python E:\path\to\vuln-research-mcp\src\server.py
```
