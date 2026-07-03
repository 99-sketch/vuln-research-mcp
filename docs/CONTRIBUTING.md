# 贡献指南 (Contributing Guide)

## 行为准则

本项目致力于为安全研究社区提供高质量的开源工具。
参与贡献请保持专业、尊重他人、遵循安全披露原则。

## 贡献方式

### 报告 Bug

1. 使用 GitHub Issues 报告
2. 提供：环境信息（OS、Python 版本）、复现步骤、预期与实际结果
3. 安全漏洞请通过 Security Advisory 报告（见下文）

### 提交代码

1. **Fork 仓库** 并创建功能分支
2. **写测试** — 新功能必须有对应的 pytest 测试
3. **通过 CI 检查**：
   ```bash
   # 运行测试
   pytest tests/ -q

   # 代码检查
   mypy src/bus/ src/db/ src/correlator/ src/intel/ src/orchestrator/ src/reporting/ src/security/ src/tools/scanner_tools.py --ignore-missing-imports

   # 格式化
   ruff check src/ tests/
   ```
4. **更新 CHANGELOG.md**
5. **提交 PR** 到 `main` 分支

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/99-sketch/vuln-research-mcp.git
cd vuln-research-mcp

# 安装开发依赖
pip install -e ".[dev]"

# 安装 pre-commit hooks
pre-commit install

# 运行测试
pytest tests/ -v
```

### 项目结构约定

```
src/
├── server.py          # MCP 服务器入口 + 工具注册
├── security/          # v4.1 安全模块
│   ├── input_sanitizer.py   # 输入净化
│   ├── target_policy.py     # 目标白名单
│   ├── audit.py             # 审计日志
│   ├── key_manager.py       # 密钥管理
│   └── tool_guard.py        # 工具权限
├── bus/               # 事件总线
├── core/              # 基础设施
├── tools/             # 工具实现
├── db/                # 数据库层
├── intel/             # 威胁情报
├── correlator/        # 关联引擎
├── orchestrator/      # 流水线编排
├── reporting/         # 报告生成
├── gateway/           # REST API / CLI
├── workflow/          # 工作流引擎
└── plugins/           # 插件 SDK
```

### 安全编码规范

所有处理外部输入的函数必须遵循：

1. **参数验证优先** — 在处理用户输入前进行格式、类型、范围校验
2. **使用白名单而非黑名单** — `sanitize_command_arg()` 只允许安全字符
3. **子进程安全** — 使用 `async_run(cmd: list)` 的列表形式，不要用 shell 字符串
4. **注入模式检查** — 对任何传递到外部工具的输入调用 `sanitize_injection_patterns()`
5. **日志脱敏** — 不要在日志中打印完整 API Key、Token、密码

### 新工具添加规范

添加新工具时，在 `src/server.py` 的 `_register_all_tools()` 中注册：

```python
registry.register(ToolDefinition(
    name="my_new_tool",
    description="工具描述",
    input_schema={
        "type": "object",
        "properties": {
            "param1": {"type": "string", "description": "参数说明"},
        },
        "required": ["param1"],
    },
    handler=my_handler_function,
    requires_tools=["external_dep"],  # 可选
    requires_apis=["api_name"],       # 可选
))
```

并在 `src/security/tool_guard.py` 的 `TOOL_RISK_MAP` 中添加风险等级。

## 安全漏洞披露

**请勿在公开 Issue 中披露安全漏洞！**

安全漏洞通过 GitHub Security Advisory 报告：
https://github.com/99-sketch/vuln-research-mcp/security/advisories/new

### 披露流程

1. 通过 Security Advisory 提交漏洞报告
2. 维护者在 48 小时内确认收到
3. 漏洞修复后会发布安全更新版本
4. CVE 编号分配（如适用）
5. 公开披露（修复版本发布后 30 天）

### 漏洞严重度评级

| 等级 | 示例 | 修复时间 |
|------|------|----------|
| Critical | 远程代码执行、身份认证绕过 | 24小时 |
| High | 命令注入、SSRF、信息泄露 | 72小时 |
| Medium | 权限提升、拒绝服务 | 下一版本 |
| Low | 信息过度暴露、配置不当 | 适时修复 |

## 版本管理

遵循语义化版本（SemVer）：
- **主版本号**：不兼容的 API 变更
- **次版本号**：向后兼容的功能新增（v4.1）
- **修订号**：向后兼容的问题修复

## 许可证

本项目采用 MIT 许可证。贡献代码即表示您同意在 MIT 许可证下发布您的代码。
