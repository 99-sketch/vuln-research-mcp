# 贡献指南

> 感谢您考虑为 Vulnerability Research MCP Server 贡献代码！

---

## 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发环境搭建](#开发环境搭建)
- [代码规范](#代码规范)
- [提交流程](#提交流程)
- [添加新工具指南](#添加新工具指南)
- [测试规范](#测试规范)
- [文档规范](#文档规范)

---

## 行为准则

### 基本原则

- **尊重每一位参与者**：不论经验水平、背景或观点
- **建设性反馈**：指出问题时同时提供改进建议
- **聚焦项目目标**：所有贡献应围绕提升漏洞研究效率

### 禁止行为

- 提交恶意代码或后门
- 侵犯他人知识产权
- 人身攻击或不当言论
- 将漏洞数据用于非法目的

---

## 如何贡献

### 贡献类型

| 类型 | 说明 | 适合人群 |
|------|------|----------|
| 🐛 报告 Bug | 发现程序缺陷或异常行为 | 所有用户 |
| 💡 功能建议 | 提出新功能或改进意见 | 所有用户 |
| 📖 完善文档 | 修正文档错误或补充内容 | 技术写作人员 |
| 🔧 提交代码 | 修复 Bug 或实现新功能 | 开发者 |
| 🧪 添加测试 | 补充自动化测试用例 | 测试工程师 |
| 🔌 集成新数据源 | 添加新的漏洞数据源 | 有 API 开发经验者 |

### 首次贡献建议

如果你是第一次参与开源项目，推荐从以下任务开始：

1. **完善已有 CWE 数据库**：补充 `cwe_mapping` 函数中的内置 CWE 列表
2. **补充测试用例**：为现有工具添加更多边界测试
3. **改进文档**：修正错别字、补充遗漏的说明

---

## 开发环境搭建

### 1. Fork 仓库

访问 GitHub 仓库页面，点击 Fork 按钮。

### 2. 克隆 Fork

```bash
git clone https://github.com/YOUR_USERNAME/vuln-research-mcp.git
cd vuln-research-mcp
```

### 3. 创建虚拟环境

```bash
python -m venv venv
source venv/bin/activate  # macOS/Linux
.\venv\Scripts\Activate.ps1  # Windows
```

### 4. 安装开发依赖

```bash
pip install -r requirements.txt
pip install pytest pytest-asyncio  # 测试工具
```

### 5. 验证环境

```bash
python -c "from src.server import server; print('setup OK')"
```

---

## 代码规范

### Python 编码规范

遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/) 风格指南：

| 规范 | 要求 |
|------|------|
| 缩进 | 4 空格（禁止使用 Tab） |
| 行宽 | 最大 100 字符 |
| 命名 | 函数/变量：`snake_case`，类：`PascalCase` |
| 类型注解 | 所有函数参数和返回值必须标注类型 |
| Docstring | 所有公开函数必须有 docstring |
| import 顺序 | 标准库 → 第三方库 → 本地模块 |

### Docstring 格式

```python
async def search_cve(keyword: str, product: str = None, version: str = None, max_results: int = 10) -> dict:
    """搜索 CVE 漏洞

    Args:
        keyword: 搜索关键词
        product: 产品名称过滤（可选）
        version: 产品版本过滤（可选）
        max_results: 最大返回结果数，默认 10

    Returns:
        dict: 包含 total_results 和 vulnerabilities 列表

    Raises:
        httpx.HTTPError: NVD API 请求失败
    """
```

### 日志规范

```python
import logging
logger = logging.getLogger("vuln-research-mcp")

# 工具调用开始
logger.info(f"工具调用: {tool_name}, 参数: {arguments}")

# 工具调用成功
logger.info(f"工具 {tool_name} 执行成功")

# 错误记录
logger.error(f"工具 {tool_name} 执行失败: {str(e)}", exc_info=True)
```

### 异步编程规范

- 所有 I/O 操作必须使用 `async/await`
- 避免在异步函数中调用同步阻塞操作
- 使用 `httpx.AsyncClient` 而非 `requests`
- 外部工具调用使用 `asyncio.create_subprocess_exec` 或类似

---

## 提交流程

### 分支策略

```
main          # 稳定版本，只接受 PR
├── dev       # 开发分支
├── feat/xxx  # 功能分支
├── fix/xxx   # 修复分支
└── docs/xxx  # 文档更新
```

### 工作流程

```bash
# 1. 从 dev 创建功能分支
git checkout dev
git pull origin dev
git checkout -b feat/add-new-datasource

# 2. 进行开发，频繁提交
git add .
git commit -m "feat: 添加新数据源支持"

# 3. 保持分支与 dev 同步
git fetch origin
git rebase origin/dev

# 4. 推送分支
git push origin feat/add-new-datasource

# 5. 创建 Pull Request → 请求 Review
```

### Commit Message 规范

使用 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>: <简短描述>

[可选的详细描述]

[可选的底部备注]
```

**type 类型**：

| type | 含义 | 示例 |
|------|------|------|
| `feat` | 新功能 | `feat: 添加 CISA KEV 数据源支持` |
| `fix` | Bug 修复 | `fix: 修复 search_cve 速率限制处理` |
| `docs` | 文档更新 | `docs: 更新安装指南` |
| `test` | 测试相关 | `test: 添加 cvss_calculator 边界测试` |
| `refactor` | 代码重构 | `refactor: 提取 CVSS 计算为独立模块` |
| `chore` | 构建/工具 | `chore: 配置 pre-commit hooks` |

### Pull Request 规范

1. **标题**: 简洁描述改动，如 "feat: 添加 CISA KEV 数据源支持"
2. **描述**: 包含：
   - 改动内容概述
   - 改动原因
   - 测试方法
   - 相关 Issue 编号（如有）
3. **检查表**:
   - [ ] 代码通过现有测试
   - [ ] 添加了新的测试
   - [ ] 更新了相关文档
   - [ ] Commit message 符合规范
   - [ ] 代码通过了 linting

---

## 添加新工具指南

添加一个新工具的完整流程：

### Step 1: 声明工具

在 `list_tools()` 中添加 `Tool` 对象：

```python
Tool(
    name="cisa_kev",          # 工具名，snake_case
    description="查询 CISA Known Exploited Vulnerabilities 目录",
    inputSchema={
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE 编号（可选，不传则返回全部）"
            }
        },
        "required": []          # 空数组表示所有参数可选
    }
)
```

### Step 2: 添加路由

在 `call_tool()` 中添加分支：

```python
elif name == "cisa_kev":
    result = await cisa_kev(**arguments)
```

### Step 3: 实现函数

```python
async def cisa_kev(cve_id: str = None) -> dict:
    """查询 CISA KEV 目录"""
    async with httpx.AsyncClient() as client:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = await client.get(url, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        
        if cve_id:
            # 按 CVE 过滤
            results = [v for v in data["vulnerabilities"] if v["cveID"] == cve_id]
        else:
            results = data["vulnerabilities"][:10]
        
        return {
            "count": len(results),
            "vulnerabilities": results
        }
```

### Step 4: 添加测试

```python
# tests/test_server.py
async def test_cisa_kev():
    """测试 cisa_kev 工具"""
    print("\n测试 cisa_kev...")
    try:
        result = await cisa_kev(cve_id="CVE-2021-44228")
        assert "vulnerabilities" in result
        print("✅ cisa_kev 测试通过")
    except Exception as e:
        print(f"❌ 测试失败: {e}")
```

### Step 5: 更新文档

- 在 `USAGE.md` 中添加工具说明
- 在 `API_REFERENCE.md` 中添加 API 文档
- 在 `EXAMPLES.md` 中添加示例
- 在 `README.md` 中的功能表格中添加新工具

---

## 测试规范

### 测试框架

使用 `pytest` + `pytest-asyncio`。

### 测试文件结构

```
tests/
├── test_server.py         # 核心功能测试
├── test_search_cve.py     # search_cve 专项测试
├── test_cvss.py           # CVSS 计算测试
└── fixtures/
    └── sample_cve.json    # 测试数据（mock）
```

### 测试覆盖目标

| 级别 | 要求 | 示例 |
|------|------|------|
| 单元测试 | 每个函数至少 1 个测试 | 测试 CVSS 计算的各参数组合 |
| 集成测试 | 每个 MCP 端点至少 1 个测试 | 测试完整的工具调用链路 |
| 边界测试 | 空值、边界值、特殊字符 | 搜索空字符串、超大结果数 |

### Mock NVD API

```python
@pytest.mark.asyncio
async def test_search_cve_mocked(mocker):
    """使用 mock 测试 search_cve"""
    mocker.patch(
        'httpx.AsyncClient.get',
        return_value=mocker.Mock(
            status_code=200,
            json=lambda: {"totalResults": 0, "vulnerabilities": []}
        )
    )
    result = await search_cve(keyword="NonExistentProduct")
    assert result["total_results"] == 0
```

---

## 文档规范

### 文档文件清单

```
├── README.md              # 项目概述（中英文）
├── USAGE.md               # 使用教程
├── EXAMPLES.md            # 示例集合
├── API_REFERENCE.md       # API 参考手册
├── TROUBLESHOOTING.md     # 问题排查
├── CONTRIBUTING.md        # 贡献指南
├── CHANGELOG.md           # 版本更新日志
└── docs/
    ├── installation.md    # 安装指南
    ├── configuration.md   # 配置说明
    ├── advanced-usage.md  # 高级用法
    └── integrations.md    # 工具集成
```

### 文档写作风格

- 中文为主，技术术语保留英文（CVE、API、JSON 等）
- 简洁直接，先给结论再给论据
- 善用表格和代码块
- 所有命令和代码片段必须是可执行的

---

## 代码 Review 流程

### Reviewer 检查清单

```
□ 代码是否遵循 PEP 8 风格？
□ 是否有足够的类型注解？
□ 是否有 docstring？
□ 是否正确处理了错误场景？
□ 是否添加了对应的测试？
□ 是否更新了相关文档？
□ 是否兼容现有 API？
□ 异步操作是否使用了 async/await？
□ 日志是否完整？
```

### 需要多人的场景

以下改动建议 2+ 人 Review：
- 修改 MCP 通信协议
- 修改核心数据源（NVD API 交互）
- 大规模重构
- 添加新的外部依赖
