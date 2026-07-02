# 高级用法

> 深入探索 Vulnerability Research MCP Server 的高级能力和进阶使用技巧。

---

## 目录

- [自定义搜索策略](#自定义搜索策略)
- [CVSS 精确评分技巧](#cvss-精确评分技巧)
- [批量漏洞研究工作流](#批量漏洞研究工作流)
- [CVE → Exploit → Template 联动](#cve--exploit--template-联动)
- [构建漏洞知识库](#构建漏洞知识库)
- [扩展服务器功能](#扩展服务器功能)
- [性能优化](#性能优化)
- [审计与合规](#审计与合规)

---

## 自定义搜索策略

### 关键词组合技巧

不同的关键词组合可以显著影响搜索结果质量：

| 目标 | 推荐关键词 | 说明 |
|------|-----------|------|
| 某产品的所有漏洞 | `"产品名"` | 最宽泛的搜索 |
| 特定版本漏洞 | `"产品名 版本号"` | 缩小范围 |
| 某类型漏洞 | `"产品名 RCE"` | 按漏洞类型过滤 |
| 近期漏洞 | `"产品名 2024"` | 关注新发现的漏洞 |

### 示例：精确搜索策略

```text
# 场景：搜索 WordPress 插件漏洞

# 第 1 步：宽泛搜索（发现所有漏洞）
search_cve(keyword="WordPress Plugin", max_results=20)

# 第 2 步：获取关键漏洞详情
get_cve_details(cve_id="CVE-2024-XXXXX")

# 第 3 步：关联的 CWE 分类
cwe_mapping(cwe_id="CWE-79")  # 如果是 XSS 漏洞
```

### 分页策略

`search_cve` 的 `max_results` 参数控制每次返回的结果数：

- **初步发现**：设置为 20-50，获取概览
- **深入分析**：设置为 5-10，聚焦高价值漏洞
- **批量导出**：分多次调用，每次 50 条

---

## CVSS 精确评分技巧

### 完整参数组合对照表

| 攻击类型 | AV | AC | PR | UI | S | C | I | A | 典型分数 |
|----------|----|----|----|----|----|----|----|----|----------|
| 远程无认证 RCE | N | L | N | N | U | H | H | H | ~9.8 |
| 远程无认证 DoS | N | L | N | N | U | N | N | H | ~7.5 |
| 需要登录的 SQL 注入 | N | L | L | N | U | H | H | N | ~8.1 |
| 本地提权 | L | L | L | N | C | H | H | H | ~7.8 |
| 物理接触攻击 | P | L | N | N | U | H | H | H | ~6.2 |
| 需要用户点击的 XSS | N | L | N | R | C | L | L | N | ~5.4 |

### 如何从 NVD 官网获取准确参数

1. 打开 NVD 详情页：`https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX`
2. 找到 "CVSS 3.1 Severity and Metrics" 区域
3. 直接使用显示的 vector 参数（AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H）
4. 在 `cvss_calculator` 中填入对应值

### 参数设置细节

**attack_vector（攻击向量）选择指南**

| 值 | 适用场景 | 示例 |
|----|----------|------|
| `NETWORK` | 攻击者可从网络远程利用 | 远程代码执行、SQL 注入 |
| `ADJACENT_NETWORK` | 攻击者需在同一广播域 | ARP 欺骗、蓝牙漏洞 |
| `LOCAL` | 攻击者需本地访问系统 | 本地提权、本地文件包含 |
| `PHYSICAL` | 攻击者需物理接触设备 | USB 攻击、BIOS 漏洞 |

**attack_complexity（攻击复杂度）选择指南**

| 值 | 适用场景 |
|----|----------|
| `LOW` | 没有特殊条件，标准配置即可利用 |
| `HIGH` | 需要特定条件（如特定配置、时序窗口、社会工程） |

---

## 批量漏洞研究工作流

### 按厂商/产品批量搜索

```text
# 阶段 1：发现产品全量漏洞
1. search_cve(keyword="Apache HTTP Server", max_results=20)
2. search_cve(keyword="Apache HTTP Server", version="2.4", max_results=20)

# 阶段 2：筛选高严重性漏洞
# 从阶段 1 结果中筛选 CVSS >= 7.0 的漏洞

# 阶段 3：获取详细信息
3. get_cve_details(cve_id="CVE-2024-XXXXX")  # 对每个高严重性漏洞

# 阶段 4：关联 Exploit 和检测模板
4. search_exploit(query="Apache HTTP Server")
5. search_exploit(query="CVE-2024-XXXXX")
6. find_nuclei_template(tags="apache", severity="critical")
```

### 漏洞评估矩阵模板

在研究过程中，可以构建如下评估矩阵：

```
产品：Apache HTTP Server
版本：2.4.49
┌────────────────┬────────┬────────┬──────────┬──────────┐
│ CVE ID         │ CVSS   │ 等级   │ 有 EXP?  │ 有模板?  │
├────────────────┼────────┼────────┼──────────┼──────────┤
│ CVE-2024-XXXX1 │ 9.8    │ CRIT   │ ✅       │ ✅       │
│ CVE-2024-XXXX2 │ 7.5    │ HIGH   │ ❌       │ ✅       │
│ CVE-2024-XXXX3 │ 5.4    │ MEDIUM │ ❌       │ ❌       │
└────────────────┴────────┴────────┴──────────┴──────────┘
```

---

## CVE → Exploit → Template 联动

这是本服务器最强大的工作流：从一个 CVE 出发，获取完整的研究链路。

### 完整链路示例

```text
# Step 1: 发现 CVE
search_cve(keyword="Django", version="3.2", max_results=5)
→ 发现 CVE-2024-XXXXX（Django 模板注入）

# Step 2: 获取详情
get_cve_details(cve_id="CVE-2024-XXXXX")
→ 了解漏洞机制、影响版本、参考链接

# Step 3: 查询 CWE 分类
cwe_mapping(cwe_id="CWE-1336")  # 模板注入相关
→ 理解漏洞根本原因

# Step 4: 计算严重程度
cvss_calculator(
  attack_vector="NETWORK",
  attack_complexity="LOW",
  privileges_required="NONE",
  user_interaction="NONE",
  scope="CHANGED",
  confidentiality="HIGH",
  integrity="LOW",
  availability="NONE"
)
→ 获取 CVSS 评分用于报告

# Step 5: 搜索 Exploit
search_exploit(query="Django 3.2 RCE")
→ 获取 PoC 用于漏洞验证

# Step 6: 查找检测模板
find_nuclei_template(tags="django,cve", severity="high")
→ 获取自动化检测配置
```

### 输出汇总

完成上述步骤后，可生成如下报告：

```markdown
## 漏洞研究摘要

### CVE-2024-XXXXX - Django 模板注入漏洞

- **CVSS 评分**: 8.6 (HIGH)
- **CWE 分类**: CWE-1336（服务器端模板注入）
- **影响版本**: Django 3.2.x < 3.2.20
- **修复版本**: Django 3.2.20

### 可用资源
- ✅ Exploit: EDB-ID-12345（PoC 可用）
- ✅ Nuclei 模板: django-ssti-cve-2024-xxxxx.yaml 可用
- 📚 参考链接: nvd.nist.gov, github advisory
```

---

## 构建漏洞知识库

### 定期跟踪特定产品

通过定期搜索，建立产品漏洞跟踪体系：

```text
# 每周执行
1. search_cve(keyword="Linux Kernel", max_results=20)
   → 跟踪内核漏洞

2. search_cve(keyword="Chrome", max_results=20)
   → 跟踪浏览器漏洞

3. search_cve(keyword="Microsoft Exchange", max_results=20)
   → 跟踪办公产品漏洞
```

### 关注新发布的 CVE

利用 NVD 的排序功能，关注最新发布的漏洞：

```text
# 搜索最新关键漏洞
search_cve(keyword="2024", max_results=20)
→ 关注当年的最新漏洞
```

---

## 扩展服务器功能

当前项目代码中有 5 个预留工具尚未完整实现。如果需要扩展，可以参考以下方向：

### 添加新工具的基本步骤

```python
# Step 1: 在 list_tools() 中添加工具声明
Tool(
    name="my_new_tool",
    description="我的新工具",
    inputSchema={
        "type": "object",
        "properties": {
            "param1": {"type": "string", "description": "参数1"}
        },
        "required": ["param1"]
    }
)

# Step 2: 在 call_tool() 中添加路由
elif name == "my_new_tool":
    result = await my_new_tool(**arguments)

# Step 3: 实现工具函数
async def my_new_tool(param1: str) -> dict:
    # 工具实现逻辑
    return {"result": "success"}
```

### 建议添加的数据源

- **CISA KEV**: 已知已利用漏洞目录
- **GitHub Advisory**: GitHub 安全公告
- **OSV.dev**: 开源漏洞数据库
- **VulnDB**: 第三方漏洞数据库

---

## 性能优化

### 网络延迟优化

- **使用 CDN 镜像**: 如果 NVD API 访问慢，考虑使用中转代理
- **减少超时等待**: 当前超时设置为 30 秒，可根据网络情况调整

### 缓存策略

服务器当前不实现缓存。如果需要优化重复查询：

1. 在 MCP 客户端层面缓存频繁查询的结果
2. 在 `server.py` 中添加简单的内存缓存（字典）
3. 使用 Redis/Memcached 实现持久化缓存

### 并行查询

MCP 协议本身支持多工具并行调用，多个工具之间不会互相阻塞。例如可以同时调用：

```
search_cve(keyword="Product A")
search_cve(keyword="Product B")
```

两个调用会独立执行。

---

## 审计与合规

### 日志审计

所有工具调用都会被记录，可用于：

- **操作审计**: 记录谁在什么时候查询了什么内容
- **合规检查**: 确保漏洞查询行为符合授权范围
- **异常检测**: 发现未授权的批量查询行为

### 白帽注意事项

- 保存所有授权书副本
- 只在授权范围内使用
- 遵守目标平台的使用条款
- 及时清理从 Exploit-DB 获取的利用代码
