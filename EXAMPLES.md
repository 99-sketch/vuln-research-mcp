# 使用示例集合

> 10 个基础示例 + 5 个高级示例 + 3 个实战案例，覆盖各种使用场景。

---

## 目录

- [基础示例（10 个）](#基础示例10-个)
- [高级示例（5 个）](#高级示例5-个)
- [实战案例（3 个）](#实战案例3-个)

---

## 基础示例（10 个）

### 示例 1：搜索产品相关 CVE

**场景**：发现 Apache Log4j 存在漏洞，需要获取完整 CVE 列表。

```
用户输入：
"帮我搜索一下 Apache Log4j 的 CVE 漏洞"

工具调用：
search_cve(
  keyword="Apache Log4j",
  max_results=10
)

返回结果：
{
  "total_results": 50,
  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-44228",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "description": "Apache Log4j2 2.x 存在 JNDI 注入远程代码执行漏洞..."
    },
    ...
  ]
}
```

---

### 示例 2：获取单个 CVE 详细信息

**场景**：需要深入了解特定漏洞的完整信息。

```
用户输入：
"查看 CVE-2024-3094 的详细信息"

工具调用：
get_cve_details(cve_id="CVE-2024-3094")

返回结果包含：
- 漏洞描述
- CVSS 指标（所有版本）
- 弱分类（CWE）
- 受影响配置
- 引用链接列表
- 漏洞状态
```

---

### 示例 3：计算 CVSS 评分

**场景**：发现一个漏洞，需要计算其严重程度。

```
用户输入：
"计算一下这个漏洞的 CVSS 评分：
- 攻击者可以从远程网络发起攻击
- 攻击复杂度低
- 不需要任何权限
- 不需要用户交互
- 影响范围不变（不影响其他组件）
- 机密性、完整性、可用性全部完全泄露"

工具调用：
cvss_calculator(
  attack_vector="NETWORK",
  attack_complexity="LOW",
  privileges_required="NONE",
  user_interaction="NONE",
  scope="UNCHANGED",
  confidentiality="HIGH",
  integrity="HIGH",
  availability="HIGH"
)

输出：
{
  "base_score": 9.8,
  "severity": "CRITICAL",
  "vector": {
    "AV": "N", "AC": "L", "PR": "N",
    "UI": "N", "S": "U",
    "C": "H", "I": "H", "A": "H"
  }
}
```

---

### 示例 4：查询 CWE 弱分类定义

**场景**：需要了解 SQL 注入漏洞的分类定义和描述。

```
用户输入：
"什么是 CWE-89（SQL 注入）？"

工具调用：
cwe_mapping(cwe_id="CWE-89")

输出：
{
  "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "weakness_type": "Class",
  "status": "Draft",
  "description": "The software constructs all or part of an SQL command using externally-influenced input..."
}
```

---

### 示例 5：搜索 Exploit-DB

**场景**：搜索特定产品的已知漏洞利用代码。

```
用户输入：
"帮我找找最新的 WordPress RCE 漏洞利用代码"

工具调用：
search_exploit(query="WordPress RCE", type_filter="webapps")

输出：
{
  "query": "WordPress RCE",
  "type_filter": "webapps",
  "total_results": 23,
  "exploits": [
    {
      "Title": "WordPress Plugin X 1.0 - Remote Code Execution",
      "EDB-ID": "52022",
      "Author": "security-researcher",
      "Type": "webapps",
      "Platform": "PHP"
    }
  ]
}
```

---

### 示例 6：查找 Nuclei 检测模板

**场景**：需要快速找到特定漏洞的自动化检测模板。

```
用户输入：
"帮我找找 CVE-2023-46604 的 Nuclei 检测模板"

工具调用：
find_nuclei_template(tags="cve-2023-46604")

输出：
{
  "tags": "cve-2023-46604",
  "total_matched": 2,
  "templates": [
    "/home/user/.local/share/nuclei-templates/http/cves/2023/...yaml"
  ]
}
```

---

### 示例 7：按产品名 + 版本精确搜索

**场景**：确认特定版本的软件是否存在已知漏洞。

```
用户输入：
"检查 Apache HTTP Server 2.4.49 是否有已知 CVE"

工具调用：
search_cve(
  keyword="Apache HTTP Server",
  version="2.4.49",
  max_results=5
)

输出：
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-41773",
      "cvss_score": 7.5,
      "severity": "HIGH",
      "description": "A flaw was found in the way the Apache HTTP Server..."
    },
    {
      "cve_id": "CVE-2021-42013",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "description": "It was found that the fix for CVE-2021-41773..."
    }
  ]
}
```

---

### 示例 8：查询非内置 CWE

**场景**：查询当前内置列表中没有的 CWE 编号。

```
用户输入：
"查询 CWE-502（反序列化漏洞）的信息"

工具调用：
cwe_mapping(cwe_id="CWE-502")

输出：
{
  "note": "CWE-502 详细信息需要查询 MITRE CWE 数据库",
  "url": "https://cwe.mitre.org/data/definitions/502.html",
  "suggestion": "考虑下载完整 CWE 数据库: https://cwe.mitre.org/data/downloads.html"
}
```

---

### 示例 9：综合查询 CVE + CWE + CVSS

**场景**：完整描述一个漏洞的全部信息。

```
用户输入：
"帮我查一下 CVE-2021-44228 的 CWE 分类，再算一下评分"

工具调用链：
1. get_cve_details(cve_id="CVE-2021-44228")
2. cwe_mapping(cwe_id="CWE-502")

结果整合：
CVE-2021-44228 (Log4Shell)
- 类型：反序列化/远程代码执行 (CWE-502)
- CVSS：AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 CRITICAL
```

---

### 示例 10：搜索 CVE + 尝试获取 Exploit

**场景**：确认漏洞后立即搜索可用的利用代码。

```
用户输入：
"搜索 Spring Framework 的 RCE 漏洞，并看看是否已经有 EXP"

工具调用链：
1. search_cve(keyword="Spring Framework RCE", max_results=5)
2. search_exploit(query="Spring Framework RCE")
3. search_exploit(query="Spring4Shell")
```

---

## 高级示例（5 个）

### 示例 11：CVSS 评分精细调优

**场景**：需要为不同攻击场景计算多个 CVSS 评分。

```
用户输入：
"帮我分析一下这个 SQL 注入漏洞在不同场景下的评分差异"

调用 1 - 无需认证的 SQL 注入：
cvss_calculator(
  attack_vector="NETWORK",
  attack_complexity="LOW",
  privileges_required="NONE",      # 无需认证
  user_interaction="NONE",
  scope="UNCHANGED",
  confidentiality="HIGH",
  integrity="HIGH",
  availability="NONE"
)
→ 评分：8.6 (HIGH)

调用 2 - 需要管理员认证的 SQL 注入：
cvss_calculator(
  attack_vector="NETWORK",
  attack_complexity="LOW",
  privileges_required="HIGH",      # 需要管理员权限
  user_interaction="NONE",
  scope="UNCHANGED",
  confidentiality="HIGH",
  integrity="HIGH",
  availability="NONE"
)
→ 评分：6.0 (MEDIUM)

分析：权限要求从 NONE 变为 HIGH，评分从 8.6 降至 6.0
说明管理员后台的 SQL 注入比前台漏洞风险显著更低
```

---

### 示例 12：多产品关联漏洞分析

**场景**：分析同一组件在不同集成环境中的漏洞差异。

```
用户输入：
"搜索 ActiveMQ、Tomcat、Spring 在同一时间段的漏洞进行分析"

调用链：
1. search_cve(keyword="ActiveMQ", max_results=5)
2. search_cve(keyword="Apache Tomcat", max_results=5)
3. search_cve(keyword="Spring Framework", max_results=5)

分析思路：
- 对比各产品的 CVSS 平均分
- 识别共同依赖或组件
- 标记需要优先修复的产品
```

---

### 示例 13：完整的漏洞利用评估清单

**场景**：对单个高价值漏洞进行完整评估。

```
用户输入：
"对 CVE-2023-46604（Apache ActiveMQ RCE）进行完整研究"

完整工作流：

Step 1 - 获取详情：
get_cve_details(cve_id="CVE-2023-46604")

Step 2 - 分类分析：
cwe_mapping(cwe_id="CWE-502")  # 反序列化漏洞

Step 3 - CVSS 确认：
cvss_calculator(
  attack_vector="NETWORK", attack_complexity="LOW",
  privileges_required="NONE", user_interaction="NONE",
  scope="UNCHANGED",
  confidentiality="HIGH", integrity="HIGH", availability="HIGH"
)

Step 4 - 搜索利用代码：
search_exploit(query="ActiveMQ 46604")

Step 5 - 查找检测模板：
find_nuclei_template(tags="activemq,cve", severity="critical")

最终评估清单：
┌─────────────────────────────────────────┐
│ CVE-2023-46604 完整评估                  │
├─────────────────────────────────────────┤
│ ✅ 漏洞详情          已获取              │
│ ✅ CWE 分类          已确认 (CWE-502)    │
│ ✅ CVSS 评分         9.8 CRITICAL       │
│ ✅ Exploit 搜索      已完成              │
│ ✅ Nuclei 模板       已定位              │
│ ✅ 修复版本          已确认              │
│ ✅ 参考链接          已收集              │
└─────────────────────────────────────────┘
```

---

### 示例 14：与 Insecure 比较评分

**场景**：将自定义参数与已知 CVE 的评分进行对比验证。

```
用户输入：
"我手里有个未公开漏洞，参数类似于 CVE-2024-XXXXX，但影响范围不同"

比较分析：
已有的 CVE-2024-XXXXX：
  scope="UNCHANGED", C=H, I=H, A=H

1. 无范围变化时的评分：
cvss_calculator(AV=N, AC=L, PR=N, UI=N, S=UNCHANGED, C=H, I=H, A=H)
→ 9.8 CRITICAL

2. 有范围变化时的评分（你的漏洞）：
cvss_calculator(AV=N, AC=L, PR=N, UI=N, S=CHANGED, C=H, I=H, A=H)
→ 评分可能不同

结论：虽然漏洞参数相似，但 SCOPE 的变化会导致评分差异
```

---

### 示例 15：批量漏洞快速筛选（类似"漏斗"）

**场景**：从海量漏洞中快速筛选出高优先级目标。

```
用户输入：
"帮我筛选 Wordpress 插件中最严重的漏洞"

步骤 1 - 宽泛搜索：
search_cve(keyword="WordPress Plugin", max_results=50)

步骤 2 - 从 50 个结果中筛选 CVSS >= 7.0 的漏洞
→ 假设发现 12 个符合条件的漏洞

步骤 3 - 对每个高评分漏洞获取详情：
get_cve_details(cve_id="CVE-1")  # ×12 次

步骤 4 - 筛选有 Exploit 的：
search_exploit(query="CVE-1")  # 对每个漏洞

最终结果：5 个高评分且有可用 EXP 的漏洞 → 优先关注
```

---

## 实战案例（3 个）

### 实战案例 1：渗透测试前信息收集

**场景**：对一个运行 WordPress 5.8 + Apache 2.4.49 的 Web 服务器进行前期信息收集。

**目标**：在正式测试前获取所有已知漏洞信息。

```
工作流：

Step 1 - 搜索 WordPress 5.8 漏洞：
└─ search_cve(keyword="WordPress", version="5.8", max_results=20)

  → 发现多个 XSS、RCE、SSRF 漏洞
  → 最高评分：CVE-xxxx 9.8 CRITICAL

Step 2 - 搜索 Apache 2.4.49 漏洞：
└─ search_cve(keyword="Apache HTTP Server", version="2.4.49", max_results=20)

  → CVE-2021-41773 (路径遍历) 7.5 HIGH
  → CVE-2021-42013 (RCE) 9.8 CRITICAL ← 重点关注！

Step 3 - 获取 Apache 漏洞详情：
└─ get_cve_details(cve_id="CVE-2021-42013")

  → 确认是路径遍历 → RCE 的利用链
  → 受影响版本完全匹配 2.4.49

Step 4 - 确认 CWE 分类：
└─ cwe_mapping(cwe_id="CWE-22")  # 路径遍历

Step 5 - 搜索 Exploit：
└─ search_exploit(query="Apache 2.4.49")

  → 多个可用 PoC

Step 6 - 查找 Nuclei 模板：
└─ find_nuclei_template(tags="apache,cve-2021-42013", severity="critical")

  → 检测模板已存在

总结输出：
📋 目标信息收集完成
  - WordPress 5.8: 3 个高危漏洞（需进一步验证）
  - Apache 2.4.49: CVE-2021-42013 CRITICAL，有 PoC，有 Nuclei 模板
  🎯 优先测试 Apache 路径遍历漏洞
```

---

### 实战案例 2：漏洞验证与评级

**场景**：在内部渗透测试中发现一个疑似 SSRF 漏洞，需要验证并评估严重程度。

**目标**：确认漏洞类型、计算 CVSS 评分、判断是否可被利用。

```
用户上下文：
"在内部测试中发现了一个服务器的 SSRF 漏洞，
攻击者可以通过构造特殊请求让服务器向任意内部地址发起 HTTP 请求"

工作流：

Step 1 - 搜索已知 SSRF CVE：
└─ search_cve(keyword="Server Side Request Forgery", max_results=10)

  → 了解 SSRF 漏洞的历史严重程度
  → 确认 SSRF 通常的 CVSS 范围（6.4 - 9.1）

Step 2 - 查询 CWE 分类：
└─ cwe_mapping(cwe_id="CWE-918")

  → CWE-918: Server-Side Request Forgery (SSRF)
  → 了解完整的漏洞描述和分类

Step 3 - 评估严重程度：
假设参数：
  AV=N (远程网络) | AC=L (低复杂度)
  PR=L (需要登录) | UI=N (无需交互)
  S=C (范围变化，可访问内网) | C=L (仅确认存在)
  I=L (可修改内网内容) | A=N (不可用性不受影响)

└─ cvss_calculator(
    attack_vector="NETWORK", attack_complexity="LOW",
    privileges_required="LOW", user_interaction="NONE",
    scope="CHANGED", confidentiality="LOW",
    integrity="LOW", availability="NONE"
  )

  → 评分：约 6.8 (MEDIUM)

但如果可以读取敏感数据：
└─ cvss_calculator(
    attack_vector="NETWORK", attack_complexity="LOW",
    privileges_required="LOW", user_interaction="NONE",
    scope="CHANGED", confidentiality="HIGH",
    integrity="NONE", availability="NONE"
  )

  → 评分：约 8.0 (HIGH)

📋 漏洞评级结论：
  - 基础 SSRF: MEDIUM (6.8)，可访问内网
  - 可读取云元数据: HIGH (8.0)，需进一步验证
  - 建议尝试利用读取 AWS/GCP 元数据端点
```

---

### 实战案例 3：Outlook 漏洞链分析

**场景**：追踪 Microsoft Outlook 的最新远程代码执行漏洞链（CVE-2024-21413 + CVE-2024-30103），评估影响并准备应对。

**目标**：理解漏洞链、评估组合风险、制定防护策略。

```
工作流：

Step 1 - 搜索 Outlook 相关 CVE：
└─ search_cve(keyword="Microsoft Outlook", max_results=20)

  → CVE-2024-21413: Outlook RCE (9.8 CRITICAL)
  → CVE-2024-30103: Outlook 权限提升 (7.8 HIGH)

Step 2 - 获取各漏洞详情：
└─ get_cve_details(cve_id="CVE-2024-21413")
  → MonikerLink 漏洞，预览即可触发 RCE
  → 影响所有 Outlook 版本

└─ get_cve_details(cve_id="CVE-2024-30103")
  → 与上述漏洞配合可绕过保护机制

Step 3 - 查询 CWE 分类：
└─ cwe_mapping(cwe_id="CWE-77")  # Improper Neutralization
└─ cwe_mapping(cwe_id="CWE-287")  # Authentication Bypass

Step 4 - 搜索 Exploit：
└─ search_exploit(query="Microsoft Outlook 2024")
  → 检查是否有公开可利用代码

Step 5 - 查找 Nuclei 模板：
└─ find_nuclei_template(tags="outlook,cve-2024-21413", severity="critical")
  → 检查是否有检测模板

Step 6 - 评估攻击链组合风险：
┌────────────────────────────────────────────────────────┐
│ Outlook 漏洞链分析报告                                 │
├────────────────────────────────────────────────────────┤
│                                                        │
│ CVE-2024-21413 (9.8 CRITICAL)                          │
│  - MonikerLink 远程代码执行                            │
│  - 预览邮件即可触发                                     │
│                                                        │
│ ↓ 漏洞链                                               │
│                                                        │
│ CVE-2024-30103 (7.8 HIGH - 与上述配合后效果放大)        │
│  - 绕过 Outlook 安全机制                                │
│                                                        │
│ 🚨 组合利用风险评估：                                   │
│  - 首次利用：远程 RCE（需要用户查看邮件）                │
│  - 链路放大：权限提升，持久化                           │
│                                                        │
│ 防护建议：                                              │
│  1. 安装 KB5035854 / KB5035855 更新                     │
│  2. 限制外部邮件自动加载                                │
│  3. 启用 Outlook Protected View                         │
│  4. 邮件来源验证                                        │
└────────────────────────────────────────────────────────┘
```

---

## 示例清单索引

| # | 示例名称 | 使用的工具 | 难度 |
|---|---------|-----------|------|
| 1 | 搜索产品相关 CVE | search_cve | ⭐ |
| 2 | 获取单个 CVE 详情 | get_cve_details | ⭐ |
| 3 | 计算 CVSS 评分 | cvss_calculator | ⭐ |
| 4 | 查询 CWE 分类 | cwe_mapping | ⭐ |
| 5 | 搜索 Exploit-DB | search_exploit | ⭐ |
| 6 | 查找 Nuclei 模板 | find_nuclei_template | ⭐ |
| 7 | 按版本精确搜索 | search_cve | ⭐ |
| 8 | 查询非内置 CWE | cwe_mapping | ⭐ |
| 9 | CVE + CWE + CVSS 联合 | get_cve_details + cwe_mapping + cvss_calculator | ⭐⭐ |
| 10 | CVE + Exploit 联合 | search_cve + search_exploit | ⭐⭐ |
| 11 | 多场景 CVSS 比较 | cvss_calculator（多次调用） | ⭐⭐⭐ |
| 12 | 多产品关联分析 | search_cve（多次） | ⭐⭐⭐ |
| 13 | 完整利用评估清单 | 全部 6 工具 | ⭐⭐⭐⭐ |
| 14 | CVSS 参数对比 | cvss_calculator | ⭐⭐⭐ |
| 15 | 批量漏洞漏斗筛选 | search_cve + get_cve_details + search_exploit | ⭐⭐⭐⭐ |
| 实战 1 | 渗透测试信息收集 | 多工具链 | ⭐⭐⭐⭐⭐ |
| 实战 2 | 漏洞验证与评级 | 多工具链 | ⭐⭐⭐⭐⭐ |
| 实战 3 | Outlook 漏洞链分析 | 多工具链 | ⭐⭐⭐⭐⭐ |
