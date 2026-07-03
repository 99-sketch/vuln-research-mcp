# 🚀 5 分钟零基础上手指南

> **不需要懂编程、不需要装 Python、不需要配环境。**  
> 只要你的电脑能装 Docker, 5 分钟后就能用上企业级漏洞扫描平台。

---

## 🤔 我为什么要用这个工具？

| 你的需求 | 这个工具能做什么 |
|---|---|
| 想知道某个 CVE 漏洞是啥 | 输入 CVE 编号, 秒出详情 + 评分 + 修复建议 |
| 想检查自己的服务器有没有开危险端口 | 一键端口扫描, 自动识别风险 |
| 想了解最新的安全漏洞 | CISA KEV 已知利用漏洞库实时查询 |
| 想生成专业的渗透测试报告 | 一键导出 Markdown/STIX 格式报告 |

---

## 📦 第一步: 安装 Docker (3分钟)

Docker 就像一个"打包好的程序盒子", 你不需要装任何东西，盒子里面什么都有。

### Windows 用户

1. 下载 Docker Desktop: https://www.docker.com/products/docker-desktop/
2. 双击安装 → 一路"下一步" → 重启电脑
3. 桌面出现 Docker 图标 → 安装成功 ✅

### Mac 用户

1. 下载 Docker Desktop (选 Apple Chip 或 Intel Chip):  
   https://www.docker.com/products/docker-desktop/
2. 拖到 Applications → 打开 → 允许权限 → 完成 ✅

### Linux 用户

```bash
curl -fsSL https://get.docker.com | sh
# 把当前用户加入 docker 组
sudo usermod -aG docker $USER
# 重新登录终端
```

---

## 🚀 第二步: 一键启动 (1分钟)

打开终端（Windows: PowerShell | Mac/Linux: Terminal），复制粘贴以下命令:

```bash
# 1. 下载项目
git clone https://github.com/99-sketch/vuln-research-mcp.git
cd vuln-research-mcp

# 2. 一键启动！
docker compose up -d
```

你会看到类似这样的输出:
```
[+] Running 2/2
 ✔ Network vuln-research-mcp_vuln-net  Created
 ✔ Container vuln-research-web         Started
```

> 🎉 **搞定了！服务已经在后台运行了！**

---

## 🌐 第三步: 打开 Web 界面 (1分钟)

在浏览器地址栏输入: **http://localhost:8080**

你会看到一个漂亮的蓝色侧边栏界面:

```
🛡️ VulnResearch v5.2
├── 📊 仪表盘      ← 看看有多少工具和指纹数据
├── 🔍 CVE 查询    ← 搜漏洞的！点这里
├── 🎯 资产扫描    ← 扫描服务器端口
├── 📝 报告中心    ← 生成报告
├── 🧰 工具箱      ← 所有工具一览
└── ⚙️ 设置        ← 查看配置
```

> 💡 **推荐: 把 http://localhost:8080 加到浏览器收藏夹，下次直接点开就行。**

---

## 🧪 试试看: 查询你的第一个 CVE

1. 点击左侧 **🔍 CVE 查询**
2. 在搜索框输入: `CVE-2021-44228` (这是著名的 Log4j 漏洞)
3. 点 **查询** 按钮
4. 你会看到:
   - 漏洞描述
   - CVSS 评分 (10.0 就是最高危!)
   - 参考链接

再试试其他的:
- `CVE-2022-22965` — Spring4Shell
- `CVE-2023-44487` — HTTP/2 Rapid Reset
- `CVE-2024-3094` — xz Utils 后门

---

## 🎯 试试看: 扫描你的第一台主机

1. 点击左侧 **🎯 资产扫描**
2. 目标地址输入: `scanme.nmap.org` (nmap 官方提供的测试靶机)
3. 端口保持默认: `22,80,443,3306,6379,8080,8443`
4. 点 **🚀 开始扫描**
5. 几秒后就能看到开放端口列表！

> ⚠️ **安全提示**: 内网地址 (192.168.x.x, 10.x.x.x) 会被自动拦截。这是 7 层安全防护的一部分。

---

## 🖥️ 替代方案: 命令行交互式向导

如果不方便用浏览器，也可以用命令行菜单操作:

```bash
# 进入 Docker 容器
docker exec -it vuln-research-web python3 -m src.cli_wizard
```

你会看到一个菜单:
```
🛡️  Vuln-Research-MCP v5.2 — 交互式向导
企业级安全平台 · 零命令行操作

请选择要执行的操作:

  1. 🔍 CVE 漏洞查询
  2. 🎯 端口扫描
  3. 📊 综合漏洞评估
  ...
  9. 🌐 打开 Web 界面
  0. ❌ 退出
```

按数字选择 → 按提示输入 → 自动完成 — 就这么简单！

---

## ⚙️ 进阶: 配置 API Key (可选)

**不配也能用基本功能。** 配了之后可以实时查询 NVD 数据库，获取最新漏洞信息。

1. 免费注册 NVD API Key: https://nvd.nist.gov/developers/request-an-api-key
2. 停止服务: `docker compose down`
3. 重新启动并传入 Key:

**Windows PowerShell:**
```powershell
$env:NVD_API_KEY="你的API Key"; docker compose up -d
```

**Mac/Linux:**
```bash
NVD_API_KEY="你的API Key" docker compose up -d
```

4. 刷新 http://localhost:8080 — CVE 查询就能实时获取数据了！

---

## 🛑 停止服务

不想用了？一句话停掉:

```bash
docker compose down
```

下次想用了？再一句:

```bash
docker compose up -d
```

---

## ❓ 常见问题

### Q: Docker 是什么，安全吗？
Docker 是业界标准的容器技术，所有程序运行在隔离的环境中，不会影响你的系统。就像手机上的 App 沙盒。

### Q: 不装 Docker 能用吗？
可以，但需要装 Python + nmap + 一堆工具。**强烈建议用 Docker，一条命令就全搞定。**

### Q: 会占用很多资源吗？
Docker 镜像约 500MB，运行时约 200MB 内存。相当于开了 10 个浏览器标签页。

### Q: Web 界面打不开？
- 确认 Docker 正在运行 (任务栏有 Docker 图标)
- 确认容器在运行: `docker ps | grep vuln-research`
- 确认端口没被占用: `docker compose down && docker compose up -d`

### Q: CVE 查不出来结果？
- 检查网络连接
- 设置 NVD_API_KEY (见"进阶配置")
- NVD API 是国外的，可能需要科学上网

### Q: 怎么扫描我自己的服务器？
在"资产扫描"页面输入你的服务器 IP 或域名即可。如果是云服务器，记得在安全组里允许扫描。

---

## 🎓 术语表

| 术语 | 大白话解释 |
|---|---|
| **CVE** | 漏洞身份证号, 每个公开漏洞都有一个 CVE 编号 |
| **CVSS** | 漏洞危险度评分, 0 分不危险, 10 分最危险 |
| **NVD** | 美国的漏洞数据库, 记录所有 CVE 详情 |
| **CNVD** | 中国的漏洞数据库, 收录国内特有的漏洞 |
| **KEV** | CISA 统计的"已经被黑客利用的漏洞"列表 |
| **EPSS** | 预测这个漏洞会被利用的概率 |
| **端口** | 网络服务的门牌号, 80=Web, 443=加密Web, 22=远程登录 |
| **Banner** | 服务自报家门的信息, 如 "Apache/2.4.57" |

---

## 📞 还有问题？

- **GitHub Issues**: https://github.com/99-sketch/vuln-research-mcp/issues
- **社区文档**: [docs/COMMUNITY.md](docs/COMMUNITY.md)
- **完整文档**: [README.md](README.md)
