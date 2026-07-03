"""
Vuln-Research-MCP v5.2 — 交互式向导模式
零命令行参数 — 全部通过菜单选择完成

使用: python -m src.cli_wizard
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.layout import Layout
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    # Fallback to plain text
    class FakeConsole:
        def print(self, *a, **kw): print(*a)
        def rule(self, *a, **kw): print("-"*60)
    Console = FakeConsole


console = Console()


# =============================================================================
# 菜单定义
# =============================================================================

MAIN_MENU = """
[bold cyan]🛡️  Vuln-Research-MCP v5.2 — 交互式向导[/bold cyan]
[dim]企业级安全平台 · 零命令行操作[/dim]

请选择要执行的操作:

  [bold green]1.[/bold green] 🔍 CVE 漏洞查询      — 输入 CVE 编号查看详情
  [bold green]2.[/bold green] 🎯 端口扫描          — 扫描目标主机的开放端口
  [bold green]3.[/bold green] 📊 综合漏洞评估      — 评估特定 CVE 的风险等级
  [bold green]4.[/bold green] 📡 威胁情报查询      — 查看 CISA KEV / EPSS 评分
  [bold green]5.[/bold green] 🇨🇳 CNVD 查询        — 查询国家漏洞库信息
  [bold green]6.[/bold green] 📝 生成扫描报告      — 导出 Markdown 格式报告
  [bold green]7.[/bold green] 🔧 系统工具检查      — 检测环境中的安全工具可用性
  [bold green]8.[/bold green] ⚙️  设置             — 查看/修改配置
  [bold green]9.[/bold green] 🌐 打开 Web 界面     — 在浏览器中启动可视化面板
  [bold red]0.[/bold red] ❌ 退出
"""


# =============================================================================
# 功能实现
# =============================================================================

async def cve_lookup():
    """CVE 漏洞查询"""
    console.rule("[bold]🔍 CVE 漏洞查询[/bold]")
    cve_id = Prompt.ask("\n请输入 CVE 编号", default="CVE-2021-44228")
    cve_id = cve_id.strip().upper()

    if not cve_id.startswith("CVE-"):
        console.print("[red]❌ 无效的 CVE 格式，请使用 CVE-YYYY-NNNNN 格式[/red]")
        return

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"查询 {cve_id}...", total=None)
        try:
            from src.tools.cve_tools import get_cve_details
            result = await get_cve_details(cve_id)
        except Exception as e:
            result = {"error": str(e)}

    console.print()

    if isinstance(result, dict) and "error" in result:
        console.print(f"[yellow]⚠️ 查询受限: {result['error']}[/yellow]")
        console.print("[dim]提示: 设置 NVD_API_KEY 环境变量以启用完整查询[/dim]")
        return

    # 展示结果
    desc = str(result.get("description", "") or result.get("summary", "") or "暂无描述")[:500]
    cvss = result.get("cvss_score")
    sev = str(result.get("severity", "UNKNOWN")).upper()
    sev_color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")

    table = Table(title=f"CVE 详情: {cve_id}", title_style="bold cyan")
    table.add_column("字段", style="bold", width=14)
    table.add_column("内容")

    table.add_row("CVE 编号", cve_id)
    table.add_row("严重等级", f"[{sev_color}]● {sev}[/{sev_color}]")
    if cvss:
        table.add_row("CVSS 评分", str(cvss))
    if result.get("published"):
        table.add_row("发布日期", str(result.get("published")))
    if result.get("cwe_id"):
        table.add_row("CWE", str(result.get("cwe_id")))
    table.add_row("描述", desc)

    console.print(table)

    refs = result.get("references", [])
    if refs:
        console.print("\n[bold]📎 参考链接:[/bold]")
        for r in refs[:5]:
            console.print(f"  • {r}")


async def port_scan():
    """端口扫描"""
    console.rule("[bold]🎯 端口扫描[/bold]")

    target = Prompt.ask("目标地址 (IP 或域名)", default="scanme.nmap.org")
    ports = Prompt.ask("端口范围 (逗号分隔)", default="22,80,443,3306,8080,8443")

    # 内网检测
    target_ip = target.strip()
    try:
        from src.security.intranet_guard import get_intranet_guard
        guard = get_intranet_guard()
        allowed, reason, cat = guard.check_target(target_ip)
        if not allowed:
            console.print(f"\n[red]🛡️ 内网保护已拦截: {reason}[/red]")
            console.print("[dim]如需扫描内网，请在设置中关闭内网保护[/dim]")
            return
    except Exception:
        pass

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"扫描 {target}...", total=None)
        try:
            from src.tools.scan_tools import scan_ports
            results = await scan_ports(target=target, ports=ports)
        except Exception as e:
            results = {"error": str(e)}

    console.print()

    if isinstance(results, dict) and "error" in results:
        console.print(f"[yellow]⚠️ 扫描受限: {results['error']}[/yellow]")
        console.print("[dim]提示: 使用 Docker 部署已预装 nmap[/dim]")
        return

    if isinstance(results, dict) and results.get("open_ports"):
        table = Table(title=f"扫描结果: {target}")
        table.add_column("端口", style="cyan")
        table.add_column("状态", style="green")
        table.add_column("服务")
        table.add_column("版本")

        for p in results["open_ports"]:
            table.add_row(
                str(p.get("port", "")),
                str(p.get("state", "open")),
                str(p.get("service", "-")),
                str(p.get("version", "-")),
            )
        console.print(table)
    else:
        console.print(f"[yellow]未发现开放端口，或结果: {results}[/yellow]")


async def vuln_assessment():
    """综合漏洞评估"""
    console.rule("[bold]📊 综合漏洞评估[/bold]")
    cve_id = Prompt.ask("CVE 编号", default="CVE-2021-44228").strip().upper()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"评估 {cve_id}...", total=None)
        try:
            from src.tools.threat_intel_tool import vulnerability_assess
            result = await vulnerability_assess(cve_id=cve_id)
        except Exception as e:
            result = {"error": str(e)}

    console.print()
    if isinstance(result, dict):
        for k, v in result.items():
            if k == "error":
                console.print(f"[red]❌ {v}[/red]")
            else:
                console.print(f"[bold]{k}:[/bold] {v}")
    else:
        console.print(str(result)[:1000])


async def threat_intel():
    """威胁情报查询"""
    console.rule("[bold]📡 威胁情报查询[/bold]")
    query = Prompt.ask("输入 CVE 编号或关键词", default="CVE-2021-44228").strip().upper()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("查询威胁情报...", total=None)
        try:
            if query.startswith("CVE-"):
                from src.tools.threat_intel_tool import check_kev, get_epss_score
                kev = await check_kev(cve_id=query)
                epss = await get_epss_score(cve_id=query)
            else:
                from src.tools.threat_intel_tool import search_kev
                kev = await search_kev(query=query)
                epss = {"note": "EPSS 需要 CVE 编号"}
        except Exception as e:
            kev = {"error": str(e)}
            epss = {"error": str(e)}

    console.print()
    console.print("[bold]CISA KEV:[/bold]")
    console.print(kev)
    console.print("\n[bold]EPSS 评分:[/bold]")
    console.print(epss)


async def cnvd_query():
    """CNVD 查询"""
    console.rule("[bold]🇨🇳 CNVD 国家漏洞库查询[/bold]")
    keyword = Prompt.ask("搜索关键词", default="Apache")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"搜索 CNVD: {keyword}...", total=None)
        try:
            from src.intel.cnvd import get_cnvd_client
            client = get_cnvd_client()
            results = client.search(keyword=keyword, max_results=10)
        except Exception as e:
            results = [{"error": str(e)}]

    console.print()
    if results and not isinstance(results[0], dict):
        for r in results[:5]:
            console.print(f"  • {r}")
    else:
        console.print("[yellow]⚠️ CNVD 需要网络连接[/yellow]")


async def generate_report():
    """生成报告 (占位)"""
    console.rule("[bold]📝 生成报告[/bold]")
    console.print("[dim]报告生成功能通过 REST API 提供:[/dim]")
    console.print("  GET  /api/projects/{id}/report?format=markdown")
    console.print("  GET  /api/projects/{id}/report?format=json")
    console.print("\n[dim]打开 Web 界面可使用可视化报告功能[/dim]")


def tool_check():
    """系统工具检查"""
    console.rule("[bold]🔧 系统工具检查[/bold]")

    tools = {
        "nmap": "nmap --version",
        "git": "git --version",
        "nuclei": "nuclei -version",
        "python3": "python3 --version",
    }

    import subprocess
    table = Table(title="工具可用性")
    table.add_column("工具", style="bold")
    table.add_column("状态")
    table.add_column("版本")

    for name, cmd in tools.items():
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
            ver = result.stdout.split("\n")[0][:50]
            table.add_row(name, "[green]✅ 可用[/green]", ver)
        except Exception:
            table.add_row(name, "[red]❌ 未安装[/red]", "-")

    console.print(table)

    console.print("\n[dim]提示: Docker 部署已预装全部工具。本地使用请运行 scripts/ 下的安装脚本。[/dim]")


def show_settings():
    """显示设置"""
    console.rule("[bold]⚙️ 当前设置[/bold]")

    settings = {
        "NVD_API_KEY": "✅ 已设置" if os.environ.get("NVD_API_KEY") else "⚠️ 未设置",
        "日志级别": os.environ.get("LOG_LEVEL", "INFO"),
        "缓存": os.environ.get("CACHE_ENABLED", "true"),
        "内网保护": os.environ.get("INTRANET_BLOCK", "true"),
        "钉钉告警": "✅" if os.environ.get("DINGTALK_WEBHOOK") else "❌",
        "邮件告警": "✅" if os.environ.get("SMTP_HOST") else "❌",
    }

    table = Table()
    table.add_column("配置项", style="bold")
    table.add_column("值")
    for k, v in settings.items():
        table.add_row(k, str(v))
    console.print(table)


def open_web_ui():
    """提示打开 Web 界面"""
    console.print("\n[bold green]🌐 Web 界面[/bold green]")
    console.print("  在浏览器中打开: [bold cyan]http://localhost:8080[/bold cyan]")
    console.print("  (需先启动服务: [dim]docker compose up -d[/dim])")

    import webbrowser
    try:
        webbrowser.open("http://localhost:8080")
        console.print("  [dim]已尝试在浏览器中打开...[/dim]")
    except Exception:
        pass


# =============================================================================
# 主循环
# =============================================================================

async def main():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]Vuln-Research-MCP[/bold cyan] [dim]v5.2[/dim]\n[dim]企业级安全平台 — 小白友好 · 零命令行操作[/dim]",
        border_style="cyan",
    ))

    while True:
        console.print(MAIN_MENU)
        choice = Prompt.ask("请选择", choices=[str(i) for i in range(10)], default="1")

        if choice == "0":
            console.print("\n[dim]再见！下次直接运行 [bold]python -m src.cli_wizard[/bold] 即可~[/dim]\n")
            break
        elif choice == "1":
            await cve_lookup()
        elif choice == "2":
            await port_scan()
        elif choice == "3":
            await vuln_assessment()
        elif choice == "4":
            await threat_intel()
        elif choice == "5":
            await cnvd_query()
        elif choice == "6":
            await generate_report()
        elif choice == "7":
            tool_check()
        elif choice == "8":
            show_settings()
        elif choice == "9":
            open_web_ui()

        if choice != "0":
            console.print("\n" + "─" * 60)
            Prompt.ask("[dim]按回车继续[/dim]", default="")


if __name__ == "__main__":
    asyncio.run(main())
