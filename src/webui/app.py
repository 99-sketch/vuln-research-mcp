"""
Vuln-Research-MCP Web Dashboard v5.2
零命令行操作 — 全部在浏览器里完成
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------- 确保项目根目录在 sys.path ----------
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# ---------- 项目模块 (可选, 用 try 包裹跳过无依赖场景) ----------
try:
    from src.tools.cve_tools import search_cve, get_cve_details
    from src.tools.scan_tools import scan_ports
    from src.tools.network_tools import check_http_headers, geolocate_ip
    from src.tools.cvss_tool import cvss_calculator
    from src.tools.exploit_tool import search_exploit
    from src.correlator.fingerprint_loader import FingerprintLoader, get_fingerprint_loader
    from src.security.intranet_guard import IntranetGuardPolicy, get_intranet_guard
    HAS_MODULES = True
except Exception:
    HAS_MODULES = False

# ---------- App ----------
app = FastAPI(
    title="Vuln-Research-MCP Web Dashboard",
    description="企业级安全平台 — Web 操作面板",
    version="5.2.0",
)

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# =============================================================================
# 辅助函数
# =============================================================================

def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _template_context(request: Request, page: str, **extra) -> dict:
    return {"request": request, "page": page, "now": _now_str(), **extra}


# =============================================================================
# 路由
# =============================================================================

@app.get("/health")
async def health():
    return {"status": "ok", "version": "5.2.0", "modules": HAS_MODULES}


# ── 仪表盘 ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = {"total_tools": 55, "fingerprints": 0, "cve_cache": 0}
    if HAS_MODULES:
        try:
            fl = get_fingerprint_loader()
            if not fl.total_banner_patterns:
                fl.load_all()
            stats["fingerprints"] = fl.total_banner_patterns
        except Exception:
            pass
    return templates.TemplateResponse("dashboard.html", _template_context(request, "dashboard", stats=stats))


# ── CVE 查询 ────────────────────────────────────────────────────────

@app.get("/cve", response_class=HTMLResponse)
async def cve_page(request: Request):
    return templates.TemplateResponse("cve.html", _template_context(request, "cve"))


@app.post("/api/cve/search")
async def cve_search_api(cve_id: str = Form(...)):
    """搜索 CVE 漏洞详情"""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return JSONResponse({"error": "请输入有效的 CVE 编号, 如: CVE-2021-44228"})

    if HAS_MODULES:
        try:
            detail = await get_cve_details(cve_id)
            return JSONResponse({"ok": True, "data": detail})
        except Exception as e:
            # 回退到模拟数据 (无网络时)
            pass

    # 离线/无网络时的提示
    return JSONResponse({
        "ok": True,
        "data": {
            "cve_id": cve_id,
            "description": f"[离线模式] CVE 数据库未连接。请设置 NVD_API_KEY 环境变量以启用实时查询。",
            "cvss_score": None,
            "severity": "UNKNOWN",
            "published": "",
            "references": [],
            "offline": True,
        }
    })


# ── 资产扫描 ────────────────────────────────────────────────────────

@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    return templates.TemplateResponse("scan.html", _template_context(request, "scan"))


@app.post("/api/scan/ports")
async def scan_ports_api(target: str = Form(...), ports: str = Form("22,80,443,3306,6379,8080,8443")):
    """端口扫描"""
    target = target.strip()

    # 内网检测
    if HAS_MODULES:
        try:
            guard = get_intranet_guard()
            allowed, reason, cat = guard.check_target(target)
            if not allowed:
                return JSONResponse({"error": f"内网目标已拦截: {reason} — 如需扫描内网, 请在设置中关闭内网保护"})
        except Exception:
            pass

    if HAS_MODULES:
        try:
            results = await scan_ports(target=target, ports=ports)
            return JSONResponse({"ok": True, "target": target, "ports": ports, "results": results})
        except Exception as e:
            return JSONResponse({"ok": True, "target": target, "note": f"扫描已发起 (离线模式) — {str(e)[:200]}"})

    return JSONResponse({
        "ok": True,
        "target": target,
        "ports": ports,
        "note": "端口扫描需要 nmap 工具。Docker 镜像已预装, 本地使用请先安装 nmap。"
    })


# ── 报告中心 ────────────────────────────────────────────────────────

@app.get("/report", response_class=HTMLResponse)
async def report_page(request: Request):
    return templates.TemplateResponse("report.html", _template_context(request, "report"))


# ── 工具箱 ──────────────────────────────────────────────────────────

@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    tools_list = [
        {"name": "CVE 搜索", "desc": "查询 CVE 漏洞详情、CVSS 评分、影响版本", "icon": "🔍", "link": "/cve"},
        {"name": "端口扫描", "desc": "TCP 端口开放检测、服务识别、Banner 抓取", "icon": "🎯", "link": "/scan"},
        {"name": "CVSS 计算器", "desc": "CVSS 3.1/4.0 漏洞评分在线计算", "icon": "📐", "link": "/tools"},
        {"name": "Exploit 搜索", "desc": "在 Exploit-DB 中搜索漏洞利用代码", "icon": "💣", "link": "/tools"},
        {"name": "DNS 查询", "desc": "域名解析、MX 记录、子域名枚举", "icon": "🌐", "link": "/tools"},
        {"name": "IP 定位", "desc": "IP 归属地查询、ASN 信息", "icon": "📍", "link": "/tools"},
        {"name": "CPE 匹配", "desc": "Banner → CPE → 已知漏洞自动关联", "icon": "🔗", "link": "/tools"},
        {"name": "指纹识别", "desc": "898 产品指纹库, 识别中间件/框架/数据库", "icon": "🖐️", "link": "/tools"},
        {"name": "Nuclei 模板", "desc": "YAML POC 模板搜索与生成", "icon": "🧬", "link": "/tools"},
        {"name": "威胁情报", "desc": "CISA KEV、EPSS 利用概率评分", "icon": "📡", "link": "/tools"},
        {"name": "CNVD 查询", "desc": "国家信息安全漏洞库 (CNVD/CNNVD)", "icon": "🇨🇳", "link": "/tools"},
        {"name": "报告生成", "desc": "一键生成渗透测试报告 (Markdown/PDF)", "icon": "📝", "link": "/report"},
    ]
    return templates.TemplateResponse("tools.html", _template_context(request, "tools", tools=tools_list))


# ── 设置 ────────────────────────────────────────────────────────────

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    env_vars = {
        "NVD_API_KEY": bool(os.environ.get("NVD_API_KEY")),
        "DINGTALK_WEBHOOK": bool(os.environ.get("DINGTALK_WEBHOOK")),
        "SMTP_HOST": bool(os.environ.get("SMTP_HOST")),
        "INTRANET_BLOCK": os.environ.get("INTRANET_BLOCK", "true"),
    }
    return templates.TemplateResponse("settings.html", _template_context(request, "settings", env=env_vars))


# =============================================================================
# 启动
# =============================================================================

def main():
    import uvicorn
    print("\n" + "="*52)
    print("  Vuln-Research-MCP Web Dashboard v5.2")
    print("  打开浏览器访问: http://localhost:7879")
    print("="*52 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=7879, log_level="info")


if __name__ == "__main__":
    main()
