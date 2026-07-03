# src/core/health_check.py
"""启动健康检查 — MCP 启动时自检外部依赖，不可用只 warn 不 crash"""

import asyncio
import logging
import os
import shutil

import httpx

logger = logging.getLogger("vuln-research-mcp")

# 需要检查的 API 端点
API_CHECKS = {
    "nvd_api": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
        "timeout": 10.0,
        "description": "NVD CVE 数据库",
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "timeout": 10.0,
        "description": "CISA KEV 已知利用漏洞目录",
    },
    "epss_api": {
        "url": "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
        "timeout": 10.0,
        "description": "EPSS 漏洞利用预测评分",
    },
    "ip_api": {
        "url": "http://ip-api.com/json/8.8.8.8",
        "timeout": 10.0,
        "description": "IP 地理定位",
    },
}

# 需要检查的本地工具
TOOL_CHECKS = {
    "nmap": {"description": "端口扫描"},
    "searchsploit": {"description": "Exploit-DB 本地搜索"},
    "sublist3r": {"description": "子域名枚举"},
    "amass": {"description": "子域名枚举（备选）"},
    "nuclei": {"description": "漏洞扫描"},
    "git": {"description": "PoC 档案库克隆/更新"},
}


async def _check_api(client: httpx.AsyncClient, name: str, config: dict) -> tuple[str, bool]:
    """检查单个 API 是否可达"""
    try:
        resp = await client.get(config["url"], timeout=config["timeout"])
        ok = resp.status_code < 500
        return name, ok
    except Exception:
        return name, False


def _check_tool(name: str, config: dict) -> tuple[str, bool]:
    """检查单个本地工具是否安装"""
    path = shutil.which(name)
    return name, path is not None


async def _check_nuclei_templates() -> tuple[str, bool]:
    """检查 nuclei 模板目录"""
    possible_paths = [
        os.path.expanduser("~/.local/share/nuclei-templates"),
        os.path.join(os.environ.get("USERPROFILE", ""), "nuclei-templates"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "nuclei-templates"),
        "C:\\Tools\\nuclei-templates",
    ]
    for p in possible_paths:
        if os.path.isdir(p):
            return "nuclei_templates", True
    return "nuclei_templates", False


async def startup_health_check() -> dict:
    """
    启动时运行健康检查，返回所有检查结果
    
    不阻塞启动 — 外部工具不可用只 warn 不 crash
    """
    results = {
        "apis": {},
        "tools": {},
        "nuclei_templates": False,
        "summary": {},
    }

    # 并行检查所有 API
    async with httpx.AsyncClient() as client:
        api_tasks = [
            _check_api(client, name, config)
            for name, config in API_CHECKS.items()
        ]
        api_results = await asyncio.gather(*api_tasks, return_exceptions=True)
        for r in api_results:
            if isinstance(r, tuple):
                results["apis"][r[0]] = r[1]

    # 检查本地工具
    for name, config in TOOL_CHECKS.items():
        tool_name, ok = _check_tool(name, config)
        results["tools"][tool_name] = ok

    # 检查 nuclei 模板
    _, nuclei_ok = await _check_nuclei_templates()
    results["nuclei_templates"] = nuclei_ok

    # 汇总
    api_ok = sum(1 for v in results["apis"].values() if v)
    tool_ok = sum(1 for v in results["tools"].values() if v)
    results["summary"] = {
        "apis_available": f"{api_ok}/{len(results['apis'])}",
        "tools_available": f"{tool_ok}/{len(results['tools'])}",
        "nuclei_templates": nuclei_ok,
    }

    # 日志输出
    for name, ok in results["apis"].items():
        status = "OK" if ok else "UNAVAILABLE"
        desc = API_CHECKS.get(name, {}).get("description", name)
        if ok:
            logger.info(f"健康检查: {name} ({desc}) — {status}")
        else:
            logger.warning(f"健康检查: {name} ({desc}) — {status}，对应工具将降级运行")

    for name, ok in results["tools"].items():
        desc = TOOL_CHECKS.get(name, {}).get("description", name)
        if ok:
            logger.info(f"健康检查: {name} ({desc}) — OK")
        else:
            logger.warning(f"健康检查: {name} ({desc}) — NOT FOUND，对应工具将降级运行")

    if not nuclei_ok:
        logger.warning("健康检查: nuclei-templates 未找到，find_nuclei_template 将仅使用在线 API")

    return results


def get_degraded_tools(health: dict) -> list[str]:
    """根据健康检查结果，返回哪些工具将降级运行"""
    degraded = []
    if not health.get("apis", {}).get("nvd_api"):
        degraded.extend(["search_cve", "get_cve_details"])
    if not health.get("apis", {}).get("cisa_kev"):
        degraded.append("check_kev")
    if not health.get("apis", {}).get("epss_api"):
        degraded.append("get_epss_score")
    if not health.get("apis", {}).get("ip_api"):
        degraded.append("geolocate_ip")
    if not health.get("tools", {}).get("nmap"):
        degraded.append("scan_ports")
    if not health.get("tools", {}).get("searchsploit"):
        degraded.append("search_exploit (local fallback)")
    if not health.get("tools", {}).get("sublist3r") and not health.get("tools", {}).get("amass"):
        degraded.append("enumerate_subdomains")
    if not health.get("tools", {}).get("git"):
        degraded.extend(["clone_poc_archive", "update_poc_archive"])
    return degraded
