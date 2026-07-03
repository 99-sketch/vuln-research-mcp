#!/usr/bin/env python3
"""
Vulnerability Research MCP Server v0.2.0
模块化架构：server.py = 路由层，tools/ = 实现层，validators/ = 安全校验层
"""

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools.cve_tools import search_cve, get_cve_details
from .tools.cvss_tool import cvss_calculator
from .tools.cwe_tool import cwe_mapping
from .tools.exploit_tool import search_exploit
from .tools.nuclei_tool import find_nuclei_template
from .tools.scan_tools import scan_ports, enumerate_subdomains
from .tools.network_tools import check_http_headers, query_dns, geolocate_ip

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("vuln-research-mcp")

server = Server("vuln-research-mcp")

# ---------- 工具注册 ----------

TOOL_DEFINITIONS = [
    Tool(
        name="search_cve",
        description="搜索 CVE 漏洞（按产品名称、版本或关键词）",
        inputSchema={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "搜索关键词（如：Apache Log4j、WordPress Plugin）"},
                "product": {"type": "string", "description": "产品名称（可选）"},
                "version": {"type": "string", "description": "产品版本（可选）"},
                "max_results": {"type": "number", "description": "最大返回结果数（默认 10）", "default": 10},
            },
            "required": ["keyword"],
        },
    ),
    Tool(
        name="get_cve_details",
        description="获取指定 CVE-ID 的详细信息",
        inputSchema={
            "type": "object",
            "properties": {"cve_id": {"type": "string", "description": "CVE ID（如：CVE-2021-44228）"}},
            "required": ["cve_id"],
        },
    ),
    Tool(
        name="search_exploit",
        description="在 Exploit-DB 中搜索 PoC/EXP（在线 API 优先，本地 searchsploit 降级）",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "搜索关键词（如：WordPress、RCE、SQLi）"},
                "type_filter": {"type": "string", "description": "利用类型过滤（可选：remote、webapps、local、dos）"},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="cvss_calculator",
        description="计算 CVSS v3.1 评分（支持完整 vector 字符串或分解参数）",
        inputSchema={
            "type": "object",
            "properties": {
                "vector": {"type": "string", "description": "完整 CVSS v3.1 vector 字符串"},
                "attack_vector": {"type": "string", "enum": ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]},
                "attack_complexity": {"type": "string", "enum": ["LOW", "HIGH"]},
                "privileges_required": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
                "user_interaction": {"type": "string", "enum": ["NONE", "REQUIRED"]},
                "scope": {"type": "string", "enum": ["UNCHANGED", "CHANGED"]},
                "confidentiality": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
                "integrity": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
                "availability": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
            },
            "required": [],
        },
    ),
    Tool(
        name="cwe_mapping",
        description="查询 CWE（Common Weakness Enumeration）信息",
        inputSchema={
            "type": "object",
            "properties": {"cwe_id": {"type": "string", "description": "CWE ID（如：CWE-79、CWE-89）"}},
            "required": ["cwe_id"],
        },
    ),
    Tool(
        name="find_nuclei_template",
        description="在 Nuclei Templates 仓库中搜索相关模板（在线 GitHub API 优先，本地降级）",
        inputSchema={
            "type": "object",
            "properties": {
                "tags": {"type": "string", "description": "标签关键词（如：cve, rce, wordpress, sql）"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "description": "严重等级过滤（可选）"},
            },
            "required": ["tags"],
        },
    ),
    Tool(
        name="scan_ports",
        description="端口扫描（集成 nmap）",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 IP 或域名"},
                "ports": {"type": "string", "description": "端口范围（如：80,443 或 1-1000，默认：常见端口）"},
                "scan_type": {"type": "string", "enum": ["quick", "full", "stealth", "version"], "description": "扫描类型"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="enumerate_subdomains",
        description="子域名枚举（集成 sublist3r 或 amass）",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标域名（如：example.com）"},
                "tool": {"type": "string", "enum": ["sublist3r", "amass"], "description": "枚举工具选择（默认：sublist3r）"},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="check_http_headers",
        description="HTTP 安全头检查",
        inputSchema={
            "type": "object",
            "properties": {"url": {"type": "string", "description": "目标 URL（如：https://example.com）"}},
            "required": ["url"],
        },
    ),
    Tool(
        name="query_dns",
        description="DNS 记录查询",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "域名（如：example.com）"},
                "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "ALL"], "description": "DNS 记录类型（默认：A）"},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="geolocate_ip",
        description="IP 地理位置查询",
        inputSchema={
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IP 地址（如：8.8.8.8）"}},
            "required": ["ip"],
        },
    ),
]

# 工具名 → 处理函数映射
TOOL_HANDLERS = {
    "search_cve": search_cve,
    "get_cve_details": get_cve_details,
    "search_exploit": search_exploit,
    "cvss_calculator": cvss_calculator,
    "cwe_mapping": cwe_mapping,
    "find_nuclei_template": find_nuclei_template,
    "scan_ports": scan_ports,
    "enumerate_subdomains": enumerate_subdomains,
    "check_http_headers": check_http_headers,
    "query_dns": query_dns,
    "geolocate_ip": geolocate_ip,
}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOL_DEFINITIONS


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    logger.info(f"工具调用: {name}, 参数: {arguments}")

    handler = TOOL_HANDLERS.get(name)
    if not handler:
        raise ValueError(f"未知工具: {name}")

    try:
        result = await handler(**arguments)
        logger.info(f"工具 {name} 执行成功")
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except ValueError as e:
        logger.warning(f"工具 {name} 输入验证失败: {e}")
        return [TextContent(type="text", text=json.dumps({"error": f"输入验证失败: {str(e)}"}, ensure_ascii=False))]
    except Exception as e:
        logger.error(f"工具 {name} 执行失败: {e}")
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, ensure_ascii=False))]


# ---------- 主函数 ----------

async def main():
    logger.info("Vulnerability Research MCP Server v0.2.0 启动中...")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
