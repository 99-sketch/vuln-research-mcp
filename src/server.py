#!/usr/bin/env python3
"""
Vulnerability Research MCP Server v2.0.0
安全情报工作站 — 异步架构 + 熔断器 + 缓存 + CISA KEV + EPSS + 综合风险评估 + 跨源搜索

架构:
  core/         基础设施 (async_subprocess, circuit_breaker, cache, health_check, config, registry, logger)
  tools/        工具实现 (15+4=19 个工具)
  validators/   输入校验
  rate_limiter  速率控制
"""

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Core
from .core.config_manager import load_config, AppConfig
from .core.structured_logger import setup_logging
from .core.cache_manager import init_cache, get_cache
from .core.circuit_breaker import get_breaker, all_breaker_status
from .core.health_check import startup_health_check, get_degraded_tools
from .core.tool_registry import get_registry, ToolDefinition, register_all_tools

# Tools
from .tools.cve_tools import search_cve, get_cve_details
from .tools.cvss_tool import cvss_calculator
from .tools.cwe_tool import cwe_mapping
from .tools.exploit_tool import search_exploit
from .tools.nuclei_tool import find_nuclei_template
from .tools.scan_tools import scan_ports, enumerate_subdomains
from .tools.network_tools import check_http_headers, query_dns, geolocate_ip
from .tools.poc_archive_tool import search_poc_archive, list_poc_archive, clone_archive, update_archive
from .tools.threat_intel_tool import check_kev, get_epss_score, vulnerability_assess, search_kev
from .tools.cross_search_tool import cross_source_search

# ---------- 初始化 ----------

_config: AppConfig = None
_health: dict = None


def _register_all_tools():
    """注册所有工具到 ToolRegistry"""
    registry = get_registry()

    # 原有工具 (15)
    registry.register(ToolDefinition(
        name="search_cve", description="搜索 CVE 漏洞（按产品名称、版本或关键词）",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "搜索关键词"},
            "product": {"type": "string", "description": "产品名称（可选）"},
            "version": {"type": "string", "description": "产品版本（可选）"},
            "max_results": {"type": "number", "description": "最大返回结果数（默认 10）", "default": 10},
        }, "required": ["keyword"]},
        handler=search_cve, requires_apis=["nvd"],
    ))
    registry.register(ToolDefinition(
        name="get_cve_details", description="获取指定 CVE-ID 的详细信息",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=get_cve_details, requires_apis=["nvd"],
    ))
    registry.register(ToolDefinition(
        name="search_exploit", description="在 Exploit-DB 中搜索 PoC/EXP（在线 API 优先，本地 searchsploit 降级）",
        input_schema={"type": "object", "properties": {
            "query": {"type": "string", "description": "搜索关键词"},
            "type_filter": {"type": "string", "description": "利用类型过滤（可选：remote、webapps、local、dos）"},
        }, "required": ["query"]},
        handler=search_exploit, requires_apis=["exploit_db"], requires_tools=["searchsploit"],
    ))
    registry.register(ToolDefinition(
        name="cvss_calculator", description="计算 CVSS v3.1 评分（支持完整 vector 字符串或分解参数）",
        input_schema={"type": "object", "properties": {
            "vector": {"type": "string", "description": "完整 CVSS v3.1 vector 字符串"},
            "attack_vector": {"type": "string", "enum": ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]},
            "attack_complexity": {"type": "string", "enum": ["LOW", "HIGH"]},
            "privileges_required": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
            "user_interaction": {"type": "string", "enum": ["NONE", "REQUIRED"]},
            "scope": {"type": "string", "enum": ["UNCHANGED", "CHANGED"]},
            "confidentiality": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
            "integrity": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
            "availability": {"type": "string", "enum": ["NONE", "LOW", "HIGH"]},
        }, "required": []},
        handler=cvss_calculator,
    ))
    registry.register(ToolDefinition(
        name="cwe_mapping", description="查询 CWE（Common Weakness Enumeration）信息",
        input_schema={"type": "object", "properties": {
            "cwe_id": {"type": "string", "description": "CWE ID"},
        }, "required": ["cwe_id"]},
        handler=cwe_mapping,
    ))
    registry.register(ToolDefinition(
        name="find_nuclei_template", description="在 Nuclei Templates 仓库中搜索相关模板",
        input_schema={"type": "object", "properties": {
            "tags": {"type": "string", "description": "标签关键词"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        }, "required": ["tags"]},
        handler=find_nuclei_template, requires_apis=["github"],
    ))
    registry.register(ToolDefinition(
        name="scan_ports", description="端口扫描（集成 nmap，异步不阻塞）",
        input_schema={"type": "object", "properties": {
            "target": {"type": "string", "description": "目标 IP 或域名"},
            "ports": {"type": "string", "description": "端口范围"},
            "scan_type": {"type": "string", "enum": ["quick", "full", "stealth", "version"]},
        }, "required": ["target"]},
        handler=scan_ports, requires_tools=["nmap"],
    ))
    registry.register(ToolDefinition(
        name="enumerate_subdomains", description="子域名枚举（集成 sublist3r 或 amass）",
        input_schema={"type": "object", "properties": {
            "domain": {"type": "string", "description": "目标域名"},
            "tool": {"type": "string", "enum": ["sublist3r", "amass"]},
        }, "required": ["domain"]},
        handler=enumerate_subdomains, requires_tools=["sublist3r", "amass"],
    ))
    registry.register(ToolDefinition(
        name="check_http_headers", description="HTTP 安全头检查",
        input_schema={"type": "object", "properties": {
            "url": {"type": "string", "description": "目标 URL"},
        }, "required": ["url"]},
        handler=check_http_headers,
    ))
    registry.register(ToolDefinition(
        name="query_dns", description="DNS 记录查询",
        input_schema={"type": "object", "properties": {
            "domain": {"type": "string", "description": "域名"},
            "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "ALL"]},
        }, "required": ["domain"]},
        handler=query_dns,
    ))
    registry.register(ToolDefinition(
        name="geolocate_ip", description="IP 地理位置查询",
        input_schema={"type": "object", "properties": {
            "ip": {"type": "string", "description": "IP 地址"},
        }, "required": ["ip"]},
        handler=geolocate_ip, requires_apis=["ip_api"],
    ))
    registry.register(ToolDefinition(
        name="search_poc_archive", description="搜索本地 PoC 档案库（exploitarium）",
        input_schema={"type": "object", "properties": {
            "query": {"type": "string", "description": "搜索关键词"},
            "cve_id": {"type": "string", "description": "按 CVE-ID 精确匹配"},
            "custom_path": {"type": "string", "description": "自定义档案库路径"},
        }},
        handler=search_poc_archive, requires_tools=["git"],
    ))
    registry.register(ToolDefinition(
        name="list_poc_archive", description="列出 PoC 档案库中所有条目",
        input_schema={"type": "object", "properties": {
            "custom_path": {"type": "string", "description": "自定义档案库路径"},
        }},
        handler=list_poc_archive,
    ))
    registry.register(ToolDefinition(
        name="clone_poc_archive", description="克隆 exploitarium PoC 档案库到本地",
        input_schema={"type": "object", "properties": {
            "custom_path": {"type": "string", "description": "自定义克隆路径"},
        }},
        handler=clone_archive, requires_tools=["git"],
    ))
    registry.register(ToolDefinition(
        name="update_poc_archive", description="更新（git pull）本地 PoC 档案库",
        input_schema={"type": "object", "properties": {
            "custom_path": {"type": "string", "description": "自定义档案库路径"},
        }},
        handler=update_archive, requires_tools=["git"],
    ))

    # v2.0 新增工具 (4)
    registry.register(ToolDefinition(
        name="check_kev", description="检查 CVE 是否在 CISA KEV 已知利用目录中",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=check_kev, requires_apis=["cisa_kev"],
    ))
    registry.register(ToolDefinition(
        name="get_epss_score", description="获取 EPSS 评分（预测未来30天被利用概率）",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=get_epss_score, requires_apis=["epss"],
    ))
    registry.register(ToolDefinition(
        name="vulnerability_assess", description="综合风险评估（CVSS + EPSS + CISA KEV，一次查询拿到决策所需的全部信息）",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=vulnerability_assess, requires_apis=["nvd", "cisa_kev", "epss"],
    ))
    registry.register(ToolDefinition(
        name="search_kev", description="搜索 CISA KEV 目录（按产品名、厂商名过滤）",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "搜索关键词（产品名、厂商名等）"},
            "max_results": {"type": "number", "description": "最大返回数（默认 20）", "default": 20},
        }},
        handler=search_kev, requires_apis=["cisa_kev"],
    ))
    registry.register(ToolDefinition(
        name="cross_source_search", description="跨源关联搜索（CVE + Exploit-DB + Nuclei，按 CVE-ID 自动关联）",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "搜索关键词"},
            "max_results": {"type": "number", "description": "每个源最大返回数（默认 20）", "default": 20},
        }, "required": ["keyword"]},
        handler=cross_source_search, requires_apis=["nvd", "exploit_db", "github"],
    ))

    return registry


# ---------- MCP Server ----------

server = Server("vuln-research-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    registry = get_registry()
    tools = []
    for t in registry.list_all():
        tools.append(Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"]))
    return tools


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    logger = logging.getLogger("vuln-research-mcp")
    logger.info(f"工具调用: {name}")

    registry = get_registry()
    tool_def = registry.resolve(name)
    if not tool_def:
        raise ValueError(f"未知工具: {name}")

    try:
        result = await tool_def.handler(**arguments)
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
    global _config, _health

    # 1. 加载配置
    _config = load_config()

    # 2. 设置日志
    setup_logging(level=_config.server.log_level, fmt=_config.server.log_format)
    logger = logging.getLogger("vuln-research-mcp")
    logger.info("=" * 60)
    logger.info("Vulnerability Research MCP Server v2.0.0 启动中...")
    logger.info("=" * 60)

    # 3. 初始化缓存
    init_cache(
        cache_dir=_config.cache.directory or None,
        enabled=_config.cache.enabled,
    )

    # 4. 注册工具
    _register_all_tools()
    register_all_tools(disabled=_config.tools.disabled)

    # 5. 初始化熔断器
    get_breaker("nvd_api", failure_threshold=_config.circuit_breaker.nvd_failure_threshold,
                recovery_timeout=_config.circuit_breaker.nvd_recovery_seconds)
    get_breaker("cisa_kev", failure_threshold=_config.circuit_breaker.cisa_failure_threshold,
                recovery_timeout=_config.circuit_breaker.cisa_recovery_seconds)
    get_breaker("epss_api", failure_threshold=_config.circuit_breaker.epss_failure_threshold,
                recovery_timeout=_config.circuit_breaker.epss_recovery_seconds)
    get_breaker("exploit_db", failure_threshold=3, recovery_timeout=60)
    get_breaker("ip_api", failure_threshold=3, recovery_timeout=60)

    # 6. 启动健康检查（不阻塞）
    _health = await startup_health_check()
    degraded = get_degraded_tools(_health)
    if degraded:
        logger.warning(f"降级运行的工具: {degraded}")

    registry = get_registry()
    logger.info(f"注册工具: {registry.size()} 个")
    logger.info(f"缓存: {_config.cache.enabled and 'enabled' or 'disabled'}")
    logger.info(f"API Key (NVD): {'configured' if _config.api_keys.nvd else 'not set (5 req/30s limit)'}")
    logger.info("启动完成，等待 MCP 调用...")

    # 7. 启动 MCP 服务
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
