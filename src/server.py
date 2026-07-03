#!/usr/bin/env python3
"""
Vulnerability Research MCP Server v5.0.0 — Enterprise Security Platform
Penetration Testing Infrastructure Component

v5.0 Architecture (Layered):
  gateway/       多协议接入 (MCP + REST API + WebSocket + CLI) + API认证
  security/      企业安全体系 (输入净化/数据清洗/目标策略/工具RBAC/人工审批/
                 审计日志/密钥管理/数据库加密/API认证/告警系统)
  compliance/    合规检查 (漏洞修复验证/基线合规/等保2.0)
  graph/         Neo4j 知识图谱 (大规模资产图谱 + 攻击路径分析)
  intel/         情报层 (MITRE ATT&CK + CNVD/CNNVD + 离线镜像)
  bus/           事件总线 (Pub/Sub)
  orchestrator/  流水线编排 + 任务调度
  correlator/    资产-漏洞关联引擎
  reporting/     专业渗透测试报告
  db/            SQLite 持久化 (Project/Asset/Finding/Evidence/Timeline/Report) + AES加密
  models/        统一漏洞数据模型 (UnifiedVulnerability -> STIX 2.1 / SARIF)
  tools/         39+ 工具 (CVE/CVSS/CWE/Exploit/Nuclei/Network/Scan/ThreatIntel/CNVD/CPE/Graph/Report/Scanner)
  core/          基础设施 (AsyncSubProcess, CircuitBreaker, Cache, KnowledgeGraph, Session)
  workflow/      DAG 工作流引擎 + 预设工作流 + 导出
  watchdog/      CISA KEV 轮询告警
  plugins/       社区数据源 SDK
"""

import asyncio
import json
import logging
import sys
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Core
from src.core.config_manager import load_config, AppConfig
from src.core.structured_logger import setup_logging
from src.core.cache_manager import init_cache, get_cache
from src.core.circuit_breaker import get_breaker, all_breaker_status
from src.core.health_check import startup_health_check, get_degraded_tools
from src.core.tool_registry import get_registry, ToolDefinition, register_all_tools
from src.core.knowledge_graph import get_graph, KnowledgeGraph
from src.core.session_state import get_session_manager, SessionManager

# Models
from src.models.vulnerability import UnifiedVulnerability, Source, RiskAssessment, ThreatIntel

# Tools (v2.0 + v3.0)
from src.tools.cve_tools import search_cve, get_cve_details
from src.tools.cvss_tool import cvss_calculator
from src.tools.cwe_tool import cwe_mapping
from src.tools.exploit_tool import search_exploit
from src.tools.nuclei_tool import find_nuclei_template
from src.tools.scan_tools import scan_ports, enumerate_subdomains
from src.tools.network_tools import check_http_headers, query_dns, geolocate_ip
from src.tools.poc_archive_tool import search_poc_archive, list_poc_archive, clone_archive, update_archive
from src.tools.threat_intel_tool import check_kev, get_epss_score, vulnerability_assess, search_kev
from src.tools.cross_search_tool import cross_source_search
from src.tools.cpe_tool import cpe_lookup, service_fingerprint
from src.tools.graph_tool import graph_traverse, graph_neighbors, graph_search, graph_stats, graph_add_relation
from src.tools.report_tool import generate_report, export_workflow_result

# v4.0 New Modules
from src.bus.event_bus import get_event_bus, EventBus
from src.db.database import get_db, Database
from src.db.models import Project, Asset, Finding, Scan, TimelineEvent, Evidence, PentestReport
from src.correlator.engine import Correlator, CorrelationResult
from src.orchestrator.pipeline import PipelineOrchestrator, Pipeline, PipelineStep, PipelineStage
from src.orchestrator.scheduler import TaskScheduler, ScheduledJob
from src.intel.attck import ATTACKMapper
from src.reporting.pentest_report import PentestReportGenerator, ReportConfig
from src.tools.scanner_tools import (
    parse_nmap_xml, nmap_to_assets, generate_nuclei_command,
    execute_scanner, search_metasploit, search_sploit,
    parse_nuclei_output, nuclei_output_to_findings,
)

# Workflow
from src.workflow.engine import get_engine, WorkflowEngine, WorkflowStep, WorkflowStatus
from src.workflow.presets import BUILTIN_WORKFLOWS
from src.workflow.export import ExportPipeline

# Watchdog
from src.watchdog.watcher import Watchdog, WatchRule

# Plugins
from src.plugins.sdk import get_plugin_manager, PluginManager

# v4.1 Security Module
from src.security.audit import AuditLogger, create_audit_logger
from src.security.tool_guard import ToolGuard, ToolRiskLevel, create_tool_guard
from src.security.target_policy import TargetPolicy, ScanLimitPolicy, create_default_policy
from src.security.key_manager import SecureKeyManager, create_key_manager

# v5.0 Enterprise Modules
from src.security.approval import ToolApprovalManager, ApprovalDecision, get_approval_manager
from src.security.data_sanitizer import DataContextSanitizer, get_data_sanitizer
from src.security.db_crypto import DatabaseCrypto, get_db_crypto
from src.security.api_auth import APIAuthManager, get_api_auth
from src.security.alerting import AlertManager, AlertSeverity, get_alert_manager
from src.intel.cnvd import CNVDClient, CNNVDClient, CVECNMapper, get_cnvd_client, get_cnnvd_client, get_cve_cn_mapper
from src.intel.offline_mirror import OfflineMirror, get_offline_mirror
from src.compliance.fix_verifier import FixVerifier, FixStatus, FixResult, get_fix_verifier
from src.compliance.baseline_checker import BaselineChecker, ComplianceReport, get_baseline_checker
from src.graph.neo4j_adapter import Neo4jAdapter, get_neo4j_adapter

__version__ = "5.0.0"

# ---------- State ----------

_config: Optional[AppConfig] = None
_health: dict = None
_graph: Optional[KnowledgeGraph] = None
_sessions: Optional[SessionManager] = None
_workflow_engine: Optional[WorkflowEngine] = None
_watchdog: Optional[Watchdog] = None
_bus: Optional[EventBus] = None
_db: Optional[Database] = None
_correlator: Optional[Correlator] = None
_pipeline: Optional[PipelineOrchestrator] = None
_scheduler: Optional[TaskScheduler] = None
_attack_mapper: Optional[ATTACKMapper] = None
_report_gen: Optional[PentestReportGenerator] = None
# v4.1 Security
_audit: Optional[AuditLogger] = None
_tool_guard: Optional[ToolGuard] = None
_target_policy: Optional[TargetPolicy] = None
_key_manager: Optional[SecureKeyManager] = None

# v5.0 Enterprise
_approval_mgr: Optional[ToolApprovalManager] = None
_data_sanitizer: Optional[DataContextSanitizer] = None
_db_crypto: Optional[DatabaseCrypto] = None
_api_auth: Optional[APIAuthManager] = None
_alert_mgr: Optional[AlertManager] = None
_cnvd_client: Optional[CNVDClient] = None
_cnnvd_client: Optional[CNNVDClient] = None
_cve_cn_mapper: Optional[CVECNMapper] = None
_offline_mirror: Optional[OfflineMirror] = None
_fix_verifier: Optional[FixVerifier] = None
_baseline_checker: Optional[BaselineChecker] = None
_neo4j: Optional[Neo4jAdapter] = None


def _register_all_tools():
    registry = get_registry()

    # === v1.0 基础工具 (15) ===
    registry.register(ToolDefinition(
        name="search_cve", description="Search CVEs by product name, version, or keyword",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "Search keyword"},
            "product": {"type": "string", "description": "Product name (optional)"},
            "version": {"type": "string", "description": "Product version (optional)"},
            "max_results": {"type": "number", "description": "Max results (default 10)", "default": 10},
        }, "required": ["keyword"]},
        handler=search_cve, requires_apis=["nvd"],
    ))
    registry.register(ToolDefinition(
        name="get_cve_details", description="Get full details for a CVE ID",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=get_cve_details, requires_apis=["nvd"],
    ))
    registry.register(ToolDefinition(
        name="search_exploit", description="Search Exploit-DB for PoC/Exploits",
        input_schema={"type": "object", "properties": {
            "query": {"type": "string", "description": "Search keyword"},
            "type_filter": {"type": "string", "description": "Type filter: remote, webapps, local, dos"},
        }, "required": ["query"]},
        handler=search_exploit, requires_apis=["exploit_db"], requires_tools=["searchsploit"],
    ))
    registry.register(ToolDefinition(
        name="cvss_calculator", description="Calculate CVSS v3.1 score",
        input_schema={"type": "object", "properties": {
            "vector": {"type": "string", "description": "Full CVSS v3.1 vector string"},
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
        name="cwe_mapping", description="Query CWE weakness information",
        input_schema={"type": "object", "properties": {
            "cwe_id": {"type": "string", "description": "CWE ID"},
        }, "required": ["cwe_id"]},
        handler=cwe_mapping,
    ))
    registry.register(ToolDefinition(
        name="find_nuclei_template", description="Search Nuclei templates repository",
        input_schema={"type": "object", "properties": {
            "tags": {"type": "string", "description": "Tag keywords"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        }, "required": ["tags"]},
        handler=find_nuclei_template, requires_apis=["github"],
    ))
    registry.register(ToolDefinition(
        name="scan_ports", description="Port scanning (nmap integration)",
        input_schema={"type": "object", "properties": {
            "target": {"type": "string", "description": "Target IP or domain"},
            "ports": {"type": "string", "description": "Port range"},
            "scan_type": {"type": "string", "enum": ["quick", "full", "stealth", "version"]},
        }, "required": ["target"]},
        handler=scan_ports, requires_tools=["nmap"],
    ))
    registry.register(ToolDefinition(
        name="enumerate_subdomains", description="Subdomain enumeration (sublist3r/amass)",
        input_schema={"type": "object", "properties": {
            "domain": {"type": "string", "description": "Target domain"},
            "tool": {"type": "string", "enum": ["sublist3r", "amass"]},
        }, "required": ["domain"]},
        handler=enumerate_subdomains, requires_tools=["sublist3r", "amass"],
    ))
    registry.register(ToolDefinition(
        name="check_http_headers", description="HTTP security header check",
        input_schema={"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
        }, "required": ["url"]},
        handler=check_http_headers,
    ))
    registry.register(ToolDefinition(
        name="query_dns", description="DNS record lookup",
        input_schema={"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain name"},
            "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "ALL"]},
        }, "required": ["domain"]},
        handler=query_dns,
    ))
    registry.register(ToolDefinition(
        name="geolocate_ip", description="IP geolocation lookup",
        input_schema={"type": "object", "properties": {
            "ip": {"type": "string", "description": "IP address"},
        }, "required": ["ip"]},
        handler=geolocate_ip, requires_apis=["ip_api"],
    ))
    registry.register(ToolDefinition(
        name="search_poc_archive", description="Search local PoC archive (exploitarium)",
        input_schema={"type": "object", "properties": {
            "query": {"type": "string", "description": "Search keyword"},
            "cve_id": {"type": "string", "description": "Match by CVE ID"},
            "custom_path": {"type": "string", "description": "Custom archive path"},
        }},
        handler=search_poc_archive, requires_tools=["git"],
    ))
    registry.register(ToolDefinition(
        name="list_poc_archive", description="List all entries in PoC archive",
        input_schema={"type": "object", "properties": {
            "custom_path": {"type": "string", "description": "Custom archive path"},
        }},
        handler=list_poc_archive,
    ))
    registry.register(ToolDefinition(
        name="clone_poc_archive", description="Clone exploitarium PoC archive",
        input_schema={"type": "object", "properties": {
            "custom_path": {"type": "string", "description": "Custom clone path"},
        }},
        handler=clone_archive, requires_tools=["git"],
    ))
    registry.register(ToolDefinition(
        name="update_poc_archive", description="Update (git pull) local PoC archive",
        input_schema={"type": "object", "properties": {
            "custom_path": {"type": "string", "description": "Custom archive path"},
        }},
        handler=update_archive, requires_tools=["git"],
    ))

    # === v2.0 新增工具 (5) ===
    registry.register(ToolDefinition(
        name="check_kev", description="Check CISA KEV known exploited vulnerabilities catalog",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=check_kev, requires_apis=["cisa_kev"],
    ))
    registry.register(ToolDefinition(
        name="get_epss_score", description="Get EPSS exploitation probability score",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=get_epss_score, requires_apis=["epss"],
    ))
    registry.register(ToolDefinition(
        name="vulnerability_assess", description="Comprehensive risk assessment (CVSS + EPSS + CISA KEV)",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE ID"},
        }, "required": ["cve_id"]},
        handler=vulnerability_assess, requires_apis=["nvd", "cisa_kev", "epss"],
    ))
    registry.register(ToolDefinition(
        name="search_kev", description="Search CISA KEV by product/vendor name",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "Search keyword"},
            "max_results": {"type": "number", "description": "Max results (default 20)", "default": 20},
        }},
        handler=search_kev, requires_apis=["cisa_kev"],
    ))
    registry.register(ToolDefinition(
        name="cross_source_search", description="Cross-source search (CVE + Exploit-DB + Nuclei)",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "Search keyword"},
            "max_results": {"type": "number", "description": "Max results per source (default 20)", "default": 20},
        }, "required": ["keyword"]},
        handler=cross_source_search, requires_apis=["nvd", "exploit_db", "github"],
    ))

    # === v3.0 新增工具 (9) ===
    registry.register(ToolDefinition(
        name="cpe_lookup", description="Product fingerprint -> CPE matching",
        input_schema={"type": "object", "properties": {
            "product": {"type": "string", "description": "Product name"},
        }, "required": ["product"]},
        handler=cpe_lookup,
    ))
    registry.register(ToolDefinition(
        name="service_fingerprint", description="Extract service/version from banner text",
        input_schema={"type": "object", "properties": {
            "banner": {"type": "string", "description": "Service banner text"},
        }, "required": ["banner"]},
        handler=service_fingerprint,
    ))
    registry.register(ToolDefinition(
        name="graph_traverse", description="BFS traverse knowledge graph (CVE->CWE->Exploit->Actor)",
        input_schema={"type": "object", "properties": {
            "start_node": {"type": "string", "description": "Starting node ID"},
            "max_depth": {"type": "number", "description": "Max traversal depth (default 3)", "default": 3},
            "relation_filter": {"type": "string", "description": "Comma-separated relation types to filter"},
        }, "required": ["start_node"]},
        handler=graph_traverse,
    ))
    registry.register(ToolDefinition(
        name="graph_neighbors", description="Query knowledge graph node neighbors",
        input_schema={"type": "object", "properties": {
            "node_id": {"type": "string", "description": "Node ID"},
        }, "required": ["node_id"]},
        handler=graph_neighbors,
    ))
    registry.register(ToolDefinition(
        name="graph_search", description="Search knowledge graph nodes",
        input_schema={"type": "object", "properties": {
            "query": {"type": "string", "description": "Search keyword"},
        }, "required": ["query"]},
        handler=graph_search,
    ))
    registry.register(ToolDefinition(
        name="graph_stats", description="Knowledge graph statistics",
        input_schema={"type": "object", "properties": {}},
        handler=graph_stats,
    ))
    registry.register(ToolDefinition(
        name="generate_report", description="Generate multi-format security reports (STIX 2.1/SARIF/Markdown/JSON)",
        input_schema={"type": "object", "properties": {
            "vulnerabilities": {"type": "string", "description": "JSON string of vulnerabilities"},
            "formats": {"type": "string", "description": "Comma-separated formats: json,markdown,sarif,stix21"},
            "output_dir": {"type": "string", "description": "Output directory"},
        }, "required": ["vulnerabilities"]},
        handler=_generate_report_wrapper,
    ))
    registry.register(ToolDefinition(
        name="run_workflow", description="Execute a preset penetration testing workflow",
        input_schema={"type": "object", "properties": {
            "workflow_name": {"type": "string", "description": "Workflow name: quick_assess, full_pentest_prep, vuln_deep_dive, tech_stack_audit"},
            "target": {"type": "string", "description": "Target domain, IP, or CVE ID"},
        }, "required": ["workflow_name", "target"]},
        handler=_run_workflow_tool,
    ))
    registry.register(ToolDefinition(
        name="list_workflows", description="List all available preset workflows",
        input_schema={"type": "object", "properties": {}},
        handler=_list_workflows_tool,
    ))

    # === v4.0 新增工具 (10) ===

    # Scanner tools
    registry.register(ToolDefinition(
        name="parse_nmap_xml", description="Parse Nmap XML output and return structured assets",
        input_schema={"type": "object", "properties": {
            "xml_path": {"type": "string", "description": "Path to Nmap XML file"},
            "project_id": {"type": "number", "description": "Project ID to associate assets with"},
        }, "required": ["xml_path"]},
        handler=_parse_nmap_tool,
    ))
    registry.register(ToolDefinition(
        name="generate_nuclei_cmd", description="Generate a Nuclei CLI command for target scanning",
        input_schema={"type": "object", "properties": {
            "target": {"type": "string", "description": "Target URL or IP"},
            "templates": {"type": "string", "description": "Comma-separated template paths or IDs"},
            "severity": {"type": "string", "description": "Filter by severity: critical,high,medium,low,info"},
            "output_path": {"type": "string", "description": "Path for JSON output file"},
        }, "required": ["target"]},
        handler=_nuclei_cmd_tool,
    ))
    registry.register(ToolDefinition(
        name="search_metasploit", description="Search Metasploit modules matching CVEs or services",
        input_schema={"type": "object", "properties": {
            "query": {"type": "string", "description": "Search keyword (CVE, service, product)"},
        }, "required": ["query"]},
        handler=_search_metasploit_tool, requires_tools=["msfconsole"],
    ))
    registry.register(ToolDefinition(
        name="search_sploit", description="Search Exploit-DB offline via searchsploit",
        input_schema={"type": "object", "properties": {
            "query": {"type": "string", "description": "Search keyword"},
        }, "required": ["query"]},
        handler=_search_sploit_tool, requires_tools=["searchsploit"],
    ))

    # ATT&CK tools
    registry.register(ToolDefinition(
        name="attack_technique", description="Get MITRE ATT&CK technique details",
        input_schema={"type": "object", "properties": {
            "technique_id": {"type": "string", "description": "ATT&CK technique ID (e.g., T1190)"},
        }, "required": ["technique_id"]},
        handler=_attack_technique_tool,
    ))
    registry.register(ToolDefinition(
        name="map_to_attack", description="Map a finding to MITRE ATT&CK techniques, tactics, and mitigations",
        input_schema={"type": "object", "properties": {
            "title": {"type": "string", "description": "Finding title"},
            "description": {"type": "string", "description": "Finding description"},
            "cwe_ids": {"type": "string", "description": "Comma-separated CWE IDs"},
            "severity": {"type": "string", "description": "Finding severity"},
        }, "required": ["title"]},
        handler=_map_to_attack_tool,
    ))
    registry.register(ToolDefinition(
        name="attack_navigator", description="Generate ATT&CK Navigator layer JSON from findings",
        input_schema={"type": "object", "properties": {
            "findings_json": {"type": "string", "description": "JSON array of findings"},
            "project_name": {"type": "string", "description": "Project name for the layer"},
        }, "required": ["findings_json"]},
        handler=_attack_navigator_tool,
    ))

    # Pipeline tools
    registry.register(ToolDefinition(
        name="run_pipeline", description="Execute a YAML-defined penetration testing pipeline",
        input_schema={"type": "object", "properties": {
            "pipeline_name": {"type": "string", "description": "Pipeline name (from data/pipelines/)"},
            "context_json": {"type": "string", "description": "JSON context object (target, cve_id, etc.)"},
        }, "required": ["pipeline_name"]},
        handler=_run_pipeline_tool,
    ))
    registry.register(ToolDefinition(
        name="list_pipelines", description="List all available YAML pipeline definitions",
        input_schema={"type": "object", "properties": {}},
        handler=_list_pipelines_tool,
    ))

    # Pentest report tool
    registry.register(ToolDefinition(
        name="pentest_report", description="Generate a professional penetration test report in Markdown or JSON",
        input_schema={"type": "object", "properties": {
            "project_id": {"type": "number", "description": "Project ID to generate report for"},
            "format": {"type": "string", "description": "Output format: markdown, json", "default": "markdown"},
            "project_name": {"type": "string", "description": "Project name for the report title"},
        }, "required": ["project_id"]},
        handler=_pentest_report_tool,
    ))

    # === v5.0 新增工具 (12) ===

    # CNVD 国内漏洞库
    registry.register(ToolDefinition(
        name="cnvd_search", description="搜索中国国家信息安全漏洞共享平台(CNVD)漏洞库",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "搜索关键词（中文）"},
            "max_results": {"type": "number", "description": "最大结果数", "default": 20},
            "severity": {"type": "string", "description": "严重程度过滤: 超危/高危/中危/低危"},
        }, "required": ["keyword"]},
        handler=_cnvd_search_tool,
    ))
    registry.register(ToolDefinition(
        name="cnvd_detail", description="获取CNVD漏洞详细信息",
        input_schema={"type": "object", "properties": {
            "cnvd_id": {"type": "string", "description": "CNVD编号"},
        }, "required": ["cnvd_id"]},
        handler=_cnvd_detail_tool,
    ))
    registry.register(ToolDefinition(
        name="cnnvd_search", description="搜索国家信息安全漏洞库(CNNVD)",
        input_schema={"type": "object", "properties": {
            "keyword": {"type": "string", "description": "搜索关键词"},
            "max_results": {"type": "number", "description": "最大结果数", "default": 10},
        }, "required": ["keyword"]},
        handler=_cnnvd_search_tool,
    ))
    registry.register(ToolDefinition(
        name="cve_to_cnvd", description="CVE编号映射到CNVD/CNNVD国内编号",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE编号"},
        }, "required": ["cve_id"]},
        handler=_cve_to_cnvd_tool,
    ))

    # 离线镜像管理
    registry.register(ToolDefinition(
        name="offline_mirror_status", description="查看离线漏洞库镜像下载状态",
        input_schema={"type": "object", "properties": {}},
        handler=_offline_mirror_status_tool,
    ))
    registry.register(ToolDefinition(
        name="offline_mirror_query", description="在离线漏洞库中查询CVE或Exploit",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE编号"},
            "query": {"type": "string", "description": "通用搜索关键词"},
        }},
        handler=_offline_mirror_query_tool,
    ))

    # 漏洞修复验证
    registry.register(ToolDefinition(
        name="verify_fix", description="验证漏洞是否已被修复（版本比对 + NVD参考 + 端口比对）",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "CVE编号"},
            "target": {"type": "string", "description": "目标IP或域名"},
            "current_version": {"type": "string", "description": "当前部署版本"},
            "service_name": {"type": "string", "description": "受影响的服务名称"},
        }, "required": ["cve_id", "target"]},
        handler=_verify_fix_tool,
    ))

    # 等保2.0 合规检查
    registry.register(ToolDefinition(
        name="compliance_check", description="执行等保2.0/CIS安全基线合规检查",
        input_schema={"type": "object", "properties": {
            "target": {"type": "string", "description": "目标IP或主机名"},
            "profile": {"type": "string", "description": "基线配置: dengbao_l3, cis_server, all", "default": "dengbao_l3"},
        }, "required": ["target"]},
        handler=_compliance_check_tool,
    ))

    # Neo4j 知识图谱
    registry.register(ToolDefinition(
        name="neo4j_attack_paths", description="Neo4j知识图谱: 查找资产到CVE的攻击路径",
        input_schema={"type": "object", "properties": {
            "target_ip": {"type": "string", "description": "目标IP地址"},
            "max_depth": {"type": "number", "description": "最大深度(默认5)", "default": 5},
        }, "required": ["target_ip"]},
        handler=_neo4j_attack_paths_tool,
    ))
    registry.register(ToolDefinition(
        name="neo4j_critical_assets", description="Neo4j知识图谱: 查找存在高危漏洞的资产",
        input_schema={"type": "object", "properties": {
            "cvss_threshold": {"type": "number", "description": "CVSS最低分数(默认7.0)", "default": 7.0},
        }},
        handler=_neo4j_critical_assets_tool,
    ))

    # 审计日志导出
    registry.register(ToolDefinition(
        name="audit_export", description="导出安全审计日志（JSONL/Syslog/CEF格式）",
        input_schema={"type": "object", "properties": {
            "format": {"type": "string", "description": "导出格式: jsonl, syslog, cef", "default": "jsonl"},
            "days": {"type": "number", "description": "导出最近N天(默认30)", "default": 30},
        }},
        handler=_audit_export_tool,
    ))

    return registry


# ── v3.0 wrappers ──

async def _generate_report_wrapper(vulnerabilities: str, formats: str = "json", output_dir: str = None) -> dict:
    try:
        vulns = json.loads(vulnerabilities) if isinstance(vulnerabilities, str) else vulnerabilities
    except json.JSONDecodeError:
        return {"error": "Invalid JSON for vulnerabilities"}
    return await generate_report(vulns, formats, output_dir)


async def _run_workflow_tool(workflow_name: str, target: str) -> dict:
    wf_def = BUILTIN_WORKFLOWS.get(workflow_name)
    if not wf_def:
        return {"error": f"Unknown workflow: {workflow_name}", "available": list(BUILTIN_WORKFLOWS.keys())}
    result = await _workflow_engine.execute(
        workflow_id=workflow_name,
        steps=wf_def["steps"],
        initial_context={"context": {"target": target}},
    )
    return result


async def _list_workflows_tool() -> dict:
    return {
        name: {"name": wf["name"], "description": wf["description"]}
        for name, wf in BUILTIN_WORKFLOWS.items()
    }


# ── v4.0 wrappers ──

async def _parse_nmap_tool(xml_path: str, project_id: int = 0) -> dict:
    hosts = parse_nmap_xml(xml_path)
    if project_id > 0:
        assets = nmap_to_assets(project_id, hosts)
        for a in assets:
            _db.create_asset(a)
        _bus.publish(__import__("src.bus.event_bus", fromlist=["Event"]).Event(
            event_type="nmap_imported",
            data={"project_id": project_id, "hosts": len(hosts), "assets": len(assets)},
            source="nmap_parser",
        ))
    return {
        "hosts": len(hosts),
        "assets_created": len(assets) if project_id > 0 else 0,
        "details": [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "open_ports": len(h.ports),
                "services": [f"{p.port}/{p.protocol} {p.service}" for p in h.ports if p.state == "open"],
            }
            for h in hosts if h.status == "up"
        ],
    }


async def _nuclei_cmd_tool(target: str, templates: str = "", severity: str = "",
                           output_path: str = "") -> dict:
    tpl_list = [t.strip() for t in templates.split(",")] if templates else None
    cmd = generate_nuclei_command(target, tpl_list, severity or None, output_path or None)
    return {"command": cmd, "ready_to_execute": True}


async def _search_metasploit_tool(query: str) -> dict:
    results = search_metasploit(query)
    return {"query": query, "results": results, "count": len(results)}


async def _search_sploit_tool(query: str) -> dict:
    results = search_sploit(query)
    return {"query": query, "results": results, "count": len(results)}


async def _attack_technique_tool(technique_id: str) -> dict:
    t = _attack_mapper.get_technique(technique_id.upper())
    if not t:
        return {"error": f"Technique {technique_id} not found"}
    return {
        "id": t.id, "name": t.name, "tactic": t.tactic,
        "description": t.description, "platforms": t.platforms,
        "detection": t.detection, "mitigations": t.mitigations,
    }


async def _map_to_attack_tool(title: str, description: str = "",
                              cwe_ids: str = "", severity: str = "") -> dict:
    return _attack_mapper.map_finding(title, description, cwe_ids, severity)


async def _attack_navigator_tool(findings_json: str, project_name: str = "") -> dict:
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON for findings"}
    return _attack_mapper.generate_attack_navigator_layer(findings, project_name)


async def _run_pipeline_tool(pipeline_name: str, context_json: str = "{}") -> dict:
    pipeline_obj = _pipeline.load_pipeline(pipeline_name)
    if not pipeline_obj:
        available = [p["name"] for p in _pipeline.list_pipelines()]
        return {"error": f"Pipeline '{pipeline_name}' not found", "available": available}
    try:
        context = json.loads(context_json)
    except json.JSONDecodeError:
        context = {}
    result = await _pipeline.run_pipeline(pipeline_obj, context)
    return result


async def _list_pipelines_tool() -> dict:
    return {"pipelines": _pipeline.list_pipelines()}


async def _pentest_report_tool(project_id: int, format: str = "markdown",
                               project_name: str = "") -> dict:
    findings = _db.list_findings(project_id)
    project = _db.get_project(project_id) if project_id > 0 else None
    timeline = _db.list_timeline(project_id) if project_id > 0 else []

    config = ReportConfig(
        project_name=project_name or (project.name if project else "Penetration Test"),
        timeline_events=[f"{e.event_type}: {e.title}" for e in timeline],
    )

    if format == "json":
        content = json.dumps(
            _report_gen.generate_json(findings, config), indent=2, ensure_ascii=False,
        )
    else:
        content = _report_gen.generate_markdown(findings, config)

    report = _report_gen.to_report_model(project_id, content, format, findings, config)
    rid = _db.create_report(report)
    _bus.publish(__import__("src.bus.event_bus", fromlist=["Event"]).Event(
        event_type="report_generated",
        data={"report_id": rid, "project_id": project_id, "format": format},
        source="pentest_report",
    ))

    return {
        "report_id": rid,
        "format": format,
        "finding_count": len(findings),
        "content_preview": content[:500] + "..." if len(content) > 500 else content,
    }


# ── v5.0 tool wrappers ──

async def _cnvd_search_tool(keyword: str, max_results: int = 20, severity: str = None) -> dict:
    client = _cnvd_client or get_cnvd_client()
    results = await client.search(keyword, max_results=max_results, severity=severity)
    return {"source": "CNVD", "count": len(results), "results": [r.to_dict() for r in results]}


async def _cnvd_detail_tool(cnvd_id: str) -> dict:
    client = _cnvd_client or get_cnvd_client()
    detail = await client.get_detail(cnvd_id)
    if not detail:
        return {"error": f"CNVD vulnerability not found: {cnvd_id}"}
    return detail.to_dict()


async def _cnnvd_search_tool(keyword: str, max_results: int = 10) -> dict:
    client = _cnnvd_client or get_cnnvd_client()
    results = await client.search(keyword, max_results=max_results)
    return {"source": "CNNVD", "count": len(results), "results": [r.to_dict() for r in results]}


async def _cve_to_cnvd_tool(cve_id: str) -> dict:
    mapper = _cve_cn_mapper or get_cve_cn_mapper()
    await mapper.load_mappings()
    cnvd_id = mapper.get_cnvd(cve_id)
    cnnvd_id = mapper.get_cnnvd(cve_id)
    return {"cve_id": cve_id, "cnvd_id": cnvd_id, "cnnvd_id": cnnvd_id}


async def _offline_mirror_status_tool() -> dict:
    mirror = _offline_mirror or get_offline_mirror()
    status = mirror.get_status()
    stats = mirror.get_offline_stats()
    return {"summary": mirror.get_sync_summary(), "stats": stats, "sources": {k: v.__dict__ for k, v in status.items()}}


async def _offline_mirror_query_tool(cve_id: str = "", query: str = "") -> dict:
    mirror = _offline_mirror or get_offline_mirror()
    results = []
    if cve_id:
        cve_data = mirror.query_offline_cve(cve_id)
        exploits = mirror.query_offline_exploits(cve_id)
        if cve_data:
            results.append({"type": "cve", "data": cve_data})
        results.append({"type": "exploits", "count": len(exploits), "data": exploits})
    if query:
        search_results = mirror.search_offline(query)
        results.append({"type": "search", "count": len(search_results), "data": search_results})
    return {"offline_query": True, "results": results}


async def _verify_fix_tool(cve_id: str, target: str, current_version: str = None, service_name: str = None) -> dict:
    verifier = _fix_verifier or get_fix_verifier()
    result = await verifier.verify_fix(cve_id, target, current_version, service_name)
    return result.to_dict()


async def _compliance_check_tool(target: str, profile: str = "dengbao_l3") -> dict:
    checker = _baseline_checker or get_baseline_checker()
    report = checker.run_checks(target, profile)
    return report.to_dict()


async def _neo4j_attack_paths_tool(target_ip: str, max_depth: int = 5) -> dict:
    adapter = _neo4j or get_neo4j_adapter()
    if not adapter.is_connected:
        await adapter.connect()
    if not adapter.is_connected:
        return {"error": "Neo4j not connected. Set NEO4J_URI/NEO4J_PASSWORD env vars and install neo4j package."}
    paths = await adapter.find_attack_paths(target_ip, max_depth)
    return {"target_ip": target_ip, "paths_found": len(paths), "paths": paths}


async def _neo4j_critical_assets_tool(cvss_threshold: float = 7.0) -> dict:
    adapter = _neo4j or get_neo4j_adapter()
    if not adapter.is_connected:
        await adapter.connect()
    if not adapter.is_connected:
        return {"error": "Neo4j not connected."}
    assets = await adapter.get_critical_assets(cvss_threshold)
    return {"cvss_threshold": cvss_threshold, "assets_found": len(assets), "assets": assets}


async def _audit_export_tool(format: str = "jsonl", days: int = 30) -> dict:
    import os, glob
    audit_dir = os.path.expanduser("~/.vuln-research-mcp/audit")
    if not os.path.exists(audit_dir):
        return {"error": f"Audit directory not found: {audit_dir}"}
    files = sorted(glob.glob(os.path.join(audit_dir, "audit-*.jsonl")), reverse=True)[:days]
    entries = []
    for f in files:
        if os.path.exists(f):
            with open(f, 'r') as fh:
                for line in fh:
                    if line.strip():
                        entries.append(line.strip())
    return {"total_entries": len(entries), "days": days, "format": format, "entries": entries[:1000]}


# ---------- MCP Server ----------

server = Server("vuln-research-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    registry = get_registry()
    return [Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"]) for t in registry.list_all()]


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    logger = logging.getLogger("vuln-research-mcp")
    logger.info(f"Call: {name}")

    # --- v5.0 Security Layer 1: Tool Approval (human-in-the-loop) ---
    if _approval_mgr and arguments and isinstance(arguments, dict):
        target = arguments.get("target") or arguments.get("domain") or arguments.get("ip") or arguments.get("url") or arguments.get("target_ip")
        decision = await _approval_mgr.request_approval(
            name, arguments, target=str(target) if target else None,
            timeout=30
        )
        if decision == ApprovalDecision.DENIED:
            logger.warning(f"Tool denied by approval: {name}")
            if _audit:
                _audit.log_tool_call(name, arguments, result="denied", reason="tool_approval_denied")
            if _alert_mgr:
                _alert_mgr.send_alert(AlertSeverity.WARNING, f"Tool denied by approval: {name}",
                                       f"Tool '{name}' was denied by human approval. Target: {target}")
            return [TextContent(type="text", text=json.dumps({"error": "Operation rejected by approval policy"}, ensure_ascii=False))]
        elif decision == ApprovalDecision.TIMED_OUT:
            logger.warning(f"Tool approval timed out: {name}")
            if _audit:
                _audit.log_tool_call(name, arguments, result="denied", reason="approval_timeout")
            return [TextContent(type="text", text=json.dumps({"error": "Approval timed out — operation not confirmed"}, ensure_ascii=False))]

    # --- v4.1 Security: Tool Guard check ---
    if _tool_guard:
        allowed, reason = _tool_guard.is_allowed(name)
        if not allowed:
            logger.warning(f"工具调用被拒绝: {name} - {reason}")
            if _audit:
                _audit.log_tool_call(name, arguments or {}, result="denied", reason=reason)
            if _alert_mgr:
                _alert_mgr.send_alert(AlertSeverity.WARNING, f"Tool blocked by guard: {name}",
                                       f"Tool '{name}' blocked: {reason}")
            return [TextContent(type="text", text=json.dumps({"error": f"Tool blocked: {reason}"}, ensure_ascii=False))]

    # --- v4.1 Security: Target policy check for scan tools ---
    if _target_policy and arguments and isinstance(arguments, dict):
        target = arguments.get("target") or arguments.get("domain") or arguments.get("ip") or arguments.get("url")
        if target and name in ("scan_ports", "enumerate_subdomains", "generate_nuclei_command", "check_http_headers"):
            allowed, reason = _target_policy.check_target(str(target))
            if not allowed:
                logger.warning(f"目标被策略拒绝: {target} - {reason}")
                if _audit:
                    _audit.log_scan_attempt(name, str(target), False, reason)
                if _alert_mgr:
                    _alert_mgr.send_alert(AlertSeverity.ERROR, f"Target policy violation: {name}",
                                           f"Tool '{name}' attempted to scan blocked target: {target}. Reason: {reason}",
                                           tags={"target": str(target), "tool": name})
                return [TextContent(type="text", text=json.dumps({"error": f"Target denied: {reason}"}, ensure_ascii=False))]

    # --- v5.0 Security Layer 2: SSRF Protection for HTTP tools ---
    if _target_policy and arguments and isinstance(arguments, dict):
        url_target = arguments.get("url") or arguments.get("target")
        if url_target and name in ("check_http_headers",):
            import re
            from urllib.parse import urlparse
            parsed = urlparse(str(url_target))
            if parsed.hostname:
                allowed, reason = _target_policy.check_target(parsed.hostname)
                if not allowed:
                    logger.warning(f"SSRF blocked: {url_target} - {reason}")
                    if _audit:
                        _audit.log_tool_call(name, arguments, result="denied", reason=f"SSRF: {reason}")
                    return [TextContent(type="text", text=json.dumps({"error": f"SSRF blocked: {reason}"}, ensure_ascii=False))]

    registry = get_registry()
    tool_def = registry.resolve(name)
    if not tool_def:
        raise ValueError(f"Unknown tool: {name}")

    try:
        result = await tool_def.handler(**arguments)

        # --- v5.0 Security Layer 3: External data sanitization ---
        if _data_sanitizer and isinstance(result, dict):
            clean_result, report = _data_sanitizer.sanitize_structured(result, source=name)
            if report.was_modified:
                logger.info(f"Data sanitized for tool {name}: {len(report.flags)} modifications")
                result = clean_result

        # --- v4.1 Security: Audit logging ---
        if _audit:
            _audit.log_tool_call(name, arguments or {}, result="success")
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except ValueError as e:
        logger.warning(f"Tool {name} validation failed: {e}")
        if _audit:
            _audit.log_tool_call(name, arguments or {}, result="error", reason=str(e))
        return [TextContent(type="text", text=json.dumps({"error": f"Validation failed: {e}"}, ensure_ascii=False))]
    except Exception as e:
        logger.error(f"Tool {name} failed: {e}")
        if _audit:
            _audit.log_tool_call(name, arguments or {}, result="error", reason=str(e))
        if _alert_mgr:
            _alert_mgr.send_alert(AlertSeverity.ERROR, f"Tool execution failed: {name}",
                                   f"Tool '{name}' failed with error: {str(e)}")
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, ensure_ascii=False))]


# ---------- Init ----------

async def _init():
    global _config, _health, _graph, _sessions, _workflow_engine, _watchdog
    global _bus, _db, _correlator, _pipeline, _scheduler, _attack_mapper, _report_gen
    global _audit, _tool_guard, _target_policy, _key_manager  # v4.1 Security
    global _approval_mgr, _data_sanitizer, _db_crypto, _api_auth, _alert_mgr  # v5.0 Security
    global _cnvd_client, _cnnvd_client, _cve_cn_mapper, _offline_mirror  # v5.0 Intel
    global _fix_verifier, _baseline_checker, _neo4j  # v5.0 Compliance / Graph

    _config = load_config()
    setup_logging(level=_config.server.log_level, fmt=_config.server.log_format)
    logger = logging.getLogger("vuln-research-mcp")
    logger.info("=" * 60)
    logger.info(f"Vulnerability Research MCP Server v{__version__}")
    logger.info("Penetration Testing Infrastructure Component")
    logger.info("=" * 60)

    # v4.0 - Event Bus
    _bus = get_event_bus()
    logger.info(f"EventBus: {_bus.subscriber_count} subscribers")

    # v4.0 - Database
    _db = get_db()
    logger.info(f"Database: {_db.db_path()} ({_db.db_size_mb():.1f} MB)")

    # Cache
    init_cache(cache_dir=_config.cache.directory or None, enabled=_config.cache.enabled)

    # Knowledge Graph
    _graph = get_graph()
    logger.info(f"Knowledge Graph: {_graph.stats().get('total_nodes', 0)} nodes")

    # Sessions
    _sessions = get_session_manager()

    # Tools
    _register_all_tools()
    register_all_tools(disabled=_config.tools.disabled)

    # Circuit breakers
    get_breaker("nvd_api", failure_threshold=_config.circuit_breaker.nvd_failure_threshold,
                recovery_timeout=_config.circuit_breaker.nvd_recovery_seconds)
    get_breaker("cisa_kev", failure_threshold=_config.circuit_breaker.cisa_failure_threshold,
                recovery_timeout=_config.circuit_breaker.cisa_recovery_seconds)
    get_breaker("epss_api", failure_threshold=_config.circuit_breaker.epss_failure_threshold,
                recovery_timeout=_config.circuit_breaker.epss_recovery_seconds)
    get_breaker("exploit_db", failure_threshold=3, recovery_timeout=60)
    get_breaker("ip_api", failure_threshold=3, recovery_timeout=60)

    # Workflow Engine
    registry = get_registry()
    _workflow_engine = get_engine(registry, _sessions)

    # v4.0 - Correlator
    _correlator = Correlator(nvd_api_key=_config.api_keys.nvd or "")
    logger.info("Correlator: ready")

    # v4.0 - Pipeline Orchestrator
    _pipeline = PipelineOrchestrator()
    yaml_pipelines = len(_pipeline.list_pipelines())
    logger.info(f"Pipeline Orchestrator: {yaml_pipelines} YAML pipeline(s)")

    # v4.0 - Task Scheduler
    _scheduler = TaskScheduler()
    logger.info("Task Scheduler: ready")

    # v4.0 - ATT&CK Mapper
    _attack_mapper = ATTACKMapper()
    logger.info(f"ATT&CK Mapper: {len(_attack_mapper.list_all_techniques())} techniques")

    # v4.0 - Report Generator
    _report_gen = PentestReportGenerator()
    logger.info("Report Generator: ready")

    # Watchdog
    _watchdog = Watchdog(registry)

    # Plugins
    plugin_mgr = get_plugin_manager()
    logger.info(f"Plugins: {len(plugin_mgr.list_all())} loaded")

    # v4.1 Security Module
    _audit = create_audit_logger()
    _tool_guard = create_tool_guard()
    _target_policy = create_default_policy()
    _key_manager = create_key_manager()
    _key_manager.load_from_env()
    logger.info("Security v4.1: Audit log + Tool guard + Target policy + Key manager initialized")

    # v5.0 Enterprise Security
    _approval_mgr = get_approval_manager()
    _approval_mgr.configure_from_policy({
        "default_deny_levels": ["EXPLOIT", "SYSTEM"],
        "require_approval_levels": ["ACTIVE_SCAN"],
        "auto_approve_tools": ["search_cve", "get_cve_details", "cvss_calculator", "cwe_mapping",
                                "graph_traverse", "graph_search", "graph_stats", "graph_neighbors",
                                "list_workflows", "list_pipelines", "list_poc_archive",
                                "cnvd_search", "cnvd_detail", "cnnvd_search", "cve_to_cnvd",
                                "offline_mirror_status", "offline_mirror_query", "compliance_check"],
    })
    _data_sanitizer = get_data_sanitizer(aggressive=False)
    _db_crypto = get_db_crypto()
    _api_auth = get_api_auth()
    _alert_mgr = get_alert_manager()
    logger.info("Security v5.0: Approval mgr + Data sanitizer + DB crypto + API auth + Alerting initialized")

    # v5.0 Intel — CNVD/CNNVD
    _cnvd_client = get_cnvd_client()
    _cnnvd_client = get_cnnvd_client()
    _cve_cn_mapper = get_cve_cn_mapper()
    logger.info("Intel v5.0: CNVD + CNNVD + CVE-CN Mapper initialized")

    # v5.0 Intel — Offline Mirror
    _offline_mirror = get_offline_mirror()
    mirror_status = _offline_mirror.get_status()
    mirror_count = len(mirror_status)
    logger.info(f"Offline Mirror: {mirror_count} data sources ({_offline_mirror.get_sync_summary().split(chr(10))[0] if mirror_count else 'no data yet'})")

    # v5.0 Compliance
    _fix_verifier = get_fix_verifier()
    _baseline_checker = get_baseline_checker()
    logger.info(f"Compliance: Fix verifier + Baseline checker ({len(_baseline_checker.list_profiles())} profiles)")

    # v5.0 Graph — Neo4j (optional)
    _neo4j = get_neo4j_adapter()
    neo4j_connected = await _neo4j.connect()
    if neo4j_connected:
        stats = await _neo4j.get_graph_stats()
        logger.info(f"Neo4j: Connected ({stats.get('total_nodes', 0)} nodes, {stats.get('total_edges', 0)} edges)")
    else:
        logger.info("Neo4j: Not available — using NetworkX fallback")

    # Health check
    _health = await startup_health_check()
    degraded = get_degraded_tools(_health)
    if degraded:
        logger.warning(f"Degraded: {degraded}")

    # Summary
    logger.info(f"Tools: {registry.size()} | Workflows: {len(BUILTIN_WORKFLOWS)} | YAML Pipelines: {yaml_pipelines}")
    logger.info(f"Cache: {'ON' if _config.cache.enabled else 'OFF'} | API Key: {'Yes' if _config.api_keys.nvd else 'No (5req/30s)'}")


async def main():
    await _init()
    logger = logging.getLogger("vuln-research-mcp")
    logger.info("v5.0 ready. Waiting for MCP calls...")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


# ---------- CLI / API Modes ----------

async def _interactive_mode():
    await _init()
    from src.gateway.cli import VulnResearchCLI
    cli = VulnResearchCLI(
        tool_registry=get_registry(),
        workflow_engine=_workflow_engine,
        export_pipeline=ExportPipeline(),
        knowledge_graph=_graph,
    )
    await cli.interactive()


async def _run_workflow_mode(workflow_name: str, target: str, formats: str = "json", output_dir: str = None):
    await _init()
    from src.gateway.cli import VulnResearchCLI
    cli = VulnResearchCLI(
        tool_registry=get_registry(),
        workflow_engine=_workflow_engine,
        export_pipeline=ExportPipeline(),
        knowledge_graph=_graph,
    )
    format_list = [f.strip() for f in formats.split(",")]
    output_dir = output_dir or "reports"
    await cli.run_workflow(workflow_name, target, format_list, output_dir)


async def _api_mode(host: str = "0.0.0.0", port: int = 8765):
    """Start the REST API Gateway."""
    await _init()
    from src.gateway.rest_api import RestAPIGateway
    api = RestAPIGateway(db=_db)
    logger = logging.getLogger("vuln-research-mcp")
    logger.info(f"REST API Gateway starting on {host}:{port}")
    # The pipeline orchestrator in the API needs the tool executor
    api._pipeline.set_tool_executor(_pipeline_tool_executor)
    api.run(host=host, port=port)


async def _pipeline_tool_executor(tool_name: str, params: dict) -> dict:
    """Bridge for pipeline orchestrator to call MCP tools."""
    registry = get_registry()
    tool_def = registry.resolve(tool_name)
    if not tool_def:
        return {"error": f"Unknown tool: {tool_name}"}
    try:
        return await tool_def.handler(**params)
    except Exception as e:
        return {"error": str(e)}


async def _yaml_pipeline_mode(pipeline_name: str, context_json: str = "{}"):
    """Run a YAML pipeline directly from CLI."""
    await _init()
    _pipeline.set_tool_executor(_pipeline_tool_executor)
    logger = logging.getLogger("vuln-research-mcp")
    logger.info(f"Running YAML pipeline: {pipeline_name}")

    pipeline_obj = _pipeline.load_pipeline(pipeline_name)
    if not pipeline_obj:
        logger.error(f"Pipeline '{pipeline_name}' not found")
        return

    try:
        context = json.loads(context_json)
    except json.JSONDecodeError:
        context = {}

    result = await _pipeline.run_pipeline(pipeline_obj, context)
    print(json.dumps(result, indent=2, ensure_ascii=False))


# ---------- Entry ----------

def entry():
    import argparse
    parser = argparse.ArgumentParser(
        description="VulnResearchMCP v4.0 - Penetration Testing Infrastructure Component"
    )
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive CLI mode")
    parser.add_argument("--api", action="store_true", help="Start REST API gateway")
    parser.add_argument("--api-host", type=str, default="0.0.0.0", help="API host (default: 0.0.0.0)")
    parser.add_argument("--api-port", type=int, default=8765, help="API port (default: 8765)")
    parser.add_argument("--workflow", "-w", type=str, help="Run workflow: quick_assess, full_pentest_prep, vuln_deep_dive, tech_stack_audit")
    parser.add_argument("--target", "-t", type=str, help="Target for workflow (domain, IP, or CVE)")
    parser.add_argument("--pipeline", "-p", type=str, help="Run YAML pipeline: full_recon, vuln_deep_dive, tech_stack_audit")
    parser.add_argument("--context", "-c", type=str, default="{}", help="JSON context for pipeline")
    parser.add_argument("--formats", "-f", type=str, default="json", help="Export formats (json,markdown,sarif,stix21)")
    parser.add_argument("--output", "-o", type=str, help="Output directory for reports")
    args = parser.parse_args()

    if args.version:
        print(f"vuln-research-mcp v{__version__}")
        return

    if args.api:
        asyncio.run(_api_mode(args.api_host, args.api_port))
    elif args.pipeline:
        asyncio.run(_yaml_pipeline_mode(args.pipeline, args.context))
    elif args.interactive:
        asyncio.run(_interactive_mode())
    elif args.workflow and args.target:
        asyncio.run(_run_workflow_mode(args.workflow, args.target, args.formats, args.output))
    else:
        asyncio.run(main())


if __name__ == "__main__":
    entry()
