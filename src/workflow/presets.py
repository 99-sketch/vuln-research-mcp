#!/usr/bin/env python3
"""预设工作流"""

from src.workflow.engine import WorkflowStep

BUILTIN_WORKFLOWS = {
    "quick_assess": {
        "name": "快速评估",
        "description": "端口扫描 + HTTP头 + DNS + GeoIP + 综合评估",
        "steps": [
            WorkflowStep(tool_name="scan_ports", tool_args={"target": "$context.target", "scan_type": "quick"}),
            WorkflowStep(tool_name="check_http_headers", tool_args={"url": "https://$context.target"}, depends_on=["scan_ports"]),
            WorkflowStep(tool_name="query_dns", tool_args={"domain": "$context.target"}),
            WorkflowStep(tool_name="geolocate_ip", tool_args={"ip": "$context.target"}),
        ],
    },
    "full_pentest_prep": {
        "name": "完整渗透准备",
        "description": "子域名 + 全端口 + 指纹 + 跨源搜索",
        "steps": [
            WorkflowStep(tool_name="enumerate_subdomains", tool_args={"domain": "$context.target"}),
            WorkflowStep(tool_name="scan_ports", tool_args={"target": "$context.target", "scan_type": "full"}, depends_on=["enumerate_subdomains"]),
            WorkflowStep(tool_name="cpe_lookup", tool_args={"product": "$context.target"}, depends_on=["scan_ports"]),
            WorkflowStep(tool_name="cross_source_search", tool_args={"keyword": "$context.target"}, depends_on=["scan_ports"]),
        ],
    },
    "vuln_deep_dive": {
        "name": "漏洞深度分析",
        "description": "CVE详情 + 风险评估 + Exploit + Nuclei",
        "steps": [
            WorkflowStep(tool_name="get_cve_details", tool_args={"cve_id": "$context.target"}, critical=True),
            WorkflowStep(tool_name="vulnerability_assess", tool_args={"cve_id": "$context.target"}, depends_on=["get_cve_details"]),
            WorkflowStep(tool_name="search_exploit", tool_args={"query": "$context.target"}, depends_on=["get_cve_details"]),
            WorkflowStep(tool_name="find_nuclei_template", tool_args={"tags": "$context.target"}, depends_on=["get_cve_details"]),
        ],
    },
    "tech_stack_audit": {
        "name": "技术栈审计",
        "description": "产品CVE搜索 + KEV目录检查 + EPSS评分",
        "steps": [
            WorkflowStep(tool_name="cpe_lookup", tool_args={"product": "$context.target"}),
            WorkflowStep(tool_name="search_cve", tool_args={"keyword": "$context.target", "max_results": 20}, depends_on=["cpe_lookup"]),
            WorkflowStep(tool_name="search_kev", tool_args={"keyword": "$context.target"}, depends_on=["cpe_lookup"]),
        ],
    },
}
