#!/usr/bin/env python3
"""报告导出工具 — STIX 2.1 / SARIF / Markdown / JSON"""

import json
import logging
import os
from datetime import datetime

logger = logging.getLogger("vuln-research-mcp")


async def generate_report(vulnerabilities: list, formats: str = "json", output_dir: str = None) -> dict:
    """生成多格式安全报告"""
    output_dir = output_dir or os.path.join(os.getcwd(), "reports")
    format_list = [f.strip() for f in formats.split(",")]

    try:
        from src.workflow.export import ExportPipeline
        pipeline = ExportPipeline()
        files = pipeline.export_to_files(vulnerabilities, format_list, output_dir)
        return {"status": "ok", "files": files, "output_dir": output_dir}
    except Exception as e:
        return {"error": str(e)}


async def export_workflow_result(workflow_result: dict, formats: str = "json", output_dir: str = None) -> dict:
    """从工作流结果导出报告"""
    output_dir = output_dir or os.path.join(os.getcwd(), "reports")
    format_list = [f.strip() for f in formats.split(",")]

    all_vulns = []
    for output in workflow_result.get("outputs", {}).values():
        if isinstance(output, list):
            all_vulns.extend(output)
        elif isinstance(output, dict):
            all_vulns.append(output)

    if not all_vulns:
        return {"status": "no_data", "message": "No vulnerabilities found in workflow result"}

    try:
        from src.workflow.export import ExportPipeline
        pipeline = ExportPipeline()
        files = pipeline.export_to_files(all_vulns, format_list, output_dir)
        return {"status": "ok", "files": files, "total_vulnerabilities": len(all_vulns)}
    except Exception as e:
        return {"error": str(e)}
