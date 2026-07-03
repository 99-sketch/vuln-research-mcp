#!/usr/bin/env python3
"""工作流导出 — STIX 2.1 / SARIF / PDF / Markdown"""

import json
import logging
import os
from datetime import datetime
from typing import Optional

logger = logging.getLogger("vuln-research-mcp")

try:
    from src.models.vulnerability import UnifiedVulnerability
except ImportError:
    UnifiedVulnerability = None


class STIX21Exporter:
    def export(self, vulnerabilities: list) -> dict:
        objects = []
        for v in vulnerabilities:
            if hasattr(v, "to_stix21"):
                bundle = v.to_stix21()
                objects.extend(bundle.get("objects", []))
            elif isinstance(v, dict):
                objects.append(self._dict_to_stix(v))

        return {
            "type": "bundle",
            "id": f"bundle--{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def _dict_to_stix(self, d: dict) -> dict:
        cve_id = d.get("id", d.get("cve_id", "unknown"))
        clean_id = cve_id.replace("CVE-", "").lower()
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{clean_id}",
            "name": cve_id,
            "description": d.get("description", "")[:500],
        }


class SARIFExporter:
    def export(self, vulnerabilities: list) -> dict:
        results = []
        rules = []
        for v in vulnerabilities:
            vuln_dict = v.to_dict() if hasattr(v, "to_dict") else (v if isinstance(v, dict) else {})
            vid = vuln_dict.get("id", "unknown")
            desc = vuln_dict.get("description", "")[:200]
            risk = vuln_dict.get("risk", {})
            level = "error" if risk.get("risk_level") in ("CRITICAL", "HIGH") else "warning"

            rules.append({
                "id": vid,
                "name": vid,
                "shortDescription": {"text": desc},
            })
            results.append({
                "ruleId": vid,
                "message": {"text": desc},
                "level": level,
            })

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "VulnResearchMCP", "version": "3.0.0", "rules": rules}},
                "results": results,
            }],
        }


class MarkdownExporter:
    def export(self, vulnerabilities: list) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# Vulnerability Assessment Report",
            f"Generated: {now}",
            f"Total: {len(vulnerabilities)} vulnerabilities",
            "",
        ]
        for i, v in enumerate(vulnerabilities, 1):
            d = v.to_dict() if hasattr(v, "to_dict") else (v if isinstance(v, dict) else {})
            risk = d.get("risk", {})
            lines.append(f"## {i}. {d.get('id', 'Unknown')}")
            lines.append(f"Risk Level: {risk.get('risk_level', 'N/A')} | Risk Score: {risk.get('risk_score', 'N/A')}")
            lines.append(f"CVSS v3: {risk.get('cvss_v3_score', 'N/A')} | EPSS: {risk.get('epss_score', 'N/A')}")
            lines.append(f"CISA KEV: {'YES' if risk.get('in_kev') else 'NO'} | Ransomware: {'YES' if risk.get('ransomware_known') else 'NO'}")
            lines.append(f"CWE: {d.get('cwe_id', 'N/A')} - {d.get('cwe_name', '')}")
            if d.get("description"):
                lines.append(f"Description: {d['description'][:300]}")
            if d.get("affected_versions"):
                lines.append(f"Affected: {', '.join(d['affected_versions'][:10])}")
            lines.append("")
        return "\n".join(lines)


class ExportPipeline:
    def __init__(self):
        self.stix = STIX21Exporter()
        self.sarif = SARIFExporter()
        self.markdown = MarkdownExporter()

    def export_to_files(self, vulnerabilities: list, formats: list[str], output_dir: str) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        files = {}

        if "stix21" in formats or "stix" in formats:
            data = self.stix.export(vulnerabilities)
            path = os.path.join(output_dir, f"stix_report_{ts}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            files["stix21"] = path
            logger.info(f"STIX 2.1 exported: {path}")

        if "sarif" in formats:
            data = self.sarif.export(vulnerabilities)
            path = os.path.join(output_dir, f"sarif_report_{ts}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            files["sarif"] = path
            logger.info(f"SARIF exported: {path}")

        if "markdown" in formats or "md" in formats or "pdf" in formats:
            md = self.markdown.export(vulnerabilities)
            path = os.path.join(output_dir, f"report_{ts}.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
            files["markdown"] = path
            logger.info(f"Markdown report exported: {path}")

        if "json" in formats:
            data = [v.to_dict() if hasattr(v, "to_dict") else v for v in vulnerabilities]
            path = os.path.join(output_dir, f"report_{ts}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            files["json"] = path

        return files
