# src/tools/cve_tools.py
"""CVE 搜索与详情工具"""

import logging
import httpx
from ..validators import validate_cve_id

logger = logging.getLogger("vuln-research-mcp")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"


async def search_cve(keyword: str, product: str = None, version: str = None, max_results: int = 10) -> dict:
    """搜索 CVE 漏洞 (NVD API)"""
    if not keyword or not isinstance(keyword, str):
        raise ValueError("搜索关键词不能为空")
    keyword = keyword.strip()[:200]  # 限制长度防注入

    if max_results < 1 or max_results > 200:
        max_results = 10

    async with httpx.AsyncClient() as client:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 200),
        }
        if product:
            params["keywordSearch"] = f"{keyword} {product}"
        if version:
            params["keywordSearch"] = f"{keyword} {version}"

        response = await client.get(f"{NVD_API_BASE}/cves/2.0", params=params, timeout=15.0)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])
            cvss_data = cvss_v3[0].get("cvssData", {}) if cvss_v3 else {}

            vulnerabilities.append({
                "cve_id": cve.get("id"),
                "source_identifier": cve.get("sourceIdentifier"),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "status": cve.get("vulnStatus"),
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "cvss_score": cvss_data.get("baseScore"),
                "severity": cvss_data.get("baseSeverity"),
                "vector_string": cvss_data.get("vectorString"),
            })

        return {
            "total_results": data.get("totalResults", 0),
            "returned": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }


async def get_cve_details(cve_id: str) -> dict:
    """获取 CVE 详细信息"""
    cve_id = validate_cve_id(cve_id)

    async with httpx.AsyncClient() as client:
        params = {"cveId": cve_id}
        response = await client.get(f"{NVD_API_BASE}/cves/2.0", params=params, timeout=15.0)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": f"CVE {cve_id} 未找到", "cve_id": cve_id}

        vuln = vulnerabilities[0].get("cve", {})

        return {
            "cve_id": vuln.get("id"),
            "source_identifier": vuln.get("sourceIdentifier"),
            "published": vuln.get("published"),
            "last_modified": vuln.get("lastModified"),
            "status": vuln.get("vulnStatus"),
            "description": vuln.get("descriptions", [{}])[0].get("value", ""),
            "metrics": vuln.get("metrics"),
            "weaknesses": vuln.get("weaknesses"),
            "configurations": vuln.get("configurations"),
            "references": [ref.get("url") for ref in vuln.get("references", [])],
        }
