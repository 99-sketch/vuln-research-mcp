# src/tools/cve_tools.py
"""CVE 搜索与详情工具 - v2.0: 熔断器 + 缓存 + 速率限制"""

import logging

import httpx

from ..validators import validate_cve_id
from ..rate_limiter import nvd_rate_limited_request, NVD_API_KEY
from ..core.circuit_breaker import get_breaker, CircuitOpenError
from ..core.cache_manager import get_cache

logger = logging.getLogger("vuln-research-mcp")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"


async def search_cve(keyword: str, product: str = None, version: str = None, max_results: int = 10) -> dict:
    """搜索 CVE 漏洞 (NVD API) — v2.0: 缓存 + 熔断器"""
    if not keyword or not isinstance(keyword, str):
        raise ValueError("搜索关键词不能为空")
    keyword = keyword.strip()[:200]

    if max_results < 1 or max_results > 200:
        max_results = 10

    # 缓存
    cache = get_cache()
    search_term = keyword
    if product:
        search_term = f"{keyword} {product}"
    if version:
        search_term = f"{keyword} {version}"
    cache_key = f"{search_term}:{max_results}"
    cached = cache.get("nvd_search", cache_key)
    if cached is not None:
        return cached

    # 熔断器
    breaker = get_breaker("nvd_api", failure_threshold=5, recovery_timeout=60)

    try:
        async with httpx.AsyncClient() as client:
            params = {
                "keywordSearch": search_term,
                "resultsPerPage": min(max_results, 200),
            }

            response = await breaker.call(
                nvd_rate_limited_request(client, f"{NVD_API_BASE}/cves/2.0", params)
            )
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

            result = {
                "total_results": data.get("totalResults", 0),
                "returned": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "api_key_used": bool(NVD_API_KEY),
                "rate_limit": "50 req/30s (with API key)" if NVD_API_KEY else "5 req/30s (no API key)",
            }

            cache.set("nvd_search", cache_key, result, ttl=900)
            return result

    except CircuitOpenError:
        logger.warning("NVD API: 熔断中")
        return {
            "error": "NVD API 熔断中（连续失败过多，稍后重试）",
            "keyword": keyword,
            "vulnerabilities": [],
        }


async def get_cve_details(cve_id: str) -> dict:
    """获取 CVE 详细信息 — v2.0: 缓存 + 熔断器"""
    cve_id = validate_cve_id(cve_id)

    # 缓存
    cache = get_cache()
    cached = cache.get("nvd_cve_detail", cve_id)
    if cached is not None:
        return cached

    # 熔断器
    breaker = get_breaker("nvd_api", failure_threshold=5, recovery_timeout=60)

    try:
        async with httpx.AsyncClient() as client:
            params = {"cveId": cve_id}
            response = await breaker.call(
                nvd_rate_limited_request(client, f"{NVD_API_BASE}/cves/2.0", params)
            )
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return {"error": f"CVE {cve_id} 未找到", "cve_id": cve_id}

            vuln = vulnerabilities[0].get("cve", {})

            result = {
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

            cache.set("nvd_cve_detail", cve_id, result, ttl=3600)
            return result

    except CircuitOpenError:
        logger.warning("NVD API: 熔断中")
        return {
            "error": "NVD API 熔断中",
            "cve_id": cve_id,
        }
