# src/tools/threat_intel_tool.py
"""威胁情报工具：CISA KEV 集成、EPSS 评分、综合风险评估"""

import asyncio
import logging
import httpx

from ..validators import validate_cve_id
from ..core.circuit_breaker import get_breaker, CircuitOpenError
from ..core.cache_manager import get_cache

logger = logging.getLogger("vuln-research-mcp")

# API 端点
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

# HTTP 客户端复用
_http_client: httpx.AsyncClient | None = None


async def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=30.0)
    return _http_client


async def _fetch_kev_feed() -> dict:
    """获取 CISA KEV 数据（带缓存 + 熔断器）"""
    cache = get_cache()

    # 查缓存
    cached = cache.get("cisa_kev_feed", "full_feed")
    if cached is not None:
        logger.debug("CISA KEV: 使用缓存数据")
        return cached

    # 熔断器
    breaker = get_breaker("cisa_kev", failure_threshold=3, recovery_timeout=60)
    client = await _get_client()

    try:
        resp = await breaker.call(client.get(CISA_KEV_URL))
        resp.raise_for_status()
        data = resp.json()
        cache.set("cisa_kev_feed", "full_feed", data, ttl=3600)
        logger.info(f"CISA KEV: 获取成功，{len(data.get('vulnerabilities', []))} 条记录")
        return data
    except CircuitOpenError:
        logger.warning("CISA KEV: 熔断中")
        return {"vulnerabilities": [], "_error": "CISA KEV API 熔断中"}
    except Exception as e:
        logger.error(f"CISA KEV 获取失败: {e}")
        return {"vulnerabilities": [], "_error": str(e)}


async def check_kev(cve_id: str) -> dict:
    """
    检查 CVE 是否在 CISA KEV 目录中
    
    Returns:
        {
            "cve_id": "CVE-2021-44228",
            "in_kev": True/False,
            "date_added": "2021-12-10",
            "due_date": "2021-12-24",
            "required_action": "...",
            "ransomware_known": True/False,
            "notes": "...",
        }
    """
    cve_id = validate_cve_id(cve_id)

    # 查缓存
    cache = get_cache()
    cached = cache.get("cisa_kev_feed", cve_id)
    if cached is not None:
        return cached

    feed = await _fetch_kev_feed()
    vulnerabilities = feed.get("vulnerabilities", [])

    match = next(
        (v for v in vulnerabilities if v.get("cveID", "").upper() == cve_id.upper()),
        None,
    )

    if match:
        result = {
            "cve_id": cve_id,
            "in_kev": True,
            "date_added": match.get("dateAdded", ""),
            "due_date": match.get("dueDate", ""),
            "required_action": match.get("requiredAction", ""),
            "ransomware_known": match.get("knownRansomwareCampaignUse", "") == "Known",
            "notes": match.get("notes", ""),
            "vendor_project": match.get("vendorProject", ""),
            "product": match.get("product", ""),
            "vulnerability_name": match.get("vulnerabilityName", ""),
        }
    else:
        result = {"cve_id": cve_id, "in_kev": False}

    # 写缓存
    cache.set("cisa_kev_feed", cve_id, result, ttl=3600)
    return result


async def get_epss_score(cve_id: str) -> dict:
    """
    获取 EPSS 评分 — 预测未来 30 天被利用的概率
    
    Returns:
        {
            "cve_id": "CVE-2021-44228",
            "epss_score": 0.974,
            "percentile": 97,
            "date": "2026-07-03",
        }
    """
    cve_id = validate_cve_id(cve_id)

    # 查缓存
    cache = get_cache()
    cached = cache.get("epss_score", cve_id)
    if cached is not None:
        return cached

    # 熔断器
    breaker = get_breaker("epss_api", failure_threshold=3, recovery_timeout=60)
    client = await _get_client()

    try:
        resp = await breaker.call(
            client.get(EPSS_API, params={"cve": cve_id})
        )
        resp.raise_for_status()
        data = resp.json()

        epss_data = data.get("data", [])
        if not epss_data:
            return {"cve_id": cve_id, "epss_score": 0.0, "percentile": 0, "date": "", "error": "EPSS 数据未找到"}

        entry = epss_data[0]
        result = {
            "cve_id": cve_id,
            "epss_score": float(entry.get("epss", 0)),
            "percentile": round(float(entry.get("percentile", 0)) * 100),
            "date": entry.get("date", ""),
        }

        cache.set("epss_score", cve_id, result, ttl=86400)
        return result

    except CircuitOpenError:
        logger.warning("EPSS API: 熔断中")
        return {"cve_id": cve_id, "epss_score": 0.0, "percentile": 0, "error": "EPSS API 熔断中"}
    except Exception as e:
        logger.error(f"EPSS 获取失败: {e}")
        return {"cve_id": cve_id, "epss_score": 0.0, "percentile": 0, "error": str(e)}


async def vulnerability_assess(cve_id: str) -> dict:
    """
    综合风险评估 — 一次查询，返回完整风险评估
    
    并行查询：CVE 详情 + CISA KEV + EPSS 评分
    计算 Risk Score = (CVSS/10) * EPSS * (KEV ? 2 : 1)
    
    Returns:
        {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "cvss_severity": "CRITICAL",
            "epss_score": 0.974,
            "epss_percentile": 97,
            "in_kev": True,
            "kev_details": {...},
            "risk_score": 1.948,
            "risk_severity": "CRITICAL",
            "ransomware_known": True,
            "description": "...",
            "references": [...],
            "remediation": [...],
        }
    """
    cve_id = validate_cve_id(cve_id)

    # 查缓存
    cache = get_cache()
    cached = cache.get("vulnerability_assess", cve_id)
    if cached is not None:
        logger.debug(f"vulnerability_assess: 缓存命中 {cve_id}")
        return cached

    # 并行查询三个数据源
    from .cve_tools import get_cve_details
    from ..core.circuit_breaker import get_breaker

    cve_task = get_cve_details(cve_id)
    kev_task = check_kev(cve_id)
    epss_task = get_epss_score(cve_id)

    cve_detail, kev_status, epss_score = await asyncio.gather(
        cve_task, kev_task, epss_task,
        return_exceptions=True,
    )

    # 处理异常
    if isinstance(cve_detail, Exception):
        cve_detail = {"error": str(cve_detail), "metrics": {}}
    if isinstance(kev_status, Exception):
        kev_status = {"in_kev": False, "error": str(kev_status)}
    if isinstance(epss_score, Exception):
        epss_score = {"epss_score": 0.0, "percentile": 0, "error": str(epss_score)}

    # 提取 CVSS 评分
    metrics = cve_detail.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
    cvss_data = cvss_v3[0].get("cvssData", {}) if cvss_v3 else {}
    cvss_score = cvss_data.get("baseScore", 0)
    cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")

    # 提取 EPSS
    epss = epss_score.get("epss_score", 0.0)
    epss_percentile = epss_score.get("percentile", 0)

    # 提取 KEV
    in_kev = kev_status.get("in_kev", False)
    ransomware_known = kev_status.get("ransomware_known", False)

    # 计算 Risk Score
    # Risk = (CVSS / 10) * EPSS * (KEV ? 2 : 1)
    # 范围: 0 ~ 2.0
    risk = (cvss_score / 10.0) * epss
    if in_kev:
        risk *= 2.0

    # 风险等级
    if risk > 0.5:
        risk_severity = "CRITICAL"
    elif risk > 0.1:
        risk_severity = "HIGH"
    elif risk > 0.01:
        risk_severity = "MEDIUM"
    else:
        risk_severity = "LOW"

    # 提取引用
    references = cve_detail.get("references", [])
    if not isinstance(references, list):
        references = []

    result = {
        "cve_id": cve_id,
        "description": cve_detail.get("description", ""),
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_data.get("vectorString", ""),
        "epss_score": round(epss, 4),
        "epss_percentile": epss_percentile,
        "in_kev": in_kev,
        "kev_details": kev_status if in_kev else None,
        "ransomware_known": ransomware_known,
        "risk_score": round(risk, 4),
        "risk_severity": risk_severity,
        "references": references[:10],
        "remediation": references[:5],
        "status": cve_detail.get("status", ""),
        "published": cve_detail.get("published", ""),
        "last_modified": cve_detail.get("last_modified", ""),
    }

    # 写缓存
    cache.set("vulnerability_assess", cve_id, result, ttl=1800)
    logger.info(f"vulnerability_assess: {cve_id} risk={risk:.4f} ({risk_severity})")
    return result


async def search_kev(keyword: str = None, max_results: int = 20) -> dict:
    """
    搜索 CISA KEV 目录 — 按关键词过滤
    
    Args:
        keyword: 搜索关键词（产品名、厂商名等）
        max_results: 最大返回数
    """
    cache = get_cache()
    cache_key = f"search:{keyword}:{max_results}"
    cached = cache.get("cisa_kev_feed", cache_key)
    if cached is not None:
        return cached

    feed = await _fetch_kev_feed()
    vulnerabilities = feed.get("vulnerabilities", [])

    if keyword:
        keyword_lower = keyword.lower()
        matched = [
            v for v in vulnerabilities
            if keyword_lower in v.get("vendorProject", "").lower()
            or keyword_lower in v.get("product", "").lower()
            or keyword_lower in v.get("vulnerabilityName", "").lower()
            or keyword_lower in v.get("cveID", "").lower()
            or keyword_lower in v.get("description", "").lower()
        ]
    else:
        matched = vulnerabilities

    results = [
        {
            "cve_id": v.get("cveID", ""),
            "vendor_project": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "required_action": v.get("requiredAction", ""),
            "ransomware_known": v.get("knownRansomwareCampaignUse", "") == "Known",
            "notes": v.get("notes", ""),
        }
        for v in matched[:max_results]
    ]

    result = {
        "keyword": keyword,
        "total_in_kev": len(vulnerabilities),
        "total_matched": len(matched),
        "results": results,
    }

    cache.set("cisa_kev_feed", cache_key, result, ttl=3600)
    return result
