# src/tools/cross_search_tool.py
"""跨源关联搜索 — 一次搜索，跨所有情报源，结果自动关联"""

import asyncio
import logging

from .cve_tools import search_cve
from .exploit_tool import search_exploit
from .nuclei_tool import find_nuclei_template
from ..core.cache_manager import get_cache
from ..validators import sanitize_subprocess_arg

logger = logging.getLogger("vuln-research-mcp")


async def cross_source_search(keyword: str, max_results: int = 20) -> dict:
    """
    跨源关联搜索 — 并行查询 CVE、Exploit-DB、Nuclei，按 CVE-ID 关联
    
    Args:
        keyword: 搜索关键词（如 "log4j", "wordpress rce", "apache"）
        max_results: 每个源最大返回数
    
    Returns:
        {
            "keyword": "log4j",
            "sources": {
                "cve": {"count": 42, "results": [...]},
                "exploit_db": {"count": 8, "results": [...]},
                "nuclei": {"count": 12, "results": [...]},
            },
            "cross_reference": [
                {
                    "cve_id": "CVE-2021-44228",
                    "in_cve": True,
                    "in_exploit_db": True,
                    "in_nuclei": True,
                    "description": "Log4j...",
                },
                ...
            ],
            "summary": {
                "total_cve": 42,
                "total_exploits": 8,
                "total_nuclei": 12,
                "cve_with_exploit": 5,
                "cve_with_nuclei": 3,
                "cve_with_both": 2,
            },
        }
    """
    if not keyword or not isinstance(keyword, str):
        raise ValueError("搜索关键词不能为空")
    keyword = sanitize_subprocess_arg(keyword)

    # 查缓存
    cache = get_cache()
    cache_key = f"{keyword}:{max_results}"
    cached = cache.get("cross_source_search", cache_key)
    if cached is not None:
        logger.debug(f"cross_source_search: 缓存命中 '{keyword}'")
        return cached

    # 并行查询三个数据源
    cve_task = search_cve(keyword=keyword, max_results=max_results)
    exploit_task = search_exploit(query=keyword)
    nuclei_task = find_nuclei_template(tags=keyword)

    cve_result, exploit_result, nuclei_result = await asyncio.gather(
        cve_task, exploit_task, nuclei_task,
        return_exceptions=True,
    )

    # 处理异常 — 单个源失败不影响其他源
    if isinstance(cve_result, Exception):
        cve_result = {"total_results": 0, "vulnerabilities": [], "error": str(cve_result)}
    if isinstance(exploit_result, Exception):
        exploit_result = {"total_results": 0, "results": [], "error": str(exploit_result)}
    if isinstance(nuclei_result, Exception):
        nuclei_result = {"total_matched": 0, "templates": [], "error": str(nuclei_result)}

    # 提取 CVE-ID 列表
    cve_vulns = cve_result.get("vulnerabilities", [])
    cve_ids = {v.get("cve_id", "").upper() for v in cve_vulns if v.get("cve_id")}

    # 从 Exploit-DB 结果中提取 CVE-ID
    exploit_results = exploit_result.get("results", exploit_result.get("exploits", []))
    exploit_cve_ids = set()
    for exp in exploit_results:
        exp_cve = exp.get("cve_id", exp.get("cve", ""))
        if exp_cve:
            exploit_cve_ids.add(exp_cve.upper())

    # 从 Nuclei 结果中提取 CVE-ID（从路径中解析）
    nuclei_templates = nuclei_result.get("templates", [])
    nuclei_cve_ids = set()
    import re
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    for template in nuclei_templates:
        path = template.get("path", "") if isinstance(template, dict) else str(template)
        matches = cve_pattern.findall(path)
        nuclei_cve_ids.update(m.upper() for m in matches)

    # 构建交叉引用
    all_cve_ids = cve_ids | exploit_cve_ids | nuclei_cve_ids
    cross_ref = []
    for cve_id in sorted(all_cve_ids):
        # 从 CVE 结果中找描述
        description = ""
        for v in cve_vulns:
            if v.get("cve_id", "").upper() == cve_id:
                description = v.get("description", "")
                break

        cross_ref.append({
            "cve_id": cve_id,
            "in_cve": cve_id in cve_ids,
            "in_exploit_db": cve_id in exploit_cve_ids,
            "in_nuclei": cve_id in nuclei_cve_ids,
            "description": description[:200] if description else "",
        })

    # 汇总统计
    cve_with_exploit = sum(1 for c in cross_ref if c["in_cve"] and c["in_exploit_db"])
    cve_with_nuclei = sum(1 for c in cross_ref if c["in_cve"] and c["in_nuclei"])
    cve_with_both = sum(1 for c in cross_ref if c["in_cve"] and c["in_exploit_db"] and c["in_nuclei"])

    result = {
        "keyword": keyword,
        "sources": {
            "cve": {
                "count": cve_result.get("total_results", 0),
                "returned": len(cve_vulns),
                "error": cve_result.get("error"),
            },
            "exploit_db": {
                "count": exploit_result.get("total_results", exploit_result.get("total", 0)),
                "returned": len(exploit_results),
                "error": exploit_result.get("error"),
            },
            "nuclei": {
                "count": nuclei_result.get("total_matched", 0),
                "returned": len(nuclei_templates),
                "error": nuclei_result.get("error"),
            },
        },
        "cross_reference": cross_ref[:50],  # 限制返回数量
        "summary": {
            "total_cve": len(cve_ids),
            "total_exploits": len(exploit_cve_ids),
            "total_nuclei": len(nuclei_cve_ids),
            "total_unique_cves": len(all_cve_ids),
            "cve_with_exploit": cve_with_exploit,
            "cve_with_nuclei": cve_with_nuclei,
            "cve_with_both": cve_with_both,
        },
    }

    # 写缓存
    cache.set("cross_source_search", cache_key, result, ttl=900)
    logger.info(
        f"cross_source_search: '{keyword}' — "
        f"{len(cve_ids)} CVE, {len(exploit_cve_ids)} exploits, {len(nuclei_cve_ids)} nuclei, "
        f"{cve_with_both} 有双重覆盖"
    )
    return result
