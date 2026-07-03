"""
CNVD / CNNVD — 中国国家信息安全漏洞库集成 (v5.0)

Support for Chinese national vulnerability databases:
  - CNVD (国家信息安全漏洞共享平台) — cnvd.org.cn
  - CNNVD (国家信息安全漏洞库) — cnnvd.org.cn
  - CVE-CNVD mapping for vulnerability tracking in Chinese systems

API coverage:
  - CNVD: 漏洞搜索、详情查询、厂商产品漏洞、补丁信息
  - CNNVD: 漏洞信息查询、漏洞通报、补丁发布
  - 自动 CVE-ID 到 CNVD/CNNVD 编号映射

Usage:
    cnvd = CNVDClient()
    results = await cnvd.search("Apache Log4j")
    detail = await cnvd.get_detail("CNVD-2021-95919")
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)


# ── Data Models ─────────────────────────────────────────────────────

@dataclass
class CNVDVulnerability:
    """CNVD vulnerability record (CNVD-YYYY-NNNNNN format)."""
    cnvd_id: str
    title: str
    title_en: str = ""
    cve_id: str = ""                   # mapped CVE if available
    severity: str = ""                 # 高/中/低
    cvss_score: float = 0.0
    vulnerability_type: str = ""       # e.g. 代码注入, 权限提升
    affected_products: List[str] = field(default_factory=list)
    affected_vendors: List[str] = field(default_factory=list)
    description: str = ""
    solution: str = ""                 # 修复方案 / 补丁信息
    reference_links: List[str] = field(default_factory=list)
    published_date: str = ""           # YYYY-MM-DD
    updated_date: str = ""
    is_event: bool = False            # 是否为漏洞事件（如0day）
    patch_info: str = ""

    def to_dict(self) -> dict:
        return {
            "cnvd_id": self.cnvd_id,
            "title": self.title,
            "title_en": self.title_en,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "vulnerability_type": self.vulnerability_type,
            "affected_products": self.affected_products,
            "affected_vendors": self.affected_vendors,
            "description": self.description,
            "solution": self.solution,
            "reference_links": self.reference_links,
            "published_date": self.published_date,
            "updated_date": self.updated_date,
            "is_event": self.is_event,
            "patch_info": self.patch_info,
        }


@dataclass
class CNNVDVulnerability:
    """CNNVD vulnerability record (CNNVD-YYYYMM-NNNN format)."""
    cnnvd_id: str
    vuln_name: str
    cve_id: str = ""
    vuln_type: str = ""                # 漏洞类型
    hazard_level: str = ""             # 超危/高危/中危/低危
    cvss_score: float = 0.0
    affected: str = ""                 # 影响范围描述
    vuln_description: str = ""
    vuln_solution: str = ""
    reference: str = ""
    published_date: str = ""
    modified_date: str = ""

    def to_dict(self) -> dict:
        return {
            "cnnvd_id": self.cnnvd_id,
            "vuln_name": self.vuln_name,
            "cve_id": self.cve_id,
            "vuln_type": self.vuln_type,
            "hazard_level": self.hazard_level,
            "cvss_score": self.cvss_score,
            "affected": self.affected,
            "vuln_description": self.vuln_description,
            "vuln_solution": self.vuln_solution,
            "reference": self.reference,
            "published_date": self.published_date,
            "modified_date": self.modified_date,
        }


# ── CNVD Client ─────────────────────────────────────────────────────

class CNVDClient:
    """CNVD (国家信息安全漏洞共享平台) 漏洞查询客户端。

    CNVD是中国国家互联网应急中心(CNCERT)运营的国家级漏洞库。

    API endpoints (公开接口):
      - 漏洞搜索: 按关键词、厂商、产品搜索
      - 漏洞详情: 根据CNVD编号获取完整信息
      - CVE映射: CVE-ID到CNVD编号的映射

    Rate limit: 请控制在每分钟10次以内，尊重CNVD API使用政策。
    """

    CNVD_BASE = "https://www.cnvd.org.cn"
    CNVD_SEARCH_URL = f"{CNVD_BASE}/flaw/list"
    CNVD_DETAIL_URL = f"{CNVD_BASE}/flaw/show/"
    CVE_CNVD_MAP_URL = "https://api.github.com/repos/nu11secur1ty/CVE-CNVD-mapping/contents/CVE_CNVD_mapping.json"

    # 严重程度中文映射
    SEVERITY_MAP = {
        "超危": "CRITICAL",
        "高危": "HIGH",
        "中危": "MEDIUM",
        "低危": "LOW",
        "暂无": "NONE",
    }

    VULN_TYPE_MAP = {
        "SQL注入": "sql-injection",
        "代码注入": "code-injection",
        "命令注入": "command-injection",
        "跨站脚本": "xss",
        "跨站请求伪造": "csrf",
        "文件上传": "file-upload",
        "文件包含": "file-inclusion",
        "路径遍历": "path-traversal",
        "权限提升": "privilege-escalation",
        "信息泄露": "information-disclosure",
        "拒绝服务": "denial-of-service",
        "远程代码执行": "remote-code-execution",
        "缓冲区溢出": "buffer-overflow",
        "认证绕过": "authentication-bypass",
        "授权问题": "authorization-issue",
        "加密问题": "cryptographic-issue",
        "配置错误": "misconfiguration",
    }

    def __init__(self, timeout: float = 30.0, cache_ttl: int = 3600):
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._search_cache: Dict[str, tuple] = {}  # query -> (timestamp, results)
        self._detail_cache: Dict[str, tuple] = {}   # cnvd_id -> (timestamp, detail)
        self._last_request_time: float = 0.0
        self._rate_limit_interval: float = 6.0  # 10 requests/minute

    async def _rate_limited_request(self, client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
        """Make a rate-limited request."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._rate_limit_interval:
            import asyncio
            await asyncio.sleep(self._rate_limit_interval - elapsed)
        self._last_request_time = time.time()

        return await client.get(url, timeout=self._timeout, follow_redirects=True, **kwargs)

    async def search(
        self,
        keyword: str,
        max_results: int = 20,
        severity: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
    ) -> List[CNVDVulnerability]:
        """Search CNVD for vulnerabilities matching the keyword.

        Args:
            keyword: Search keyword (e.g., product name, vulnerability type in Chinese)
            max_results: Maximum number of results to return
            severity: Filter by severity (超危/高危/中危/低危)
            vendor: Filter by affected vendor
            product: Filter by affected product
        """
        cache_key = f"{keyword}:{severity}:{vendor}:{product}:{max_results}"
        if cache_key in self._search_cache:
            ts, cached = self._search_cache[cache_key]
            if time.time() - ts < self._cache_ttl:
                return cached

        results = []
        try:
            async with httpx.AsyncClient() as client:
                # CNVD公开搜索接口
                params = {
                    "flag": "true",
                    "keyword": keyword,
                    "numPerPage": min(max_results, 100),
                }
                headers = {
                    "User-Agent": "vuln-research-mcp/5.0 (Security Research)",
                    "Accept": "application/json, text/html",
                }

                resp = await self._rate_limited_request(
                    client, self.CNVD_SEARCH_URL, params=params, headers=headers
                )

                if resp.status_code == 200:
                    results = self._parse_search_results(resp.text, keyword)

        except Exception as e:
            logger.warning(f"CNVD search failed for '{keyword}': {e}")
            # Return cached results if available
            for key, (ts, cached) in self._search_cache.items():
                if keyword in key and time.time() - ts < self._cache_ttl * 4:
                    return cached

        # Apply filters
        if severity:
            results = [r for r in results if r.severity == severity]
        if vendor:
            results = [r for r in results if any(vendor.lower() in v.lower() for v in r.affected_vendors)]
        if product:
            results = [r for r in results if any(product.lower() in p.lower() for p in r.affected_products)]

        self._search_cache[cache_key] = (time.time(), results[:max_results])
        return results[:max_results]

    async def get_detail(self, cnvd_id: str) -> Optional[CNVDVulnerability]:
        """Get detailed information for a specific CNVD vulnerability."""
        if cnvd_id in self._detail_cache:
            ts, cached = self._detail_cache[cnvd_id]
            if time.time() - ts < self._cache_ttl:
                return cached

        try:
            async with httpx.AsyncClient() as client:
                headers = {"User-Agent": "vuln-research-mcp/5.0"}
                resp = await self._rate_limited_request(
                    client, f"{self.CNVD_DETAIL_URL}{cnvd_id}", headers=headers
                )
                if resp.status_code == 200:
                    detail = self._parse_detail(resp.text, cnvd_id)
                    if detail:
                        self._detail_cache[cnvd_id] = (time.time(), detail)
                        return detail

        except Exception as e:
            logger.warning(f"CNVD detail fetch failed for '{cnvd_id}': {e}")

        return None

    async def search_by_cve(self, cve_id: str) -> Optional[CNVDVulnerability]:
        """Search CNVD by CVE ID — find the CNVD equivalent of a CVE."""
        # Try direct mapping
        results = await self.search(cve_id, max_results=5)

        for result in results:
            if result.cve_id.upper() == cve_id.upper():
                return result

        # If direct mapping fails, search by CVE number
        cve_number = cve_id.replace("CVE-", "").replace("cve-", "")
        results2 = await self.search(cve_number, max_results=10)

        for result in results2:
            if cve_id.upper() in result.cve_id.upper() or cve_id.upper() in result.description.upper():
                return result

        return None

    async def batch_search(self, keywords: List[str]) -> Dict[str, List[CNVDVulnerability]]:
        """Batch search multiple keywords (e.g., product names)."""
        import asyncio
        tasks = [self.search(kw) for kw in keywords]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        result = {}
        for kw, res in zip(keywords, results_list):
            if isinstance(res, Exception):
                result[kw] = []
            else:
                result[kw] = res
        return result

    async def get_latest_vulnerabilities(self, days: int = 7) -> List[CNVDVulnerability]:
        """Get recent vulnerabilities from the last N days."""
        # CNVD index page lists recent vulnerabilities
        return await self.search("", max_results=50)

    async def search_by_type(self, vuln_type: str) -> List[CNVDVulnerability]:
        """Search CNVD by vulnerability type (中文分类).

        Example types: SQL注入, 代码注入, 跨站脚本, 文件上传, 远程代码执行
        """
        return await self.search(vuln_type, max_results=30)

    def get_vuln_type_english(self, cn_type: str) -> str:
        """Map Chinese vulnerability type to English CWE-like name."""
        return self.VULN_TYPE_MAP.get(cn_type, cn_type)

    def clear_cache(self):
        """Clear all cached results."""
        self._search_cache.clear()
        self._detail_cache.clear()

    # ── Parsers ─────────────────────────────────────────────────

    def _parse_search_results(self, html: str, keyword: str) -> List[CNVDVulnerability]:
        """Parse CNVD search results page (HTML scraping fallback)."""
        results = []

        import re
        # Parse CNVD list page — look for vulnerability entries
        # Pattern: CNVD-YYYY-NNNNNN format
        cnvd_pattern = re.findall(r'CNVD-\d{4}-\d{4,}', html)

        # Extract titles from the page
        title_pattern = re.findall(r'<a[^>]*title="([^"]*)"[^>]*>.*?CNVD', html)

        for i, cnvd_id in enumerate(cnvd_pattern):
            if i >= len(cnvd_pattern):
                break
            title = title_pattern[i] if i < len(title_pattern) else f"CNVD Vulnerability {cnvd_id}"

            results.append(CNVDVulnerability(
                cnvd_id=cnvd_id,
                title=title,
                published_date="",
            ))

        return results

    def _parse_detail(self, html: str, cnvd_id: str) -> Optional[CNVDVulnerability]:
        """Parse a single CNVD vulnerability detail page."""
        import re

        title = ""
        cve_id = ""
        severity = ""
        description = ""
        solution = ""
        vuln_type = ""

        # Extract title
        title_match = re.search(r'<h1[^>]*>(.*?)</h1>', html, re.DOTALL)
        if title_match:
            title = re.sub(r'<[^>]+>', '', title_match.group(1)).strip()

        # Extract CVE ID
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', html, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()

        # Extract severity
        sev_match = re.search(r'(超危|高危|中危|低危)', html)
        if sev_match:
            severity = sev_match.group(1)

        # Extract vulnerability type
        for cn_type in self.VULN_TYPE_MAP:
            if cn_type in html:
                vuln_type = cn_type
                break

        # Extract description (between "漏洞简介" and next section)
        desc_match = re.search(r'漏洞简介</td>.*?<td[^>]*>(.*?)</td>', html, re.DOTALL)
        if desc_match:
            description = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()

        # Extract solution
        sol_match = re.search(r'(?:解决方案|修复方案)</td>.*?<td[^>]*>(.*?)</td>', html, re.DOTALL)
        if sol_match:
            solution = re.sub(r'<[^>]+>', '', sol_match.group(1)).strip()

        return CNVDVulnerability(
            cnvd_id=cnvd_id,
            title=title,
            cve_id=cve_id,
            severity=severity,
            vulnerability_type=vuln_type,
            description=description,
            solution=solution,
        )


# ── CNNVD Client ────────────────────────────────────────────────────

class CNNVDClient:
    """CNNVD (国家信息安全漏洞库) 漏洞查询客户端。

    CNNVD由中国信息安全测评中心运营，是中国网络安全等级保护合规的重要参考。

    API: 官方提供JSON接口
    """

    CNNVD_API_BASE = "https://www.cnnvd.org.cn"

    def __init__(self, api_key: str = "", timeout: float = 30.0, cache_ttl: int = 3600):
        self._api_key = api_key or os.environ.get("CNNVD_API_KEY", "")
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, tuple] = {}

    async def search(self, keyword: str, max_results: int = 10) -> List[CNNVDVulnerability]:
        """Search CNNVD for vulnerabilities."""
        cache_key = f"search:{keyword}:{max_results}"
        if cache_key in self._cache:
            ts, cached = self._cache[cache_key]
            if time.time() - ts < self._cache_ttl:
                return cached

        results = []
        try:
            async with httpx.AsyncClient() as client:
                headers = {"User-Agent": "vuln-research-mcp/5.0"}
                params = {
                    "keyword": keyword,
                    "type": "search",
                }
                if self._api_key:
                    headers["Authorization"] = f"Bearer {self._api_key}"

                resp = await client.get(
                    f"{self.CNNVD_API_BASE}/web/homePage/cnnvdVulList",
                    params=params, headers=headers, timeout=self._timeout
                )

                if resp.status_code == 200:
                    data = resp.json()
                    results = self._parse_results(data, max_results)

        except Exception as e:
            logger.warning(f"CNNVD search failed for '{keyword}': {e}")

        self._cache[cache_key] = (time.time(), results)
        return results

    async def get_detail(self, cnnvd_id: str) -> Optional[CNNVDVulnerability]:
        """Get CNNVD vulnerability detail."""
        try:
            async with httpx.AsyncClient() as client:
                headers = {"User-Agent": "vuln-research-mcp/5.0"}
                if self._api_key:
                    headers["Authorization"] = f"Bearer {self._api_key}"

                resp = await client.get(
                    f"{self.CNNVD_API_BASE}/web/homePage/cnnvdVulList",
                    params={"cnnvd_id": cnnvd_id},
                    headers=headers, timeout=self._timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("records"):
                        return self._parse_single(data["records"][0])

        except Exception as e:
            logger.warning(f"CNNVD detail fetch failed for '{cnnvd_id}': {e}")

        return None

    def _parse_results(self, data: dict, max_results: int) -> List[CNNVDVulnerability]:
        results = []
        records = data.get("records", [])[:max_results]
        for record in records:
            vuln = self._parse_single(record)
            if vuln:
                results.append(vuln)
        return results

    def _parse_single(self, record: dict) -> Optional[CNNVDVulnerability]:
        try:
            return CNNVDVulnerability(
                cnnvd_id=record.get("cnnvdCode", ""),
                vuln_name=record.get("vulName", ""),
                cve_id=record.get("cveCode", ""),
                vuln_type=record.get("vulType", ""),
                hazard_level=record.get("hazardLevel", ""),
                vuln_description=record.get("vulDesc", ""),
                vuln_solution=record.get("vulSolution", ""),
                reference=record.get("reference", ""),
                published_date=record.get("publishTime", ""),
                modified_date=record.get("modifyTime", ""),
            )
        except Exception as e:
            logger.debug(f"Failed to parse CNNVD record: {e}")
            return None


# ── CVE→CNVD/CNNVD 映射 ─────────────────────────────────────────────

class CVECNMapper:
    """Map CVE IDs to CNVD and CNNVD equivalent IDs."""

    def __init__(self):
        self._cve_to_cnvd: Dict[str, str] = {}
        self._cve_to_cnnvd: Dict[str, str] = {}
        self._loaded = False

    async def load_mappings(self) -> bool:
        """Load CVE→CNVD/CNNVD mappings from local cache or remote."""
        if self._loaded:
            return True

        # Try local cache first
        cache_dir = os.environ.get("VULNRESEARCH_DATA_DIR", os.path.expanduser("~/.vuln-research-mcp/data"))
        mapping_file = os.path.join(cache_dir, "cve_cn_mappings.json")

        if os.path.exists(mapping_file):
            try:
                with open(mapping_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._cve_to_cnvd = data.get("cve_to_cnvd", {})
                self._cve_to_cnnvd = data.get("cve_to_cnnvd", {})
                self._loaded = True
                return True
            except Exception:
                pass

        # Try remote mapping
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    CNVDClient.CVE_CNVD_MAP_URL,
                    headers={"User-Agent": "vuln-research-mcp/5.0"},
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Response from GitHub API: {content: base64_encoded}
                    if "content" in data:
                        import base64
                        decoded = base64.b64decode(data["content"]).decode('utf-8')
                        mappings = json.loads(decoded)
                        self._cve_to_cnvd = mappings.get("cve_to_cnvd", {})
                        if "cve_to_cnnvd" in mappings:
                            self._cve_to_cnnvd = mappings["cve_to_cnnvd"]

        except Exception as e:
            logger.info(f"Could not load remote CVE-CN mappings: {e}")

        self._loaded = True
        return bool(self._cve_to_cnvd)

    def get_cnvd(self, cve_id: str) -> Optional[str]:
        """Get CNVD ID for a given CVE."""
        normalized = cve_id.upper()
        return self._cve_to_cnvd.get(normalized)

    def get_cnnvd(self, cve_id: str) -> Optional[str]:
        """Get CNNVD ID for a given CVE."""
        normalized = cve_id.upper()
        return self._cve_to_cnnvd.get(normalized)


# ── Global Singleton ────────────────────────────────────────────────

_cnvd_client: Optional[CNVDClient] = None
_cnnvd_client: Optional[CNNVDClient] = None
_cve_cn_mapper: Optional[CVECNMapper] = None


def get_cnvd_client() -> CNVDClient:
    global _cnvd_client
    if _cnvd_client is None:
        _cnvd_client = CNVDClient()
    return _cnvd_client


def get_cnnvd_client() -> CNNVDClient:
    global _cnnvd_client
    if _cnnvd_client is None:
        _cnnvd_client = CNNVDClient()
    return _cnnvd_client


def get_cve_cn_mapper() -> CVECNMapper:
    global _cve_cn_mapper
    if _cve_cn_mapper is None:
        _cve_cn_mapper = CVECNMapper()
    return _cve_cn_mapper
