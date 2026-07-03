"""Asset-Vulnerability Correlation Engine.

Automatically matches discovered assets (services, versions, CPEs)
to known CVEs and produces ranked findings.

Algorithm:
    1. For each asset with service+version, compute CPE string
    2. Query local CPE-to-CVE mapping and online NVD API
    3. Enrich each CVE with EPSS, KEV, exploit availability
    4. Compute risk score using the unified model
    5. Rank findings by risk_score DESC
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from src.bus.event_bus import Event, get_event_bus
from src.db.models import Asset, Finding, Severity

CPE_PRODUCT_MAP: Dict[str, str] = {
    "apache": "cpe:2.3:a:apache:{product}:{version}:*:*:*:*:*:*:*",
    "nginx": "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
    "mysql": "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
    "mariadb": "cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*",
    "postgresql": "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*",
    "redis": "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*",
    "mongodb": "cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*",
    "openssh": "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*",
    "openssl": "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*",
    "tomcat": "cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*",
    "wordpress": "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
    "drupal": "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
    "joomla": "cpe:2.3:a:joomla:joomla:{version}:*:*:*:*:*:*:*",
    "django": "cpe:2.3:a:djangoproject:django:{version}:*:*:*:*:*:*:*",
    "flask": "cpe:2.3:a:palletsprojects:flask:{version}:*:*:*:*:*:*:*",
    "spring": "cpe:2.3:a:vmware:spring_framework:{version}:*:*:*:*:*:*:*",
    "laravel": "cpe:2.3:a:laravel:laravel:{version}:*:*:*:*:*:*:*",
    "nodejs": "cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*",
    "kubernetes": "cpe:2.3:a:kubernetes:kubernetes:{version}:*:*:*:*:*:*:*",
    "docker": "cpe:2.3:a:docker:docker:{version}:*:*:*:*:*:*:*",
    "jenkins": "cpe:2.3:a:jenkins:jenkins:{version}:*:*:*:*:*:*:*",
    "gitlab": "cpe:2.3:a:gitlab:gitlab:{version}:*:*:*:*:*:*:*",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*",
    "kibana": "cpe:2.3:a:elastic:kibana:{version}:*:*:*:*:*:*:*",
    "rabbitmq": "cpe:2.3:a:vmware:rabbitmq:{version}:*:*:*:*:*:*:*",
    "php": "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*",
    "python": "cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
    "ruby": "cpe:2.3:a:ruby-lang:ruby:{version}:*:*:*:*:*:*:*",
}

KNOWN_VERSION_VULNS: Dict[str, List[Dict[str, Any]]] = {
    "apache:2.4.49": [
        {"cve": "CVE-2021-41773", "cvss": 7.5, "epss": 97.5, "kev": True, "desc": "Path traversal/RCE in Apache HTTP Server 2.4.49"},
    ],
    "apache:2.4.50": [
        {"cve": "CVE-2021-42013", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Path traversal/RCE in Apache HTTP Server 2.4.50"},
    ],
    "openssh:7.4": [
        {"cve": "CVE-2018-15473", "cvss": 5.3, "epss": 97.5, "kev": False, "desc": "OpenSSH user enumeration"},
    ],
    "openssh:8.5": [
        {"cve": "CVE-2021-41617", "cvss": 7.0, "epss": 50.0, "kev": False, "desc": "OpenSSH privilege escalation"},
    ],
    "openssl:1.1.1": [
        {"cve": "CVE-2022-3602", "cvss": 7.5, "epss": 60.0, "kev": False, "desc": "OpenSSL buffer overflow (CVE-2022-3602/CVE-2022-3786)"},
    ],
    "wordpress:5.0": [
        {"cve": "CVE-2019-8942", "cvss": 9.8, "epss": 30.0, "kev": False, "desc": "WordPress arbitrary file deletion"},
    ],
    "wordpress:5.7": [
        {"cve": "CVE-2021-29447", "cvss": 6.5, "epss": 20.0, "kev": False, "desc": "WordPress XXE vulnerability"},
    ],
    "tomcat:9.0.31": [
        {"cve": "CVE-2020-9484", "cvss": 7.0, "epss": 85.0, "kev": False, "desc": "Tomcat session persistence RCE"},
    ],
    "tomcat:8.5.60": [
        {"cve": "CVE-2021-25329", "cvss": 7.0, "epss": 40.0, "kev": False, "desc": "Tomcat incomplete fix for CVE-2020-9484"},
    ],
    "nginx:1.20.1": [
        {"cve": "CVE-2021-3618", "cvss": 7.4, "epss": 10.0, "kev": False, "desc": "nginx ALPACA TLS vulnerability"},
    ],
    "mysql:5.7": [
        {"cve": "CVE-2020-14750", "cvss": 7.5, "epss": 5.0, "kev": False, "desc": "Oracle MySQL Server vulnerability"},
    ],
    "redis:5.0": [
        {"cve": "CVE-2022-24736", "cvss": 7.0, "epss": 15.0, "kev": False, "desc": "Redis Lua script execution vulnerability"},
    ],
    "django:2.2": [
        {"cve": "CVE-2021-35042", "cvss": 9.8, "epss": 40.0, "kev": False, "desc": "Django SQL injection in QuerySet.order_by()"},
    ],
    "django:3.0": [
        {"cve": "CVE-2021-3281", "cvss": 5.3, "epss": 20.0, "kev": False, "desc": "Django directory traversal"},
    ],
    "spring:5.2": [
        {"cve": "CVE-2022-22965", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Spring4Shell RCE vulnerability"},
    ],
    "jenkins:2.263": [
        {"cve": "CVE-2021-21605", "cvss": 9.8, "epss": 30.0, "kev": False, "desc": "Jenkins arbitrary file read via directory traversal"},
    ],
    "kubernetes:1.20": [
        {"cve": "CVE-2021-25741", "cvss": 8.8, "epss": 25.0, "kev": False, "desc": "Kubernetes symlink exchange can allow host filesystem access"},
    ],
    "php:7.4": [
        {"cve": "CVE-2021-21703", "cvss": 7.0, "epss": 15.0, "kev": False, "desc": "PHP-FPM privilege escalation in PHP 7.4"},
    ],
    "php:8.0": [
        {"cve": "CVE-2022-31625", "cvss": 7.5, "epss": 10.0, "kev": False, "desc": "PHP pg_query_params() uninitialized array memory disclosure"},
    ],
    "elasticsearch:7.10": [
        {"cve": "CVE-2021-22145", "cvss": 7.5, "epss": 20.0, "kev": False, "desc": "Elasticsearch information disclosure via error messages"},
    ],
}

BANNER_PATTERNS: Dict[str, str] = {
    # Order matters: more specific patterns before generic ones
    "OpenSSH": "openssh",
    "Apache Tomcat": "tomcat",
    "Tomcat": "tomcat",
    "Apache/2": "apache",
    "Apache": "apache",
    "nginx": "nginx",
    "MySQL": "mysql",
    "MariaDB": "mariadb",
    "PostgreSQL": "postgresql",
    "Redis": "redis",
    "MongoDB": "mongodb",
    "WordPress": "wordpress",
    "Drupal": "drupal",
    "Django": "django",
    "Spring Boot": "spring",
    "Spring": "spring",
    "PHP": "php",
    "Python": "python",
    "Node.js": "nodejs",
    "Jenkins": "jenkins",
    "Elasticsearch": "elasticsearch",
    "Kibana": "kibana",
    "RabbitMQ": "rabbitmq",
    "Docker": "docker",
    "Kubernetes": "kubernetes",
    "GitLab": "gitlab",
    "Laravel": "laravel",
}


@dataclass
class CorrelationResult:
    asset: Asset
    matched_vulns: List[Dict[str, Any]] = field(default_factory=list)
    total_risk: float = 0.0
    top_severity: str = "info"


class Correlator:
    """Correlates discovered assets to known vulnerabilities."""

    def __init__(self, nvd_api_key: str = ""):
        self._nvd_api_key = nvd_api_key
        self._bus = get_event_bus()

    def _parse_banner(self, banner: str) -> Optional[Tuple[str, str]]:
        """Extract product name and version from a service banner.

        Examples:
            "Apache/2.4.49 (Unix)" -> ("apache", "2.4.49")
            "OpenSSH_7.4p1" -> ("openssh", "7.4")
            "nginx/1.20.1" -> ("nginx", "1.20.1")
        """
        for pattern, product in BANNER_PATTERNS.items():
            if pattern.lower() in banner.lower() or pattern in banner:
                import re
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
                if version_match:
                    return (product, version_match.group(1))
        return None

    def _lookup_local(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Look up known vulnerabilities in the local mapping."""
        key = f"{product}:{version}"
        exact_key = key

        vulns = KNOWN_VERSION_VULNS.get(exact_key, [])

        if not vulns:
            for k in KNOWN_VERSION_VULNS:
                if k.startswith(f"{product}:") and k.split(":")[1].startswith(version.split(".")[0]):
                    vulns = KNOWN_VERSION_VULNS[k]
                    break

        return [
            {
                "cve": v["cve"],
                "cvss_score": v["cvss"],
                "epss_score": v["epss"],
                "is_kev": v.get("kev", False),
                "description": v["desc"],
                "remediation": f"Upgrade {product} from {version} to latest version",
                "source": "local",
            }
            for v in vulns
        ]

    async def _lookup_nvd(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Query NVD API for CVEs matching product+version."""
        if not self._nvd_api_key:
            return []

        cpe_match = CPE_PRODUCT_MAP.get(product)
        if not cpe_match:
            return []

        cpe_str = cpe_match.format(product=product, version=version)

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                params: Dict[str, Any] = {
                    "cpeName": cpe_str,
                    "resultsPerPage": 20,
                }
                headers = {"apiKey": self._nvd_api_key}
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params, headers=headers,
                )
                if resp.status_code != 200:
                    return []

                data = resp.json()
                results = []
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    metrics = cve_data.get("metrics", {})

                    cvss31 = None
                    if "cvssMetricV31" in metrics:
                        cvss31 = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        cvss31 = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                    desc_text = ""
                    for desc in cve_data.get("descriptions", []):
                        if desc.get("lang") == "en":
                            desc_text = desc.get("value", "")[:200]
                            break

                    results.append({
                        "cve": cve_id,
                        "cvss_score": cvss31 or 0,
                        "description": desc_text,
                        "remediation": "Refer to vendor advisory",
                        "source": "nvd",
                    })

                return results
        except Exception:
            return []

    async def correlate_asset(self, asset: Asset,
                              include_online: bool = False) -> CorrelationResult:
        """Correlate an asset to known vulnerabilities."""
        result = CorrelationResult(asset=asset)
        vulns = []

        banner = asset.banner or ""
        service = asset.service or ""
        version = asset.version or ""

        if banner:
            parsed = self._parse_banner(banner if banner else f"{service} {version}")
            if parsed:
                product, ver = parsed
                local_vulns = self._lookup_local(product, ver)
                vulns.extend(local_vulns)

                if include_online:
                    online_vulns = await self._lookup_nvd(product, ver)
                    seen_cves = {v["cve"] for v in vulns}
                    for v in online_vulns:
                        if v["cve"] not in seen_cves:
                            vulns.append(v)

        if (service or version) and not vulns:
            if service and version:
                local_vulns = self._lookup_local(service.lower(), version)
                vulns.extend(local_vulns)

        if not vulns and asset.cpe:
            cpe_product = asset.cpe.split(":")[4] if len(asset.cpe.split(":")) > 4 else ""
            cpe_version = asset.cpe.split(":")[5] if len(asset.cpe.split(":")) > 5 else ""
            if cpe_product and cpe_version:
                local_vulns = self._lookup_local(cpe_product, cpe_version)
                vulns.extend(local_vulns)

        max_severity = "info"
        total_risk = 0.0

        for v in vulns:
            cvss = v.get("cvss_score", 0)
            epss = v.get("epss_score", 0)
            is_kev = v.get("is_kev", False)
            risk = (cvss / 10.0) * (1 + epss / 100.0)
            if is_kev:
                risk *= 2.0
            v["risk_score"] = round(risk, 2)
            total_risk += risk

            if cvss >= 9.0:
                max_severity = "critical"
            elif cvss >= 7.0 and max_severity != "critical":
                max_severity = "high"
            elif cvss >= 4.0 and max_severity not in ("critical", "high"):
                max_severity = "medium"
            elif cvss > 0 and max_severity not in ("critical", "high", "medium"):
                max_severity = "low"

            vulns.sort(key=lambda x: x["risk_score"], reverse=True)
            result.matched_vulns = vulns
            result.total_risk = round(total_risk, 2)
            result.top_severity = max_severity

            self._bus.publish(Event(
                event_type="correlation_complete",
                data={
                    "asset_id": asset.id,
                    "asset_value": asset.value,
                    "vuln_count": len(vulns),
                    "top_severity": max_severity,
                    "total_risk": total_risk,
                },
                source="correlator",
            ))

        return result

    def correlate_batch(self, assets: List[Asset],
                        include_online: bool = False) -> List[CorrelationResult]:
        """Synchronously correlate a batch of assets."""
        results = []
        for asset in assets:
            local_vulns = self._lookup_local(asset.service.lower(), asset.version or "")
            result = CorrelationResult(asset=asset)
            result.matched_vulns = local_vulns
            result.total_risk = sum(v.get("risk_score", 0) for v in local_vulns)
            if local_vulns:
                max_cvss = max(v.get("cvss_score", 0) for v in local_vulns)
                if max_cvss >= 9.0:
                    result.top_severity = "critical"
                elif max_cvss >= 7.0:
                    result.top_severity = "high"
                elif max_cvss >= 4.0:
                    result.top_severity = "medium"
                elif max_cvss > 0:
                    result.top_severity = "low"
            results.append(result)
        return sorted(results, key=lambda r: r.total_risk, reverse=True)

    def findings_from_result(self, project_id: int, result: CorrelationResult) -> List[Finding]:
        """Convert correlation results to Finding objects."""
        findings = []
        for v in result.matched_vulns:
            cvss = v.get("cvss_score", 0)
            severity = "info"
            if cvss >= 9.0:
                severity = "critical"
            elif cvss >= 7.0:
                severity = "high"
            elif cvss >= 4.0:
                severity = "medium"
            elif cvss > 0:
                severity = "low"

            finding = Finding(
                project_id=project_id,
                asset_id=result.asset.id,
                title=v.get("cve", ""),
                description=v.get("description", ""),
                severity=severity,
                cvss_score=cvss,
                cve_ids=v.get("cve", ""),
                epss_score=v.get("epss_score"),
                is_kev=v.get("is_kev", False),
                impact=f"CVSS {cvss}, Risk Score {v.get('risk_score', 0)}",
                remediation=v.get("remediation", ""),
                risk_score=v.get("risk_score", 0),
                tags=result.asset.service,
            )
            findings.append(finding)
        return findings
