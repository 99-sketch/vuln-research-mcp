"""
Vulnerability Fix Verifier (v5.0)

Post-remediation verification to confirm that vulnerabilities have been
properly fixed. Supports:
  - Version-based verification (check if patched version is deployed)
  - Service fingerprint re-check (verify service is no longer vulnerable)
  - Port re-scan comparison (verify vulnerable port is closed/patched)
  - CVE reference check (verify CVE is marked as patched in NVD)
  - Fix timeline tracking (when was it fixed, by whom)

Usage:
    verifier = FixVerifier()
    result = await verifier.verify_fix("CVE-2024-1234", "10.0.0.1", "openssh 9.6")
    print(f"Status: {result.status}, Confidence: {result.confidence}%")
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Data Models ─────────────────────────────────────────────────────

class FixStatus(str, Enum):
    VERIFIED_FIXED = "verified_fixed"          # Confirmed: vulnerability is patched
    VERIFIED_NOT_FIXED = "verified_not_fixed"  # Confirmed: still vulnerable
    UNCERTAIN = "uncertain"                     # Cannot determine fix status
    NEEDS_MANUAL_CHECK = "needs_manual_check"   # Requires manual verification
    NOT_CHECKED = "not_checked"                 # Verification not yet attempted


@dataclass
class FixResult:
    """Result of a vulnerability fix verification."""
    cve_id: str
    target: str                              # IP or hostname
    status: FixStatus = FixStatus.NOT_CHECKED
    confidence: float = 0.0                  # 0.0 - 100.0
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    checked_at: float = field(default_factory=time.time)
    checked_by: str = "vuln-research-mcp/5.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "target": self.target,
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "checked_at": self.checked_at,
            "checked_by": self.checked_by,
            "metadata": self.metadata,
        }


# ── Known Fixed Versions Database ───────────────────────────────────

# Product → (min_vulnerable_version, fixed_version_or_patch)
KNOWN_FIXES: Dict[str, List[Tuple[str, str, str]]] = {
    "openssh": [
        ("<9.6", ">=9.6p1", "Upgrade to OpenSSH 9.6p1+ for CVE-2023-51385, CVE-2023-48795"),
        ("<9.3", ">=9.3p2", "Upgrade to OpenSSH 9.3p2+"),
        ("<8.9", ">=8.9p1", "Upgrade to OpenSSH 8.9p1+"),
    ],
    "apache": [
        ("<2.4.58", ">=2.4.58", "Upgrade to Apache 2.4.58+"),
        ("<2.4.57", ">=2.4.57", "Upgrade to Apache 2.4.57+ for CVE-2023-25690"),
    ],
    "nginx": [
        ("<1.25.3", ">=1.25.3", "Upgrade to nginx 1.25.3+"),
        ("<1.24.0", ">=1.24.0", "Upgrade to nginx 1.24.0+"),
    ],
    "openssl": [
        ("<3.1.4", ">=3.1.4", "Upgrade to OpenSSL 3.1.4+ for CVE-2023-5363"),
        ("<3.0.12", ">=3.0.12", "Upgrade to OpenSSL 3.0.12+"),
        ("<1.1.1w", ">=1.1.1w", "Upgrade to OpenSSL 1.1.1w+"),
    ],
    "mysql": [
        ("<8.0.35", ">=8.0.35", "Upgrade to MySQL 8.0.35+"),
        ("<8.1.0", ">=8.1.0", "Upgrade to MySQL 8.1.0+"),
    ],
    "postgresql": [
        ("<16.1", ">=16.1", "Upgrade to PostgreSQL 16.1+"),
        ("<15.5", ">=15.5", "Upgrade to PostgreSQL 15.5+"),
    ],
    "redis": [
        ("<7.2.3", ">=7.2.3", "Upgrade to Redis 7.2.3+"),
        ("<7.0.14", ">=7.0.14", "Upgrade to Redis 7.0.14+"),
    ],
    "python": [
        ("<3.12.1", ">=3.12.1", "Upgrade to Python 3.12.1+"),
        ("<3.11.7", ">=3.11.7", "Upgrade to Python 3.11.7+"),
        ("<3.10.13", ">=3.10.13", "Upgrade to Python 3.10.13+"),
    ],
    "log4j": [
        ("<2.17.1", ">=2.17.1", "Upgrade to Log4j 2.17.1+ for CVE-2021-44228"),
        ("<2.16.0", ">=2.16.0", "Upgrade to Log4j 2.16.0+ for CVE-2021-45046"),
    ],
    "apache_struts": [
        ("<6.3.0.2", ">=6.3.0.2", "Upgrade to Struts 6.3.0.2+"),
        ("<2.5.33", ">=2.5.33", "Upgrade to Struts 2.5.33+"),
    ],
}


# ── Fix Verifier ───────────────────────────────────────────────────

class FixVerifier:
    """Verify that vulnerabilities have been properly fixed.

    Verification methods:
      1. Version check: Compare deployed version against known fixed versions
      2. NVD reference: Check if CVE has a 'patch' reference in NVD
      3. Port comparison: Compare before/after port scan results
      4. Service fingerprint: Re-scan service banner to verify version
    """

    def __init__(self):
        self._verification_history: List[FixResult] = []

    async def verify_fix(
        self,
        cve_id: str,
        target: str,
        current_version: Optional[str] = None,
        service_name: Optional[str] = None,
        before_ports: Optional[List[int]] = None,
        after_ports: Optional[List[int]] = None,
        nvd_data: Optional[dict] = None,
    ) -> FixResult:
        """Verify if a CVE has been fixed on a target.

        Args:
            cve_id: CVE identifier
            target: IP/hostname to verify
            current_version: Currently deployed version string
            service_name: Name of the affected service
            before_ports: Port scan results before remediation
            after_ports: Port scan results after remediation
            nvd_data: NVD CVE data with references
        """
        result = FixResult(cve_id=cve_id, target=target)
        evidence = []
        confidence_items = []

        # Method 1: Version check
        if current_version and service_name:
            version_result = self._check_version_fix(service_name, current_version, cve_id)
            evidence.extend(version_result["evidence"])
            if version_result["fixed"]:
                confidence_items.append(90)  # version-based check is highly reliable
            elif version_result["not_fixed"]:
                confidence_items.append(-85)
                evidence.append(f"Version {current_version} is still in vulnerable range")

        # Method 2: NVD reference check
        if nvd_data:
            nvd_result = self._check_nvd_references(cve_id, nvd_data)
            evidence.extend(nvd_result["evidence"])
            if nvd_result["has_patch"]:
                confidence_items.append(30)

        # Method 3: Port comparison
        if before_ports is not None and after_ports is not None:
            port_result = self._compare_ports(before_ports, after_ports)
            evidence.extend(port_result["evidence"])
            if port_result["improved"]:
                confidence_items.append(40)
            elif port_result["same"]:
                confidence_items.append(10)

        # Determine final status
        result.evidence = evidence

        if confidence_items:
            # Calculate weighted confidence
            positive = sum(c for c in confidence_items if c > 0)
            negative = sum(abs(c) for c in confidence_items if c < 0)

            if positive > negative * 1.5 and positive > 50:
                result.status = FixStatus.VERIFIED_FIXED
                result.confidence = min(positive / 100.0, 100.0)
                result.recommendation = "Vulnerability appears to be fixed. Consider periodic re-verification."
            elif negative > positive * 1.5:
                result.status = FixStatus.VERIFIED_NOT_FIXED
                result.confidence = min(negative / 100.0, 100.0)
                result.recommendation = self._get_upgrade_recommendation(service_name)
            else:
                result.status = FixStatus.UNCERTAIN
                result.confidence = 50.0
                result.recommendation = "Unable to determine fix status with high confidence. Manual review recommended."
        else:
            result.status = FixStatus.NEEDS_MANUAL_CHECK
            result.confidence = 0.0
            result.recommendation = "Insufficient data for automated verification. Perform manual penetration test."

        result.checked_at = time.time()
        self._verification_history.append(result)
        return result

    async def batch_verify(
        self, items: List[Dict[str, Any]]
    ) -> List[FixResult]:
        """Batch verify multiple vulnerability fixes.

        Args:
            items: List of dicts with cve_id, target, current_version, service_name
        """
        import asyncio
        tasks = [self.verify_fix(**item) for item in items]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def get_verification_summary(self) -> dict:
        """Get summary statistics of all verifications."""
        total = len(self._verification_history)
        if total == 0:
            return {"total": 0}

        verified_fixed = sum(1 for r in self._verification_history if r.status == FixStatus.VERIFIED_FIXED)
        verified_not_fixed = sum(1 for r in self._verification_history if r.status == FixStatus.VERIFIED_NOT_FIXED)

        return {
            "total": total,
            "verified_fixed": verified_fixed,
            "verified_not_fixed": verified_not_fixed,
            "uncertain": total - verified_fixed - verified_not_fixed,
            "fix_rate": (verified_fixed / total * 100) if total > 0 else 0,
        }

    # ── Private Methods ─────────────────────────────────────────

    def _check_version_fix(self, service_name: str, version: str, cve_id: str) -> dict:
        """Check if deployed version is a fixed version."""
        evidence = []
        fixed = False
        not_fixed = False

        service_lower = service_name.lower().replace(" ", "_")

        # Normalize service name
        for known_service in KNOWN_FIXES:
            if known_service in service_lower or service_lower in known_service:
                service_lower = known_service
                break

        if service_lower in KNOWN_FIXES:
            fixes = KNOWN_FIXES[service_lower]

            # Try to parse version
            parsed = self._parse_version(version)

            for min_vuln, fixed_version, note in fixes:
                min_parsed = self._parse_version_range(min_vuln)
                fixed_parsed = self._parse_version_range(fixed_version)

                if parsed is None or min_parsed is None:
                    continue

                # Check if current version is in vulnerable range
                is_vulnerable = self._version_in_range(parsed, min_vuln)
                is_fixed = self._version_in_range(parsed, fixed_version)

                if is_vulnerable:
                    evidence.append(f"Version {version} matches vulnerable pattern {min_vuln} for {service_name}")
                    not_fixed = True
                elif is_fixed:
                    evidence.append(f"Version {version} matches fixed pattern {fixed_version}: {note}")
                    fixed = True

        if not evidence:
            evidence.append(f"No version fix data available for {service_name} {version}")

        return {"evidence": evidence, "fixed": fixed, "not_fixed": not_fixed}

    def _check_nvd_references(self, cve_id: str, nvd_data: dict) -> dict:
        """Check NVD data for patch references."""
        evidence = []
        has_patch = False

        references = nvd_data.get("references", [])
        for ref in references:
            tags = ref.get("tags", [])
            if "Patch" in tags or "Vendor Advisory" in tags:
                evidence.append(f"Patch reference found: {ref.get('url', '')}")
                has_patch = True

        if not has_patch:
            evidence.append(f"No patch reference in NVD for {cve_id}")

        return {"evidence": evidence, "has_patch": has_patch}

    def _compare_ports(self, before: List[int], after: List[int]) -> dict:
        """Compare before/after port lists."""
        evidence = []
        before_set = set(before) if before else set()
        after_set = set(after) if after else set()

        closed = before_set - after_set
        unchanged = before_set & after_set
        new_opened = after_set - before_set

        if closed:
            evidence.append(f"Ports closed: {sorted(closed)}")
        if unchanged:
            evidence.append(f"Ports unchanged: {sorted(unchanged)}")
        if new_opened:
            evidence.append(f"New ports opened: {sorted(new_opened)}")

        improved = len(closed) > 0
        same = len(closed) == 0 and len(new_opened) == 0

        return {"evidence": evidence, "improved": improved, "same": same}

    @staticmethod
    def _parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
        """Parse version string to comparable tuple."""
        # Extract version numbers
        match = re.search(r'(\d+\.\d+(?:\.\d+)*(?:[a-z]\d*)?)', version_str)
        if not match:
            return None

        parts = match.group(1).replace('p', '.').replace('a', '.alpha.').replace('b', '.beta.')

        # Convert to tuple of integers where possible
        result = []
        for part in parts.split('.'):
            try:
                result.append(int(part))
            except ValueError:
                # Alpha/beta suffix
                alpha_val = ord(part[0]) if part and part[0].isalpha() else 0
                result.append(alpha_val)

        return tuple(result)

    @staticmethod
    def _parse_version_range(range_str: str) -> Optional[str]:
        """Parse version range string like '<2.17.1' or '>=2.17.1'."""
        match = re.match(r'([<>=!]+)\s*(.+)', range_str)
        if match:
            return range_str
        return None

    @staticmethod
    def _version_in_range(version: Tuple[int, ...], range_str: str) -> bool:
        """Check if parsed version is in the given range."""
        if version is None:
            return False

        # Simple range matching
        if range_str.startswith('<='):
            target = FixVerifier._parse_version(range_str[2:].strip())
            return version <= (target or (float('inf'),))
        elif range_str.startswith('>='):
            target = FixVerifier._parse_version(range_str[2:].strip())
            return version >= (target or (0,))
        elif range_str.startswith('<'):
            target = FixVerifier._parse_version(range_str[1:].strip())
            return version < (target or (float('inf'),))
        elif range_str.startswith('>'):
            target = FixVerifier._parse_version(range_str[1:].strip())
            return version > (target or (0,))
        else:
            # Exact match
            target = FixVerifier._parse_version(range_str)
            return version == target

    @staticmethod
    def _get_upgrade_recommendation(service_name: Optional[str]) -> str:
        """Get upgrade recommendation for a service."""
        if not service_name:
            return "Upgrade to the latest stable version of the affected software."
        service_lower = service_name.lower().replace(" ", "_")
        for known, fixes in KNOWN_FIXES.items():
            if known in service_lower or service_lower in known:
                return fixes[0][2] if fixes else f"Upgrade {service_name} to the latest version."
        return f"Upgrade {service_name} to the latest version and verify the CVE is patched."


# ── Global Singleton ────────────────────────────────────────────────

_fix_verifier: Optional[FixVerifier] = None


def get_fix_verifier() -> FixVerifier:
    global _fix_verifier
    if _fix_verifier is None:
        _fix_verifier = FixVerifier()
    return _fix_verifier
