"""MITRE ATT&CK Framework Mapper.

Maps CVEs, CWEs, and pentest findings to MITRE ATT&CK techniques,
tactics, threat actors, and mitigations.

References:
    - MITRE ATT&CK v15: https://attack.mitre.org/
    - CWE-to-ATT&CK: https://cwe.mitre.org/data/definitions/
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ATTCTechnique:
    id: str  # e.g., "T1190"
    name: str
    tactic: str  # e.g., "Initial Access"
    description: str = ""
    platforms: List[str] = field(default_factory=list)
    detection: str = ""
    mitigations: List[str] = field(default_factory=list)


# Core ATT&CK techniques relevant to penetration testing
ATTACK_TECHNIQUES: Dict[str, ATTCTechnique] = {
    "T1190": ATTCTechnique(
        id="T1190", name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries exploit vulnerabilities in public-facing applications to gain initial access.",
        platforms=["Web", "IaaS", "Containers"],
        detection="Monitor application logs for unusual behavior patterns",
        mitigations=["Regular patching", "WAF deployment", "Vulnerability scanning"],
    ),
    "T1059": ATTCTechnique(
        id="T1059", name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries abuse command and script interpreters to execute commands or payloads.",
        platforms=["Linux", "Windows", "macOS", "Containers"],
        detection="Monitor process creation and command-line arguments",
        mitigations=["Application allowlisting", "PowerShell logging", "Disable unused shells"],
    ),
    "T1505": ATTCTechnique(
        id="T1505", name="Server Software Component",
        tactic="Persistence",
        description="Adversaries abuse legitimate extensibility features of server software.",
        platforms=["Linux", "Windows"],
        detection="Monitor web server plugin directories and configurations",
        mitigations=["File integrity monitoring", "Least privilege for web servers"],
    ),
    "T1068": ATTCTechnique(
        id="T1068", name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Adversaries exploit software vulnerabilities to elevate privileges.",
        platforms=["Linux", "Windows", "macOS", "Containers"],
        detection="Monitor for unusual process privilege changes",
        mitigations=["Patch management", "Least privilege", "Application sandboxing"],
    ),
    "T1078": ATTCTechnique(
        id="T1078", name="Valid Accounts",
        tactic="Defense Evasion",
        description="Adversaries obtain and abuse credentials of existing accounts.",
        platforms=["Linux", "Windows", "macOS", "SaaS", "IaaS"],
        detection="Monitor for anomalous account usage patterns",
        mitigations=["MFA", "Audit account usage", "Password policies"],
    ),
    "T1003": ATTCTechnique(
        id="T1003", name="OS Credential Dumping",
        tactic="Credential Access",
        description="Adversaries attempt to dump credentials from operating system stores.",
        platforms=["Linux", "Windows", "macOS"],
        detection="Monitor access to credential stores (SAM, /etc/shadow)",
        mitigations=["Credential Guard", "LSA Protection", "Restrict admin access"],
    ),
    "T1046": ATTCTechnique(
        id="T1046", name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries attempt to get a listing of services running on remote hosts.",
        platforms=["Linux", "Windows", "macOS", "Containers"],
        detection="Monitor for port scanning activity via network logs",
        mitigations=["Network segmentation", "IDS/IPS", "Service hardening"],
    ),
    "T1041": ATTCTechnique(
        id="T1041", name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Adversaries steal data by exfiltrating over their command and control channel.",
        platforms=["Linux", "Windows", "macOS", "Containers"],
        detection="Monitor for large outbound data transfers",
        mitigations=["Data loss prevention", "Network traffic analysis", "Egress filtering"],
    ),
    "T1199": ATTCTechnique(
        id="T1199", name="Trusted Relationship",
        tactic="Initial Access",
        description="Adversaries breach and leverage third-party access vectors.",
        platforms=["SaaS", "IaaS"],
        detection="Monitor third-party access patterns",
        mitigations=["Third-party risk assessment", "Access review", "Session monitoring"],
    ),
    "T1210": ATTCTechnique(
        id="T1210", name="Exploitation of Remote Services",
        tactic="Lateral Movement",
        description="Adversaries exploit remote services to move laterally in a network.",
        platforms=["Linux", "Windows", "macOS", "Containers"],
        detection="Monitor network flows for unusual remote service exploitation",
        mitigations=["Segmentation", "Patch management", "Disable unused services"],
    ),
}

# CWE to ATT&CK technique mapping
CWE_TO_ATTACK: Dict[str, List[str]] = {
    "CWE-89": ["T1190"],    # SQL Injection -> Exploit Public-Facing Application
    "CWE-79": ["T1190"],    # XSS -> Exploit Public-Facing Application
    "CWE-78": ["T1059"],    # Command Injection -> Command & Scripting Interpreter
    "CWE-77": ["T1059"],    # Command Injection variant
    "CWE-22": ["T1190"],    # Path Traversal -> Exploit Public-Facing App
    "CWE-434": ["T1505"],   # Unrestricted File Upload -> Server Software Component
    "CWE-502": ["T1059", "T1068"],  # Deserialization -> Execution + Privilege Escalation
    "CWE-287": ["T1078"],   # Auth Bypass -> Valid Accounts
    "CWE-306": ["T1078"],   # Missing Auth -> Valid Accounts
    "CWE-200": ["T1046"],   # Information Disclosure -> Discovery
    "CWE-918": ["T1190"],   # SSRF -> Exploit Public-Facing App
    "CWE-611": ["T1190"],   # XXE -> Exploit Public-Facing App
    "CWE-862": ["T1078"],   # Missing Authorization -> Valid Accounts
    "CWE-20":  ["T1190"],   # Improper Input Validation -> Exploit Public-Facing App
}

# Tactics list for reference
TACTICS_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class ATTACKMapper:
    """Maps vulnerabilities and findings to MITRE ATT&CK framework."""

    def __init__(self):
        self._techniques = dict(ATTACK_TECHNIQUES)

    def get_technique(self, technique_id: str) -> Optional[ATTCTechnique]:
        """Get a single ATT&CK technique by ID."""
        return self._techniques.get(technique_id.upper())

    def map_cwe(self, cwe_id: str) -> List[ATTCTechnique]:
        """Map a CWE ID to ATT&CK techniques."""
        technique_ids = CWE_TO_ATTACK.get(cwe_id.upper(), [])
        return [self._techniques[t] for t in technique_ids if t in self._techniques]

    def map_cve(self, cve_id: str, cwe_ids: Optional[List[str]] = None) -> List[ATTCTechnique]:
        """Map a CVE to ATT&CK techniques via its CWE associations."""
        techniques = []
        if cwe_ids:
            for cwe in cwe_ids:
                techniques.extend(self.map_cwe(cwe))
        return list({t.id: t for t in techniques}.values())

    def map_finding(self, title: str, description: str = "",
                    cwe_ids: str = "", severity: str = "") -> Dict[str, Any]:
        """Map a pentest finding to ATT&CK techniques, tactics, and threat actors.

        Returns a comprehensive ATT&CK mapping report.
        """
        techniques = []
        matched_cwes = []

        if cwe_ids:
            for cwe in cwe_ids.split(","):
                cwe_clean = cwe.strip().upper()
                if not cwe_clean.startswith("CWE-"):
                    cwe_clean = f"CWE-{cwe_clean}"
                matched_cwes.append(cwe_clean)
                techs = self.map_cwe(cwe_clean)
                for t in techs:
                    if t not in techniques:
                        techniques.append(t)

        combined_text = f"{title} {description}".lower()

        keyword_mappings = {
            "sql injection": "CWE-89",
            "xss": "CWE-79",
            "cross-site": "CWE-79",
            "command injection": "CWE-78",
            "path traversal": "CWE-22",
            "directory traversal": "CWE-22",
            "file upload": "CWE-434",
            "deserialization": "CWE-502",
            "authentication bypass": "CWE-287",
            "authorization bypass": "CWE-862",
            "ssrf": "CWE-918",
            "xxe": "CWE-611",
            "privilege escalation": "",
            "rce": "CWE-78",
            "remote code execution": "CWE-78",
            "information disclosure": "CWE-200",
            "buffer overflow": "CWE-120",
        }

        for keyword, cwe in keyword_mappings.items():
            if keyword in combined_text and cwe and cwe not in matched_cwes:
                matched_cwes.append(cwe)
                for t in self.map_cwe(cwe):
                    if t not in techniques:
                        techniques.append(t)

        tactics_covered = list(dict.fromkeys(t.tactic for t in techniques))
        tactics_status = {}
        for tactic in TACTICS_ORDER:
            tactics_status[tactic] = tactic in tactics_covered

        return {
            "title": title,
            "severity": severity,
            "techniques": [
                {
                    "id": t.id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "description": t.description,
                    "detection": t.detection,
                    "mitigations": t.mitigations,
                }
                for t in techniques
            ],
            "tactics_covered": tactics_covered,
            "tactics_matrix": tactics_status,
            "cwe_mappings": matched_cwes,
            "technique_count": len(techniques),
            "tactic_count": len(tactics_covered),
        }

    def generate_attack_navigator_layer(self, findings: List[Dict[str, Any]],
                                        project_name: str = "") -> Dict[str, Any]:
        """Generate an ATT&CK Navigator layer JSON from findings."""
        techniques_set: Dict[str, int] = {}
        for finding in findings:
            mapping = self.map_finding(
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("cwe_ids", ""),
                finding.get("severity", ""),
            )
            for t in mapping["techniques"]:
                techniques_set[t["id"]] = techniques_set.get(t["id"], 0) + 1

        techniques_list = []
        for tid, count in techniques_set.items():
            color = "#e24b4a" if count >= 3 else "#d85a30" if count >= 2 else "#ef9f27"
            techniques_list.append({
                "techniqueID": tid,
                "score": count,
                "color": color,
                "comment": f"Mentioned in {count} finding(s)",
            })

        return {
            "name": f"{project_name} Findings - ATT&CK Mapping" if project_name else "Findings ATT&CK Mapping",
            "versions": {"attack": "15", "navigator": "4.9.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"ATT&CK techniques mapped from {len(findings)} pentest findings",
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#ef9f27", "#d85a30", "#e24b4a"],
                "minValue": 1,
                "maxValue": max(techniques_set.values()) if techniques_set else 1,
            },
        }

    def list_all_techniques(self) -> List[Dict[str, Any]]:
        """List all known ATT&CK techniques."""
        return [
            {
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic,
                "platforms": t.platforms,
            }
            for t in self._techniques.values()
        ]

    def techniques_by_tactic(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group techniques by tactic."""
        by_tactic: Dict[str, List[Dict[str, Any]]] = {}
        for t in self._techniques.values():
            by_tactic.setdefault(t.tactic, []).append({
                "id": t.id, "name": t.name,
                "platforms": t.platforms, "description": t.description,
            })
        return by_tactic
