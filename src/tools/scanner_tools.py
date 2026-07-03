"""Scanner Integration Tools for the pentest infrastructure.

Provides bridging between vuln-research-mcp and external scanners:
    nmap_parse       — Parse Nmap XML/gnmap output into Assets
    nuclei_exec      — Execute Nuclei templates against targets
    metasploit_search — Search Metasploit for modules matching CVEs/services
    searchsploit     — Search Exploit-DB offline via searchsploit CLI
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.bus.event_bus import Event, get_event_bus
from src.db.models import Asset, Finding, Scan, ScanType


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    product: str = ""
    banner: str = ""
    cpe: str = ""
    scripts: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class NmapHost:
    ip: str
    hostname: str = ""
    os: str = ""
    os_accuracy: int = 0
    ports: List[NmapPort] = field(default_factory=list)
    status: str = "up"


def parse_nmap_xml(xml_path: str) -> List[NmapHost]:
    """Parse Nmap XML output into structured host data."""
    hosts = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return []

    for host_elem in root.findall("host"):
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        addr_elem = host_elem.find("address")
        ip = addr_elem.get("addr", "") if addr_elem is not None else ""

        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_name = ""
        os_accuracy = 0
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osm = os_elem.find("osmatch")
            if osm is not None:
                os_name = osm.get("name", "")
                try:
                    os_accuracy = int(osm.get("accuracy", 0))
                except (ValueError, TypeError):
                    pass

        host = NmapHost(ip=ip, hostname=hostname, os=os_name,
                        os_accuracy=os_accuracy, status=status)

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                pid = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service_name = ""
                product = ""
                version = ""
                cpe_str = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    banner = f"{product} {version}".strip() if product or version else service_name
                    for cpe_elem in service_elem.findall("cpe"):
                        cpe_str = cpe_elem.text or ""
                        break

                scripts = []
                for script_elem in port_elem.findall("script"):
                    scripts.append({
                        "id": script_elem.get("id", ""),
                        "output": script_elem.get("output", ""),
                    })

                host.ports.append(NmapPort(
                    port=pid, protocol=protocol, state=state,
                    service=service_name, version=version,
                    product=product, banner=banner, cpe=cpe_str,
                    scripts=scripts,
                ))

        hosts.append(host)

    return hosts


def nmap_to_assets(project_id: int, hosts: List[NmapHost]) -> List[Asset]:
    """Convert NmapHost objects to Asset database records."""
    assets = []
    for host in hosts:
        if host.status != "up":
            continue

        for hp in host.ports:
            if hp.state != "open":
                continue
            assets.append(Asset(
                project_id=project_id,
                asset_type="service",
                value=host.ip,
                port=hp.port,
                protocol=hp.protocol,
                service=hp.service,
                banner=hp.banner,
                version=hp.version,
                cpe=hp.cpe,
                os=host.os,
                hostname=host.hostname or host.ip,
            ))
    return assets


def generate_nuclei_command(target: str, templates: Optional[List[str]] = None,
                            severity: Optional[str] = None,
                            output_path: Optional[str] = None,
                            extra_args: Optional[List[str]] = None) -> str:
    """Generate a nuclei CLI command string.

    Args:
        target: Target URL, IP, or file
        templates: Specific template paths or IDs
        severity: Filter by severity (critical,high,medium,low,info)
        output_path: Path for JSON output
        extra_args: Additional nuclei arguments

    Returns:
        Full nuclei command string
    """
    cmd_parts = ["nuclei", "-u", target]

    if templates:
        for tpl in templates:
            cmd_parts.extend(["-t", tpl])

    if severity:
        cmd_parts.extend(["-severity", severity])

    if output_path:
        cmd_parts.extend(["-json-export", output_path])

    cmd_parts.extend(["-silent", "-no-color"])

    if extra_args:
        cmd_parts.extend(extra_args)

    return " ".join(cmd_parts)


async def execute_scanner(command: str, timeout_seconds: int = 300) -> Dict[str, Any]:
    """Execute an external scanner command and return results.

    Security: Uses shlex.split() to parse command into a list, then
    executes via create_subprocess_exec(*args) to avoid shell injection.
    Pipe operators and shell metacharacters are intentionally rejected
    by the list-based execution model.

    Returns:
        {success: bool, stdout: str, stderr: str, returncode: int, duration_ms: int}
    """
    import shlex as _shlex
    import time as _time

    # Parse command into a safe arg list (rejects shell metacharacters)
    try:
        cmd_args = _shlex.split(command)
    except ValueError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Invalid command syntax: {e}",
            "returncode": -1,
            "duration_ms": 0,
        }

    if not cmd_args:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Empty command",
            "returncode": -1,
            "duration_ms": 0,
        }

    # Sanitize each argument against injection patterns
    from ..security.input_sanitizer import sanitize_injection_patterns
    for i, arg in enumerate(cmd_args):
        if i > 0:  # Skip the binary name
            sanitize_injection_patterns(arg)

    bus = get_event_bus()
    bus.publish(Event(
        event_type="scanner_started",
        data={"command": command[:200]},
        source="scanner",
    ))

    start = _time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds,
        )
        duration = int((_time.time() - start) * 1000)

        result = {
            "success": proc.returncode == 0,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "returncode": proc.returncode,
            "duration_ms": duration,
        }

        bus.publish(Event(
            event_type="scanner_completed",
            data={"command": command[:200], "success": result["success"], "duration_ms": duration},
            source="scanner",
        ))

        return result
    except asyncio.TimeoutError:
        duration = int((_time.time() - start) * 1000)
        bus.publish(Event(
            event_type="scanner_failed",
            data={"command": command[:200], "error": "timeout"},
            source="scanner",
        ))
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Command timed out after {timeout_seconds}s",
            "returncode": -1,
            "duration_ms": duration,
        }
    except Exception as e:
        duration = int((_time.time() - start) * 1000)
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "duration_ms": duration,
        }


def search_metasploit(query: str) -> List[Dict[str, str]]:
    """Search Metasploit modules matching a query.

    Uses msfconsole -q -x "search <query>; exit" or searchsploit as fallback.
    Query is sanitized to prevent command injection.

    Security: Input sanitized via sanitize_shell_query() before reaching
    msfconsole subprocess. All shell metacharacters are rejected.
    """
    from ..security.input_sanitizer import sanitize_shell_query

    query = sanitize_shell_query(query)
    results = []

    try:
        output = subprocess.check_output(
            ["msfconsole", "-q", "-x", f"search {query}; exit"],
            timeout=30, stderr=subprocess.DEVNULL,
        )
        lines = output.decode("utf-8", errors="replace").split("\n")
        in_results = False
        for line in lines:
            if line.startswith("---"):
                in_results = not in_results
                continue
            if in_results and line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    results.append({
                        "name": parts[0],
                        "disclosure": parts[1] if len(parts) > 1 else "",
                        "rank": parts[2] if len(parts) > 2 else "",
                        "description": " ".join(parts[3:]) if len(parts) > 3 else "",
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    return results


def search_sploit(query: str) -> List[Dict[str, str]]:
    """Search Exploit-DB using searchsploit CLI."""
    results = []
    try:
        output = subprocess.check_output(
            ["searchsploit", query, "--json"],
            timeout=15, stderr=subprocess.DEVNULL,
        )
        data = json.loads(output)
        for entry in data.get("RESULTS_EXPLOIT", []):
            results.append({
                "title": entry.get("Title", ""),
                "edb_id": str(entry.get("EDB-ID", "")),
                "path": entry.get("Path", ""),
                "date": entry.get("Date", ""),
                "author": entry.get("Author", ""),
                "type": entry.get("Type", ""),
                "platform": entry.get("Platform", ""),
            })
    except (FileNotFoundError, subprocess.TimeoutExpired,
            subprocess.CalledProcessError, json.JSONDecodeError):
        pass
    return results


def parse_nuclei_output(json_path: str) -> List[Dict[str, Any]]:
    """Parse Nuclei JSON output file."""
    results = []
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    results.append({
                        "template_id": entry.get("template-id", ""),
                        "name": entry.get("info", {}).get("name", ""),
                        "severity": entry.get("info", {}).get("severity", ""),
                        "host": entry.get("host", ""),
                        "matched_at": entry.get("matched-at", ""),
                        "curl_command": entry.get("curl-command", ""),
                        "description": entry.get("info", {}).get("description", ""),
                        "tags": entry.get("info", {}).get("tags", []),
                    })
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return results


def nuclei_output_to_findings(project_id: int, asset_id: Optional[int],
                              nuclei_results: List[Dict[str, Any]]) -> List[Finding]:
    """Convert Nuclei results to Finding objects."""
    findings = []
    for r in nuclei_results:
        sev = r.get("severity", "info").lower()
        cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.0, "info": 0.0}
        cvss = cvss_map.get(sev, 0.0)

        findings.append(Finding(
            project_id=project_id,
            asset_id=asset_id,
            title=r.get("name", "Nuclei Finding"),
            description=r.get("description", ""),
            severity=sev,
            cvss_score=cvss,
            impact=f"Found at: {r.get('matched_at', '')}\nTemplate: {r.get('template_id', '')}",
            remediation="Refer to template details for remediation guidance",
            references=r.get("curl_command", ""),
            risk_score=cvss / 10.0,
            tags=",".join(r.get("tags", [])),
        ))
    return findings
