"""SQLite data models for the pentest infrastructure.

Tables:
    projects       — pentest engagement projects
    assets         — discovered targets (IPs, domains, services)
    scans          — individual scan runs
    findings       — vulnerability findings with severity and status
    evidences      — proof-of-concept files/screenshots for findings
    timeline       — chronological event log per project
    reports        — generated pentest reports
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class ScanType(Enum):
    PORT_SCAN = "port_scan"
    SUBDOMAIN_ENUM = "subdomain_enum"
    VULN_SCAN = "vuln_scan"
    WEB_SCAN = "web_scan"
    CVE_CHECK = "cve_check"
    NUCLEI = "nuclei"
    CUSTOM = "custom"


class AssetType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    SERVICE = "service"
    WEBAPP = "webapp"
    API = "api"
    CONTAINER = "container"
    CLOUD = "cloud"


class EvidenceType(Enum):
    SCREENSHOT = "screenshot"
    LOG = "log"
    REQUEST = "request"
    RESPONSE = "response"
    CODE = "code"
    FILE = "file"
    OUTPUT = "output"


@dataclass
class Project:
    """A pentest engagement project."""

    id: Optional[int] = None
    name: str = ""
    description: str = ""
    client: str = ""
    scope: str = ""  # JSON string of scope targets
    status: str = "active"  # active, completed, archived
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    tags: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "client": self.client,
            "scope": self.scope,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "tags": self.tags,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "Project":
        return cls(
            id=row[0],
            name=row[1] or "",
            description=row[2] or "",
            client=row[3] or "",
            scope=row[4] or "",
            status=row[5] or "active",
            created_at=row[6] or "",
            updated_at=row[7] or "",
            completed_at=row[8],
            tags=row[9] or "",
        )


@dataclass
class Asset:
    """A discovered asset during pentest."""

    id: Optional[int] = None
    project_id: int = 0
    asset_type: str = "ip"
    value: str = ""  # IP address, domain, URL
    port: Optional[int] = None
    protocol: str = ""
    service: str = ""
    banner: str = ""
    version: str = ""
    cpe: str = ""
    os: str = ""
    hostname: str = ""
    tags: str = ""
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    is_alive: bool = True
    metadata: str = "{}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "asset_type": self.asset_type,
            "value": self.value,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "cpe": self.cpe,
            "os": self.os,
            "hostname": self.hostname,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_alive": self.is_alive,
            "metadata": self.metadata,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "Asset":
        return cls(
            id=row[0],
            project_id=row[1] or 0,
            asset_type=row[2] or "ip",
            value=row[3] or "",
            port=row[4],
            protocol=row[5] or "",
            service=row[6] or "",
            banner=row[7] or "",
            version=row[8] or "",
            cpe=row[9] or "",
            os=row[10] or "",
            hostname=row[11] or "",
            tags=row[12] or "",
            first_seen=row[13] or "",
            last_seen=row[14] or "",
            is_alive=bool(row[15]) if row[15] is not None else True,
            metadata=row[16] or "{}",
        )


@dataclass
class Scan:
    """A scan execution record."""

    id: Optional[int] = None
    project_id: int = 0
    scan_type: str = "custom"
    tool: str = ""
    target: str = ""
    command: str = ""
    output: str = ""
    result_count: int = 0
    status: str = "pending"  # pending, running, completed, failed
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    metadata: str = "{}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_type": self.scan_type,
            "tool": self.tool,
            "target": self.target,
            "command": self.command,
            "output": self.output,
            "result_count": self.result_count,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "Scan":
        return cls(
            id=row[0],
            project_id=row[1] or 0,
            scan_type=row[2] or "custom",
            tool=row[3] or "",
            target=row[4] or "",
            command=row[5] or "",
            output=row[6] or "",
            result_count=row[7] or 0,
            status=row[8] or "pending",
            started_at=row[9] or "",
            completed_at=row[10],
            duration_ms=row[11],
            metadata=row[12] or "{}",
        )


@dataclass
class Finding:
    """A vulnerability finding with full context."""

    id: Optional[int] = None
    project_id: int = 0
    asset_id: Optional[int] = None
    scan_id: Optional[int] = None
    title: str = ""
    description: str = ""
    severity: str = "medium"
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cve_ids: str = ""  # comma-separated
    cwe_ids: str = ""  # comma-separated
    epss_score: Optional[float] = None
    is_kev: bool = False
    has_exploit: bool = False
    exploit_url: str = ""
    impact: str = ""
    remediation: str = ""
    references: str = ""
    status: str = "open"
    assigned_to: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    resolved_at: Optional[str] = None
    risk_score: float = 0.0
    tags: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "asset_id": self.asset_id,
            "scan_id": self.scan_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "has_exploit": self.has_exploit,
            "exploit_url": self.exploit_url,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "discovered_at": self.discovered_at,
            "resolved_at": self.resolved_at,
            "risk_score": self.risk_score,
            "tags": self.tags,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "Finding":
        return cls(
            id=row[0],
            project_id=row[1] or 0,
            asset_id=row[2],
            scan_id=row[3],
            title=row[4] or "",
            description=row[5] or "",
            severity=row[6] or "medium",
            cvss_score=row[7],
            cvss_vector=row[8] or "",
            cve_ids=row[9] or "",
            cwe_ids=row[10] or "",
            epss_score=row[11],
            is_kev=bool(row[12]) if row[12] is not None else False,
            has_exploit=bool(row[13]) if row[13] is not None else False,
            exploit_url=row[14] or "",
            impact=row[15] or "",
            remediation=row[16] or "",
            references=row[17] or "",
            status=row[18] or "open",
            assigned_to=row[19] or "",
            discovered_at=row[20] or "",
            resolved_at=row[21],
            risk_score=row[22] or 0.0,
            tags=row[23] or "",
        )


@dataclass
class Evidence:
    """Proof-of-concept evidence for a finding."""

    id: Optional[int] = None
    finding_id: int = 0
    evidence_type: str = "screenshot"
    title: str = ""
    description: str = ""
    file_path: str = ""
    content: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "evidence_type": self.evidence_type,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "content": self.content,
            "created_at": self.created_at,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "Evidence":
        return cls(
            id=row[0],
            finding_id=row[1] or 0,
            evidence_type=row[2] or "screenshot",
            title=row[3] or "",
            description=row[4] or "",
            file_path=row[5] or "",
            content=row[6] or "",
            created_at=row[7] or "",
        )


@dataclass
class TimelineEvent:
    """Chronological event in a project timeline."""

    id: Optional[int] = None
    project_id: int = 0
    event_type: str = ""
    title: str = ""
    description: str = ""
    severity: str = "info"
    source: str = ""
    metadata: str = "{}"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "TimelineEvent":
        return cls(
            id=row[0],
            project_id=row[1] or 0,
            event_type=row[2] or "",
            title=row[3] or "",
            description=row[4] or "",
            severity=row[5] or "info",
            source=row[6] or "",
            metadata=row[7] or "{}",
            timestamp=row[8] or "",
        )


@dataclass
class PentestReport:
    """A generated pentest report."""

    id: Optional[int] = None
    project_id: int = 0
    title: str = ""
    format: str = "markdown"  # markdown, json, pdf, stix, sarif
    content: str = ""
    summary: str = ""
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    file_path: str = ""
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "title": self.title,
            "format": self.format,
            "content": self.content,
            "summary": self.summary,
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "file_path": self.file_path,
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "PentestReport":
        return cls(
            id=row[0],
            project_id=row[1] or 0,
            title=row[2] or "",
            format=row[3] or "markdown",
            content=row[4] or "",
            summary=row[5] or "",
            finding_count=row[6] or 0,
            critical_count=row[7] or 0,
            high_count=row[8] or 0,
            medium_count=row[9] or 0,
            low_count=row[10] or 0,
            info_count=row[11] or 0,
            file_path=row[12] or "",
            generated_at=row[13] or "",
        )
