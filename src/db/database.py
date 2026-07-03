"""SQLite persistence layer for the pentest infrastructure.

Provides a thread-safe Database class with full CRUD operations
for all entity types: Project, Asset, Scan, Finding, Evidence,
TimelineEvent, PentestReport.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import (
    Asset,
    Evidence,
    Finding,
    PentestReport,
    Project,
    Scan,
    TimelineEvent,
)

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    client TEXT DEFAULT '',
    scope TEXT DEFAULT '[]',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    tags TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    asset_type TEXT DEFAULT 'ip',
    value TEXT NOT NULL,
    port INTEGER,
    protocol TEXT DEFAULT '',
    service TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    version TEXT DEFAULT '',
    cpe TEXT DEFAULT '',
    os TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_alive INTEGER DEFAULT 1,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    scan_type TEXT DEFAULT 'custom',
    tool TEXT DEFAULT '',
    target TEXT DEFAULT '',
    command TEXT DEFAULT '',
    output TEXT DEFAULT '',
    result_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_ms INTEGER,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    asset_id INTEGER,
    scan_id INTEGER,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    cvss_score REAL,
    cvss_vector TEXT DEFAULT '',
    cve_ids TEXT DEFAULT '',
    cwe_ids TEXT DEFAULT '',
    epss_score REAL,
    is_kev INTEGER DEFAULT 0,
    has_exploit INTEGER DEFAULT 0,
    exploit_url TEXT DEFAULT '',
    impact TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    "references" TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    assigned_to TEXT DEFAULT '',
    discovered_at TEXT NOT NULL,
    resolved_at TEXT,
    risk_score REAL DEFAULT 0.0,
    tags TEXT DEFAULT '',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    evidence_type TEXT DEFAULT 'screenshot',
    title TEXT DEFAULT '',
    description TEXT DEFAULT '',
    file_path TEXT DEFAULT '',
    content TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    event_type TEXT DEFAULT '',
    title TEXT DEFAULT '',
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    source TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}',
    timestamp TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    title TEXT DEFAULT '',
    format TEXT DEFAULT 'markdown',
    content TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    finding_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    file_path TEXT DEFAULT '',
    generated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_timeline_project ON timeline(project_id);
CREATE INDEX IF NOT EXISTS idx_reports_project ON reports(project_id);
"""


class Database:
    """Thread-safe SQLite database manager.

    Usage:
        db = Database("data/pentest.db")
        db.initialize()
        project_id = db.create_project(Project(name="Test"))
    """

    def __init__(self, path: str = "data/pentest.db"):
        self._path = path
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a thread-local connection."""
        thread_id = threading.get_ident()
        if not hasattr(self, "_connections"):
            self._connections: Dict[int, sqlite3.Connection] = {}
        if thread_id not in self._connections:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._connections[thread_id] = conn
        return self._connections[thread_id]

    def initialize(self) -> None:
        """Create tables and indexes if they don't exist."""
        with self._lock:
            conn = self._get_conn()
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    def close(self) -> None:
        """Close all connections."""
        with self._lock:
            if hasattr(self, "_connections"):
                for conn in self._connections.values():
                    conn.close()
                self._connections.clear()

    # ── Project CRUD ──

    def create_project(self, project: Project) -> int:
        with self._lock:
            conn = self._get_conn()
            now = datetime.utcnow().isoformat()
            cursor = conn.execute(
                """INSERT INTO projects (name, description, client, scope, status,
                   created_at, updated_at, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (project.name, project.description, project.client, project.scope,
                 project.status, now, now, project.tags),
            )
            conn.commit()
            return cursor.lastrowid

    def get_project(self, project_id: int) -> Optional[Project]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return Project.from_row(tuple(row)) if row else None

    def list_projects(self, status: Optional[str] = None) -> List[Project]:
        conn = self._get_conn()
        if status:
            rows = conn.execute(
                "SELECT * FROM projects WHERE status = ? ORDER BY created_at DESC", (status,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        return [Project.from_row(tuple(r)) for r in rows]

    def update_project(self, project: Project) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """UPDATE projects SET name=?, description=?, client=?, scope=?,
                   status=?, updated_at=?, completed_at=?, tags=? WHERE id=?""",
                (project.name, project.description, project.client, project.scope,
                 project.status, datetime.utcnow().isoformat(), project.completed_at,
                 project.tags, project.id),
            )
            conn.commit()

    def delete_project(self, project_id: int) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            conn.commit()

    # ── Asset CRUD ──

    def create_asset(self, asset: Asset) -> int:
        with self._lock:
            conn = self._get_conn()
            now = datetime.utcnow().isoformat()
            cursor = conn.execute(
                """INSERT INTO assets (project_id, asset_type, value, port, protocol,
                   service, banner, version, cpe, os, hostname, tags, first_seen,
                   last_seen, is_alive, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (asset.project_id, asset.asset_type, asset.value, asset.port,
                 asset.protocol, asset.service, asset.banner, asset.version,
                 asset.cpe, asset.os, asset.hostname, asset.tags, now, now,
                 1 if asset.is_alive else 0, asset.metadata),
            )
            conn.commit()
            return cursor.lastrowid

    def get_asset(self, asset_id: int) -> Optional[Asset]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        return Asset.from_row(tuple(row)) if row else None

    def list_assets(self, project_id: Optional[int] = None,
                    asset_type: Optional[str] = None) -> List[Asset]:
        conn = self._get_conn()
        query = "SELECT * FROM assets WHERE 1=1"
        params: List[Any] = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        query += " ORDER BY last_seen DESC"
        rows = conn.execute(query, params).fetchall()
        return [Asset.from_row(tuple(r)) for r in rows]

    def update_asset(self, asset: Asset) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """UPDATE assets SET asset_type=?, value=?, port=?, protocol=?,
                   service=?, banner=?, version=?, cpe=?, os=?, hostname=?,
                   tags=?, last_seen=?, is_alive=?, metadata=? WHERE id=?""",
                (asset.asset_type, asset.value, asset.port, asset.protocol,
                 asset.service, asset.banner, asset.version, asset.cpe,
                 asset.os, asset.hostname, asset.tags,
                 datetime.utcnow().isoformat(),
                 1 if asset.is_alive else 0, asset.metadata, asset.id),
            )
            conn.commit()

    def upsert_asset(self, project_id: int, asset_type: str, value: str,
                     port: Optional[int] = None) -> int:
        """Insert or update asset by unique (project_id, asset_type, value, port)."""
        conn = self._get_conn()
        row = conn.execute(
            """SELECT id FROM assets WHERE project_id=? AND asset_type=? AND value=?
               AND (port=? OR (port IS NULL AND ? IS NULL))""",
            (project_id, asset_type, value, port, port),
        ).fetchone()
        if row:
            asset_id = row[0]
            with self._lock:
                conn.execute(
                    "UPDATE assets SET last_seen=? WHERE id=?",
                    (datetime.utcnow().isoformat(), asset_id),
                )
                conn.commit()
            return asset_id
        asset = Asset(project_id=project_id, asset_type=asset_type, value=value, port=port)
        return self.create_asset(asset)

    # ── Scan CRUD ──

    def create_scan(self, scan: Scan) -> int:
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """INSERT INTO scans (project_id, scan_type, tool, target, command,
                   output, result_count, status, started_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan.project_id, scan.scan_type, scan.tool, scan.target,
                 scan.command, scan.output, scan.result_count, scan.status,
                 scan.started_at or datetime.utcnow().isoformat(), scan.metadata),
            )
            conn.commit()
            return cursor.lastrowid

    def update_scan_result(self, scan_id: int, status: str, output: str = "",
                           result_count: int = 0, duration_ms: Optional[int] = None) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """UPDATE scans SET status=?, output=?, result_count=?, completed_at=?,
                   duration_ms=? WHERE id=?""",
                (status, output, result_count, datetime.utcnow().isoformat(),
                 duration_ms, scan_id),
            )
            conn.commit()

    def list_scans(self, project_id: Optional[int] = None) -> List[Scan]:
        conn = self._get_conn()
        if project_id is not None:
            rows = conn.execute(
                "SELECT * FROM scans WHERE project_id=? ORDER BY started_at DESC", (project_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [Scan.from_row(tuple(r)) for r in rows]

    # ── Finding CRUD ──

    def create_finding(self, finding: Finding) -> int:
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """INSERT INTO findings (project_id, asset_id, scan_id, title, description,
                   severity, cvss_score, cvss_vector, cve_ids, cwe_ids, epss_score,
                   is_kev, has_exploit, exploit_url, impact, remediation, "references",
                   status, assigned_to, discovered_at, risk_score, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.project_id, finding.asset_id, finding.scan_id, finding.title,
                 finding.description, finding.severity, finding.cvss_score,
                 finding.cvss_vector, finding.cve_ids, finding.cwe_ids,
                 finding.epss_score, 1 if finding.is_kev else 0,
                 1 if finding.has_exploit else 0, finding.exploit_url,
                 finding.impact, finding.remediation, finding.references,
                 finding.status, finding.assigned_to,
                 finding.discovered_at or datetime.utcnow().isoformat(),
                 finding.risk_score, finding.tags),
            )
            conn.commit()
            return cursor.lastrowid

    def list_findings(self, project_id: Optional[int] = None,
                      severity: Optional[str] = None,
                      status: Optional[str] = None) -> List[Finding]:
        conn = self._get_conn()
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY risk_score DESC, discovered_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [Finding.from_row(tuple(r)) for r in rows]

    def update_finding_status(self, finding_id: int, status: str,
                              assigned_to: str = "") -> None:
        with self._lock:
            conn = self._get_conn()
            resolved_at = datetime.utcnow().isoformat() if status in (
                "fixed", "wont_fix", "false_positive") else None
            conn.execute(
                "UPDATE findings SET status=?, assigned_to=?, resolved_at=? WHERE id=?",
                (status, assigned_to, resolved_at, finding_id),
            )
            conn.commit()

    def get_finding_stats(self, project_id: int) -> Dict[str, int]:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT severity, COUNT(*) as cnt FROM findings
               WHERE project_id=? GROUP BY severity""",
            (project_id,),
        ).fetchall()
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in rows:
            sev = row["severity"]
            if sev in stats:
                stats[sev] = row["cnt"]
        return stats

    # ── Evidence CRUD ──

    def create_evidence(self, evidence: Evidence) -> int:
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """INSERT INTO evidences (finding_id, evidence_type, title, description,
                   file_path, content, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (evidence.finding_id, evidence.evidence_type, evidence.title,
                 evidence.description, evidence.file_path, evidence.content,
                 evidence.created_at or datetime.utcnow().isoformat()),
            )
            conn.commit()
            return cursor.lastrowid

    def list_evidences(self, finding_id: int) -> List[Evidence]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM evidences WHERE finding_id=? ORDER BY created_at", (finding_id,)
        ).fetchall()
        return [Evidence.from_row(tuple(r)) for r in rows]

    # ── Timeline CRUD ──

    def add_timeline_event(self, event: TimelineEvent) -> int:
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """INSERT INTO timeline (project_id, event_type, title, description,
                   severity, source, metadata, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.project_id, event.event_type, event.title, event.description,
                 event.severity, event.source, event.metadata,
                 event.timestamp or datetime.utcnow().isoformat()),
            )
            conn.commit()
            return cursor.lastrowid

    def list_timeline(self, project_id: int, limit: int = 100) -> List[TimelineEvent]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM timeline WHERE project_id=? ORDER BY timestamp DESC LIMIT ?",
            (project_id, limit),
        ).fetchall()
        return [TimelineEvent.from_row(tuple(r)) for r in reversed(rows)]

    # ── Report CRUD ──

    def create_report(self, report: PentestReport) -> int:
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """INSERT INTO reports (project_id, title, format, content, summary,
                   finding_count, critical_count, high_count, medium_count, low_count,
                   info_count, file_path, generated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (report.project_id, report.title, report.format, report.content,
                 report.summary, report.finding_count, report.critical_count,
                 report.high_count, report.medium_count, report.low_count,
                 report.info_count, report.file_path,
                 report.generated_at or datetime.utcnow().isoformat()),
            )
            conn.commit()
            return cursor.lastrowid

    def list_reports(self, project_id: Optional[int] = None) -> List[PentestReport]:
        conn = self._get_conn()
        if project_id is not None:
            rows = conn.execute(
                "SELECT * FROM reports WHERE project_id=? ORDER BY generated_at DESC",
                (project_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM reports ORDER BY generated_at DESC"
            ).fetchall()
        return [PentestReport.from_row(tuple(r)) for r in rows]

    def get_report(self, report_id: int) -> Optional[PentestReport]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        return PentestReport.from_row(tuple(row)) if row else None

    # ── Aggregation ──

    def get_project_summary(self, project_id: int) -> Dict[str, Any]:
        conn = self._get_conn()
        project = self.get_project(project_id)
        assets = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE project_id=?", (project_id,)
        ).fetchone()[0]
        scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE project_id=?", (project_id,)
        ).fetchone()[0]
        stats = self.get_finding_stats(project_id)
        timeline_count = conn.execute(
            "SELECT COUNT(*) FROM timeline WHERE project_id=?", (project_id,)
        ).fetchone()[0]

        return {
            "project": project.to_dict() if project else {},
            "asset_count": assets,
            "scan_count": scans,
            "findings": stats,
            "total_findings": sum(stats.values()),
            "timeline_events": timeline_count,
        }

    # ── DB Info ──

    def db_size_mb(self) -> float:
        try:
            return os.path.getsize(self._path) / (1024 * 1024)
        except OSError:
            return 0.0

    def db_path(self) -> str:
        return os.path.abspath(self._path)


# Global singleton
_db: Optional[Database] = None


def get_db(path: str = "data/pentest.db") -> Database:
    global _db
    if _db is None:
        _db = Database(path)
        _db.initialize()
    return _db
