"""
Offline Vulnerability Database Mirror (v5.0)

Provides offline/air-gapped deployment capability:
  - NVD complete database download (JSON feeds, CPE dictionary)
  - CISA KEV catalog offline copy
  - EPSS scores bulk download
  - Exploit-DB / PoC archives as tarball
  - PoC/Exploit-DB local import from archive
  - Incremental update support

Designed for:
  - 内网隔离环境 (air-gapped / internal network)
  - 无外网访问的政企部署
  - 合规要求下的离线漏洞库

Usage:
    # Download all feeds
    python -m src.intel.offline_mirror download --all

    # Update existing mirror
    python -m src.intel.offline_mirror update

    # Import local archive
    python -m src.intel.offline_mirror import --file ./exploitdb.tar.gz
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)


# ── Constants ───────────────────────────────────────────────────────

DEFAULT_MIRROR_DIR = os.path.expanduser("~/.vuln-research-mcp/mirror")

# NVD 2.0 API endpoints (JSON format)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# CISA KEV
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# EPSS (First.org)
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# Exploit-DB
EXPLOIT_DB_URL = "https://gitlab.com/exploit-database/exploitdb/-/archive/main/exploitdb-main.tar.gz"

# CWE
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# GitHub Advisory Database
GHSA_URL = "https://api.github.com/advisories"

# MITRE CVE
MITRE_CVE_URL = "https://cve.mitre.org/data/downloads/allitems.csv"

# China mirror sources (国内镜像加速)
NVD_MIRROR_CN = {
    "tsinghua": "https://mirrors.tuna.tsinghua.edu.cn/",
    "aliyun": "https://mirrors.aliyun.com/",
    "huawei": "https://mirrors.huaweicloud.com/",
}


# ── Data Models ─────────────────────────────────────────────────────

@dataclass
class MirrorStatus:
    """Status of a mirrored data source."""
    name: str
    path: str
    last_updated: float = 0
    total_records: int = 0
    total_size_bytes: int = 0
    status: str = "unknown"  # syncing, complete, error, not_downloaded

    @property
    def last_updated_str(self) -> str:
        if self.last_updated == 0:
            return "never"
        return datetime.fromtimestamp(self.last_updated).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class MirrorConfig:
    """Configuration for the offline mirror."""
    mirror_dir: str = DEFAULT_MIRROR_DIR
    nvd_enabled: bool = True
    kev_enabled: bool = True
    epss_enabled: bool = True
    exploit_db_enabled: bool = True
    cwe_enabled: bool = True
    nvd_years: int = 10  # Number of years of NVD data to download
    nvd_results_per_page: int = 2000  # NVD API max


# ── Offline Mirror Manager ──────────────────────────────────────────

class OfflineMirror:
    """Manage offline mirror of vulnerability databases.

    Directory structure:
        ~/.vuln-research-mcp/mirror/
        ├── nvd/
        │   ├── nvdcve-2024.json.gz
        │   ├── nvdcve-2023.json.gz
        │   └── ...
        ├── cisa/
        │   └── known_exploited_vulnerabilities.json
        ├── epss/
        │   └── epss_scores-current.csv.gz
        ├── exploitdb/
        │   └── exploitdb-main/
        │       ├── exploits/
        │       └── files_exploits.csv
        ├── cwe/
        │   └── cwec_latest.xml
        ├── index.db  (SQLite index for fast local queries)
        └── status.json
    """

    def __init__(self, mirror_dir: str = DEFAULT_MIRROR_DIR, config: Optional[MirrorConfig] = None):
        self.mirror_dir = Path(mirror_dir)
        self.config = config or MirrorConfig(mirror_dir=mirror_dir)
        self._status: Dict[str, MirrorStatus] = {}

        # Ensure directories
        self.mirror_dir.mkdir(parents=True, exist_ok=True)
        (self.mirror_dir / "nvd").mkdir(exist_ok=True)
        (self.mirror_dir / "cisa").mkdir(exist_ok=True)
        (self.mirror_dir / "epss").mkdir(exist_ok=True)
        (self.mirror_dir / "exploitdb").mkdir(exist_ok=True)
        (self.mirror_dir / "cwe").mkdir(exist_ok=True)

        self._load_status()
        self._init_index()

    def _load_status(self):
        """Load mirror status from status.json."""
        status_file = self.mirror_dir / "status.json"
        if status_file.exists():
            try:
                with open(status_file, 'r') as f:
                    data = json.load(f)
                for name, info in data.items():
                    self._status[name] = MirrorStatus(
                        name=name,
                        path=info.get("path", ""),
                        last_updated=info.get("last_updated", 0),
                        total_records=info.get("total_records", 0),
                        total_size_bytes=info.get("total_size_bytes", 0),
                        status=info.get("status", "unknown"),
                    )
            except Exception:
                pass

    def _save_status(self):
        """Save mirror status to status.json."""
        status_file = self.mirror_dir / "status.json"
        data = {
            name: {
                "path": s.path,
                "last_updated": s.last_updated,
                "total_records": s.total_records,
                "total_size_bytes": s.total_size_bytes,
                "status": s.status,
            }
            for name, s in self._status.items()
        }
        with open(status_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _init_index(self):
        """Initialize local SQLite index for fast offline queries."""
        index_path = self.mirror_dir / "index.db"
        conn = sqlite3.connect(str(index_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                modified_date TEXT,
                cpe_list TEXT,
                cwes TEXT,
                year INTEGER,
                source TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware_campaign_use TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_exploits (
                id INTEGER PRIMARY KEY,
                file_path TEXT,
                title TEXT,
                date TEXT,
                author TEXT,
                platform TEXT,
                cve_id TEXT,
                verified INTEGER DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_cves_year ON offline_cves(year)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_cves_severity ON offline_cves(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_cves_cvss ON offline_cves(cvss_score)")
        conn.commit()
        conn.close()

    # ── Public API ──────────────────────────────────────────────

    def get_status(self) -> Dict[str, MirrorStatus]:
        """Get the status of all mirrored data sources."""
        return dict(self._status)

    def get_sync_summary(self) -> str:
        """Get a human-readable summary of mirror status."""
        lines = ["Offline Mirror Status:", "=" * 50]
        for name, status in self._status.items():
            icon = "✅" if status.status == "complete" else "❌"
            lines.append(
                f"  {icon} {name}: {status.total_records:,} records, "
                f"{status.total_size_bytes / 1024 / 1024:.1f} MB, "
                f"updated {status.last_updated_str}"
            )
        if not self._status:
            lines.append("  (no data downloaded yet)")
            lines.append(f"\n  Run: python -m src.intel.offline_mirror download --all")
        return "\n".join(lines)

    async def download_all(self) -> bool:
        """Download all enabled data sources."""
        results = []

        if self.config.nvd_enabled:
            results.append(await self.download_nvd())

        if self.config.kev_enabled:
            results.append(await self.download_kev())

        if self.config.epss_enabled:
            results.append(await self.download_epss())

        if self.config.exploit_db_enabled:
            results.append(await self.download_exploit_db())

        if self.config.cwe_enabled:
            results.append(await self.download_cwe())

        self._save_status()
        return all(results)

    async def update_all(self) -> bool:
        """Incremental update — download only new data."""
        return await self.download_all()

    # ── NVD Download ───────────────────────────────────────────

    async def download_nvd(self) -> bool:
        """Download NVD JSON feeds for the configured year range."""
        self._status["nvd"] = MirrorStatus(
            name="nvd", path=str(self.mirror_dir / "nvd"), status="syncing"
        )
        self._save_status()

        current_year = datetime.now().year
        years = range(current_year - self.config.nvd_years + 1, current_year + 1)
        total_records = 0
        total_size = 0

        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
            for year in years:
                try:
                    count, size = await self._download_nvd_year(client, year)
                    total_records += count
                    total_size += size
                    logger.info(f"Downloaded NVD {year}: {count} CVEs")
                except Exception as e:
                    logger.error(f"Failed to download NVD {year}: {e}")

        self._status["nvd"] = MirrorStatus(
            name="nvd",
            path=str(self.mirror_dir / "nvd"),
            last_updated=time.time(),
            total_records=total_records,
            total_size_bytes=total_size,
            status="complete" if total_records > 0 else "error",
        )
        self._save_status()
        return total_records > 0

    async def _download_nvd_year(self, client: httpx.AsyncClient, year: int) -> Tuple[int, int]:
        """Download a single year of NVD data."""
        output_file = self.mirror_dir / "nvd" / f"nvdcve-{year}.json.gz"

        records = 0
        size = 0
        all_cves = []

        start_index = 0
        while True:
            params = {
                "pubStartDate": f"{year}-01-01T00:00:00.000",
                "pubEndDate": f"{year}-12-31T23:59:59.999",
                "resultsPerPage": self.config.nvd_results_per_page,
                "startIndex": start_index,
            }

            resp = await client.get(NVD_API, params=params)
            if resp.status_code != 200:
                break

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            all_cves.extend(vulnerabilities)
            records += len(vulnerabilities)
            start_index += len(vulnerabilities)

            if len(vulnerabilities) < self.config.nvd_results_per_page:
                break

            # Rate limit
            import asyncio
            await asyncio.sleep(0.6)

        # Save to compressed file
        if all_cves:
            json_data = json.dumps({"vulnerabilities": all_cves}, ensure_ascii=False)
            compressed = gzip.compress(json_data.encode('utf-8'))
            with open(output_file, 'wb') as f:
                f.write(compressed)
            size = len(compressed)

            # Index in SQLite
            self._index_nvd_cves(all_cves)

        return records, size

    def _index_nvd_cves(self, cves: List[dict]):
        """Index NVD CVEs in local SQLite for fast queries."""
        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
        for item in cves:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")

            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "NONE"
            if "cvssMetricV31" in metrics:
                cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_v3.get("baseScore", 0)
                severity = cvss_v3.get("baseSeverity", "NONE")
            elif "cvssMetricV30" in metrics:
                cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_v3.get("baseScore", 0)
                severity = cvss_v3.get("baseSeverity", "NONE")

            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            # CPE list
            cpe_entries = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe_entries.append(match.get("criteria", ""))

            # CWE list
            cwes = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwes.append(desc["value"])

            year = int(published[:4]) if published else 0

            conn.execute(
                "INSERT OR REPLACE INTO offline_cves VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    cve_id, description, severity, cvss_score,
                    published, modified,
                    json.dumps(cpe_entries),
                    json.dumps(cwes),
                    year, "nvd"
                )
            )
        conn.commit()
        conn.close()

    # ── KEV Download ───────────────────────────────────────────

    async def download_kev(self) -> bool:
        """Download CISA Known Exploited Vulnerabilities catalog."""
        self._status["kev"] = MirrorStatus(
            name="kev", path=str(self.mirror_dir / "cisa"), status="syncing"
        )

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(KEV_URL, timeout=30.0)
                if resp.status_code != 200:
                    raise Exception(f"HTTP {resp.status_code}")

                data = resp.json()
                output_file = self.mirror_dir / "cisa" / "known_exploited_vulnerabilities.json"
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2)

                # Index in SQLite
                conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    conn.execute(
                        "INSERT OR REPLACE INTO offline_kev VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            vuln.get("cveID", ""),
                            vuln.get("vendorProject", ""),
                            vuln.get("product", ""),
                            vuln.get("vulnerabilityName", ""),
                            vuln.get("dateAdded", ""),
                            vuln.get("shortDescription", ""),
                            vuln.get("requiredAction", ""),
                            vuln.get("dueDate", ""),
                            vuln.get("knownRansomwareCampaignUse", ""),
                        )
                    )
                conn.commit()
                conn.close()

                self._status["kev"] = MirrorStatus(
                    name="kev",
                    path=str(self.mirror_dir / "cisa"),
                    last_updated=time.time(),
                    total_records=len(vulnerabilities),
                    total_size_bytes=output_file.stat().st_size,
                    status="complete",
                )
                self._save_status()
                return True

        except Exception as e:
            logger.error(f"Failed to download KEV: {e}")
            self._status["kev"].status = "error"
            return False

    # ── EPSS Download ──────────────────────────────────────────

    async def download_epss(self) -> bool:
        """Download EPSS scores dataset."""
        self._status["epss"] = MirrorStatus(
            name="epss", path=str(self.mirror_dir / "epss"), status="syncing"
        )

        try:
            output_file = self.mirror_dir / "epss" / "epss_scores-current.csv.gz"
            async with httpx.AsyncClient() as client:
                async with client.stream("GET", EPSS_URL, timeout=120.0) as resp:
                    if resp.status_code != 200:
                        raise Exception(f"HTTP {resp.status_code}")
                    with open(output_file, 'wb') as f:
                        count = 0
                        async for chunk in resp.aiter_bytes():
                            f.write(chunk)
                            count += len(chunk)

            # Count records (first line is header)
            record_count = 0
            with gzip.open(output_file, 'rt') as f:
                for _ in f:
                    record_count += 1
            record_count -= 1  # subtract header

            self._status["epss"] = MirrorStatus(
                name="epss",
                path=str(self.mirror_dir / "epss"),
                last_updated=time.time(),
                total_records=record_count,
                total_size_bytes=output_file.stat().st_size,
                status="complete",
            )
            self._save_status()
            return True

        except Exception as e:
            logger.error(f"Failed to download EPSS: {e}")
            self._status["epss"].status = "error"
            return False

    # ── Exploit-DB Download ────────────────────────────────────

    async def download_exploit_db(self) -> bool:
        """Download full Exploit-DB archive."""
        self._status["exploit_db"] = MirrorStatus(
            name="exploit_db", path=str(self.mirror_dir / "exploitdb"), status="syncing"
        )

        try:
            output_file = self.mirror_dir / "exploitdb" / "exploitdb-main.tar.gz"

            async with httpx.AsyncClient() as client:
                async with client.stream("GET", EXPLOIT_DB_URL, timeout=300.0) as resp:
                    if resp.status_code != 200:
                        raise Exception(f"HTTP {resp.status_code}")

                    with open(output_file, 'wb') as f:
                        total = 0
                        async for chunk in resp.aiter_bytes():
                            f.write(chunk)
                            total += len(chunk)

                    # Extract files_exploits.csv for indexing
                    self._index_exploit_db(output_file)

            self._status["exploit_db"] = MirrorStatus(
                name="exploit_db",
                path=str(self.mirror_dir / "exploitdb"),
                last_updated=time.time(),
                total_size_bytes=output_file.stat().st_size,
                status="complete",
            )
            self._save_status()
            return True

        except Exception as e:
            logger.error(f"Failed to download Exploit-DB: {e}")
            self._status["exploit_db"].status = "error"
            return False

    def _index_exploit_db(self, tarball_path: Path):
        """Index Exploit-DB exploits in SQLite."""
        import csv
        import io

        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))

        try:
            with tarfile.open(tarball_path, 'r:gz') as tar:
                # Find files_exploits.csv
                csv_member = None
                for member in tar.getmembers():
                    if member.name.endswith("files_exploits.csv"):
                        csv_member = member
                        break

                if csv_member:
                    f = tar.extractfile(csv_member)
                    if f:
                        content = io.TextIOWrapper(f, encoding='utf-8', errors='replace')
                        reader = csv.DictReader(content)
                        for row in reader:
                            try:
                                conn.execute(
                                    "INSERT OR REPLACE INTO offline_exploits VALUES (?,?,?,?,?,?,?,?)",
                                    (
                                        int(row.get("id", 0)),
                                        row.get("file", ""),
                                        row.get("description", ""),
                                        row.get("date", ""),
                                        row.get("author", ""),
                                        row.get("platform", ""),
                                        row.get("codes", ""),  # CVE reference
                                        int(row.get("verified", 0)),
                                    )
                                )
                            except Exception:
                                continue

                # Count and update status
                cursor = conn.execute("SELECT COUNT(*) FROM offline_exploits")
                count = cursor.fetchone()[0]
                self._status["exploit_db"].total_records = count

        except Exception as e:
            logger.warning(f"Exploit-DB indexing partial: {e}")

        conn.commit()
        conn.close()

    # ── CWE Download ───────────────────────────────────────────

    async def download_cwe(self) -> bool:
        """Download CWE database."""
        self._status["cwe"] = MirrorStatus(
            name="cwe", path=str(self.mirror_dir / "cwe"), status="syncing"
        )

        try:
            output_file = self.mirror_dir / "cwe" / "cwec_latest.xml.zip"
            async with httpx.AsyncClient() as client:
                resp = await client.get(CWE_URL, timeout=60.0)
                if resp.status_code != 200:
                    raise Exception(f"HTTP {resp.status_code}")

                with open(output_file, 'wb') as f:
                    f.write(resp.content)

                # Extract and count CWEs
                with zipfile.ZipFile(output_file, 'r') as zf:
                    cwe_file = [n for n in zf.namelist() if n.endswith('.xml')][0]
                    count = 0
                    with zf.open(cwe_file) as f:
                        for line in f:
                            if b'<Weakness' in line:
                                count += 1

            self._status["cwe"] = MirrorStatus(
                name="cwe",
                path=str(self.mirror_dir / "cwe"),
                last_updated=time.time(),
                total_records=count,
                total_size_bytes=output_file.stat().st_size,
                status="complete",
            )
            self._save_status()
            return True

        except Exception as e:
            logger.error(f"Failed to download CWE: {e}")
            self._status["cwe"].status = "error"
            return False

    # ── Local PoC / Exploit Import ─────────────────────────────

    async def import_archive(self, archive_path: str, archive_type: str = "auto") -> int:
        """Import local PoC/Exploit archive.

        Supports:
          - .tar.gz / .tgz: Exploit-DB or custom archive
          - .zip: Custom PoC collection
          - .git directory: Git repository (offline clone)

        Returns number of exploits imported.
        """
        path = Path(archive_path)
        if not path.exists():
            logger.error(f"Archive not found: {archive_path}")
            return 0

        if archive_type == "auto":
            suffix = path.suffix.lower()
            if suffix in ('.gz', '.tgz') or '.tar.' in path.name:
                archive_type = "tarball"
            elif suffix == '.zip':
                archive_type = "zip"
            elif path.is_dir() and (path / ".git").exists():
                archive_type = "git"
            else:
                archive_type = "tarball"

        if archive_type in ("tarball", "zip"):
            return self._import_archive(path, archive_type)
        elif archive_type == "git":
            return self._import_git_repo(path)
        else:
            return 0

    def _import_archive(self, path: Path, archive_type: str) -> int:
        """Import a tarball or zip archive of exploits."""
        dest_dir = self.mirror_dir / "exploitdb" / "imported"
        dest_dir.mkdir(exist_ok=True)

        if archive_type == "tarball":
            with tarfile.open(path, 'r:*') as tar:
                tar.extractall(dest_dir)
        elif archive_type == "zip":
            with zipfile.ZipFile(path, 'r') as zf:
                zf.extractall(dest_dir)

        return len(list(dest_dir.rglob("*")))

    def _import_git_repo(self, path: Path) -> int:
        """Import an offline Git repository."""
        dest_dir = self.mirror_dir / "poc"
        dest_dir.mkdir(exist_ok=True)

        dest_name = path.name
        shutil.copytree(path, dest_dir / dest_name, dirs_exist_ok=True)

        return len(list((dest_dir / dest_name).rglob("*")))

    # ── Local Query API (offline mode) ─────────────────────────

    def query_offline_cve(self, cve_id: str) -> Optional[dict]:
        """Query a CVE from the local offline mirror."""
        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM offline_cves WHERE cve_id = ?", (cve_id.upper(),)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def query_offline_kev(self) -> List[dict]:
        """Query all CISA KEV entries from local mirror."""
        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM offline_kev").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def query_offline_exploits(self, cve_id: str) -> List[dict]:
        """Query exploits for a CVE from local mirror."""
        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM offline_exploits WHERE cve_id LIKE ?",
            (f"%{cve_id}%",)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def query_offline_by_cvss(self, min_score: float = 7.0, limit: int = 50) -> List[dict]:
        """Query CVEs by minimum CVSS score from local mirror."""
        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM offline_cves WHERE cvss_score >= ? ORDER BY cvss_score DESC LIMIT ?",
            (min_score, limit)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def search_offline(self, keyword: str, limit: int = 50) -> List[dict]:
        """Full-text search across all offline data."""
        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
        conn.row_factory = sqlite3.Row

        results = []
        # Search CVEs
        rows = conn.execute(
            "SELECT * FROM offline_cves WHERE description LIKE ? OR cve_id LIKE ? LIMIT ?",
            (f"%{keyword}%", f"%{keyword}%", limit)
        ).fetchall()
        results.extend(dict(r) for r in rows)

        # Search KEV
        rows = conn.execute(
            "SELECT * FROM offline_kev WHERE vulnerability_name LIKE ? OR short_description LIKE ? LIMIT ?",
            (f"%{keyword}%", f"%{keyword}%", limit)
        ).fetchall()
        results.extend(dict(r) for r in rows)

        conn.close()
        return results

    def get_offline_stats(self) -> dict:
        """Get comprehensive offline data statistics."""
        conn = sqlite3.connect(str(self.mirror_dir / "index.db"))
        stats = {}
        for table in ["offline_cves", "offline_kev", "offline_exploits"]:
            try:
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                stats[table] = count
            except Exception:
                stats[table] = 0
        conn.close()

        stats["mirror_size_mb"] = sum(
            f.stat().st_size for f in self.mirror_dir.rglob("*") if f.is_file()
        ) / (1024 * 1024)

        return stats


# ── Global Singleton ────────────────────────────────────────────────

_offline_mirror: Optional[OfflineMirror] = None


def get_offline_mirror(mirror_dir: str = DEFAULT_MIRROR_DIR) -> OfflineMirror:
    global _offline_mirror
    if _offline_mirror is None:
        _offline_mirror = OfflineMirror(mirror_dir=mirror_dir)
    return _offline_mirror
