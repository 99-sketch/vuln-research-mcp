"""REST API Gateway for the pentest infrastructure.

Provides HTTP endpoints for external toolchain integration:
    GET  /api/health            — Health check
    GET  /api/projects           — List projects
    POST /api/projects           — Create project
    GET  /api/projects/{id}      — Project summary
    GET  /api/projects/{id}/assets — List assets
    POST /api/projects/{id}/assets — Create asset
    GET  /api/projects/{id}/findings — List findings
    POST /api/projects/{id}/findings — Create finding
    POST /api/projects/{id}/scan    — Start a scan
    GET  /api/projects/{id}/report  — Generate report
    GET  /api/cve/{cve_id}          — CVE lookup
    POST /api/correlate             — Correlate assets to vulns
    GET  /api/attack/{technique_id} — ATT&CK technique lookup
    POST /api/pipeline/run          — Run a YAML pipeline
    GET  /api/pipelines             — List pipelines
    GET  /api/ws                    — WebSocket for live events
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.bus.event_bus import Event, get_event_bus
from src.correlator.engine import Correlator
from src.db.database import Database, get_db
from src.db.models import (
    Asset,
    Evidence,
    Finding,
    PentestReport,
    Project,
    Scan,
    TimelineEvent,
)
from src.intel.attck import ATTACKMapper
from src.orchestrator.pipeline import PipelineOrchestrator
from src.reporting.pentest_report import PentestReportGenerator, ReportConfig

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


class RestAPIGateway:
    """FastAPI-based REST API gateway."""

    def __init__(self, db: Optional[Database] = None):
        self._db = db or get_db()
        self._bus = get_event_bus()
        self._correlator = Correlator()
        self._attack_mapper = ATTACKMapper()
        self._pipeline = PipelineOrchestrator()
        self._report_generator = PentestReportGenerator()

        self._app: Optional[Any] = None
        self._ws_clients: List[Any] = []

        if HAS_FASTAPI:
            self._build_app()

    def _build_app(self) -> None:
        if not HAS_FASTAPI:
            return

        self._app = FastAPI(
            title="Vuln-Research-MCP REST API",
            description="Penetration Testing Infrastructure - REST Gateway",
            version="4.0.0",
        )
        self._app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self._register_routes()

    def _register_routes(self) -> None:
        app = self._app

        @app.get("/api/health")
        async def health():
            return {
                "status": "ok",
                "version": "4.0.0",
                "db_size_mb": self._db.db_size_mb(),
                "event_count": self._bus.event_count,
            }

        # Projects
        @app.get("/api/projects")
        async def list_projects(status: Optional[str] = None):
            projects = self._db.list_projects(status=status)
            return {"projects": [p.to_dict() for p in projects], "count": len(projects)}

        @app.post("/api/projects")
        async def create_project(project: dict):
            p = Project(
                name=project.get("name", ""),
                description=project.get("description", ""),
                client=project.get("client", ""),
                scope=project.get("scope", "[]"),
                tags=project.get("tags", ""),
            )
            pid = self._db.create_project(p)
            self._bus.publish(Event(
                event_type="project_created",
                data={"project_id": pid, "name": p.name},
                source="rest_api",
            ))
            return {"id": pid, "name": p.name}

        @app.get("/api/projects/{project_id}")
        async def get_project(project_id: int):
            summary = self._db.get_project_summary(project_id)
            if not summary["project"]:
                raise HTTPException(status_code=404, detail="Project not found")
            return summary

        # Assets
        @app.get("/api/projects/{project_id}/assets")
        async def list_assets(project_id: int, asset_type: Optional[str] = None):
            assets = self._db.list_assets(project_id=project_id, asset_type=asset_type)
            return {"assets": [a.to_dict() for a in assets], "count": len(assets)}

        @app.post("/api/projects/{project_id}/assets")
        async def create_asset(project_id: int, asset: dict):
            a = Asset(
                project_id=project_id,
                asset_type=asset.get("asset_type", "ip"),
                value=asset.get("value", ""),
                port=asset.get("port"),
                protocol=asset.get("protocol", ""),
                service=asset.get("service", ""),
                banner=asset.get("banner", ""),
                version=asset.get("version", ""),
                cpe=asset.get("cpe", ""),
                os=asset.get("os", ""),
                hostname=asset.get("hostname", ""),
                tags=asset.get("tags", ""),
            )
            aid = self._db.create_asset(a)
            self._bus.publish(Event(
                event_type="asset_created",
                data={"asset_id": aid, "value": a.value, "type": a.asset_type},
                source="rest_api",
            ))
            return {"id": aid}

        # Findings
        @app.get("/api/projects/{project_id}/findings")
        async def list_findings(project_id: int, severity: Optional[str] = None,
                                status: Optional[str] = None):
            findings = self._db.list_findings(project_id, severity=severity, status=status)
            return {"findings": [f.to_dict() for f in findings], "count": len(findings)}

        @app.post("/api/projects/{project_id}/findings")
        async def create_finding(project_id: int, finding: dict):
            f = Finding(
                project_id=project_id,
                asset_id=finding.get("asset_id"),
                scan_id=finding.get("scan_id"),
                title=finding.get("title", ""),
                description=finding.get("description", ""),
                severity=finding.get("severity", "medium"),
                cvss_score=finding.get("cvss_score"),
                cve_ids=finding.get("cve_ids", ""),
                cwe_ids=finding.get("cwe_ids", ""),
                impact=finding.get("impact", ""),
                remediation=finding.get("remediation", ""),
                references=finding.get("references", ""),
                risk_score=finding.get("risk_score", 0),
                tags=finding.get("tags", ""),
            )
            fid = self._db.create_finding(f)
            self._bus.publish(Event(
                event_type="finding_created",
                data={"finding_id": fid, "title": f.title, "severity": f.severity},
                source="rest_api",
            ))
            return {"id": fid}

        @app.put("/api/findings/{finding_id}/status")
        async def update_finding_status(finding_id: int, data: dict):
            self._db.update_finding_status(
                finding_id,
                status=data.get("status", "open"),
                assigned_to=data.get("assigned_to", ""),
            )
            return {"ok": True}

        # Scan
        @app.post("/api/projects/{project_id}/scan")
        async def start_scan(project_id: int, scan_data: dict):
            s = Scan(
                project_id=project_id,
                scan_type=scan_data.get("scan_type", "custom"),
                tool=scan_data.get("tool", ""),
                target=scan_data.get("target", ""),
                command=scan_data.get("command", ""),
                status="running",
                metadata=json.dumps(scan_data.get("metadata", {})),
            )
            sid = self._db.create_scan(s)
            self._bus.publish(Event(
                event_type="scan_started",
                data={"scan_id": sid, "type": s.scan_type, "target": s.target},
                source="rest_api",
            ))
            return {"id": sid, "status": "running"}

        # Reports
        @app.get("/api/projects/{project_id}/report")
        async def generate_report(project_id: int, format: str = "markdown"):
            findings = self._db.list_findings(project_id)
            project = self._db.get_project(project_id)
            timeline = self._db.list_timeline(project_id)

            config = ReportConfig(
                project_name=project.name if project else "Penetration Test",
                version="1.0",
                timeline_events=[f"{e.event_type}: {e.title}" for e in timeline],
            )

            if format == "json":
                content = json.dumps(
                    self._report_generator.generate_json(findings, config),
                    indent=2, ensure_ascii=False,
                )
            else:
                content = self._report_generator.generate_markdown(findings, config)

            return {
                "format": format,
                "content": content,
                "finding_count": len(findings),
            }

        @app.post("/api/projects/{project_id}/report/save")
        async def save_report(project_id: int, data: dict):
            findings = self._db.list_findings(project_id)
            fmt = data.get("format", "markdown")

            if fmt == "json":
                content = json.dumps(
                    self._report_generator.generate_json(findings),
                    indent=2, ensure_ascii=False,
                )
            else:
                content = self._report_generator.generate_markdown(findings)

            report = self._report_generator.to_report_model(project_id, content, fmt, findings)
            rid = self._db.create_report(report)
            self._bus.publish(Event(
                event_type="report_generated",
                data={"report_id": rid, "project_id": project_id, "format": fmt},
                source="rest_api",
            ))
            return {"id": rid, "format": fmt}

        # CVE
        @app.get("/api/cve/{cve_id}")
        async def cve_lookup(cve_id: str):
            return {"cve_id": cve_id, "info": "CVE lookup via NVD API - use MCP tool get_cve_details"}

        # Correlate
        @app.post("/api/correlate")
        async def correlate(data: dict):
            asset = Asset(
                project_id=data.get("project_id", 0),
                service=data.get("service", ""),
                version=data.get("version", ""),
                banner=data.get("banner", ""),
                cpe=data.get("cpe", ""),
                value=data.get("value", ""),
            )
            result = self._correlator.correlate_batch([asset])[0]
            return {
                "service": asset.service,
                "version": asset.version,
                "vulns": result.matched_vulns,
                "total_risk": result.total_risk,
                "top_severity": result.top_severity,
            }

        @app.post("/api/correlate/batch")
        async def correlate_batch(data: dict):
            assets_data = data.get("assets", [])
            assets = [
                Asset(
                    project_id=a.get("project_id", 0),
                    service=a.get("service", ""),
                    version=a.get("version", ""),
                    banner=a.get("banner", ""),
                    cpe=a.get("cpe", ""),
                    value=a.get("value", ""),
                )
                for a in assets_data
            ]
            results = self._correlator.correlate_batch(assets)
            return {
                "results": [
                    {
                        "service": r.asset.service,
                        "version": r.asset.version,
                        "vulns": r.matched_vulns,
                        "total_risk": r.total_risk,
                        "top_severity": r.top_severity,
                    }
                    for r in results
                ]
            }

        # ATT&CK
        @app.get("/api/attack/{technique_id}")
        async def attack_technique(technique_id: str):
            t = self._attack_mapper.get_technique(technique_id.upper())
            if not t:
                raise HTTPException(status_code=404, detail="Technique not found")
            return {"id": t.id, "name": t.name, "tactic": t.tactic,
                    "description": t.description, "mitigations": t.mitigations}

        @app.post("/api/attack/map")
        async def attack_map(data: dict):
            result = self._attack_mapper.map_finding(
                data.get("title", ""),
                data.get("description", ""),
                data.get("cwe_ids", ""),
                data.get("severity", ""),
            )
            return result

        @app.get("/api/attack/techniques")
        async def attack_techniques():
            return {"techniques": self._attack_mapper.list_all_techniques()}

        # Pipelines
        @app.get("/api/pipelines")
        async def list_pipelines():
            return {"pipelines": self._pipeline.list_pipelines()}

        @app.post("/api/pipeline/run")
        async def run_pipeline(data: dict):
            pipeline_name = data.get("name", "")
            context = data.get("context", {})
            pipeline_obj = self._pipeline.load_pipeline(pipeline_name)
            if not pipeline_obj:
                raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_name}' not found")
            result = await self._pipeline.run_pipeline(pipeline_obj, context)
            return result

        # Timeline
        @app.get("/api/projects/{project_id}/timeline")
        async def get_timeline(project_id: int, limit: int = 100):
            events = self._db.list_timeline(project_id, limit)
            return {"events": [e.to_dict() for e in events], "count": len(events)}

        @app.post("/api/projects/{project_id}/timeline")
        async def add_timeline(project_id: int, data: dict):
            event = TimelineEvent(
                project_id=project_id,
                event_type=data.get("event_type", ""),
                title=data.get("title", ""),
                description=data.get("description", ""),
                severity=data.get("severity", "info"),
                source=data.get("source", "rest_api"),
                metadata=json.dumps(data.get("metadata", {})),
            )
            eid = self._db.add_timeline_event(event)
            return {"id": eid}

        # Events - SSE stream
        @app.get("/api/events")
        async def event_stream():
            from fastapi.responses import StreamingResponse
            async def generate():
                while True:
                    events = self._bus.get_history(limit=10)
                    for e in events:
                        yield f"data: {json.dumps({'type': e.event_type, 'data': e.data, 'source': e.source})}\n\n"
                    await asyncio.sleep(2)
            return StreamingResponse(generate(), media_type="text/event-stream")

        # WebSocket
        @app.websocket("/api/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self._ws_clients.append(websocket)
            try:
                await websocket.send_text(json.dumps({"type": "connected", "message": "Vuln-Research-MCP WebSocket"}))
                while True:
                    data = await websocket.receive_text()
                    msg = json.loads(data)
                    action = msg.get("action", "")
                    if action == "subscribe":
                        await websocket.send_text(json.dumps({"type": "subscribed", "events": msg.get("events", [])}))
                    elif action == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                self._ws_clients.remove(websocket)
            except Exception:
                if websocket in self._ws_clients:
                    self._ws_clients.remove(websocket)

    async def broadcast_ws(self, message: Dict[str, Any]) -> None:
        """Broadcast a message to all connected WebSocket clients."""
        for ws in list(self._ws_clients):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                if ws in self._ws_clients:
                    self._ws_clients.remove(ws)

    @property
    def app(self):
        return self._app

    def get_app(self):
        return self._app

    def run(self, host: str = "0.0.0.0", port: int = 8765) -> None:
        """Start the REST API server."""
        if not self._app:
            raise RuntimeError("FastAPI not installed. Run: pip install fastapi uvicorn")
        import uvicorn
        uvicorn.run(self._app, host=host, port=port, log_level="info")
