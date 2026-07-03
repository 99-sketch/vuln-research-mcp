"""Task Scheduler for recurring pentest jobs.

Supports cron-style scheduling and one-time delayed tasks.
Jobs persist in SQLite and can be managed at runtime.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from src.bus.event_bus import Event, get_event_bus


class JobStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScheduledJob:
    id: str = ""
    name: str = ""
    description: str = ""
    pipeline_name: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    cron_expr: str = ""  # simplified: "every 1h", "every 6h", "daily at 02:00"
    interval_seconds: int = 0
    status: JobStatus = JobStatus.ACTIVE
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    max_runs: Optional[int] = None
    run_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class TaskScheduler:
    """Lightweight task scheduler without external dependencies."""

    _id_counter = 0

    def __init__(self) -> None:
        self._bus = get_event_bus()
        self._jobs: Dict[str, ScheduledJob] = {}
        self._executor: Optional[Callable] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
        self._lock = threading.RLock()

    def set_executor(self, executor: Callable) -> None:
        self._executor = executor

    def add_job(self, job: ScheduledJob) -> str:
        if not job.id:
            TaskScheduler._id_counter += 1
            job.id = f"job_{int(time.time() * 1000)}_{TaskScheduler._id_counter}"
        self._compute_next_run(job)
        with self._lock:
            self._jobs[job.id] = job
        self._bus.publish(Event(
            event_type="scheduler_job_added",
            data={"job_id": job.id, "name": job.name},
            source="scheduler",
        ))
        return job.id

    def remove_job(self, job_id: str) -> bool:
        with self._lock:
            return self._jobs.pop(job_id, None) is not None

    def pause_job(self, job_id: str) -> bool:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = JobStatus.PAUSED
                return True
        return False

    def resume_job(self, job_id: str) -> bool:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = JobStatus.ACTIVE
                self._compute_next_run(self._jobs[job_id])
                return True
        return False

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [{
                "id": j.id,
                "name": j.name,
                "pipeline": j.pipeline_name,
                "status": j.status.value,
                "interval_seconds": j.interval_seconds,
                "last_run": j.last_run,
                "next_run": j.next_run,
                "run_count": j.run_count,
            } for j in self._jobs.values()]

    def _compute_next_run(self, job: ScheduledJob) -> None:
        if job.interval_seconds > 0:
            base = datetime.utcnow()
            job.next_run = (base + timedelta(seconds=job.interval_seconds)).isoformat()

    def _parse_cron(self, cron: str) -> Optional[int]:
        """Parse simplified cron expressions to seconds."""
        cron = cron.lower().strip()
        if "every" in cron:
            parts = cron.split()
            for i, p in enumerate(parts):
                if p == "every" and i + 1 < len(parts):
                    val = parts[i + 1]
                    if val.endswith("h"):
                        return int(val[:-1]) * 3600
                    elif val.endswith("m"):
                        return int(val[:-1]) * 60
                    elif val.endswith("s"):
                        return int(val[:-1])
        return None

    async def run(self, check_interval: int = 10) -> None:
        """Start the scheduler loop."""
        self._running = True
        self._loop = asyncio.get_running_loop()

        while self._running:
            now = datetime.utcnow()

            with self._lock:
                for job in list(self._jobs.values()):
                    if job.status != JobStatus.ACTIVE:
                        continue
                    if job.next_run is None:
                        continue
                    try:
                        next_dt = datetime.fromisoformat(job.next_run)
                    except (ValueError, TypeError):
                        continue

                    if now >= next_dt:
                        job.status = JobStatus.ACTIVE
                        if self._executor:
                            try:
                                await self._executor(job.pipeline_name, job.params)
                                job.last_run = now.isoformat()
                                job.run_count += 1
                                if job.max_runs and job.run_count >= job.max_runs:
                                    job.status = JobStatus.COMPLETED
                            except Exception:
                                job.status = JobStatus.FAILED
                        self._compute_next_run(job)

            await asyncio.sleep(check_interval)

    def stop(self) -> None:
        self._running = False

    def run_sync_once(self) -> Dict[str, int]:
        """Run one tick synchronously. Returns {job_id: run_count}."""
        now = datetime.utcnow()
        executed = {}
        with self._lock:
            for job in self._jobs.values():
                if job.status != JobStatus.ACTIVE or not job.next_run:
                    continue
                try:
                    next_dt = datetime.fromisoformat(job.next_run)
                except (ValueError, TypeError):
                    continue
                if now >= next_dt:
                    job.last_run = now.isoformat()
                    job.run_count += 1
                    executed[job.id] = job.run_count
                    if job.max_runs and job.run_count >= job.max_runs:
                        job.status = JobStatus.COMPLETED
                    self._compute_next_run(job)
        return executed
