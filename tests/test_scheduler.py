"""Tests for Task Scheduler — Recurring Pentest Jobs."""

import pytest
from src.orchestrator.scheduler import (
    TaskScheduler, ScheduledJob, JobStatus,
)


@pytest.fixture
def scheduler():
    return TaskScheduler()


class TestScheduledJob:
    def test_create_job_defaults(self):
        job = ScheduledJob(name="Daily Vuln Scan")
        assert job.name == "Daily Vuln Scan"
        assert job.status == JobStatus.ACTIVE
        assert job.run_count == 0

    def test_create_job_with_interval(self):
        job = ScheduledJob(
            name="Hourly Check",
            pipeline_name="vuln_deep_dive",
            interval_seconds=3600,
            params={"cve_id": "CVE-2021-44228"},
        )
        assert job.interval_seconds == 3600
        assert job.pipeline_name == "vuln_deep_dive"
        assert job.params["cve_id"] == "CVE-2021-44228"


class TestJobManagement:
    def test_add_job(self, scheduler):
        job = ScheduledJob(name="Test Job", interval_seconds=60)
        job_id = scheduler.add_job(job)
        assert job_id
        assert job_id.startswith("job_")

    def test_add_job_assigns_id(self, scheduler):
        job = ScheduledJob(name="Unnamed")
        job_id = scheduler.add_job(job)
        assert job.id == job_id

    def test_add_job_preserves_id(self, scheduler):
        job = ScheduledJob(id="custom_123", name="Custom ID")
        job_id = scheduler.add_job(job)
        assert job_id == "custom_123"

    def test_remove_job(self, scheduler):
        job = ScheduledJob(name="Temp Job")
        job_id = scheduler.add_job(job)
        assert scheduler.remove_job(job_id) is True
        assert scheduler.remove_job(job_id) is False  # already removed

    def test_remove_nonexistent_job(self, scheduler):
        assert scheduler.remove_job("nonexistent") is False

    def test_pause_resume_job(self, scheduler):
        job = ScheduledJob(name="Pausable", interval_seconds=10)
        job_id = scheduler.add_job(job)

        assert scheduler.pause_job(job_id) is True
        assert scheduler._jobs[job_id].status == JobStatus.PAUSED

        assert scheduler.resume_job(job_id) is True
        assert scheduler._jobs[job_id].status == JobStatus.ACTIVE

    def test_pause_nonexistent(self, scheduler):
        assert scheduler.pause_job("nonexistent") is False

    def test_resume_nonexistent(self, scheduler):
        assert scheduler.resume_job("nonexistent") is False


class TestJobScheduling:
    def test_compute_next_run(self, scheduler):
        job = ScheduledJob(name="Every 5 Min", interval_seconds=300)
        scheduler.add_job(job)
        assert job.next_run is not None

    def test_parse_cron_hours(self, scheduler):
        seconds = scheduler._parse_cron("every 1h")
        assert seconds == 3600

    def test_parse_cron_minutes(self, scheduler):
        seconds = scheduler._parse_cron("every 30m")
        assert seconds == 1800

    def test_parse_cron_seconds(self, scheduler):
        seconds = scheduler._parse_cron("every 45s")
        assert seconds == 45

    def test_parse_cron_case_insensitive(self, scheduler):
        assert scheduler._parse_cron("EVERY 1H") == 3600

    def test_parse_cron_invalid(self, scheduler):
        assert scheduler._parse_cron("nope") is None
        assert scheduler._parse_cron("every") is None
        assert scheduler._parse_cron("") is None

    def test_run_sync_once_no_jobs(self, scheduler):
        result = scheduler.run_sync_once()
        assert result == {}

    def test_run_sync_once_with_jobs(self, scheduler):
        job = ScheduledJob(name="Ready Job", interval_seconds=0)
        job_id = scheduler.add_job(job)
        # Force next_run to be in the past
        job.next_run = "2020-01-01T00:00:00"

        result = scheduler.run_sync_once()
        assert job_id in result
        assert result[job_id] == 1  # run_count incremented

    def test_run_sync_once_paused_is_skipped(self, scheduler):
        job = ScheduledJob(name="Paused Job", interval_seconds=0)
        job_id = scheduler.add_job(job)
        scheduler.pause_job(job_id)
        job.next_run = "2020-01-01T00:00:00"

        result = scheduler.run_sync_once()
        assert job_id not in result

    def test_run_sync_once_max_runs(self, scheduler):
        job = ScheduledJob(name="Limited Job", interval_seconds=0, max_runs=1)
        job_id = scheduler.add_job(job)
        job.next_run = "2020-01-01T00:00:00"

        result = scheduler.run_sync_once()
        assert job_id in result
        assert scheduler._jobs[job_id].status == JobStatus.COMPLETED


class TestListJobs:
    def test_list_jobs_empty(self, scheduler):
        assert scheduler.list_jobs() == []

    def test_list_jobs(self, scheduler):
        scheduler.add_job(ScheduledJob(name="Job A", pipeline_name="p1", interval_seconds=60))
        scheduler.add_job(ScheduledJob(name="Job B", pipeline_name="p2", interval_seconds=300))

        jobs = scheduler.list_jobs()
        assert len(jobs) == 2
        for j in jobs:
            assert "id" in j
            assert "name" in j
            assert "pipeline" in j
            assert "status" in j
            assert "interval_seconds" in j
            assert "run_count" in j

    def test_list_jobs_respects_status(self, scheduler):
        job = ScheduledJob(name="Active")
        job_id = scheduler.add_job(job)
        scheduler.pause_job(job_id)

        jobs = scheduler.list_jobs()
        paused = [j for j in jobs if j["name"] == "Active"]
        assert paused[0]["status"] == "paused"
