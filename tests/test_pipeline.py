"""Tests for Pipeline Orchestrator — YAML Pipeline Execution."""

import os
import pytest
from src.orchestrator.pipeline import (
    PipelineOrchestrator, Pipeline, PipelineStage, PipelineStep,
    PipelineStatus, StepStatus,
)


@pytest.fixture
def orchestrator():
    return PipelineOrchestrator()


class TestPipelineLoading:
    def test_load_existing_pipeline(self, orchestrator):
        pipeline = orchestrator.load_pipeline("vuln_deep_dive")
        assert pipeline is not None
        assert pipeline.name == "Vulnerability Deep Dive"
        assert len(pipeline.stages) == 3

    def test_load_full_recon_pipeline(self, orchestrator):
        pipeline = orchestrator.load_pipeline("full_recon")
        assert pipeline is not None
        assert len(pipeline.stages) >= 4

    def test_load_tech_stack_pipeline(self, orchestrator):
        pipeline = orchestrator.load_pipeline("tech_stack_audit")
        assert pipeline is not None
        assert pipeline.name == "Technology Stack Audit"
        assert len(pipeline.stages) == 4

    def test_load_nonexistent_pipeline(self, orchestrator):
        assert orchestrator.load_pipeline("nonexistent_pipeline") is None

    def test_pipeline_stages_have_steps(self, orchestrator):
        pipeline = orchestrator.load_pipeline("vuln_deep_dive")
        for stage in pipeline.stages:
            assert len(stage.steps) > 0
            for step in stage.steps:
                assert step.tool != ""
                assert step.name != ""


class TestPipelineListing:
    def test_list_pipelines(self, orchestrator):
        pipelines = orchestrator.list_pipelines()
        assert len(pipelines) >= 3

        names = [p["name"] for p in pipelines]
        assert "Vulnerability Deep Dive" in names
        assert "Full Pentest Recon" in names
        assert "Technology Stack Audit" in names

    def test_list_pipeline_metadata(self, orchestrator):
        pipelines = orchestrator.list_pipelines()
        for p in pipelines:
            assert "name" in p
            assert "description" in p
            assert "stages" in p
            assert "file" in p
            assert p["stages"] > 0


class TestPipelineExecution:
    @pytest.mark.asyncio
    async def test_run_without_executor(self, orchestrator):
        pipeline = orchestrator.load_pipeline("vuln_deep_dive")
        assert pipeline is not None

        result = await orchestrator.run_pipeline(pipeline, {"cve_id": "CVE-2021-44228"})
        assert result["pipeline"] == "Vulnerability Deep Dive"
        assert result["status"] in ("completed", "failed")
        assert "stages" in result
        assert len(result["stages"]) == 3

    @pytest.mark.asyncio
    async def test_run_resolves_context(self, orchestrator):
        pipeline = orchestrator.load_pipeline("vuln_deep_dive")
        result = await orchestrator.run_pipeline(
            pipeline, {"cve_id": "CVE-2021-41773"}
        )
        assert result["status"] in ("completed", "failed")
        assert len(result["stages"]) == 3

    @pytest.mark.asyncio
    async def test_run_full_recon(self, orchestrator):
        pipeline = orchestrator.load_pipeline("full_recon")
        result = await orchestrator.run_pipeline(
            pipeline, {"target": "example.com"}
        )
        assert result["status"] in ("completed", "failed")
        assert len(result["stages"]) >= 4

    @pytest.mark.asyncio
    async def test_run_tech_stack_audit(self, orchestrator):
        pipeline = orchestrator.load_pipeline("tech_stack_audit")
        result = await orchestrator.run_pipeline(
            pipeline, {"product": "apache", "version": "2.4.49", "cve_id": "CVE-2021-41773"}
        )
        assert result["status"] in ("completed", "failed")
        # tech_stack_audit has 4 stages
        assert len(result["stages"]) == 4


class TestPipelineCancel:
    def test_cancel_running_pipeline(self, orchestrator):
        pipeline = Pipeline(name="test_cancel")
        orchestrator._running[pipeline.name] = pipeline
        assert orchestrator.cancel_pipeline("test_cancel") is True
        assert "test_cancel" not in orchestrator._running

    def test_cancel_nonexistent(self, orchestrator):
        assert orchestrator.cancel_pipeline("not_running") is False

    def test_get_running_empty(self, orchestrator):
        assert orchestrator.get_running() == []


class TestPipelineDataClasses:
    def test_pipeline_step_defaults(self):
        step = PipelineStep(name="Test Step", tool="test_tool")
        assert step.name == "Test Step"
        assert step.tool == "test_tool"
        assert step.params == {}
        assert step.timeout == 60
        assert step.retry == 0
        assert step.on_failure == "continue"
        assert step.status == StepStatus.PENDING

    def test_pipeline_stage_parallel(self):
        steps = [
            PipelineStep(name="S1", tool="t1"),
            PipelineStep(name="S2", tool="t2"),
        ]
        stage = PipelineStage(name="Parallel Stage", steps=steps, parallel=True)
        assert stage.parallel is True
        assert len(stage.steps) == 2

    def test_pipeline_dataclass(self):
        p = Pipeline(name="Custom Pipeline", description="Custom desc")
        assert p.name == "Custom Pipeline"
        assert p.description == "Custom desc"
        assert p.stages == []
        assert p.status == PipelineStatus.PENDING
        assert p.context == {}
