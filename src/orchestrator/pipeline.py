"""YAML-based Pentest Pipeline Orchestrator.

Defines and executes pentest pipelines from YAML configuration files.
Each pipeline is a sequence of stages, each containing parallel steps
that call MCP tools or external scanners.

Pipeline YAML format:
    name: "Full Pentest Recon"
    description: "Complete reconnaissance pipeline"
    stages:
      - name: "Discovery"
        parallel: true
        steps:
          - tool: scan_ports
            params: {target: "$context.target", ports: "1-1000"}
            timeout: 120
          - tool: enumerate_subdomains
            params: {domain: "$context.target"}
      - name: "Vulnerability Analysis"
        depends_on: ["Discovery"]
        steps:
          - tool: find_exploits
            params: {query: "$context.target"}
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import yaml

from src.bus.event_bus import Event, get_event_bus


class PipelineStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PipelineStep:
    name: str
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 60
    retry: int = 0
    on_failure: str = "continue"  # continue, skip_stage, abort
    condition: str = ""
    status: StepStatus = StepStatus.PENDING
    output: Any = None
    error: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class PipelineStage:
    name: str
    steps: List[PipelineStep] = field(default_factory=list)
    parallel: bool = False
    depends_on: List[str] = field(default_factory=list)
    status: PipelineStatus = PipelineStatus.PENDING


@dataclass
class Pipeline:
    name: str
    description: str = ""
    stages: List[PipelineStage] = field(default_factory=list)
    status: PipelineStatus = PipelineStatus.PENDING
    context: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class PipelineOrchestrator:
    """Loads, validates, and executes YAML-defined pentest pipelines."""

    def __init__(self) -> None:
        self._bus = get_event_bus()
        self._pipelines_dir = "data/pipelines"
        self._tool_executor: Optional[Callable] = None
        self._running: Dict[str, Pipeline] = {}

    def set_tool_executor(self, executor: Callable) -> None:
        self._tool_executor = executor

    def load_pipeline(self, name: str) -> Optional[Pipeline]:
        """Load a pipeline from YAML file."""
        filepath = os.path.join(self._pipelines_dir, f"{name}.yaml")
        if not os.path.exists(filepath):
            filepath = os.path.join(self._pipelines_dir, f"{name}.yml")
        if not os.path.exists(filepath):
            return None

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        stages = []
        for stage_data in data.get("stages", []):
            steps = [
                PipelineStep(
                    name=s.get("name", s.get("tool", "")),
                    tool=s.get("tool", ""),
                    params=s.get("params", {}),
                    timeout=s.get("timeout", 60),
                    retry=s.get("retry", 0),
                    on_failure=s.get("on_failure", "continue"),
                    condition=s.get("condition", ""),
                )
                for s in stage_data.get("steps", [])
            ]
            stages.append(PipelineStage(
                name=stage_data.get("name", ""),
                steps=steps,
                parallel=stage_data.get("parallel", False),
                depends_on=stage_data.get("depends_on", []),
            ))

        return Pipeline(
            name=data.get("name", name),
            description=data.get("description", ""),
            stages=stages,
        )

    def list_pipelines(self) -> List[Dict[str, Any]]:
        """List available pipeline YAML files."""
        pipelines = []
        if os.path.isdir(self._pipelines_dir):
            for f in sorted(os.listdir(self._pipelines_dir)):
                if f.endswith((".yaml", ".yml")):
                    filepath = os.path.join(self._pipelines_dir, f)
                    try:
                        with open(filepath, "r", encoding="utf-8") as fh:
                            data = yaml.safe_load(fh)
                        pipelines.append({
                            "name": data.get("name", f.replace(".yaml", "").replace(".yml", "")),
                            "description": data.get("description", ""),
                            "stages": len(data.get("stages", [])),
                            "file": f,
                        })
                    except Exception:
                        pass
        return pipelines

    async def run_pipeline(self, pipeline: Pipeline,
                           context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a pipeline, stage by stage.

        Returns the execution report with per-stage results.
        """
        pipeline.context = context or {}
        pipeline.status = PipelineStatus.RUNNING
        pipeline.started_at = datetime.utcnow().isoformat()
        self._running[pipeline.name] = pipeline

        self._bus.publish(Event(
            event_type="pipeline_started",
            data={"name": pipeline.name, "stages": len(pipeline.stages)},
            source="pipeline",
        ))

        stage_results: List[Dict[str, Any]] = []
        overall_success = True

        for idx, stage in enumerate(pipeline.stages):
            stage.status = PipelineStatus.RUNNING
            self._bus.publish(Event(
                event_type="stage_started",
                data={"pipeline": pipeline.name, "stage": stage.name, "index": idx},
                source="pipeline",
            ))

            if stage.parallel:
                tasks = []
                for step in stage.steps:
                    tasks.append(self._execute_step(step, pipeline.context, pipeline.name))
                step_results = await asyncio.gather(*tasks, return_exceptions=True)
                for step, result in zip(stage.steps, step_results):
                    if isinstance(result, Exception):
                        step.status = StepStatus.FAILED
                        step.error = str(result)
                stage_results.append({"stage": stage.name, "steps": [
                    {"name": s.name, "status": s.status.value, "output": s.output, "error": s.error}
                    for s in stage.steps
                ]})
            else:
                for step in stage.steps:
                    await self._execute_step(step, pipeline.context, pipeline.name)
                stage_results.append({"stage": stage.name, "steps": [
                    {"name": s.name, "status": s.status.value, "output": s.output, "error": s.error}
                    for s in stage.steps
                ]})

            stage_failed = any(s.status == StepStatus.FAILED for s in stage.steps)
            if stage_failed:
                stage.status = PipelineStatus.FAILED
                overall_success = False
            else:
                stage.status = PipelineStatus.COMPLETED

            self._bus.publish(Event(
                event_type="stage_completed",
                data={
                    "pipeline": pipeline.name,
                    "stage": stage.name,
                    "success": not stage_failed,
                },
                source="pipeline",
            ))

        pipeline.status = PipelineStatus.COMPLETED if overall_success else PipelineStatus.FAILED
        pipeline.completed_at = datetime.utcnow().isoformat()

        self._bus.publish(Event(
            event_type="pipeline_completed",
            data={
                "name": pipeline.name,
                "success": overall_success,
                "stages_total": len(pipeline.stages),
                "stages_completed": len([r for r in stage_results
                                         if all(s["status"] == "completed" for s in r["steps"])]),
            },
            source="pipeline",
        ))

        self._running.pop(pipeline.name, None)

        return {
            "pipeline": pipeline.name,
            "status": pipeline.status.value,
            "started_at": pipeline.started_at,
            "completed_at": pipeline.completed_at,
            "stages": stage_results,
        }

    async def _execute_step(self, step: PipelineStep, context: Dict[str, Any],
                            pipeline_name: str) -> None:
        step.status = StepStatus.RUNNING
        step.started_at = datetime.utcnow().isoformat()

        self._bus.publish(Event(
            event_type="step_started",
            data={"pipeline": pipeline_name, "step": step.name, "tool": step.tool},
            source="pipeline",
        ))

        for attempt in range(step.retry + 1):
            try:
                resolved_params = self._resolve_params(step.params, context)
                if self._tool_executor:
                    result = await self._tool_executor(step.tool, resolved_params)
                    step.output = result
                else:
                    step.output = {"info": f"Tool '{step.tool}' called with {resolved_params}"}

                step.status = StepStatus.COMPLETED
                step.completed_at = datetime.utcnow().isoformat()

                self._bus.publish(Event(
                    event_type="step_completed",
                    data={"pipeline": pipeline_name, "step": step.name, "tool": step.tool},
                    source="pipeline",
                ))
                return
            except asyncio.TimeoutError:
                if attempt < step.retry:
                    continue
                step.status = StepStatus.FAILED
                step.error = f"Timeout after {step.timeout}s"
            except Exception as e:
                if attempt < step.retry:
                    continue
                step.status = StepStatus.FAILED
                step.error = str(e)

        if step.on_failure == "abort":
            raise RuntimeError(f"Step {step.name} failed: {step.error}")

        self._bus.publish(Event(
            event_type="step_failed",
            data={"pipeline": pipeline_name, "step": step.name, "error": step.error},
            source="pipeline",
        ))

    def _resolve_params(self, params: Dict[str, Any],
                        context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve $context.* variable references in params."""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("$context."):
                ctx_key = value[len("$context."):]
                resolved[key] = context.get(ctx_key, value)
            elif isinstance(value, dict):
                resolved[key] = self._resolve_params(value, context)
            else:
                resolved[key] = value
        return resolved

    def get_running(self) -> List[str]:
        return list(self._running.keys())

    def cancel_pipeline(self, name: str) -> bool:
        if name in self._running:
            self._running[name].status = PipelineStatus.CANCELLED
            self._running.pop(name, None)
            return True
        return False
