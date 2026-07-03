#!/usr/bin/env python3
"""DAG 工作流引擎 — 并行执行 + 优雅降级 + 步骤依赖解析"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger("vuln-research-mcp")


class WorkflowStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class WorkflowStep:
    tool_name: str
    tool_args: dict = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    critical: bool = False


@dataclass
class StepResult:
    step_name: str
    status: str  # success / failed / skipped
    output: Any = None
    error: str = ""
    duration_ms: float = 0


class WorkflowEngine:
    def __init__(self, tool_registry, session_manager=None):
        self.tool_registry = tool_registry
        self.session_manager = session_manager
        self._running_workflows: dict[str, dict] = {}

    async def execute(
        self,
        workflow_id: str,
        steps: list[WorkflowStep],
        initial_context: dict = None,
        timeout: float = 300,
    ) -> dict:
        ctx = initial_context or {}
        results: dict[str, StepResult] = {}
        step_defs = {s.tool_name: s for s in steps}
        completed = set()
        failed = set()

        self._running_workflows[workflow_id] = {
            "status": WorkflowStatus.RUNNING,
            "completed": [],
            "failed": [],
            "started_at": time.time(),
        }

        try:
            async with asyncio.timeout(timeout):
                while len(completed) + len(failed) < len(steps):
                    ready = self._get_ready_steps(steps, completed, failed, step_defs, results)
                    if not ready and len(completed) + len(failed) < len(steps):
                        logger.warning(f"工作流 {workflow_id}: 检测到死锁或依赖不可达")
                        remaining = [s.tool_name for s in steps if s.tool_name not in completed and s.tool_name not in failed]
                        for name in remaining:
                            results[name] = StepResult(step_name=name, status="skipped", error="依赖不可达")
                            failed.add(name)
                        break

                    tasks = []
                    for step in ready:
                        tasks.append(self._execute_step(step, ctx, results))

                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                    for step, result in zip(ready, batch_results):
                        if isinstance(result, Exception):
                            results[step.tool_name] = StepResult(
                                step_name=step.tool_name,
                                status="failed",
                                error=str(result),
                            )
                            if step.critical:
                                self._running_workflows[workflow_id]["status"] = WorkflowStatus.FAILED
                                raise result
                            failed.add(step.tool_name)
                        else:
                            results[step.tool_name] = result
                            if result.status == "success":
                                completed.add(step.tool_name)
                            else:
                                failed.add(step.tool_name)
        except asyncio.TimeoutError:
            logger.error(f"工作流 {workflow_id}: 超时")
            self._running_workflows[workflow_id]["status"] = WorkflowStatus.FAILED
        except Exception as e:
            logger.error(f"工作流 {workflow_id}: 严重错误 - {e}")
            self._running_workflows[workflow_id]["status"] = WorkflowStatus.FAILED

        status = WorkflowStatus.SUCCESS if not failed else (WorkflowStatus.PARTIAL if completed else WorkflowStatus.FAILED)
        self._running_workflows[workflow_id] = {
            "status": status,
            "completed": list(completed),
            "failed": list(failed),
            "elapsed": time.time() - self._running_workflows[workflow_id]["started_at"],
        }

        return {
            "workflow_id": workflow_id,
            "status": status.value,
            "steps_completed": len(completed),
            "steps_failed": len(failed),
            "results": {name: {"status": r.status, "output": r.output, "error": r.error, "duration_ms": r.duration_ms} for name, r in results.items()},
            "outputs": {name: r.output for name, r in results.items() if r.status == "success"},
        }

    def _get_ready_steps(self, all_steps, completed, failed, step_defs, results):
        ready = []
        for step in all_steps:
            if step.tool_name in completed or step.tool_name in failed:
                continue
            deps_met = all(d in completed or d not in step_defs for d in step.depends_on)
            deps_failed = any(d in failed for d in step.depends_on)
            if deps_failed:
                if step.critical:
                    failed.add(step.tool_name)
                else:
                    results[step.tool_name] = StepResult(step_name=step.tool_name, status="skipped", error="上游步骤失败")
                    failed.add(step.tool_name)
                continue
            if deps_met:
                ready.append(step)
        return ready

    async def _execute_step(self, step: WorkflowStep, ctx: dict, results: dict) -> StepResult:
        tool_def = self.tool_registry.resolve(step.tool_name)
        if not tool_def:
            return StepResult(step_name=step.tool_name, status="failed", error=f"工具未注册: {step.tool_name}")

        args = dict(step.tool_args)
        for k, v in args.items():
            if isinstance(v, str) and v.startswith("$context."):
                key = v[9:]
                args[k] = ctx.get("context", {}).get(key, v)
            elif isinstance(v, str) and v.startswith("$output."):
                parts = v[8:].split(".", 1)
                step_name = parts[0]
                field = parts[1] if len(parts) > 1 else None
                output = results.get(step_name)
                if output and output.output:
                    args[k] = output.output.get(field, output.output) if field else output.output
                else:
                    args[k] = None

        start = time.time()
        try:
            output = await tool_def.handler(**{k: v for k, v in args.items() if v is not None})
            duration = (time.time() - start) * 1000
            logger.info(f"步骤 {step.tool_name}: 成功 ({duration:.0f}ms)")
            return StepResult(step_name=step.tool_name, status="success", output=output, duration_ms=duration)
        except Exception as e:
            duration = (time.time() - start) * 1000
            logger.error(f"步骤 {step.tool_name}: 失败 - {e}")
            return StepResult(step_name=step.tool_name, status="failed", error=str(e), duration_ms=duration)

    def get_status(self, workflow_id: str) -> dict:
        return self._running_workflows.get(workflow_id, {"status": "not_found"})


# 全局实例
_engine: Optional[WorkflowEngine] = None


def get_engine(tool_registry, session_manager=None) -> WorkflowEngine:
    global _engine
    if _engine is None:
        _engine = WorkflowEngine(tool_registry, session_manager)
    return _engine
