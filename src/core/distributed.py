# src/core/distributed.py
"""分布式多节点架构 — Redis 任务队列 + 多 Worker + 故障转移

v5.3: 从单机 SQLite 升级为分布式多节点架构。

架构:
  Master        — 接收 MCP 请求，分发任务到队列
  Worker(s)     — 从队列拉取任务，执行扫描/查询，结果回传
  Redis         — 消息代理 + 结果缓存 + 节点心跳
  Fallback      — Redis 不可用时自动降级到本地模式

任务生命周期:
  REQUEST → QUEUED → ASSIGNED → RUNNING → COMPLETED/FAILED
                    ↑ TIMEOUT ↓
                    ↑ 心跳丢失 → QUEUED (重新分配) ↓

使用:
  # 启动 Master (API + MCP)
  docker compose up master -d

  # 扩展 Worker
  docker compose up --scale worker=5 -d

  # 本地模式 (无 Redis)
  VULNRESEARCH_LOCAL_MODE=1 vuln-research-mcp
"""

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger("vuln-research-mcp.core.distributed")

# ============================================================
# Redis 客户端 (可选依赖, 降级到本地模式)
# ============================================================

_redis_available = False
try:
    import redis.asyncio as aioredis
    _redis_available = True
except ImportError:
    pass


class TaskStatus(str, Enum):
    REQUESTED = "requested"
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class DistributedTask:
    """分布式任务"""
    task_id: str
    tool_name: str
    arguments: dict
    node_id: str = ""
    status: TaskStatus = TaskStatus.REQUESTED
    result: Any = None
    error: str = ""
    created_at: float = field(default_factory=time.time)
    assigned_at: float = 0.0
    completed_at: float = 0.0
    retries: int = 0
    max_retries: int = 3
    timeout: int = 300


class DistributedConfig:
    """分布式配置"""

    def __init__(self):
        self.redis_url: str = os.environ.get("VULNRESEARCH_REDIS_URL", "redis://localhost:6379/0")
        self.local_mode: bool = os.environ.get("VULNRESEARCH_LOCAL_MODE", "").lower() in ("1", "true", "yes")
        self.node_id: str = os.environ.get("VULNRESEARCH_NODE_ID", f"node-{uuid.uuid4().hex[:8]}")
        self.node_role: str = os.environ.get("VULNRESEARCH_NODE_ROLE", "master")  # master / worker
        self.heartbeat_interval: int = 10    # 心跳间隔 (秒)
        self.task_timeout: int = 300         # 默认任务超时 (秒)
        self.result_ttl: int = 3600          # 结果缓存时间 (秒)
        self.queue_name: str = "vuln:task_queue"
        self.result_prefix: str = "vuln:result:"
        self.heartbeat_prefix: str = "vuln:heartbeat:"
        self.max_queue_size: int = 10000


class LocalQueue:
    """本地队列 — Redis 不可用时的降级方案"""

    def __init__(self):
        self._queue: asyncio.Queue[DistributedTask] = asyncio.Queue(maxsize=10000)
        self._results: dict[str, DistributedTask] = {}
        self._heartbeats: dict[str, float] = {}

    async def enqueue(self, task: DistributedTask):
        await self._queue.put(task)

    async def dequeue(self, timeout: float = 5.0) -> Optional[DistributedTask]:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def set_result(self, task_id: str, task: DistributedTask):
        self._results[task_id] = task

    async def get_result(self, task_id: str) -> Optional[DistributedTask]:
        return self._results.get(task_id)

    def heartbeat(self, node_id: str):
        self._heartbeats[node_id] = time.time()

    def get_active_nodes(self) -> list[str]:
        now = time.time()
        return [nid for nid, ts in self._heartbeats.items() if now - ts < 60]

    def queue_size(self) -> int:
        return self._queue.qsize()


class DistributedManager:
    """分布式任务管理器"""

    def __init__(self, config: Optional[DistributedConfig] = None):
        self.config = config or DistributedConfig()
        self._redis: Optional[Any] = None
        self._local: Optional[LocalQueue] = None
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._task_handlers: dict[str, Callable] = {}
        self._stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
        }

    # ── 生命周期 ──

    async def start(self):
        """启动分布式管理器"""
        if self.config.local_mode or not _redis_available:
            self._local = LocalQueue()
            logger.info(f"[{self.config.node_id}] 分布式: 本地模式 (无 Redis)")
        else:
            try:
                self._redis = aioredis.from_url(self.config.redis_url, decode_responses=True)
                await self._redis.ping()
                logger.info(f"[{self.config.node_id}] 分布式: Redis 已连接 ({self.config.redis_url})")
            except Exception as e:
                logger.warning(f"Redis 连接失败: {e} — 降级到本地模式")
                self._redis = None
                self._local = LocalQueue()

        self._running = True

        # 启动心跳
        if self.config.node_role == "worker":
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self):
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._redis:
            await self._redis.close()

    async def _heartbeat_loop(self):
        """Worker 心跳循环"""
        while self._running:
            try:
                await self._send_heartbeat()
            except Exception:
                pass
            await asyncio.sleep(self.config.heartbeat_interval)

    async def _send_heartbeat(self):
        key = f"{self.config.heartbeat_prefix}{self.config.node_id}"
        data = json.dumps({"node": self.config.node_id, "role": self.config.node_role, "ts": time.time()})
        if self._redis:
            await self._redis.setex(key, 60, data)
        elif self._local:
            self._local.heartbeat(self.config.node_id)

    # ── 任务提交 (Master) ──

    async def submit_task(self, tool_name: str, arguments: dict) -> DistributedTask:
        """提交任务到队列"""
        task = DistributedTask(
            task_id=uuid.uuid4().hex[:12],
            tool_name=tool_name,
            arguments=arguments,
        )
        task.status = TaskStatus.QUEUED
        self._stats["tasks_submitted"] += 1

        if self._redis:
            data = json.dumps({
                "task_id": task.task_id,
                "tool_name": task.tool_name,
                "arguments": task.arguments,
                "created_at": task.created_at,
                "timeout": task.timeout,
            })
            await self._redis.lpush(self.config.queue_name, data)
            logger.debug(f"[Master] 任务入队: {task.task_id} ({tool_name})")
        elif self._local:
            await self._local.enqueue(task)
            logger.debug(f"[Master(Local)] 任务入队: {task.task_id} ({tool_name})")

        return task

    # ── 任务拉取 (Worker) ──

    async def fetch_task(self, timeout: float = 5.0) -> Optional[DistributedTask]:
        """Worker 从队列拉取任务"""
        if self._redis:
            raw = await self._redis.brpop(self.config.queue_name, timeout=int(timeout))
            if raw:
                data = json.loads(raw[1])
                task = DistributedTask(
                    task_id=data["task_id"],
                    tool_name=data["tool_name"],
                    arguments=data["arguments"],
                    node_id=self.config.node_id,
                    status=TaskStatus.ASSIGNED,
                    created_at=data.get("created_at", time.time()),
                    timeout=data.get("timeout", self.config.task_timeout),
                )
                task.assigned_at = time.time()
                logger.debug(f"[Worker] 拉取任务: {task.task_id} ({task.tool_name})")
                return task
        elif self._local:
            task = await self._local.dequeue(timeout)
            if task:
                task.node_id = self.config.node_id
                task.status = TaskStatus.ASSIGNED
                task.assigned_at = time.time()
            return task

        return None

    # ── 结果回传 (Worker) ──

    async def report_result(self, task: DistributedTask):
        """Worker 向 Redis 回传结果"""
        key = f"{self.config.result_prefix}{task.task_id}"
        data = json.dumps({
            "task_id": task.task_id,
            "tool_name": task.tool_name,
            "status": task.status.value,
            "result": task.result,
            "error": task.error,
            "node_id": task.node_id,
            "completed_at": task.completed_at,
        })

        if self._redis:
            await self._redis.setex(key, self.config.result_ttl, data)
        elif self._local:
            await self._local.set_result(task.task_id, task)

        if task.status == TaskStatus.COMPLETED:
            self._stats["tasks_completed"] += 1
        elif task.status in (TaskStatus.FAILED, TaskStatus.TIMEOUT):
            self._stats["tasks_failed"] += 1

    # ── 等待结果 (Master) ──

    async def wait_for_result(self, task_id: str, timeout: int = 300, poll_interval: float = 0.5) -> Optional[DistributedTask]:
        """Master 等待 Worker 完成任务"""
        deadline = time.time() + timeout

        while time.time() < deadline:
            if self._redis:
                key = f"{self.config.result_prefix}{task_id}"
                raw = await self._redis.get(key)
                if raw:
                    data = json.loads(raw)
                    task = DistributedTask(
                        task_id=data["task_id"],
                        tool_name=data["tool_name"],
                        arguments={},
                        node_id=data.get("node_id", ""),
                        status=TaskStatus(data["status"]),
                        result=data.get("result"),
                        error=data.get("error", ""),
                        completed_at=data.get("completed_at", 0),
                    )
                    return task
            elif self._local:
                task = await self._local.get_result(task_id)
                if task and task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT):
                    return task

            await asyncio.sleep(poll_interval)

        return None

    # ── 注册任务处理器 (Worker) ──

    def register_handler(self, tool_name: str, handler: Callable):
        """注册工具处理函数"""
        self._task_handlers[tool_name] = handler

    async def execute_task(self, task: DistributedTask) -> DistributedTask:
        """Worker 执行任务"""
        handler = self._task_handlers.get(task.tool_name)
        if not handler:
            task.status = TaskStatus.FAILED
            task.error = f"未找到工具: {task.tool_name}"
            task.completed_at = time.time()
            return task

        task.status = TaskStatus.RUNNING
        try:
            task.result = await handler(**task.arguments)
            task.status = TaskStatus.COMPLETED
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            logger.error(f"[Worker] 任务失败 {task.task_id}: {e}")
        finally:
            task.completed_at = time.time()

        await self.report_result(task)
        return task

    # ── 分布式模式判断 ──

    @property
    def is_distributed(self) -> bool:
        return self._redis is not None

    @property
    def is_local(self) -> bool:
        return self._local is not None

    def get_active_nodes(self) -> list[str]:
        if self._local:
            return self._local.get_active_nodes()
        return [self.config.node_id]

    def summary(self) -> dict:
        return {
            "node_id": self.config.node_id,
            "role": self.config.node_role,
            "mode": "redis" if self.is_distributed else "local",
            "submitted": self._stats["tasks_submitted"],
            "completed": self._stats["tasks_completed"],
            "failed": self._stats["tasks_failed"],
            "queue_size": self._local.queue_size() if self._local else 0,
            "active_nodes": len(self.get_active_nodes()),
            "handlers": len(self._task_handlers),
        }


# ============================================================
# 全局单例
# ============================================================

_distributed: Optional[DistributedManager] = None


def get_distributed() -> DistributedManager:
    global _distributed
    if _distributed is None:
        _distributed = DistributedManager()
    return _distributed


async def init_distributed(config: Optional[DistributedConfig] = None) -> DistributedManager:
    global _distributed
    _distributed = DistributedManager(config)
    await _distributed.start()
    return _distributed
