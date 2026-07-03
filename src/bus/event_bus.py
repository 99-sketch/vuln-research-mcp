"""Event-driven message bus with synchronous and asynchronous Pub/Sub.

All modules communicate through this bus, enabling loose coupling
between scanners, correlators, persistence, and reporting layers.

Standard events:
    scan_started, scan_completed, port_found, service_discovered
    vuln_found, exploit_available, cve_matched, kev_alert
    asset_created, finding_created, report_generated
    workflow_started, workflow_step_completed, workflow_completed
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set


class EventPriority(Enum):
    HIGH = 0
    NORMAL = 1
    LOW = 2


@dataclass
class Event:
    """A typed event with payload, timestamp, and source origin."""

    event_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    timestamp: float = field(default_factory=time.time)
    priority: EventPriority = EventPriority.NORMAL
    correlation_id: str = ""
    session_id: str = ""


HandlerFn = Callable[[Event], None]
AsyncHandlerFn = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Global event bus supporting sync and async handlers.

    Thread-safe. All events are published immediately to subscribers.
    Async handlers are scheduled via asyncio event loop if available.
    """

    def __init__(self):
        self._sync_handlers: Dict[str, List[HandlerFn]] = defaultdict(list)
        self._async_handlers: Dict[str, List[AsyncHandlerFn]] = defaultdict(list)
        self._wildcard_handlers: List[HandlerFn] = []
        self._wildcard_async_handlers: List[AsyncHandlerFn] = []
        self._lock = threading.RLock()
        self._history: List[Event] = []
        self._max_history = 1000
        self._counter = 0

    def subscribe(self, event_type: str, handler: HandlerFn) -> None:
        """Subscribe a synchronous handler to a specific event type."""
        with self._lock:
            self._sync_handlers[event_type].append(handler)

    def subscribe_async(self, event_type: str, handler: AsyncHandlerFn) -> None:
        """Subscribe an async handler to a specific event type."""
        with self._lock:
            self._async_handlers[event_type].append(handler)

    def subscribe_all(self, handler: HandlerFn) -> None:
        """Subscribe to ALL events (sync)."""
        with self._lock:
            self._wildcard_handlers.append(handler)

    def subscribe_all_async(self, handler: AsyncHandlerFn) -> None:
        """Subscribe to ALL events (async)."""
        with self._lock:
            self._wildcard_async_handlers.append(handler)

    def unsubscribe(self, event_type: str, handler: HandlerFn) -> None:
        """Remove a sync subscription."""
        with self._lock:
            if event_type in self._sync_handlers:
                self._sync_handlers[event_type] = [
                    h for h in self._sync_handlers[event_type] if h is not handler
                ]

    def publish(self, event: Event) -> None:
        """Publish an event. Sync handlers run inline; async handlers scheduled."""
        self._counter += 1

        with self._lock:
            if len(self._history) >= self._max_history:
                self._history = self._history[-self._max_history // 2 :]
            self._history.append(event)

        syncs = []
        wildcards = []
        asyncs = []
        async_wildcards = []

        with self._lock:
            syncs = list(self._sync_handlers.get(event.event_type, []))
            wildcards = list(self._wildcard_handlers)
            asyncs = list(self._async_handlers.get(event.event_type, []))
            async_wildcards = list(self._wildcard_async_handlers)

        for handler in syncs:
            try:
                handler(event)
            except Exception:
                pass

        for handler in wildcards:
            try:
                handler(event)
            except Exception:
                pass

        if asyncs or async_wildcards:
            self._schedule_async(event, asyncs, async_wildcards)

    def _schedule_async(
        self,
        event: Event,
        asyncs: List[AsyncHandlerFn],
        wildcards: List[AsyncHandlerFn],
    ) -> None:
        """Schedule async handlers in the event loop if available."""
        try:
            loop = asyncio.get_running_loop()
            for handler in asyncs:
                loop.create_task(self._safe_async(handler, event))
            for handler in wildcards:
                loop.create_task(self._safe_async(handler, event))
        except RuntimeError:
            pass

    async def _safe_async(self, handler: AsyncHandlerFn, event: Event) -> None:
        try:
            await handler(event)
        except Exception:
            pass

    async def publish_async(self, event: Event) -> None:
        """Publish event and await all async handlers."""
        self._counter += 1

        with self._lock:
            if len(self._history) >= self._max_history:
                self._history = self._history[-self._max_history // 2 :]
            self._history.append(event)

        syncs = []
        wildcards = []
        asyncs = []
        async_wildcards = []

        with self._lock:
            syncs = list(self._sync_handlers.get(event.event_type, []))
            wildcards = list(self._wildcard_handlers)
            asyncs = list(self._async_handlers.get(event.event_type, []))
            async_wildcards = list(self._wildcard_async_handlers)

        for handler in syncs:
            try:
                handler(event)
            except Exception:
                pass
        for handler in wildcards:
            try:
                handler(event)
            except Exception:
                pass

        tasks = []
        for handler in asyncs:
            tasks.append(self._safe_async(handler, event))
        for handler in wildcards:
            tasks.append(self._safe_async(handler, event))
        if tasks:
            await asyncio.gather(*tasks)

    def get_history(self, event_type: Optional[str] = None, limit: int = 100) -> List[Event]:
        """Retrieve recent event history with optional type filter."""
        with self._lock:
            if event_type:
                return [e for e in self._history[-limit:] if e.event_type == event_type]
            return self._history[-limit:]

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._sync_handlers.values()) + sum(
                len(v) for v in self._async_handlers.values()
            ) + len(self._wildcard_handlers) + len(self._wildcard_async_handlers)

    @property
    def event_count(self) -> int:
        return self._counter


# Global singleton
_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Return the global singleton EventBus."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
