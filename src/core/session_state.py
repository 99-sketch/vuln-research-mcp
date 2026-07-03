#!/usr/bin/env python3
"""会话状态管理 — 多会话上下文追踪"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("vuln-research-mcp")


@dataclass
class SessionContext:
    session_id: str
    created_at: float = field(default_factory=time.time)
    target: str = ""
    ports: list[int] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    workflow_results: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "target": self.target,
            "ports": self.ports,
            "subdomains": self.subdomains,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "workflow_results": self.workflow_results,
            "metadata": self.metadata,
        }


class SessionManager:
    def __init__(self):
        self._sessions: dict[str, SessionContext] = {}
        self._current_id: Optional[str] = None

    def create(self, session_id: str = None) -> SessionContext:
        if session_id is None:
            session_id = f"session-{int(time.time())}"
        ctx = SessionContext(session_id=session_id)
        self._sessions[session_id] = ctx
        self._current_id = session_id
        logger.info(f"会话创建: {session_id}")
        return ctx

    def get(self, session_id: str = None) -> Optional[SessionContext]:
        sid = session_id or self._current_id
        return self._sessions.get(sid)

    def current(self) -> Optional[SessionContext]:
        return self.get(self._current_id)

    def switch(self, session_id: str) -> bool:
        if session_id in self._sessions:
            self._current_id = session_id
            return True
        return False

    def list_all(self) -> list[dict]:
        return [ctx.to_dict() for ctx in self._sessions.values()]

    def cleanup(self, max_age_seconds: float = 3600):
        now = time.time()
        expired = [sid for sid, ctx in self._sessions.items() if now - ctx.created_at > max_age_seconds]
        for sid in expired:
            del self._sessions[sid]
        if expired:
            logger.info(f"清理过期会话: {len(expired)} 个")

    def update_context(self, **kwargs):
        ctx = self.current()
        if ctx:
            for k, v in kwargs.items():
                if hasattr(ctx, k):
                    setattr(ctx, k, v)


# 全局实例
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
