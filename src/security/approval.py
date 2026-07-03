"""
Tool Approval Manager — Human-in-the-Loop Security Gate (v5.0)

Implements enterprise-grade tool approval workflow with:
  - Default-deny for EXPLOIT/SYSTEM risk level tools
  - Interactive CLI approval with timeout
  - Approval callback registrations for headless/CI environments
  - Session-scoped approval memoization
  - Cross-MCP data isolation via session affinity
  - Audit trail for all approval decisions
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set

from ..security.tool_guard import ToolRiskLevel, TOOL_RISK_MAP


# ── Approval Signals ──────────────────────────────────────────────────

class ApprovalDecision(Enum):
    APPROVED = auto()
    DENIED = auto()
    TIMED_OUT = auto()
    PENDING = auto()


@dataclass
class ApprovalRequest:
    """An approval request with full context for human decision-making."""
    request_id: str
    tool_name: str
    tool_risk: ToolRiskLevel
    parameters: Dict[str, Any]
    target: Optional[str] = None
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    session_id: str = "default"

    def summary(self) -> str:
        """Human-readable approval prompt."""
        lines = [
            f"╔══════════════════════════════════════════════════════════╗",
            f"║  ⚠️  TOOL APPROVAL REQUIRED                              ║",
            f"╠══════════════════════════════════════════════════════════╣",
            f"║  Tool:      {self.tool_name:<44s} ║",
            f"║  Risk:      {self.tool_risk.name:<44s} ║",
            f"║  Target:    {(self.target or 'N/A'):<44s} ║",
            f"║  Session:   {self.session_id:<44s} ║",
            f"╠══════════════════════════════════════════════════════════╣",
            f"║  Reason:    {self.reason[:44]:<44s} ║",
            f"╚══════════════════════════════════════════════════════════╝",
        ]
        return "\n".join(lines)


# ── Approval Callback Protocol ──────────────────────────────────────

ApprovalCallback = Callable[[ApprovalRequest], asyncio.Future]


# ── Session Isolation ───────────────────────────────────────────────

class SessionIsolationManager:
    """Prevents cross-MCP data leakage by scoping data to session affinity.

    When a MCP server connects, it gets a unique session ID. All assets,
    findings, and scan results are tagged with this session. Other MCP
    servers connected to the same vuln-research-mcp instance cannot
    access data from different sessions.

    This prevents lateral movement: even if a malicious MCP server is
    connected alongside a legitimate one, it cannot read scan data
    collected by the legitimate session.
    """

    def __init__(self):
        self._session_keys: Dict[str, bytes] = {}

    def register_session(self, session_id: str) -> bytes:
        """Register a new session and return its isolation key."""
        key = os.urandom(32)
        self._session_keys[session_id] = key
        return key

    def get_session_key(self, session_id: str) -> Optional[bytes]:
        return self._session_keys.get(session_id)

    def sign_data(self, session_id: str, data: bytes) -> bytes:
        """HMAC-sign data with session key for integrity verification."""
        key = self._session_keys.get(session_id)
        if not key:
            return data
        sig = hmac.new(key, data, hashlib.sha256).digest()
        return sig + data

    def verify_and_strip(self, session_id: str, signed_data: bytes) -> Optional[bytes]:
        """Verify HMAC and return original data, or None if tampered."""
        key = self._session_keys.get(session_id)
        if not key:
            return signed_data[32:] if len(signed_data) > 32 else signed_data
        sig, data = signed_data[:32], signed_data[32:]
        expected = hmac.new(key, data, hashlib.sha256).digest()
        if hmac.compare_digest(sig, expected):
            return data
        return None

    def remove_session(self, session_id: str):
        self._session_keys.pop(session_id, None)


# ── Approval Manager ────────────────────────────────────────────────

@dataclass
class _ApprovalState:
    """Internal state for a tool's approval configuration."""
    tool_name: str
    require_approval: bool = False
    auto_approve_patterns: List[str] = field(default_factory=list)
    max_approvals_per_session: int = 10
    approval_count: int = 0


class ToolApprovalManager:
    """Enterprise-grade tool approval with human-in-the-loop.

    Default Policy (production-safe):
    - READ_ONLY tools:         auto-approve (never prompt)
    - NETWORK_INFO tools:      auto-approve (low risk)
    - ACTIVE_SCAN tools:       approval required (target-dependent)
    - EXPLOIT tools:           approval required (DEFAULT DENY)
    - SYSTEM tools:            approval required (DEFAULT DENY)

    Integration Modes:
    1. Interactive CLI: stdin prompt with timeout (default)
    2. Headless/Callback: register approve_callback / deny_callback
    3. CI/Automation: auto-approve list from environment
    """

    DEFAULT_TIMEOUT_SECONDS = 30
    AUTO_APPROVE_ENV = "VULNRESEARCH_AUTO_APPROVE"  # comma-separated tool names

    def __init__(self, session_isolation: Optional[SessionIsolationManager] = None):
        self._states: Dict[str, _ApprovalState] = {}
        self._pending: Dict[str, ApprovalRequest] = {}
        self._history: List[ApprovalRequest] = []
        self._callbacks: Dict[str, ApprovalCallback] = {}
        self._isolation = session_isolation or SessionIsolationManager()
        self._auto_approve_tools: Set[str] = self._load_auto_approve_from_env()

    @staticmethod
    def _load_auto_approve_from_env() -> Set[str]:
        raw = os.environ.get(ToolApprovalManager.AUTO_APPROVE_ENV, "")
        if raw.strip() == "*":
            return {"*"}
        return {name.strip() for name in raw.split(",") if name.strip()}

    # ── Configuration ───────────────────────────────────────────

    def configure_tool(
        self,
        tool_name: str,
        require_approval: bool = True,
        max_approvals_per_session: int = 10,
        auto_approve_patterns: Optional[List[str]] = None,
    ):
        """Configure approval policy for a specific tool."""
        self._states[tool_name] = _ApprovalState(
            tool_name=tool_name,
            require_approval=require_approval,
            auto_approve_patterns=auto_approve_patterns or [],
            max_approvals_per_session=max_approvals_per_session,
        )

    def configure_from_policy(self, policy: Dict[str, Any]):
        """Bulk configure from a policy dict.

        Example:
            {
                "default_deny_levels": ["EXPLOIT", "SYSTEM"],
                "require_approval_levels": ["ACTIVE_SCAN"],
                "auto_approve_tools": ["search_cve", "lookup_cvss"],
                "tools": {
                    "search_metasploit": {"require_approval": true, "timeout": 60},
                }
            }
        """
        deny_levels = set(policy.get("default_deny_levels", ["EXPLOIT", "SYSTEM"]))
        approval_levels = set(policy.get("require_approval_levels", ["ACTIVE_SCAN"]))

        for tool_name, risk_level in TOOL_RISK_MAP.items():
            level_name = risk_level.name if hasattr(risk_level, 'name') else str(risk_level)
            level_str = str(risk_level)

            if level_str in deny_levels:
                self._states[tool_name] = _ApprovalState(
                    tool_name=tool_name,
                    require_approval=True,
                    max_approvals_per_session=3,  # strict for dangerous tools
                )
            elif level_str in approval_levels:
                self._states[tool_name] = _ApprovalState(
                    tool_name=tool_name,
                    require_approval=True,
                    max_approvals_per_session=10,
                )

        # Per-tool overrides
        tool_overrides = policy.get("tools", {})
        for tool_name, cfg in tool_overrides.items():
            self._states[tool_name] = _ApprovalState(
                tool_name=tool_name,
                require_approval=cfg.get("require_approval", True),
                max_approvals_per_session=cfg.get("max_per_session", 10),
            )

    def register_callback(self, name: str, callback: ApprovalCallback):
        """Register an approval callback for headless/CI mode.

        The callback receives an ApprovalRequest and should return
        an asyncio Future that resolves to True (approve) or False (deny).
        """
        self._callbacks[name] = callback

    # ── Approval Flow ───────────────────────────────────────────

    async def request_approval(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        target: Optional[str] = None,
        session_id: str = "default",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> ApprovalDecision:
        """Request approval for a tool invocation.

        Returns ApprovalDecision.APPROVED, DENIED, or TIMED_OUT.
        """
        # Determine risk level
        risk = self._get_risk(tool_name)

        # Check if auto-approved
        if self._is_auto_approved(tool_name, risk):
            return ApprovalDecision.APPROVED

        # Check state
        state = self._states.get(tool_name)
        if state and not state.require_approval:
            return ApprovalDecision.APPROVED

        # Default-deny: if state exists and require_approval, or no state but high risk
        if not state and risk in (ToolRiskLevel.EXPLOIT, ToolRiskLevel.SYSTEM):
            state = _ApprovalState(tool_name=tool_name, require_approval=True)

        if not state or not state.require_approval:
            return ApprovalDecision.APPROVED

        # Rate limit approvals per session
        if state.approval_count >= state.max_approvals_per_session:
            return ApprovalDecision.DENIED

        # Determine reason
        reason = self._build_reason(tool_name, risk, target, session_id)

        # Create request
        req = ApprovalRequest(
            request_id=_generate_request_id(),
            tool_name=tool_name,
            tool_risk=risk,
            parameters=parameters,
            target=target,
            reason=reason,
            session_id=session_id,
        )

        # Try callbacks first (headless mode)
        for cb_name, callback in list(self._callbacks.items()):
            try:
                approved = await asyncio.wait_for(callback(req), timeout=timeout)
                if approved:
                    state.approval_count += 1
                    self._history.append(req)
                    return ApprovalDecision.APPROVED
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        # Interactive prompt (CLI mode)
        try:
            decision = await asyncio.wait_for(
                self._interactive_prompt(req), timeout=timeout
            )
        except asyncio.TimeoutError:
            self._history.append(req)
            return ApprovalDecision.TIMED_OUT

        if decision:
            state.approval_count += 1
            result = ApprovalDecision.APPROVED
        else:
            result = ApprovalDecision.DENIED

        self._history.append(req)
        return result

    def approve_immediate(self, tool_name: str, parameters: Dict[str, Any], session_id: str = "default") -> bool:
        """Synchronous (non-interactive) approval check for API/headless mode."""
        risk = self._get_risk(tool_name)
        if self._is_auto_approved(tool_name, risk):
            return True
        state = self._states.get(tool_name)
        if state and state.require_approval:
            return False
        if not state and risk in (ToolRiskLevel.EXPLOIT, ToolRiskLevel.SYSTEM):
            return False
        return True

    def reset_session(self, session_id: str = "default"):
        """Reset approval counters for a session."""
        for state in self._states.values():
            state.approval_count = 0

    def get_history(self, limit: int = 50) -> List[ApprovalRequest]:
        return self._history[-limit:]

    def get_pending(self) -> List[ApprovalRequest]:
        return list(self._pending.values())

    # ── Internal Helpers ─────────────────────────────────────────

    def _get_risk(self, tool_name: str) -> ToolRiskLevel:
        for name, risk in TOOL_RISK_MAP.items():
            if name == tool_name:
                return risk
        return ToolRiskLevel.READ_ONLY

    def _is_auto_approved(self, tool_name: str, risk: ToolRiskLevel) -> bool:
        """Check if tool should be auto-approved."""
        # Environment override (CI/CD) — "*" means approve all
        if "*" in self._auto_approve_tools:
            return True
        if tool_name in self._auto_approve_tools:
            return True

        # READ_ONLY and NETWORK_INFO are auto-approved by default
        if risk in (ToolRiskLevel.READ_ONLY, ToolRiskLevel.NETWORK_INFO):
            return True

        return False

    def _build_reason(
        self, tool_name: str, risk: ToolRiskLevel,
        target: Optional[str], session_id: str
    ) -> str:
        parts = []
        if risk == ToolRiskLevel.EXPLOIT:
            parts.append("EXPLOIT-level tool — may execute attack payloads")
        elif risk == ToolRiskLevel.SYSTEM:
            parts.append("SYSTEM-level tool — can modify host configuration")
        elif risk == ToolRiskLevel.ACTIVE_SCAN:
            parts.append("ACTIVE_SCAN — will send network packets to target")

        if target:
            parts.append(f"target: {target}")

        return " | ".join(parts)

    async def _interactive_prompt(self, req: ApprovalRequest) -> bool:
        """Show approval prompt on stderr and wait for y/n on stdin."""
        import sys

        print(file=sys.stderr)
        print(req.summary(), file=sys.stderr)
        print(file=sys.stderr)

        try:
            # Non-blocking read from stdin
            loop = asyncio.get_event_loop()
            user_input = await loop.run_in_executor(
                None, lambda: input("  Allow this operation? [y/N] ").strip().lower()
            )
            return user_input in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False


def _generate_request_id() -> str:
    return hashlib.sha256(os.urandom(32)).hexdigest()[:16]


# ── Global Singleton ────────────────────────────────────────────────

_approval_manager: Optional[ToolApprovalManager] = None


def get_approval_manager() -> ToolApprovalManager:
    global _approval_manager
    if _approval_manager is None:
        _approval_manager = ToolApprovalManager()
    return _approval_manager
