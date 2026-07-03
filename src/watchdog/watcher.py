#!/usr/bin/env python3
"""看门狗 — CISA KEV 轮询 + 规则告警"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger("vuln-research-mcp")


@dataclass
class WatchRule:
    name: str
    cpe_list: list[str] = field(default_factory=list)
    vendor_list: list[str] = field(default_factory=list)
    product_list: list[str] = field(default_factory=list)
    cvss_above: float = 0.0
    epss_above: float = 0.0
    kev_added: bool = False
    enabled: bool = True


class Watchdog:
    def __init__(self, tool_registry, poll_interval: int = 900):
        self.tool_registry = tool_registry
        self.poll_interval = poll_interval
        self._rules: list[WatchRule] = []
        self._alert_callbacks: list[Callable] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_kev_count = 0

    def add_rule(self, rule: WatchRule):
        self._rules.append(rule)
        logger.info(f"Watch rule added: {rule.name}")

    def remove_rule(self, name: str):
        self._rules = [r for r in self._rules if r.name != name]

    def on_alert(self, callback: Callable):
        self._alert_callbacks.append(callback)

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(f"Watchdog started (poll={self.poll_interval}s)")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Watchdog stopped")

    async def _poll_loop(self):
        while self._running:
            try:
                await self._check_kev()
            except Exception as e:
                logger.error(f"Watchdog poll error: {e}")
            await asyncio.sleep(self.poll_interval)

    async def _check_kev(self):
        tool = self.tool_registry.resolve("search_kev")
        if not tool:
            return

        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                for keyword in (rule.vendor_list + rule.product_list):
                    result = await tool.handler(keyword=keyword, max_results=10)
                    if not result or "error" in str(result):
                        continue
                    vulns = result.get("vulnerabilities", result) if isinstance(result, dict) else []
                    if isinstance(vulns, list):
                        for v in vulns:
                            v_dict = v if isinstance(v, dict) else {}
                            self._fire_alert(rule, v_dict)
            except Exception as e:
                logger.debug(f"Rule {rule.name} check failed: {e}")

    def _fire_alert(self, rule: WatchRule, vuln: dict):
        cve_id = vuln.get("cveID", vuln.get("id", "unknown"))
        logger.info(f"WATCHDOG ALERT [{rule.name}]: {cve_id}")
        for cb in self._alert_callbacks:
            try:
                cb(rule, vuln)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")

    def list_rules(self) -> list[dict]:
        return [
            {
                "name": r.name,
                "cpe_list": r.cpe_list,
                "vendor_list": r.vendor_list,
                "product_list": r.product_list,
                "cvss_above": r.cvss_above,
                "epss_above": r.epss_above,
                "kev_added": r.kev_added,
                "enabled": r.enabled,
            }
            for r in self._rules
        ]
