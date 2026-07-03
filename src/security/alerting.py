"""
Enterprise Alerting System — DingTalk / Email / Syslog / Webhook (v5.0)

Multi-channel alerting with:
  - DingTalk (钉钉) webhook integration
  - Email (SMTP) alerting
  - Syslog (RFC 5424) integration for SIEM
  - Generic webhook for custom integrations
  - Rate-limited alerting (prevents storm)
  - Severity-based routing
  - Alert deduplication

Usage:
    alerter = AlertManager()
    alerter.add_dingtalk_channel("ops", webhook_url="https://oapi.dingtalk.com/...")
    alerter.send_alert(
        severity="CRITICAL",
        title="Unauthorized scan attempt blocked",
        details="Tool: scan_ports | Target: 10.0.0.1 | Action: BLOCKED"
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import smtplib
import socket
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


logger = logging.getLogger(__name__)


# ── Alert Severity ──────────────────────────────────────────────────

class AlertSeverity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# ── Alert Event ─────────────────────────────────────────────────────

@dataclass
class Alert:
    """A structured alert event."""
    id: str
    severity: AlertSeverity
    title: str
    details: str
    source: str = "vuln-research-mcp"
    hostname: str = field(default_factory=socket.gethostname)
    timestamp: float = field(default_factory=time.time)
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, severity: AlertSeverity, title: str, details: str, **kwargs) -> "Alert":
        """Create an alert with auto-generated dedup ID."""
        # Dedup key: hash of (source, title, first 200 chars of details)
        dedup_input = f"{kwargs.get('source', 'vuln-research-mcp')}:{title}:{details[:200]}"
        alert_id = hashlib.sha256(dedup_input.encode()).hexdigest()[:16]

        return cls(id=alert_id, severity=severity, title=title, details=details, **kwargs)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "details": self.details,
            "source": self.source,
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "tags": self.tags,
            "metadata": self.metadata,
        }


# ── Alert Channel Interface ─────────────────────────────────────────

class AlertChannel:
    """Base class for alert delivery channels."""

    async def send(self, alert: Alert) -> bool:
        raise NotImplementedError

    def send_sync(self, alert: Alert) -> bool:
        """Synchronous send (for non-async contexts)."""
        raise NotImplementedError


# ── DingTalk Channel ────────────────────────────────────────────────

class DingTalkChannel(AlertChannel):
    """钉钉群机器人 Webhook 告警通道。

    Setup:
        1. 创建钉钉群
        2. 群设置 -> 智能群助手 -> 添加机器人 -> 自定义
        3. 获取 Webhook URL
        4. 设置 VULNRESEARCH_DINGTALK_WEBHOOK 环境变量或代码配置

    Rate limit: 20 messages/minute per bot (钉钉限制)
    """

    MAX_MESSAGE_LENGTH = 20000  # 钉钉限制

    def __init__(self, name: str, webhook_url: str, secret: Optional[str] = None):
        self.name = name
        self.webhook_url = webhook_url
        self.secret = secret
        self._last_send_time = 0.0
        self._send_count_this_minute = 0
        self._minute_start = 0.0

    def send_sync(self, alert: Alert) -> bool:
        """Send alert to DingTalk via webhook."""
        now = time.time()

        # Rate limit: 20 per minute
        if now - self._minute_start > 60:
            self._minute_start = now
            self._send_count_this_minute = 0
        if self._send_count_this_minute >= 19:  # leave one for margin
            logger.warning(f"DingTalk channel '{self.name}' rate limited")
            return False

        # Build DingTalk Markdown message
        severity_emoji = {
            AlertSeverity.CRITICAL: "🔴",
            AlertSeverity.ERROR: "🟠",
            AlertSeverity.WARNING: "🟡",
            AlertSeverity.INFO: "🔵",
            AlertSeverity.DEBUG: "⚪",
        }

        emoji = severity_emoji.get(alert.severity, "📢")
        markdown_text = f"""## {emoji} {alert.severity.value}: {alert.title}

**来源**: {alert.source}
**主机**: {alert.hostname}
**时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp))}

---

{alert.details[:self.MAX_MESSAGE_LENGTH - 500]}

---

> 自动告警 · vuln-research-mcp v5.0
"""
        if len(markdown_text) > self.MAX_MESSAGE_LENGTH:
            markdown_text = markdown_text[:self.MAX_MESSAGE_LENGTH - 100] + "\n\n> ...内容过长已截断"

        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": f"[{alert.severity.value}] {alert.title[:50]}",
                "text": markdown_text,
            },
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                if result.get("errcode") == 0:
                    self._send_count_this_minute += 1
                    self._last_send_time = now
                    return True
                else:
                    logger.error(f"DingTalk returned error: {result.get('errmsg')}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send DingTalk alert: {e}")
            return False


# ── Email Channel ──────────────────────────────────────────────────

class EmailChannel(AlertChannel):
    """Email alerting via SMTP.

    Env vars:
        VULNRESEARCH_SMTP_HOST, VULNRESEARCH_SMTP_PORT,
        VULNRESEARCH_SMTP_USER, VULNRESEARCH_SMTP_PASS,
        VULNRESEARCH_ALERT_EMAIL_FROM, VULNRESEARCH_ALERT_EMAIL_TO
    """

    def __init__(
        self,
        name: str,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_pass: str = "",
        from_addr: str = "",
        to_addrs: Optional[List[str]] = None,
        use_tls: bool = True,
    ):
        self.name = name
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.from_addr = from_addr
        self.to_addrs = to_addrs or []
        self.use_tls = use_tls

    @classmethod
    def from_env(cls, name: str = "email") -> Optional["EmailChannel"]:
        """Create from environment variables. Returns None if not configured."""
        host = os.environ.get("VULNRESEARCH_SMTP_HOST", "")
        if not host:
            return None

        to_str = os.environ.get("VULNRESEARCH_ALERT_EMAIL_TO", "")
        to_addrs = [a.strip() for a in to_str.split(",") if a.strip()]

        return cls(
            name=name,
            smtp_host=host,
            smtp_port=int(os.environ.get("VULNRESEARCH_SMTP_PORT", "587")),
            smtp_user=os.environ.get("VULNRESEARCH_SMTP_USER", ""),
            smtp_pass=os.environ.get("VULNRESEARCH_SMTP_PASS", ""),
            from_addr=os.environ.get("VULNRESEARCH_ALERT_EMAIL_FROM", ""),
            to_addrs=to_addrs,
        )

    def send_sync(self, alert: Alert) -> bool:
        if not self.to_addrs or not self.smtp_host:
            return False

        subject = f"[{alert.severity.value}] {alert.title} — vuln-research-mcp"
        body = f"""vuln-research-mcp Alert

Severity:  {alert.severity.value}
Title:     {alert.title}
Source:    {alert.source}
Host:      {alert.hostname}
Time:      {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp))}

Details:
{alert.details}

---
This is an automated alert from vuln-research-mcp v5.0
"""
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = self.from_addr
        msg['To'] = ", ".join(self.to_addrs)

        try:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
            if self.use_tls:
                server.starttls()
            if self.smtp_user:
                server.login(self.smtp_user, self.smtp_pass)
            server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            server.quit()
            return True
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False


# ── Syslog / SIEM Channel ──────────────────────────────────────────

class SyslogChannel(AlertChannel):
    """RFC 5424 syslog integration for SIEM (Splunk, ELK, QRadar, etc.).

    Supports:
        - Local syslog (/dev/log or UDP 514)
        - Remote syslog (TCP/UDP)
        - CEF (Common Event Format) for ArcSight/Splunk
        - LEEF (Log Event Extended Format) for QRadar
    """

    FACILITY_USER = 1
    SEVERITY_MAP = {
        AlertSeverity.DEBUG: 7,      # debug
        AlertSeverity.INFO: 6,       # informational
        AlertSeverity.WARNING: 4,    # warning
        AlertSeverity.ERROR: 3,      # error
        AlertSeverity.CRITICAL: 2,   # critical
    }

    def __init__(
        self,
        name: str,
        host: str = "localhost",
        port: int = 514,
        protocol: str = "udp",
        format: str = "rfc5424",  # rfc5424, cef, leef
        facility: int = FACILITY_USER,
        app_name: str = "vuln-research-mcp",
    ):
        self.name = name
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.format = format.lower()
        self.facility = facility
        self.app_name = app_name

    def send_sync(self, alert: Alert) -> bool:
        try:
            if self.format == "cef":
                message = self._format_cef(alert)
            elif self.format == "leef":
                message = self._format_leef(alert)
            else:
                message = self._format_rfc5424(alert)

            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode('utf-8'), (self.host, self.port))
                sock.close()
            elif self.protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.host, self.port))
                sock.sendall((message + '\n').encode('utf-8'))
                sock.close()

            return True
        except Exception as e:
            logger.error(f"Failed to send syslog alert: {e}")
            return False

    def _format_rfc5424(self, alert: Alert) -> str:
        """RFC 5424 formatted syslog message."""
        pri = (self.facility << 3) | self.SEVERITY_MAP.get(alert.severity, 6)

        # Structured data for SIEM parsing
        sd = f'[alert@{alert.id} severity="{alert.severity.value}" title="{alert.title}" source="{alert.source}" hostname="{alert.hostname}"]'

        msg = f"{alert.title} | {alert.details[:500]}"
        return f"<{pri}>1 {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(alert.timestamp))} {alert.hostname} {self.app_name} - - {sd} {msg}"

    def _format_cef(self, alert: Alert) -> str:
        """CEF (Common Event Format) for ArcSight/Splunk."""
        cef_severity = {
            AlertSeverity.CRITICAL: "10",
            AlertSeverity.ERROR: "7",
            AlertSeverity.WARNING: "5",
            AlertSeverity.INFO: "3",
            AlertSeverity.DEBUG: "1",
        }.get(alert.severity, "5")

        extensions = (
            f"msg={alert.details[:500]} "
            f"source={alert.source} "
            f"shost={alert.hostname} "
            f"dhost={alert.tags.get('target', 'N/A')}"
        )

        return (
            f"CEF:0|vuln-research-mcp|vuln-research-mcp|5.0.0|{alert.id}|{alert.title}|"
            f"{cef_severity}|{extensions}"
        )

    def _format_leef(self, alert: Alert) -> str:
        """LEEF (Log Event Extended Format) for QRadar."""
        leef_severity = {
            AlertSeverity.CRITICAL: "10",
            AlertSeverity.ERROR: "8",
            AlertSeverity.WARNING: "5",
            AlertSeverity.INFO: "3",
            AlertSeverity.DEBUG: "1",
        }.get(alert.severity, "5")

        return (
            f"LEEF:2.0|vuln-research-mcp|vuln-research-mcp|5.0.0|{alert.id}|"
            f"sev={leef_severity}\t"
            f"title={alert.title}\t"
            f"msg={alert.details[:500]}\t"
            f"src={alert.hostname}\t"
            f"target={alert.tags.get('target', 'N/A')}"
        )


# ── Webhook Channel ─────────────────────────────────────────────────

class WebhookChannel(AlertChannel):
    """Generic webhook channel for custom integrations (企业微信, 飞书, Slack, etc.)."""

    def __init__(self, name: str, url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 10):
        self.name = name
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout

    def send_sync(self, alert: Alert) -> bool:
        try:
            data = json.dumps(alert.to_dict()).encode('utf-8')
            req = urllib.request.Request(self.url, data=data, headers=self.headers)
            urllib.request.urlopen(req, timeout=self.timeout)
            return True
        except Exception as e:
            logger.error(f"Failed to send webhook alert to '{self.name}': {e}")
            return False


# ── Alert Manager ───────────────────────────────────────────────────

class AlertManager:
    """Central alert manager with multi-channel routing and deduplication.

    Features:
        - Route alerts by severity (e.g., CRITICAL -> all channels, INFO -> log only)
        - Deduplicate identical alerts within a time window
        - Rate limit to prevent alert storms
        - Minimum severity threshold per channel
    """

    DEDUP_WINDOW = 300  # 5 minutes

    def __init__(self):
        self._channels: Dict[str, AlertChannel] = {}
        self._dedup_cache: Dict[str, float] = {}  # alert_id -> last_sent_time
        self._sent_count: int = 0
        self._start_time: float = time.time()
        self._min_severity_per_channel: Dict[str, AlertSeverity] = {}
        self._callbacks: List[Callable[[Alert], None]] = []

    # ── Channel Management ──────────────────────────────────────

    def add_channel(self, channel: AlertChannel, min_severity: AlertSeverity = AlertSeverity.WARNING):
        """Add an alert channel with minimum severity threshold."""
        self._channels[channel.name] = channel
        self._min_severity_per_channel[channel.name] = min_severity

    def add_dingtalk_channel(self, name: str, webhook_url: str, secret: Optional[str] = None, min_severity: AlertSeverity = AlertSeverity.WARNING):
        """Convenience method for adding DingTalk."""
        channel = DingTalkChannel(name, webhook_url, secret)
        self.add_channel(channel, min_severity)

    def add_email_channel(self, name: str = "email", min_severity: AlertSeverity = AlertSeverity.ERROR):
        """Convenience method for adding email from environment."""
        channel = EmailChannel.from_env(name)
        if channel:
            self.add_channel(channel, min_severity)

    def add_syslog_channel(self, name: str = "syslog", host: str = "localhost", port: int = 514, format: str = "rfc5424", min_severity: AlertSeverity = AlertSeverity.WARNING):
        """Convenience method for adding syslog/SIEM."""
        channel = SyslogChannel(name, host, port, format=format)
        self.add_channel(channel, min_severity)

    def register_callback(self, callback: Callable[[Alert], None]):
        """Register a custom callback for all alerts (e.g., write to audit log)."""
        self._callbacks.append(callback)

    # ── Sending Alerts ──────────────────────────────────────────

    def send_alert(
        self,
        severity: AlertSeverity,
        title: str,
        details: str,
        source: str = "vuln-research-mcp",
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        dedup: bool = True,
    ) -> bool:
        """Send an alert to all configured channels.

        Args:
            severity: Alert severity level
            title: Short alert title
            details: Detailed alert message
            source: Alert source identifier
            tags: Key-value tags for routing/filtering
            metadata: Additional structured metadata
            dedup: Whether to deduplicate (skip duplicate alerts within DEDUP_WINDOW)

        Returns:
            True if alert was sent to at least one channel
        """
        alert = Alert.create(
            severity=severity,
            title=title,
            details=details,
            source=source,
            tags=tags or {},
            metadata=metadata or {},
        )

        # Deduplication
        if dedup:
            now = time.time()
            # Clean expired dedup entries
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items()
                if now - v < self.DEDUP_WINDOW
            }
            if alert.id in self._dedup_cache:
                logger.debug(f"Dedup: skipping duplicate alert '{alert.id}'")
                return False
            self._dedup_cache[alert.id] = now

        sent_any = False

        # Route to channels
        for channel_name, channel in self._channels.items():
            min_sev = self._min_severity_per_channel.get(channel_name, AlertSeverity.WARNING)
            if self._severity_meets_threshold(alert.severity, min_sev):
                try:
                    if channel.send_sync(alert):
                        sent_any = True
                except Exception as e:
                    logger.error(f"Channel '{channel_name}' failed: {e}")

        # Fire callbacks
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")

        if sent_any:
            self._sent_count += 1

        return sent_any

    def send_sync(self, severity: str, title: str, details: str, **kwargs) -> bool:
        """Synchronous convenience wrapper."""
        sev = AlertSeverity(severity) if isinstance(severity, str) else severity
        return self.send_alert(sev, title, details, **kwargs)

    # ── Stats ──────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "channels": len(self._channels),
            "sent_total": self._sent_count,
            "uptime_seconds": time.time() - self._start_time,
            "dedup_cache_size": len(self._dedup_cache),
        }

    # ── Helpers ────────────────────────────────────────────────

    @staticmethod
    def _severity_meets_threshold(severity: AlertSeverity, threshold: AlertSeverity) -> bool:
        order = {
            AlertSeverity.DEBUG: 0,
            AlertSeverity.INFO: 1,
            AlertSeverity.WARNING: 2,
            AlertSeverity.ERROR: 3,
            AlertSeverity.CRITICAL: 4,
        }
        return order.get(severity, 0) >= order.get(threshold, 0)


# ── Global Singleton ────────────────────────────────────────────────

_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get or create the global AlertManager."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()

        # Auto-configure from environment
        dingtalk_url = os.environ.get("VULNRESEARCH_DINGTALK_WEBHOOK", "")
        if dingtalk_url:
            _alert_manager.add_dingtalk_channel("dingtalk", dingtalk_url)

        email_channel = EmailChannel.from_env("email")
        if email_channel:
            _alert_manager.add_channel(email_channel, AlertSeverity.ERROR)

        syslog_host = os.environ.get("VULNRESEARCH_SYSLOG_HOST", "")
        if syslog_host:
            _alert_manager.add_syslog_channel("syslog", syslog_host)

    return _alert_manager
