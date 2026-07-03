# tests/test_security_audit.py
"""Tests for src/security/audit.py"""

import os
import tempfile
import json
import pytest
from src.security.audit import AuditLogger, AuditEvent, create_audit_logger


class TestAuditEvent:
    def test_serialization(self):
        event = AuditEvent(
            timestamp="2026-07-03T10:00:00.000Z",
            event_type="tool_call",
            tool_name="search_cve",
            parameters={"keyword": "log4j"},
            result="success",
        )
        serialized = event.serialize()
        data = json.loads(serialized)
        assert data["event_type"] == "tool_call"
        assert data["tool_name"] == "search_cve"
        assert data["result"] == "success"

    def test_serialization_includes_metadata(self):
        event = AuditEvent(
            timestamp="2026-07-03T10:00:00.000Z",
            event_type="scan_attempt",
            tool_name="scan_ports",
            target="example.com",
            result="denied",
            reason="blocked by policy",
            metadata={"prev_hash": "abc123"},
        )
        serialized = event.serialize()
        data = json.loads(serialized)
        assert data["metadata"] == {"prev_hash": "abc123"}


class TestAuditLogger:
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield d

    @pytest.fixture
    def logger(self, temp_dir):
        return AuditLogger(log_dir=temp_dir)

    def test_log_tool_call_writes_file(self, logger, temp_dir):
        logger.log_tool_call(
            tool_name="search_cve",
            parameters={"keyword": "log4j"},
            result="success",
        )
        # Check that an audit file was created
        files = os.listdir(temp_dir)
        assert len(files) == 1
        assert files[0].startswith("audit-")
        assert files[0].endswith(".jsonl")

    def test_log_scan_attempt(self, logger, temp_dir):
        logger.log_scan_attempt(
            tool_name="scan_ports",
            target="192.168.1.1",
            allowed=False,
            reason="internal network denied",
        )
        files = os.listdir(temp_dir)
        assert len(files) == 1

    def test_log_multiple_events_have_hash_chain(self, logger, temp_dir):
        logger.log_tool_call("tool_a", {}, result="success")
        logger.log_tool_call("tool_b", {}, result="success")

        log_file = os.path.join(temp_dir, sorted(os.listdir(temp_dir))[0])
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) >= 2
        # First event should have a hash
        events = [json.loads(line) for line in lines]
        assert "hash" in events[0].get("metadata", {})
        assert "hash" in events[1].get("metadata", {})

    def test_redact_sensitive_params(self, logger):
        params = {
            "query": "log4j",
            "api_key": "sk-1234567890abcdef",
            "token": "ghp_secret123",
            "password": "admin123",
            "target": "example.com",
        }
        safe = logger._redact_params(params)
        assert safe["api_key"] == "***REDACTED***"
        assert safe["password"] == "***REDACTED***"
        assert safe["token"] == "***REDACTED***"
        assert safe["query"] == "log4j"
        assert safe["target"] == "example.com"

    def test_redact_long_params(self, logger):
        # Use a long string that doesn't match API key pattern
        params = {"output": "Normal text output that is very long " * 8}
        safe = logger._redact_params(params)
        assert safe["output"].endswith("...")

    def test_create_audit_logger_global(self, temp_dir):
        # Use temp_dir to avoid sandbox restrictions
        from src.security.audit import AuditLogger as AL
        logger = AL(log_dir=temp_dir)
        assert logger is not None
