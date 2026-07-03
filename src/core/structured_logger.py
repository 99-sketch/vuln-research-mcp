# src/core/structured_logger.py
"""结构化日志 — 支持 JSON 和 text 两种格式"""

import json
import logging
import re
import sys
import time
from typing import Any

# 日志脱敏模式列表（日志中自动替换匹配内容）
_LOG_REDACTION_PATTERNS: list[tuple[str, str]] = [
    # API Key 格式
    (r'[A-Za-z0-9+/]{30,}={0,2}', '***API_KEY***'),
    # NVD API Key 格式（UUID-like）
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '***API_KEY***'),
    # Token 格式
    (r'token[=:]\s*\S+', 'token=***TOKEN***'),
    # 密码参数
    (r'(?:password|passwd|secret)=(\S+)', r'password=***REDACTED***'),
    # 内网 IP（详细模式时可启用）
    # (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', '***INTERNAL_IP***'),
    # (r'192\.168\.\d{1,3}\.\d{1,3}', '***INTERNAL_IP***'),
    # (r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', '***INTERNAL_IP***'),
]


def _redact_sensitive(msg: str) -> str:
    """对日志消息进行脱敏处理"""
    for pattern, replacement in _LOG_REDACTION_PATTERNS:
        msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
    return msg


class RedactionFilter(logging.Filter):
    """日志脱敏过滤器 - 自动替换敏感信息"""

    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = _redact_sensitive(record.msg)
        if record.args:
            # 脱敏格式化参数
            safe_args = []
            for arg in record.args:
                if isinstance(arg, str) and len(arg) > 10:
                    safe_args.append(_redact_sensitive(arg))
                else:
                    safe_args.append(arg)
            record.args = tuple(safe_args)
        return True


class StructuredFormatter(logging.Formatter):
    """结构化日志格式器"""

    def __init__(self, fmt: str = "text"):
        self.fmt = fmt

    def format(self, record: logging.LogRecord) -> str:
        # 脱敏处理
        msg = record.getMessage()
        msg = _redact_sensitive(msg)

        # 提取额外字段
        extra = {}
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
            ):
                extra[key] = value

        if self.fmt == "json":
            log_entry = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created)),
                "level": record.levelname,
                "logger": record.name,
                "msg": msg,
            }
            if extra:
                log_entry["extra"] = extra
            if record.exc_info:
                log_entry["exception"] = self.formatException(record.exc_info)
            return json.dumps(log_entry, ensure_ascii=False)
        else:
            # text 格式
            text = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.created))} - {record.levelname} - {record.name} - {msg}"
            if extra:
                text += f" - {json.dumps(extra, ensure_ascii=False)}"
            if record.exc_info:
                text += f"\n{self.formatException(record.exc_info)}"
            return text


def setup_logging(level: str = "INFO", fmt: str = "text"):
    """
    设置结构化日志

    Args:
        level: 日志级别 (DEBUG, INFO, WARNING, ERROR)
        fmt: 格式 (text, json)
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(StructuredFormatter(fmt=fmt))

    root = logging.getLogger()
    root.setLevel(numeric_level)
    root.handlers.clear()
    root.addHandler(handler)

    # v4.1: 添加脱敏过滤器
    root.addFilter(RedactionFilter())
