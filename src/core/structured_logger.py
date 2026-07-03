# src/core/structured_logger.py
"""结构化日志 — 支持 JSON 和 text 两种格式"""

import json
import logging
import sys
import time
from typing import Any


class StructuredFormatter(logging.Formatter):
    """结构化日志格式器"""

    def __init__(self, fmt: str = "text"):
        self.fmt = fmt

    def format(self, record: logging.LogRecord) -> str:
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
                "msg": record.getMessage(),
            }
            if extra:
                log_entry["extra"] = extra
            if record.exc_info:
                log_entry["exception"] = self.formatException(record.exc_info)
            return json.dumps(log_entry, ensure_ascii=False)
        else:
            # text 格式
            msg = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.created))} - {record.levelname} - {record.name} - {record.getMessage()}"
            if extra:
                msg += f" - {json.dumps(extra, ensure_ascii=False)}"
            if record.exc_info:
                msg += f"\n{self.formatException(record.exc_info)}"
            return msg


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
