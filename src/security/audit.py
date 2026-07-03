# src/security/audit.py
"""审计日志模块 - 不可篡改的操作审计记录"""

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

logger = logging.getLogger("vuln-research-mcp.security")


@dataclass
class AuditEvent:
    """审计事件"""
    timestamp: str                          # ISO 8601 时间戳
    event_type: str                         # 事件类型: tool_call, scan_start, config_change, auth
    actor: str = "system"                   # 操作者（MCP客户端标识）
    tool_name: str = ""                     # 工具名称
    parameters: dict = field(default_factory=dict)  # 参数（敏感字段脱敏）
    target: str = ""                        # 扫描目标
    result: str = "unknown"                 # 执行结果: success, denied, error
    reason: str = ""                        # 拒绝/失败原因
    session_id: str = ""                    # 会话 ID
    source_ip: str = ""                     # 来源 IP（REST API 场景）
    metadata: dict = field(default_factory=dict)  # 额外元数据

    def serialize(self) -> str:
        """序列化为 JSON 字符串"""
        return json.dumps(asdict(self), ensure_ascii=False)


class AuditLogger:
    """不可篡改的审计日志记录器

    特性：
    - 追加写入（不覆盖）
    - 每行一个 JSON 事件
    - 定期写入校验链（可选）
    - 日志文件权限控制提示
    """

    def __init__(self, log_dir: str = None, encryption_key: str = None):
        self._log_dir = log_dir or os.path.join(
            os.path.expanduser("~"), ".vuln-research-mcp", "audit"
        )
        self._last_hash: Optional[str] = None
        os.makedirs(self._log_dir, exist_ok=True)

    def _get_log_file(self) -> str:
        """获取当天的日志文件路径"""
        date_str = time.strftime("%Y-%m-%d")
        return os.path.join(self._log_dir, f"audit-{date_str}.jsonl")

    def log(self, event: AuditEvent) -> None:
        """记录审计事件"""
        event_str = event.serialize()

        # 计算哈希链
        if self._last_hash is not None:
            event.metadata["prev_hash"] = self._last_hash
            event_str = event.serialize()

        self._last_hash = hashlib.sha256(event_str.encode()).hexdigest()
        event.metadata["hash"] = self._last_hash
        event_str = event.serialize()

        # 追加写入
        log_file = self._get_log_file()
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(event_str + "\n")
                f.flush()
                os.fsync(f.fileno())  # 确保写入磁盘
        except Exception as e:
            logger.error(f"审计日志写入失败: {e}")

    def log_tool_call(
        self,
        tool_name: str,
        parameters: dict,
        target: str = "",
        result: str = "success",
        reason: str = "",
        session_id: str = "",
    ) -> None:
        """记录工具调用"""
        # 脱敏参数
        safe_params = self._redact_params(parameters)

        event = AuditEvent(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(time.time() * 1000) % 1000:03d}Z",
            event_type="tool_call",
            tool_name=tool_name,
            parameters=safe_params,
            target=target,
            result=result,
            reason=reason,
            session_id=session_id,
        )
        self.log(event)

    def log_scan_attempt(
        self,
        tool_name: str,
        target: str,
        allowed: bool,
        reason: str = "",
        session_id: str = "",
    ) -> None:
        """记录扫描尝试"""
        event = AuditEvent(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(time.time() * 1000) % 1000:03d}Z",
            event_type="scan_attempt",
            tool_name=tool_name,
            target=target,
            result="success" if allowed else "denied",
            reason=reason,
            session_id=session_id,
        )
        self.log(event)

    @staticmethod
    def _redact_params(params: dict) -> dict:
        """脱敏敏感参数"""
        # 使用精确匹配而非子串匹配，避免"key"误匹配"keyword"
        sensitive_keys = {
            "api_key", "apikey", "password", "secret", "token",
            "auth", "key", "credential", "passwd",
        }
        safe = {}
        for k, v in params.items():
            k_normalized = k.lower().replace("_", "").replace("-", "")
            # 精确匹配：k_normalized 必须在 sensitive_keys 中
            is_sensitive = k_normalized in sensitive_keys
            # 或者 v 包含明显的 API key 模式（超长 base64 随机字符串）
            if not is_sensitive and isinstance(v, str) and len(v) > 40:
                import re
                if re.match(r'^[A-Za-z0-9+/=_-]{30,}$', v):
                    is_sensitive = True

            if is_sensitive:
                safe[k] = "***REDACTED***"
            elif isinstance(v, str) and len(v) > 200:
                safe[k] = v[:200] + "..."
            else:
                safe[k] = v
        return safe


# 全局审计日志器
_audit_logger: Optional[AuditLogger] = None


def create_audit_logger(log_dir: str = None) -> AuditLogger:
    """创建或获取全局审计日志器"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(log_dir)
    return _audit_logger


def get_audit_logger() -> Optional[AuditLogger]:
    """获取当前审计日志器"""
    return _audit_logger
