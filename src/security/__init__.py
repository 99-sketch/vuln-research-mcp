# src/security/__init__.py
"""v4.1 Security Module — 输入净化、目标白名单、审计日志、密钥管理、工具权限控制"""

from .input_sanitizer import (
    SecuritySanitizer,
    sanitize_command_arg,
    sanitize_shell_query,
    sanitize_file_path,
    sanitize_http_param,
    sanitize_injection_patterns,
)
from .target_policy import (
    TargetPolicy,
    ScanLimitPolicy,
    create_default_policy,
)
from .audit import (
    AuditLogger,
    AuditEvent,
    create_audit_logger,
)
from .key_manager import (
    SecureKeyManager,
    create_key_manager,
)
from .tool_guard import (
    ToolRiskLevel,
    ToolGuard,
    create_tool_guard,
)

__all__ = [
    "SecuritySanitizer",
    "sanitize_command_arg",
    "sanitize_shell_query",
    "sanitize_file_path",
    "sanitize_http_param",
    "sanitize_injection_patterns",
    "TargetPolicy",
    "ScanLimitPolicy",
    "create_default_policy",
    "AuditLogger",
    "AuditEvent",
    "create_audit_logger",
    "SecureKeyManager",
    "create_key_manager",
    "ToolRiskLevel",
    "ToolGuard",
    "create_tool_guard",
]
