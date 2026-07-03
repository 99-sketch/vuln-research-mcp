# src/security/__init__.py
"""v5.0 Enterprise Security Module — 完整安全防护体系

层级架构:
  第一层: 输入净化 (input_sanitizer) — 命令注入/SSRF/路径遍历防护
  第二层: 数据清洗 (data_sanitizer) — 外部数据上下文净化/间接提示注入防护
  第三层: 目标策略 (target_policy) — IP白名单/内网防护/扫描限制
  第四层: 工具守卫 (tool_guard) — RBAC 5级权限/频率限制/哈希校验
  第五层: 工具审批 (approval) — 人工确认/human-in-the-loop
  底层支持: 审计日志 (audit) / 密钥管理 (key_manager) / 数据库加密 (db_crypto) / API认证 (api_auth) / 告警 (alerting)
"""

from .input_sanitizer import (
    SecuritySanitizer,
    sanitize_command_arg,
    sanitize_shell_query,
    sanitize_file_path,
    sanitize_http_param,
    sanitize_injection_patterns,
)
from .data_sanitizer import (
    DataContextSanitizer,
    SanitizationReport,
    get_data_sanitizer,
)
from .target_policy import (
    TargetPolicy,
    ScanLimitPolicy,
    create_default_policy,
    create_enterprise_policy,
)
from .tool_guard import (
    ToolRiskLevel,
    ToolGuard,
    TOOL_RISK_MAP,
    create_tool_guard,
)
from .approval import (
    ToolApprovalManager,
    ApprovalDecision,
    ApprovalRequest,
    SessionIsolationManager,
    get_approval_manager,
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
from .db_crypto import (
    DatabaseCrypto,
    get_db_crypto,
    DecryptionError,
)
from .api_auth import (
    APIAuthManager,
    APIKey,
    get_api_auth,
)
from .alerting import (
    AlertManager,
    AlertSeverity,
    Alert,
    get_alert_manager,
    DingTalkChannel,
    EmailChannel,
    SyslogChannel,
)

__all__ = [
    # Input sanitizer
    "SecuritySanitizer",
    "sanitize_command_arg",
    "sanitize_shell_query",
    "sanitize_file_path",
    "sanitize_http_param",
    "sanitize_injection_patterns",
    # Data sanitizer
    "DataContextSanitizer",
    "SanitizationReport",
    "get_data_sanitizer",
    # Target policy
    "TargetPolicy",
    "ScanLimitPolicy",
    "create_default_policy",
    "create_enterprise_policy",
    # Tool guard
    "ToolRiskLevel",
    "ToolGuard",
    "TOOL_RISK_MAP",
    "create_tool_guard",
    # Approval
    "ToolApprovalManager",
    "ApprovalDecision",
    "ApprovalRequest",
    "SessionIsolationManager",
    "get_approval_manager",
    # Audit
    "AuditLogger",
    "AuditEvent",
    "create_audit_logger",
    # Key manager
    "SecureKeyManager",
    "create_key_manager",
    # DB crypto
    "DatabaseCrypto",
    "get_db_crypto",
    "DecryptionError",
    # API auth
    "APIAuthManager",
    "APIKey",
    "get_api_auth",
    # Alerting
    "AlertManager",
    "AlertSeverity",
    "Alert",
    "get_alert_manager",
    "DingTalkChannel",
    "EmailChannel",
    "SyslogChannel",
]
