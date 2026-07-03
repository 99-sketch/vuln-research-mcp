# src/security/__init__.py
"""v5.3 Enterprise Security Module — 完整安全防护体系 + 极致输入防御 + RBAC + 目标授权

层级架构:
  第零层: 授权声明 (target_authorization) — 启动确定认授权 + 目标白名单校验
  第一层: RBAC权限 (rbac) — 4角色/5等级工具权限控制
  第二层: 极致输入净化 (enhanced_sanitizer) — AST级 Shell 解析/Unicode混淆/多层编码检测
  第三层: 数据清洗 (data_sanitizer) — 外部数据上下文净化/间接提示注入防护
  第四层: 内网防护 (intranet_guard) — 全RFC 1918阻断/敏感端口告警/扫描范围限制
  第五层: 目标策略 (target_policy) — IP白名单/内网防护/扫描限制 (已增强)
  第六层: 工具守卫 (tool_guard) — 5级权限/频率限制/哈希校验
  第七层: 工具审批 (approval) — 人工确认/human-in-the-loop
  第八层: 权限执行 (privilege_enforcer) — Root/Admin 检测阻断/最小权限执行
  底层支持: 审计日志/密钥管理/数据库加密/API认证/告警
"""

from .input_sanitizer import (
    SecuritySanitizer,
    sanitize_command_arg,
    sanitize_shell_query,
    sanitize_file_path,
    sanitize_http_param,
    sanitize_injection_patterns,
)
from .enhanced_sanitizer import (
    ExtremeSanitizer,
    SanitizationVerdict,
    SafeCommand,
    execute_safe_command,
    get_extreme_sanitizer,
    extreme_sanitize,
)
from .data_sanitizer import (
    DataContextSanitizer,
    SanitizationReport,
    get_data_sanitizer,
)
from .intranet_guard import (
    IntranetGuardPolicy,
    ScanLimitPolicy,
    NetworkCategory,
    SENSITIVE_PORTS,
    get_intranet_guard,
    get_scan_limits,
)
from .target_policy import (
    TargetPolicy,
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
from .rbac import (
    RBACManager,
    RBACConfig,
    Role,
    RiskLevel,
    AccessDecision,
    TOOL_RISK_MAP as RBAC_TOOL_RISK_MAP,
    get_rbac,
    init_rbac,
    check_authorization_confirmed,
    confirm_authorization,
    AUTHORIZATION_DISCLAIMER,
)
from .target_authorization import (
    TargetAuthorizer,
    AuthzConfig,
    AuthzDecision,
    get_authorizer,
    init_authorizer,
)

__all__ = [
    # v5.3 RBAC
    "RBACManager",
    "RBACConfig",
    "Role",
    "RiskLevel",
    "AccessDecision",
    "RBAC_TOOL_RISK_MAP",
    "get_rbac",
    "init_rbac",
    "check_authorization_confirmed",
    "confirm_authorization",
    "AUTHORIZATION_DISCLAIMER",
    # v5.3 Target Authorization
    "TargetAuthorizer",
    "AuthzConfig",
    "AuthzDecision",
    "get_authorizer",
    "init_authorizer",
    # v5.1 Enhanced
    "ExtremeSanitizer",
    "SanitizationVerdict",
    "SafeCommand",
    "execute_safe_command",
    "get_extreme_sanitizer",
    "extreme_sanitize",
    "IntranetGuardPolicy",
    "NetworkCategory",
    "SENSITIVE_PORTS",
    "get_intranet_guard",
    "get_scan_limits",
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
    # Target policy (legacy)
    "TargetPolicy",
    "create_default_policy",
    "create_enterprise_policy",
    # Scan limits (enhanced)
    "ScanLimitPolicy",
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
