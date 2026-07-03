# src/core/config_manager.py
"""配置管理 — 支持优先级: 命令行参数 > 环境变量 > config.yaml > 默认值"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("vuln-research-mcp")

DEFAULT_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".vuln-research-mcp")
DEFAULT_CONFIG_FILE = os.path.join(DEFAULT_CONFIG_DIR, "config.yaml")


@dataclass
class ServerConfig:
    name: str = "vuln-research-mcp"
    log_level: str = "INFO"
    log_format: str = "text"  # text | json


@dataclass
class ApiKeysConfig:
    nvd: str = ""


@dataclass
class RateLimitConfig:
    nvd_requests_per_window: int = 5
    nvd_window_seconds: int = 30
    nvd_max_retries: int = 3


@dataclass
class CacheConfig:
    enabled: bool = True
    directory: str = ""
    max_size_mb: int = 200


@dataclass
class CircuitBreakerConfig:
    nvd_failure_threshold: int = 5
    nvd_recovery_seconds: float = 60.0
    cisa_failure_threshold: int = 3
    cisa_recovery_seconds: float = 60.0
    epss_failure_threshold: int = 3
    epss_recovery_seconds: float = 60.0


@dataclass
class ToolsConfig:
    disabled: list[str] = field(default_factory=list)


@dataclass
class SecurityConfig:
    """v4.1 安全配置"""
    max_risk_level: str = "system"      # read_only | network_info | active_scan | exploit | system
    audit_enabled: bool = True
    audit_dir: str = ""                 # 审计日志目录
    target_whitelist_enabled: bool = False
    target_whitelist_file: str = ""     # 目标白名单配置文件
    log_redaction: bool = True          # 日志脱敏
    require_approval_for_scans: bool = True  # 扫描需审批


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    api_keys: ApiKeysConfig = field(default_factory=ApiKeysConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)


def _load_yaml(path: str) -> dict:
    """加载 YAML 配置文件"""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        logger.warning("PyYAML 未安装，跳过 config.yaml")
        return {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.warning(f"读取配置文件失败: {e}")
        return {}


def _env_override(config_dict: dict):
    """环境变量覆盖"""
    env_map = {
        "NVD_API_KEY": ("api_keys", "nvd"),
        "LOG_LEVEL": ("server", "log_level"),
        "LOG_FORMAT": ("server", "log_format"),
        "CACHE_ENABLED": ("cache", "enabled"),
        "CACHE_DIR": ("cache", "directory"),
    }
    for env_key, (section, field_name) in env_map.items():
        val = os.environ.get(env_key)
        if val is not None:
            if section not in config_dict:
                config_dict[section] = {}
            # 类型转换
            if field_name == "enabled":
                config_dict[section][field_name] = val.lower() in ("true", "1", "yes")
            else:
                config_dict[section][field_name] = val


def load_config(config_path: str = None) -> AppConfig:
    """
    加载配置 — 优先级: 环境变量 > config.yaml > 默认值
    
    Args:
        config_path: 自定义配置文件路径（默认 ~/.vuln-research-mcp/config.yaml）
    """
    config_file = config_path or DEFAULT_CONFIG_FILE

    # 1. 加载 YAML
    raw = _load_yaml(config_file)

    # 2. 环境变量覆盖
    _env_override(raw)

    # 3. 构建配置对象
    cfg = AppConfig()

    # Server
    if "server" in raw:
        s = raw["server"]
        cfg.server = ServerConfig(
            name=s.get("name", cfg.server.name),
            log_level=s.get("log_level", cfg.server.log_level),
            log_format=s.get("log_format", cfg.server.log_format),
        )

    # API Keys
    if "api_keys" in raw:
        a = raw["api_keys"]
        cfg.api_keys = ApiKeysConfig(
            nvd=a.get("nvd", ""),
        )

    # Tools
    if "tools" in raw:
        t = raw["tools"]
        cfg.tools = ToolsConfig(
            disabled=t.get("disabled", []),
        )

    # Rate Limit
    if "rate_limit" in raw:
        r = raw["rate_limit"]
        cfg.rate_limit = RateLimitConfig(
            nvd_requests_per_window=r.get("nvd_requests_per_window", 5),
            nvd_window_seconds=r.get("nvd_window_seconds", 30),
            nvd_max_retries=r.get("nvd_max_retries", 3),
        )

    # Cache
    if "cache" in raw:
        c = raw["cache"]
        cfg.cache = CacheConfig(
            enabled=c.get("enabled", True),
            directory=c.get("directory", ""),
            max_size_mb=c.get("max_size_mb", 200),
        )

    # Circuit Breaker
    if "circuit_breaker" in raw:
        cb = raw["circuit_breaker"]
        cfg.circuit_breaker = CircuitBreakerConfig(
            nvd_failure_threshold=cb.get("nvd_failure_threshold", 5),
            nvd_recovery_seconds=cb.get("nvd_recovery_seconds", 60.0),
            cisa_failure_threshold=cb.get("cisa_failure_threshold", 3),
            cisa_recovery_seconds=cb.get("cisa_recovery_seconds", 60.0),
            epss_failure_threshold=cb.get("epss_failure_threshold", 3),
            epss_recovery_seconds=cb.get("epss_recovery_seconds", 60.0),
        )

    # v4.1 Security
    if "security" in raw:
        sec = raw["security"]
        cfg.security = SecurityConfig(
            max_risk_level=sec.get("max_risk_level", "system"),
            audit_enabled=sec.get("audit_enabled", True),
            audit_dir=sec.get("audit_dir", ""),
            target_whitelist_enabled=sec.get("target_whitelist_enabled", False),
            target_whitelist_file=sec.get("target_whitelist_file", ""),
            log_redaction=sec.get("log_redaction", True),
            require_approval_for_scans=sec.get("require_approval_for_scans", True),
        )

    # NVD API Key 特殊处理：环境变量 > config.yaml
    nvd_key = os.environ.get("NVD_API_KEY", cfg.api_keys.nvd)
    if nvd_key:
        cfg.api_keys.nvd = nvd_key

    logger.debug(f"配置加载完成: {config_file}")
    return cfg


def create_default_config(path: str = None):
    """创建默认配置文件"""
    config_file = path or DEFAULT_CONFIG_FILE
    os.makedirs(os.path.dirname(config_file), exist_ok=True)

    default_content = """# vuln-research-mcp 配置文件
# 优先级: 命令行参数 > 环境变量 > 本文件 > 默认值

server:
  name: vuln-research-mcp
  log_level: INFO       # DEBUG | INFO | WARNING | ERROR
  log_format: text      # text | json

api_keys:
  nvd: ""               # 或设置环境变量 NVD_API_KEY

tools:
  disabled: []           # ["scan_ports"] 按需禁用

rate_limit:
  nvd_requests_per_window: 5    # 无 API Key: 5次/30秒
  nvd_window_seconds: 30
  nvd_max_retries: 3

cache:
  enabled: true
  directory: ~/.vuln-research-mcp/cache
  max_size_mb: 200

circuit_breaker:
  nvd_failure_threshold: 5
  nvd_recovery_seconds: 60
  cisa_failure_threshold: 3
  cisa_recovery_seconds: 60
  epss_failure_threshold: 3
  epss_recovery_seconds: 60

# v4.1 安全配置
security:
  max_risk_level: system        # read_only | network_info | active_scan | exploit | system
  audit_enabled: true
  audit_dir: ~/.vuln-research-mcp/audit
  target_whitelist_enabled: false  # 启用后仅允许白名单目标
  target_whitelist_file: ""        # 白名单 JSON 文件路径
  log_redaction: true              # 日志脱敏（自动替换 API Key 等敏感信息）
  require_approval_for_scans: true  # 批量扫描需人工审批
"""

    with open(config_file, "w", encoding="utf-8") as f:
        f.write(default_content)

    logger.info(f"默认配置文件已创建: {config_file}")
    return config_file
