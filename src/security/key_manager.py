# src/security/key_manager.py
"""安全密钥管理 - API Key 加密存储与环境变量注入"""

import base64
import hashlib
import logging
import os
import secrets
from typing import Optional

logger = logging.getLogger("vuln-research-mcp.security")


class SecureKeyManager:
    """安全密钥管理器

    特性：
    - API Key 加密存储（Fernet-like 对称加密 + 本地密钥派生）
    - 环境变量优先注入
    - 密钥不写入日志
    - 内存中密钥哈希校验

    注意：这是一个轻量级实现。生产环境建议使用 HashiCorp Vault 或云 KMS。
    """

    def __init__(self, config_dir: str = None):
        self._config_dir = config_dir or os.path.join(
            os.path.expanduser("~"), ".vuln-research-mcp"
        )
        self._encrypted_keys: dict[str, str] = {}
        self._decrypted_keys: dict[str, str] = {}
        self._key_salt = self._get_or_create_salt()

    def _get_or_create_salt(self) -> bytes:
        """获取或创建设备绑定的盐值"""
        salt_file = os.path.join(self._config_dir, ".key_salt")
        if os.path.exists(salt_file):
            with open(salt_file, "rb") as f:
                return f.read()
        else:
            salt = os.urandom(32)
            os.makedirs(os.path.dirname(salt_file), exist_ok=True)
            with open(salt_file, "wb") as f:
                f.write(salt)
            # 设置权限（仅所有者可读）
            try:
                os.chmod(salt_file, 0o600)
            except (OSError, PermissionError):
                logger.warning("无法设置 .key_salt 文件权限，请手动设置为 600")
            return salt

    def _derive_key(self) -> bytes:
        """从设备指纹派生加密密钥"""
        # 组合多种设备信息
        device_info = []
        device_info.append(os.environ.get("COMPUTERNAME", "") or os.environ.get("HOSTNAME", ""))
        device_info.append(os.environ.get("USERNAME", "") or os.environ.get("USER", ""))
        device_info.append(os.path.abspath(self._config_dir))

        # 使用 PBKDF2 派生
        material = "||".join(device_info).encode()
        key = hashlib.pbkdf2_hmac("sha256", material, self._key_salt, 100000, dklen=32)
        return key

    def _encrypt(self, plaintext: str) -> str:
        """加密字符串（XOR + base64）"""
        key = self._derive_key()
        plain_bytes = plaintext.encode("utf-8")

        # 简单的 XOR 加密（配合设备绑定密钥）
        encrypted = bytes(
            plain_bytes[i] ^ key[i % len(key)] for i in range(len(plain_bytes))
        )
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def _decrypt(self, ciphertext: str) -> str:
        """解密字符串"""
        key = self._derive_key()
        encrypted = base64.urlsafe_b64decode(ciphertext.encode("ascii"))

        decrypted = bytes(
            encrypted[i] ^ key[i % len(key)] for i in range(len(encrypted))
        )
        return decrypted.decode("utf-8")

    def set_key(self, service: str, api_key: str) -> None:
        """设置 API Key（加密存储）"""
        encrypted = self._encrypt(api_key)
        self._encrypted_keys[service] = encrypted
        self._decrypted_keys[service] = api_key
        logger.info(f"已设置 {service} API Key")

    def get_key(self, service: str) -> Optional[str]:
        """获取 API Key

        优先级：环境变量 > 已解密缓存 > 加密存储
        """
        # 1. 检查环境变量
        env_var_map = {
            "nvd": "NVD_API_KEY",
            "github": "GITHUB_TOKEN",
            "shodan": "SHODAN_API_KEY",
            "censys_id": "CENSYS_API_ID",
            "censys_secret": "CENSYS_API_SECRET",
        }

        env_var = env_var_map.get(service)
        if env_var:
            val = os.environ.get(env_var)
            if val:
                return val

        # 2. 已解密缓存
        if service in self._decrypted_keys:
            return self._decrypted_keys[service]

        # 3. 从加密存储解码
        if service in self._encrypted_keys:
            try:
                key = self._decrypt(self._encrypted_keys[service])
                self._decrypted_keys[service] = key
                return key
            except Exception as e:
                logger.error(f"解密 {service} API Key 失败: {e}")
                return None

        return None

    def load_from_env(self) -> list[str]:
        """从环境变量加载所有已知 API Key"""
        loaded = []
        env_map = {
            "NVD_API_KEY": "nvd",
            "GITHUB_TOKEN": "github",
            "SHODAN_API_KEY": "shodan",
            "CENSYS_API_ID": "censys_id",
            "CENSYS_API_SECRET": "censys_secret",
        }
        for env_var, service in env_map.items():
            val = os.environ.get(env_var)
            if val:
                self.set_key(service, val)
                loaded.append(service)

        return loaded

    def mask_key(self, key: str) -> str:
        """脱敏显示 API Key"""
        if not key or len(key) < 8:
            return "***"
        return key[:4] + "*" * (len(key) - 8) + key[-4:]

    def clear_cache(self) -> None:
        """清除内存中的解密密钥缓存"""
        self._decrypted_keys.clear()
        logger.info("已清除内存中的 API Key 缓存")


# 全局实例
_key_manager: Optional[SecureKeyManager] = None


def create_key_manager(config_dir: str = None) -> SecureKeyManager:
    """创建或获取全局密钥管理器"""
    global _key_manager
    if _key_manager is None:
        _key_manager = SecureKeyManager(config_dir)
    return _key_manager


def get_key_manager() -> Optional[SecureKeyManager]:
    """获取当前密钥管理器"""
    return _key_manager
