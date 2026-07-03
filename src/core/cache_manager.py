# src/core/cache_manager.py
"""TTL 缓存层 — 基于 diskcache，SQLite 持久化，重启不丢"""

import hashlib
import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger("vuln-research-mcp")

# 默认缓存目录
DEFAULT_CACHE_DIR = os.path.join(
    os.path.expanduser("~"), ".vuln-research-mcp", "cache"
)

# 各类数据的 TTL（秒）
TTL_MAP = {
    "nvd_cve_detail": 3600,       # 1小时，CVE 详情不常变
    "nvd_search": 900,             # 15分钟，搜索结果有微小波动
    "cwe_definition": 86400,       # 24小时，CWE 几乎不变
    "cisa_kev_feed": 3600,         # 1小时
    "epss_score": 86400,           # 24小时，EPSS 每天更新
    "dns_lookup": 300,             # 5分钟，服从 DNS TTL
    "ip_geolocation": 86400,       # 24小时
    "nuclei_search": 3600,         # 1小时
    "exploit_search": 3600,        # 1小时
    "poc_archive_list": 300,       # 5分钟
    "vulnerability_assess": 1800,  # 30分钟
    "cross_source_search": 900,    # 15分钟
}

# 尝试导入 diskcache，失败则降级到内存缓存
try:
    import diskcache
    _HAS_DISKCACHE = True
    logger.debug("cache_manager: 使用 diskcache 持久化缓存")
except ImportError:
    _HAS_DISKCACHE = False
    logger.warning("cache_manager: diskcache 未安装，降级到内存缓存（重启丢失）")


class MemoryCache:
    """内存缓存降级方案"""
    def __init__(self):
        self._store: dict[str, tuple[Any, float]] = {}  # key -> (value, expire_at)

    def get(self, key: str) -> Optional[Any]:
        if key in self._store:
            value, expire_at = self._store[key]
            if time.time() < expire_at:
                return value
            del self._store[key]
        return None

    def set(self, key: str, value: Any, expire: float):
        self._store[key] = (value, time.time() + expire)

    def delete(self, key: str):
        self._store.pop(key, None)

    def clear(self):
        self._store.clear()

    def size(self) -> int:
        return len(self._store)


class CacheManager:
    """统一缓存管理器"""

    def __init__(self, cache_dir: str = None, enabled: bool = True):
        self.enabled = enabled
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR

        if not enabled:
            self._cache = MemoryCache()
            logger.info("CacheManager: 缓存已禁用")
            return

        if _HAS_DISKCACHE:
            os.makedirs(self.cache_dir, exist_ok=True)
            self._cache = diskcache.Cache(self.cache_dir)
            logger.info(f"CacheManager: diskcache 初始化于 {self.cache_dir}")
        else:
            self._cache = MemoryCache()
            logger.info("CacheManager: 使用内存缓存")

    def _make_key(self, category: str, identifier: str) -> str:
        """生成缓存 key"""
        raw = f"{category}:{identifier}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get(self, category: str, identifier: str) -> Optional[Any]:
        """从缓存获取数据"""
        if not self.enabled:
            return None

        key = self._make_key(category, identifier)
        value = self._cache.get(key)

        if value is not None:
            logger.debug(f"缓存命中: {category}:{identifier[:50]}")

        return value

    def set(self, category: str, identifier: str, value: Any, ttl: float = None):
        """写入缓存"""
        if not self.enabled:
            return

        ttl = ttl or TTL_MAP.get(category, 3600)
        key = self._make_key(category, identifier)

        if _HAS_DISKCACHE and isinstance(self._cache, diskcache.Cache):
            self._cache.set(key, value, expire=ttl)
        else:
            self._cache.set(key, value, ttl)

        logger.debug(f"缓存写入: {category}:{identifier[:50]} (TTL={ttl}s)")

    def delete(self, category: str, identifier: str):
        """删除缓存条目"""
        key = self._make_key(category, identifier)
        self._cache.delete(key)

    def clear(self):
        """清空所有缓存"""
        self._cache.clear()
        logger.info("CacheManager: 已清空所有缓存")

    def stats(self) -> dict:
        """缓存统计"""
        if _HAS_DISKCACHE and isinstance(self._cache, diskcache.Cache):
            return {
                "type": "diskcache",
                "directory": self.cache_dir,
                "size": len(self._cache),
                "volume": f"{self._cache.volume()} bytes",
            }
        else:
            return {
                "type": "memory",
                "size": self._cache.size(),
            }

    def close(self):
        """关闭缓存"""
        if _HAS_DISKCACHE and isinstance(self._cache, diskcache.Cache):
            self._cache.close()


# 全局缓存实例（延迟初始化）
_cache_instance: Optional[CacheManager] = None


def get_cache() -> CacheManager:
    """获取全局缓存实例"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = CacheManager()
    return _cache_instance


def init_cache(cache_dir: str = None, enabled: bool = True):
    """初始化全局缓存实例"""
    global _cache_instance
    if _cache_instance is not None:
        _cache_instance.close()
    _cache_instance = CacheManager(cache_dir=cache_dir, enabled=enabled)
