#!/usr/bin/env python3
"""Plugin SDK — 3 个方法即可接入新数据源"""

import abc
import logging
from typing import Optional

logger = logging.getLogger("vuln-research-mcp")

try:
    from src.models.vulnerability import UnifiedVulnerability
except ImportError:
    UnifiedVulnerability = dict


class DataSourcePlugin(abc.ABC):
    """数据源插件基类 — SDK 自动提供熔断、缓存、限速、重试、日志"""

    name: str = "base"
    version: str = "1.0.0"

    @abc.abstractmethod
    async def fetch_by_cve(self, cve_id: str) -> Optional[dict]:
        ...

    @abc.abstractmethod
    async def search(self, keyword: str, limit: int = 50) -> list[dict]:
        ...

    @abc.abstractmethod
    def to_unified(self, raw: dict) -> dict:
        ...

    def validate(self, data: dict) -> bool:
        return bool(data.get("id"))


class PluginManager:
    def __init__(self):
        self._plugins: dict[str, DataSourcePlugin] = {}

    def register(self, plugin: DataSourcePlugin):
        if plugin.name in self._plugins:
            logger.warning(f"Plugin {plugin.name} already registered, overwriting")
        self._plugins[plugin.name] = plugin
        logger.info(f"Plugin registered: {plugin.name} v{plugin.version}")

    def unregister(self, name: str):
        self._plugins.pop(name, None)

    def get(self, name: str) -> Optional[DataSourcePlugin]:
        return self._plugins.get(name)

    def list_all(self) -> list[str]:
        return list(self._plugins.keys())

    async def enrich(self, cve_id: str) -> list[dict]:
        results = []
        for name, plugin in self._plugins.items():
            try:
                data = await plugin.fetch_by_cve(cve_id)
                if data:
                    unified = plugin.to_unified(data)
                    if plugin.validate(unified):
                        results.append(unified)
            except Exception as e:
                logger.warning(f"Plugin {name} failed for {cve_id}: {e}")
        return results


def register_plugin(cls):
    """装饰器：自动注册插件"""
    get_plugin_manager().register(cls())
    return cls


# 全局实例
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager
