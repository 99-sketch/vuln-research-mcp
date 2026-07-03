# src/core/tool_registry.py
"""插件化工具注册表 — 加新工具只需新建模块 + register，路由层零改动"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

logger = logging.getLogger("vuln-research-mcp")


@dataclass
class ToolDefinition:
    """工具定义"""
    name: str
    description: str
    input_schema: dict
    handler: Callable[..., Coroutine]
    requires_tools: list[str] = field(default_factory=list)   # 依赖的外部工具
    requires_apis: list[str] = field(default_factory=list)    # 依赖的在线 API


class ToolRegistry:
    """工具注册表 — 统一管理所有工具的生命周期"""
    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition):
        """注册工具"""
        if tool.name in self._tools:
            logger.warning(f"工具 {tool.name} 已注册，覆盖旧定义")
        self._tools[tool.name] = tool
        logger.debug(f"注册工具: {tool.name}")

    def resolve(self, name: str) -> ToolDefinition | None:
        """解析工具"""
        return self._tools.get(name)

    def list_all(self) -> list[dict]:
        """列出所有工具"""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in self._tools.values()
        ]

    def list_handlers(self) -> dict[str, Callable]:
        """返回工具名 → handler 映射"""
        return {name: t.handler for name, t in self._tools.items()}

    def get_dependencies(self, name: str) -> tuple[list[str], list[str]]:
        """获取工具的外部依赖"""
        tool = self._tools.get(name)
        if not tool:
            return [], []
        return tool.requires_tools, tool.requires_apis

    def filter_disabled(self, disabled: list[str]) -> list[str]:
        """过滤被禁用的工具"""
        removed = [name for name in disabled if name in self._tools]
        for name in removed:
            del self._tools[name]
        if removed:
            logger.info(f"已禁用工具: {removed}")
        return removed

    def size(self) -> int:
        return len(self._tools)


# 全局注册表实例
_registry = ToolRegistry()


def get_registry() -> ToolRegistry:
    """获取全局工具注册表"""
    return _registry


def register_tool(tool: ToolDefinition):
    """便捷注册函数"""
    _registry.register(tool)


def register_all_tools(disabled: list[str] = None):
    """
    注册所有工具 — 在 server.py 启动时调用
    
    每个工具模块通过 register_tool() 自注册，
    本函数只负责过滤禁用工具。
    """
    if disabled:
        _registry.filter_disabled(disabled)

    logger.info(f"工具注册完成: {_registry.size()} 个工具已注册")
    return _registry
