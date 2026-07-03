# src/core/circuit_breaker.py
"""熔断器 — 连续失败后快速失败，避免卡等超时"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Coroutine

logger = logging.getLogger("vuln-research-mcp")


class CircuitOpenError(Exception):
    """熔断器开启时抛出"""
    pass


@dataclass
class CircuitBreaker:
    """
    三态熔断器：CLOSED → OPEN → HALF_OPEN → CLOSED
    
    - CLOSED: 正常运行，记录失败次数
    - OPEN: 快速失败，不调用外部 API，直接返回错误
    - HALF_OPEN: 放一个请求探测，成功则恢复 CLOSED
    """
    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    _failures: int = 0
    _last_failure: float = 0.0
    _state: str = "CLOSED"
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def state(self) -> str:
        return self._state

    async def call(self, coro: Coroutine) -> Any:
        """通过熔断器执行协程"""
        async with self._lock:
            if self._state == "OPEN":
                if time.time() - self._last_failure > self.recovery_timeout:
                    logger.info(f"熔断器 {self.name} 进入 HALF_OPEN，放一个探测请求")
                    self._state = "HALF_OPEN"
                else:
                    raise CircuitOpenError(
                        f"{self.name} 熔断中（连续 {self._failures} 次失败，"
                        f"{self.recovery_timeout - (time.time() - self._last_failure):.0f}s 后重试）"
                    )

        try:
            result = await coro
            async with self._lock:
                if self._state == "HALF_OPEN":
                    logger.info(f"熔断器 {self.name} 恢复 CLOSED")
                    self._state = "CLOSED"
                self._failures = 0
            return result
        except Exception as e:
            async with self._lock:
                self._failures += 1
                self._last_failure = time.time()
                if self._failures >= self.failure_threshold:
                    self._state = "OPEN"
                    logger.warning(
                        f"熔断器 {self.name} 打开 OPEN（连续 {self._failures} 次失败）"
                    )
            raise

    def reset(self):
        """手动重置熔断器"""
        self._failures = 0
        self._last_failure = 0.0
        self._state = "CLOSED"


# 全局熔断器实例
_breakers: dict[str, CircuitBreaker] = {}


def get_breaker(name: str, **kwargs) -> CircuitBreaker:
    """获取或创建熔断器实例"""
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name=name, **kwargs)
    return _breakers[name]


def all_breaker_status() -> dict[str, dict]:
    """获取所有熔断器状态（用于健康检查）"""
    return {
        name: {
            "state": b.state,
            "failures": b._failures,
            "failure_threshold": b.failure_threshold,
            "recovery_timeout": b.recovery_timeout,
        }
        for name, b in _breakers.items()
    }
