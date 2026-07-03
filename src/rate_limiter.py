# src/rate_limiter.py
"""速率限制器 + 重试机制"""

import asyncio
import logging
import os
import time
from functools import wraps

import httpx

logger = logging.getLogger("vuln-research-mcp")

# NVD API Key（从环境变量读取）
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# 速率限制：无 Key 5次/30秒，有 Key 50次/30秒
NVD_RATE_LIMIT = 50 if NVD_API_KEY else 5
NVD_RATE_WINDOW = 30  # 秒

# 全局速率限制器
_nvd_semaphore = asyncio.Semaphore(NVD_RATE_LIMIT)
_nvd_call_times: list[float] = []


async def nvd_rate_limited_request(client: httpx.AsyncClient, url: str, params: dict, max_retries: int = 3) -> httpx.Response:
    """带速率限制和重试的 NVD API 请求"""
    for attempt in range(max_retries):
        async with _nvd_semaphore:
            # 清理过期时间窗口
            now = time.time()
            global _nvd_call_times
            _nvd_call_times = [t for t in _nvd_call_times if now - t < NVD_RATE_WINDOW]
            
            if len(_nvd_call_times) >= NVD_RATE_LIMIT:
                sleep_time = NVD_RATE_WINDOW - (now - _nvd_call_times[0]) + 1
                logger.warning(f"NVD 速率限制：等待 {sleep_time:.1f} 秒")
                await asyncio.sleep(sleep_time)
            
            _nvd_call_times.append(time.time())
            
            # 添加 API Key header
            headers = {}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY
            
            try:
                response = await client.get(url, params=params, headers=headers, timeout=15.0)
                
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", "5"))
                    logger.warning(f"NVD API 429 限速，等待 {retry_after} 秒后重试 (attempt {attempt+1}/{max_retries})")
                    await asyncio.sleep(retry_after)
                    continue
                
                response.raise_for_status()
                return response
            
            except httpx.TimeoutException:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    logger.warning(f"NVD API 超时，{wait}秒后重试 (attempt {attempt+1}/{max_retries})")
                    await asyncio.sleep(wait)
                    continue
                raise
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(f"NVD API {e.response.status_code}，{wait}秒后重试 (attempt {attempt+1}/{max_retries})")
                    await asyncio.sleep(wait)
                    continue
                raise
    
    raise httpx.HTTPStatusError(
        "NVD API 请求失败（已重试 {} 次）".format(max_retries),
        request=response.request,
        response=response,
    )
