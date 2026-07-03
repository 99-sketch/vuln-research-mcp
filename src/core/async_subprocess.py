# src/core/async_subprocess.py
"""异步 subprocess wrapper — 替代 subprocess.run，不阻塞 MCP 事件循环"""

import asyncio
import logging

logger = logging.getLogger("vuln-research-mcp")


async def async_run(cmd: list[str], timeout: float = 300) -> tuple[int, str, str]:
    """
    用 asyncio.create_subprocess_exec 替代 subprocess.run
    
    Args:
        cmd: 命令列表，如 ["nmap", "-sS", "127.0.0.1"]
        timeout: 超时秒数（默认 300s = 5分钟）
    
    Returns:
        (returncode, stdout, stderr)
    
    Raises:
        asyncio.TimeoutError: 超时后进程被 kill
        FileNotFoundError: 命令不存在
    """
    logger.debug(f"async_run: {' '.join(cmd)}")
    
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return (
            proc.returncode,
            stdout.decode(errors="ignore"),
            stderr.decode(errors="ignore"),
        )
    except asyncio.TimeoutError:
        logger.warning(f"async_run 超时 ({timeout}s)，杀死进程 PID={proc.pid}: {' '.join(cmd)}")
        proc.kill()
        await proc.wait()
        raise


async def async_run_safe(cmd: list[str], timeout: float = 300) -> dict:
    """
    安全版本的 async_run — 不抛异常，返回结构化结果
    
    Returns:
        {
            "returncode": int,
            "stdout": str,
            "stderr": str,
            "error": str | None,  # 超时或命令不存在时
        }
    """
    try:
        rc, stdout, stderr = await async_run(cmd, timeout)
        return {
            "returncode": rc,
            "stdout": stdout,
            "stderr": stderr,
            "error": None,
        }
    except asyncio.TimeoutError:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "error": f"命令超时 ({timeout}s): {' '.join(cmd)}",
        }
    except FileNotFoundError as e:
        return {
            "returncode": -2,
            "stdout": "",
            "stderr": "",
            "error": f"命令不存在: {e}",
        }
    except Exception as e:
        return {
            "returncode": -3,
            "stdout": "",
            "stderr": "",
            "error": str(e),
        }
