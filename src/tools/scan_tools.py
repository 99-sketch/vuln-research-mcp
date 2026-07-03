# src/tools/scan_tools.py
"""端口扫描与子域名枚举工具 - 含版本检测"""

import logging
import subprocess
import os
import tempfile
import shutil
from ..validators import validate_target, validate_ports, sanitize_subprocess_arg

logger = logging.getLogger("vuln-research-mcp")


def _check_tool_version(tool_name: str) -> dict:
    """检测外部工具是否安装及其版本"""
    path = shutil.which(tool_name)
    if not path:
        return {"installed": False, "version": None, "path": None}
    
    try:
        if tool_name == "nmap":
            result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
            version_line = result.stdout.split("\n")[0] if result.stdout else ""
            return {"installed": True, "version": version_line.strip(), "path": path}
        elif tool_name == "searchsploit":
            result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
            return {"installed": True, "version": result.stdout.strip(), "path": path}
        elif tool_name == "sublist3r":
            result = subprocess.run([path, "--help"], capture_output=True, text=True, timeout=5)
            return {"installed": True, "version": "unknown", "path": path}
        elif tool_name == "amass":
            result = subprocess.run([path, "version"], capture_output=True, text=True, timeout=5)
            return {"installed": True, "version": result.stdout.strip(), "path": path}
    except Exception:
        pass
    return {"installed": True, "version": "unknown", "path": path}


async def scan_ports(target: str, ports: str = None, scan_type: str = "quick") -> dict:
    """端口扫描（集成 nmap）"""
    target = validate_target(target)
    if ports:
        ports = validate_ports(ports)

    if scan_type not in ("quick", "full", "stealth", "version"):
        scan_type = "quick"

    # 版本检测
    tool_info = _check_tool_version("nmap")
    if not tool_info["installed"]:
        return {
            "error": "nmap 未安装",
            "installation": [
                "Kali/Debian: sudo apt install nmap",
                "macOS: brew install nmap",
                "Windows: https://nmap.org/download.html",
            ],
            "target": target,
        }

    try:
        cmd = ["nmap"]

        if scan_type == "quick":
            cmd.extend(["-T4", "-F"])
        elif scan_type == "full":
            cmd.extend(["-T4", "-p", "1-65535"])
        elif scan_type == "stealth":
            cmd.extend(["-sS", "-T2"])
        elif scan_type == "version":
            cmd.extend(["-sV", "-T4"])

        if ports:
            cmd.extend(["-p", ports])

        cmd.append(target)

        logger.info(f"执行 nmap: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            return {
                "target": target,
                "scan_type": scan_type,
                "ports": ports or "default",
                "output": result.stdout,
                "status": "success",
                "nmap_version": tool_info["version"],
            }
        else:
            return {
                "target": target,
                "error": "nmap 执行失败",
                "stderr": result.stderr[:500],
                "nmap_version": tool_info["version"],
            }
    except subprocess.TimeoutExpired:
        return {
            "error": "nmap 扫描超时（5分钟）",
            "target": target,
            "suggestion": "尝试减少端口范围或使用 quick 扫描类型",
        }
    except ValueError as e:
        return {"error": f"输入验证失败: {str(e)}", "target": target}
    except Exception as e:
        logger.error(f"scan_ports 失败: {e}")
        return {"error": str(e), "target": target}


async def enumerate_subdomains(domain: str, tool: str = "sublist3r") -> dict:
    """子域名枚举（集成 sublist3r 或 amass）"""
    from ..validators import validate_domain
    domain = validate_domain(domain)

    if tool not in ("sublist3r", "amass"):
        tool = "sublist3r"

    # 版本检测
    tool_info = _check_tool_version(tool)
    if not tool_info["installed"]:
        install_cmds = {
            "sublist3r": [
                "pip install sublist3r",
                "或: git clone https://github.com/aboul3la/Sublist3r.git",
            ],
            "amass": [
                "Kali: sudo apt install amass",
                "macOS: brew install amass",
                "Go: go install -v github.com/owasp-amass/amass/v4/...@master",
            ],
        }
        return {
            "error": f"{tool} 未安装",
            "installation": install_cmds.get(tool, ["请查看工具官方文档"]),
            "domain": domain,
        }

    try:
        if tool == "sublist3r":
            tmp_dir = tempfile.gettempdir()
            output_file = os.path.join(tmp_dir, f"sublist3r_{domain}.txt")

            cmd = ["sublist3r", "-d", domain, "-o", output_file]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            subdomains = []
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                try:
                    os.remove(output_file)
                except OSError:
                    pass

            return {
                "domain": domain,
                "tool": tool,
                "tool_version": tool_info["version"],
                "total_found": len(subdomains),
                "subdomains": subdomains[:50],
                "output": result.stdout[:2000] if result.stdout else "",
                "source": "sublist3r",
            }

        elif tool == "amass":
            cmd = ["amass", "enum", "-passive", "-d", domain]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            subdomains = [line.strip() for line in result.stdout.split("\n") if line.strip()]

            return {
                "domain": domain,
                "tool": tool,
                "tool_version": tool_info["version"],
                "total_found": len(subdomains),
                "subdomains": subdomains[:50],
                "source": "amass",
            }

    except subprocess.TimeoutExpired:
        return {
            "error": f"{tool} 枚举超时（5分钟）",
            "domain": domain,
            "suggestion": "尝试使用 passive 模式或减少数据源",
        }
    except ValueError as e:
        return {"error": f"输入验证失败: {str(e)}", "domain": domain}
    except Exception as e:
        logger.error(f"enumerate_subdomains 失败: {e}")
        return {"error": str(e), "domain": domain}
