# src/tools/nuclei_tool.py
"""Nuclei 模板搜索 - 在线 GitHub API 优先 + 本地降级"""

import logging
import os
import glob
import httpx
from ..validators import sanitize_subprocess_arg

logger = logging.getLogger("vuln-research-mcp")

NUCLEI_TEMPLATES_API = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"


async def _search_nuclei_online(tags: str, severity: str = None) -> dict:
    """在线搜索 Nuclei 模板（GitHub API）"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                NUCLEI_TEMPLATES_API,
                timeout=15.0,
                headers={"User-Agent": "vuln-research-mcp/0.2.0"},
            )

            if response.status_code != 200:
                return None

            data = response.json()
            tree = data.get("tree", [])

            tag_list = [t.strip().lower() for t in tags.split(",")]
            matched = []

            for item in tree:
                path = item.get("path", "")
                if not path.endswith(".yaml") and not path.endswith(".yml"):
                    continue

                path_lower = path.lower()

                # 标签匹配：检查路径中是否包含所有标签关键词
                if not all(tag in path_lower for tag in tag_list):
                    continue

                # 严重等级匹配
                if severity:
                    sev_lower = severity.lower()
                    if sev_lower not in path_lower:
                        # 同时检查文件名中常见的 severity 标记
                        severity_paths = {
                            "critical": ["critical"],
                            "high": ["high"],
                            "medium": ["medium"],
                            "low": ["low"],
                            "info": ["info"],
                        }
                        if not any(s in path_lower for s in severity_paths.get(sev_lower, [])):
                            continue

                matched.append({
                    "path": path,
                    "url": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}",
                    "type": item.get("type"),
                })

                if len(matched) >= 20:
                    break

            return {
                "tags": tags,
                "severity": severity,
                "total_matched": len(matched),
                "templates": matched,
                "source": "GitHub API (nuclei-templates)",
            }
    except Exception as e:
        logger.warning(f"在线搜索 nuclei 模板失败: {e}")
        return None


async def _search_nuclei_local(tags: str, severity: str = None) -> dict:
    """本地搜索 Nuclei 模板"""
    templates_dir = os.path.expanduser("~/.local/share/nuclei-templates")

    # Windows 也检查其他常见路径
    if not os.path.exists(templates_dir):
        alt_paths = [
            os.path.join(os.environ.get("USERPROFILE", ""), "nuclei-templates"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "nuclei-templates"),
            "C:\\Tools\\nuclei-templates",
        ]
        for alt in alt_paths:
            if os.path.exists(alt):
                templates_dir = alt
                break

    if not os.path.exists(templates_dir):
        return {
            "error": "nuclei-templates 仓库未找到",
            "installation": [
                "方法1: nuclei -update-templates",
                "方法2: git clone https://github.com/projectdiscovery/nuclei-templates.git",
            ],
            "tags": tags,
            "severity": severity,
        }

    try:
        tag_list = [t.strip().lower() for t in tags.split(",")]
        search_pattern = os.path.join(templates_dir, "**", "*.yaml")
        all_templates = glob.glob(search_pattern, recursive=True)

        matched_templates = []
        for template_path in all_templates:
            path_lower = template_path.lower()
            if not all(tag in path_lower for tag in tag_list):
                continue
            if severity and severity.lower() not in path_lower:
                continue
            matched_templates.append(template_path)
            if len(matched_templates) >= 20:
                break

        return {
            "tags": tags,
            "severity": severity,
            "total_matched": len(matched_templates),
            "templates": matched_templates[:20],
            "search_dir": templates_dir,
            "source": "local filesystem",
        }
    except Exception as e:
        return {"error": str(e), "tags": tags, "severity": severity}


async def find_nuclei_template(tags: str, severity: str = None) -> dict:
    """搜索 Nuclei 模板（在线优先，本地降级）"""
    if not tags or not isinstance(tags, str):
        raise ValueError("标签关键词不能为空")
    tags = sanitize_subprocess_arg(tags)

    if severity and severity not in ("info", "low", "medium", "high", "critical"):
        raise ValueError(f"无效的严重等级: {severity}")

    # 1. 先尝试在线 API
    result = await _search_nuclei_online(tags, severity)
    if result is not None:
        return result

    # 2. 在线失败，降级到本地
    logger.info("在线搜索不可用，降级到本地 nuclei-templates")
    return await _search_nuclei_local(tags, severity)
