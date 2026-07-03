# src/tools/poc_archive_tool.py
"""PoC 档案库搜索工具 - 索引本地 exploitarium 仓库，按 CVE/关键词/软件名搜索"""

import logging
import os
import re
import subprocess
import shutil
from pathlib import Path
from ..validators import sanitize_subprocess_arg

logger = logging.getLogger("vuln-research-mcp")

# 默认仓库地址
EXPLOITARIUM_REPO = "https://github.com/bikini/exploitarium.git"

# 默认本地路径（用户可自定义）
DEFAULT_LOCAL_PATH = os.path.join(os.path.expanduser("~"), "exploitarium")

# CVE-ID 正则
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def _get_archive_path(custom_path: str = None) -> str:
    """获取 PoC 档案库本地路径"""
    path = custom_path or DEFAULT_LOCAL_PATH
    return os.path.expanduser(path)


def _is_cloned(path: str) -> bool:
    """检查仓库是否已克隆"""
    return os.path.isdir(os.path.join(path, ".git"))


def clone_archive(custom_path: str = None) -> dict:
    """克隆 exploitarium 仓库"""
    path = _get_archive_path(custom_path)
    
    if _is_cloned(path):
        return {
            "status": "already_cloned",
            "path": path,
            "message": "仓库已存在，使用 update_archive 更新",
        }
    
    git_path = shutil.which("git")
    if not git_path:
        return {
            "error": "git 未安装",
            "installation": [
                "Windows: https://git-scm.com/download/win",
                "Linux: sudo apt install git",
                "macOS: brew install git",
            ],
        }
    
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        result = subprocess.run(
            [git_path, "clone", "--depth", "1", EXPLOITARIUM_REPO, path],
            capture_output=True, text=True, timeout=120,
        )
        
        if result.returncode == 0:
            return {
                "status": "success",
                "path": path,
                "message": f"已克隆 exploitarium 到 {path}",
            }
        else:
            return {
                "error": "git clone 失败",
                "stderr": result.stderr[:500],
            }
    except subprocess.TimeoutExpired:
        return {"error": "git clone 超时（2分钟）"}
    except Exception as e:
        return {"error": str(e)}


def update_archive(custom_path: str = None) -> dict:
    """更新（git pull）exploitarium 仓库"""
    path = _get_archive_path(custom_path)
    
    if not _is_cloned(path):
        return {
            "error": "仓库未克隆",
            "path": path,
            "suggestion": "先调用 clone_archive 克隆仓库",
        }
    
    git_path = shutil.which("git")
    if not git_path:
        return {"error": "git 未安装"}
    
    try:
        result = subprocess.run(
            [git_path, "pull", "--ff-only"],
            cwd=path,
            capture_output=True, text=True, timeout=60,
        )
        
        if result.returncode == 0:
            return {
                "status": "success",
                "path": path,
                "output": result.stdout.strip() or "Already up to date.",
            }
        else:
            return {
                "error": "git pull 失败",
                "stderr": result.stderr[:500],
            }
    except subprocess.TimeoutExpired:
        return {"error": "git pull 超时"}
    except Exception as e:
        return {"error": str(e)}


def _index_archive(path: str) -> list[dict]:
    """扫描仓库目录，索引所有 PoC 条目"""
    entries = []
    
    for entry in os.listdir(path):
        entry_path = os.path.join(path, entry)
        if not os.path.isdir(entry_path) or entry.startswith('.'):
            continue
        
        readme_path = os.path.join(entry_path, "README.md")
        readme_content = ""
        if os.path.isfile(readme_path):
            with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
                readme_content = f.read()
        
        # 提取 CVE-ID
        cves = list(set(CVE_PATTERN.findall(readme_content)))
        cves = [c.upper() for c in cves]
        
        # 提取标题（README 第一行）
        title = entry
        for line in readme_content.split("\n"):
            line = line.strip()
            if line.startswith("# "):
                title = line[2:].strip()
                break
        
        # 提取前 500 字符作为摘要
        summary = readme_content[:500].strip()
        if not summary:
            summary = f"PoC 目录: {entry}"
        
        # 列出文件
        files = []
        for root, dirs, filenames in os.walk(entry_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in filenames:
                rel_path = os.path.relpath(os.path.join(root, fname), entry_path)
                files.append(rel_path)
        
        entries.append({
            "folder": entry,
            "title": title,
            "path": entry_path,
            "cves": cves,
            "file_count": len(files),
            "files": files[:20],
            "summary": summary,
            "readme_url": f"https://github.com/bikini/exploitarium/tree/main/{entry}",
        })
    
    return entries


async def search_poc_archive(
    query: str = None,
    cve_id: str = None,
    custom_path: str = None,
) -> dict:
    """
    搜索本地 PoC 档案库
    
    Args:
        query: 搜索关键词（软件名、漏洞类型等）
        cve_id: 按 CVE-ID 精确匹配
        custom_path: 自定义仓库路径（默认 ~/exploitarium）
    """
    path = _get_archive_path(custom_path)
    
    if not os.path.isdir(path):
        return {
            "error": "PoC 档案库未克隆",
            "path": path,
            "suggestion": f"先执行 clone_archive 克隆到 {path}，或指定 custom_path",
            "repo_url": EXPLOITARIUM_REPO,
        }
    
    # 索引
    entries = _index_archive(path)
    
    if not entries:
        return {
            "error": "档案库为空或目录结构异常",
            "path": path,
        }
    
    # 搜索
    results = entries
    
    if cve_id:
        cve_id = cve_id.strip().upper()
        # 验证 CVE-ID 格式
        if not CVE_PATTERN.match(cve_id):
            return {"error": f"无效的 CVE-ID: {cve_id}（格式: CVE-2026-55200）"}
        results = [e for e in results if cve_id in e["cves"]]
    
    if query:
        query = sanitize_subprocess_arg(query)
        query_lower = query.lower()
        results = [
            e for e in results
            if query_lower in e["folder"].lower()
            or query_lower in e["title"].lower()
            or query_lower in e["summary"].lower()
            or any(query_lower in c.lower() for c in e["cves"])
        ]
    
    # 构建返回
    return {
        "query": query,
        "cve_id": cve_id,
        "total_in_archive": len(entries),
        "total_matched": len(results),
        "results": [
            {
                "folder": e["folder"],
                "title": e["title"],
                "cves": e["cves"],
                "file_count": e["file_count"],
                "files": e["files"],
                "summary": e["summary"][:300],
                "local_path": e["path"],
                "readme_url": e["readme_url"],
            }
            for e in results[:20]
        ],
        "archive_path": path,
    }


async def list_poc_archive(custom_path: str = None) -> dict:
    """列出 PoC 档案库中的所有条目"""
    path = _get_archive_path(custom_path)
    
    if not os.path.isdir(path):
        return {
            "error": "PoC 档案库未克隆",
            "path": path,
            "suggestion": f"先执行 clone_archive 克隆到 {path}",
            "repo_url": EXPLOITARIUM_REPO,
        }
    
    entries = _index_archive(path)
    
    return {
        "total_entries": len(entries),
        "archive_path": path,
        "entries": [
            {
                "folder": e["folder"],
                "title": e["title"],
                "cves": e["cves"],
                "file_count": e["file_count"],
            }
            for e in entries
        ],
    }
