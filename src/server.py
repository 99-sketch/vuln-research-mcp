#!/usr/bin/env python3
"""
Vulnerability Research MCP Server
一个用于渗透测试的漏洞研究 MCP 服务器
整合 CVE、CWE、Exploit-DB、Nuclei 模板等数据源
"""

import asyncio
import json
import logging
import subprocess
import os
import socket
import re
from typing import Any
import httpx
import dns.resolver
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, EmbeddedResource

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("vuln-research-mcp")

# NVD API 基础 URL
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"
EXPLOIT_DB_API = "https://www.exploit-db.com/api/v1"
NUCLEI_TEMPLATES_REPO = "https://api.github.com/repos/projectdiscovery/nuclei-templates"

server = Server("vuln-research-mcp")

# ---------- 工具定义 ----------

@server.list_tools()
async def list_tools() -> list[Tool]:
    """列出所有可用工具"""
    return [
        Tool(
            name="search_cve",
            description="搜索 CVE 漏洞（按产品名称、版本或关键词）",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "搜索关键词（如：Apache Log4j、WordPress Plugin）"
                    },
                    "product": {
                        "type": "string",
                        "description": "产品名称（可选）"
                    },
                    "version": {
                        "type": "string",
                        "description": "产品版本（可选）"
                    },
                    "max_results": {
                        "type": "number",
                        "description": "最大返回结果数（默认 10）",
                        "default": 10
                    }
                },
                "required": ["keyword"]
            }
        ),
        Tool(
            name="get_cve_details",
            description="获取指定 CVE-ID 的详细信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE ID（如：CVE-2021-44228）"
                    }
                },
                "required": ["cve_id"]
            }
        ),
        Tool(
            name="search_exploit",
            description="在 Exploit-DB 中搜索 PoC/EXP（需要本地 searchsploit）",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "搜索关键词（如：WordPress、RCE、SQLi）"
                    },
                    "type_filter": {
                        "type": "string",
                        "description": "利用类型过滤（可选：remote、webapps、local、dos）"
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="cvss_calculator",
            description="计算 CVSS v3.1 评分",
            inputSchema={
                "type": "object",
                "properties": {
                    "attack_vector": {
                        "type": "string",
                        "enum": ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"],
                        "description": "攻击向量（AV）"
                    },
                    "attack_complexity": {
                        "type": "string",
                        "enum": ["LOW", "HIGH"],
                        "description": "攻击复杂度（AC）"
                    },
                    "privileges_required": {
                        "type": "string",
                        "enum": ["NONE", "LOW", "HIGH"],
                        "description": "所需权限（PR）"
                    },
                    "user_interaction": {
                        "type": "string",
                        "enum": ["NONE", "REQUIRED"],
                        "description": "用户交互（UI）"
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["UNCHANGED", "CHANGED"],
                        "description": "作用域（S）"
                    },
                    "confidentiality": {
                        "type": "string",
                        "enum": ["NONE", "LOW", "HIGH"],
                        "description": "机密性影响（C）"
                    },
                    "integrity": {
                        "type": "string",
                        "enum": ["NONE", "LOW", "HIGH"],
                        "description": "完整性影响（I）"
                    },
                    "availability": {
                        "type": "string",
                        "enum": ["NONE", "LOW", "HIGH"],
                        "description": "可用性影响（A）"
                    }
                },
                "required": ["attack_vector", "attack_complexity", "privileges_required", 
                           "user_interaction", "scope", "confidentiality", 
                           "integrity", "availability"]
            }
        ),
        Tool(
            name="cwe_mapping",
            description="查询 CWE（Common Weakness Enumeration）信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE ID（如：CWE-79、CWE-89）"
                    }
                },
                "required": ["cwe_id"]
            }
        ),
        Tool(
            name="find_nuclei_template",
            description="在 Nuclei Templates 仓库中搜索相关模板（需要本地克隆）",
            inputSchema={
                "type": "object",
                "properties": {
                    "tags": {
                        "type": "string",
                        "description": "标签关键词（如：cve, rce, wordpress, sql）"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                        "description": "严重等级过滤（可选）"
                    }
                },
                "required": ["tags"]
            }
        ),
        # ---------- 新增工具 ----------
        Tool(
            name="scan_ports",
            description="端口扫描（集成 nmap）",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP 或域名"
                    },
                    "ports": {
                        "type": "string",
                        "description": "端口范围（如：80,443 或 1-1000，默认：常见端口）"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "stealth", "version"],
                        "description": "扫描类型（quick=快速, full=全端口, stealth=隐蔽, version=版本检测）"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="enumerate_subdomains",
            description="子域名枚举（集成 sublist3r 或 amass）",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "目标域名（如：example.com）"
                    },
                    "tool": {
                        "type": "string",
                        "enum": ["sublist3r", "amass"],
                        "description": "枚举工具选择（默认：sublist3r）"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="check_http_headers",
            description="HTTP 安全头检查",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL（如：https://example.com）"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="query_dns",
            description="DNS 记录查询",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "域名（如：example.com）"
                    },
                    "record_type": {
                        "type": "string",
                        "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "ALL"],
                        "description": "DNS 记录类型（默认：A）"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="geolocate_ip",
            description="IP 地理位置查询",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP 地址（如：8.8.8.8）"
                    }
                },
                "required": ["ip"]
            }
        )
    ]

# ---------- 工具实现 ----------

@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """处理工具调用"""
    logger.info(f"工具调用: {name}, 参数: {arguments}")
    
    try:
        if name == "search_cve":
            result = await search_cve(**arguments)
        elif name == "get_cve_details":
            result = await get_cve_details(**arguments)
        elif name == "search_exploit":
            result = await search_exploit(**arguments)
        elif name == "cvss_calculator":
            result = await cvss_calculator(**arguments)
        elif name == "cwe_mapping":
            result = await cwe_mapping(**arguments)
        elif name == "find_nuclei_template":
            result = await find_nuclei_template(**arguments)
        # 新增工具
        elif name == "scan_ports":
            result = await scan_ports(**arguments)
        elif name == "enumerate_subdomains":
            result = await enumerate_subdomains(**arguments)
        elif name == "check_http_headers":
            result = await check_http_headers(**arguments)
        elif name == "query_dns":
            result = await query_dns(**arguments)
        elif name == "geolocate_ip":
            result = await geolocate_ip(**arguments)
        else:
            raise ValueError(f"未知工具: {name}")
        
        logger.info(f"工具 {name} 执行成功")
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    
    except Exception as e:
        logger.error(f"工具 {name} 执行失败: {str(e)}")
        raise

# ---------- 具体实现 ----------

async def search_cve(keyword: str, product: str = None, version: str = None, max_results: int = 10) -> dict:
    """搜索 CVE 漏洞"""
    async with httpx.AsyncClient() as client:
        # 构建查询参数
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results
        }
        
        response = await client.get(f"{NVD_API_BASE}/cves/2.0", params=params, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        
        # 解析结果
        vulnerabilities = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            
            vulnerabilities.append({
                "cve_id": cve.get("id"),
                "source_identifier": cve.get("sourceIdentifier"),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "status": cve.get("vulnStatus"),
                "description": cve.get("descriptions", [{}])[0].get("value"),
                "cvss_score": cvss_v3.get("baseScore"),
                "severity": cvss_v3.get("baseSeverity"),
                "vector_string": cvss_v3.get("vectorString")
            })
        
        return {
            "total_results": data.get("totalResults", 0),
            "vulnerabilities": vulnerabilities
        }

async def get_cve_details(cve_id: str) -> dict:
    """获取 CVE 详细信息"""
    async with httpx.AsyncClient() as client:
        params = {"cveId": cve_id}
        response = await client.get(f"{NVD_API_BASE}/cves/2.0", params=params, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": f"CVE {cve_id} 未找到"}
        
        vuln = vulnerabilities[0].get("cve", {})
        
        # 提取详细信息
        return {
            "cve_id": vuln.get("id"),
            "source_identifier": vuln.get("sourceIdentifier"),
            "published": vuln.get("published"),
            "last_modified": vuln.get("lastModified"),
            "status": vuln.get("vulnStatus"),
            "description": vuln.get("descriptions", [{}])[0].get("value"),
            "metrics": vuln.get("metrics"),
            "weaknesses": vuln.get("weaknesses"),
            "configurations": vuln.get("configurations"),
            "references": [ref.get("url") for ref in vuln.get("references", [])]
        }

async def search_exploit(query: str, type_filter: str = None) -> dict:
    """搜索 Exploit-DB（使用本地 searchsploit）"""
    try:
        # 使用本地 searchsploit 命令
        cmd = ["searchsploit", "--json", query]
        if type_filter:
            cmd.extend(["-t", type_filter])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            # 解析 JSON 输出
            try:
                exploits = json.loads(result.stdout)
                return {
                    "query": query,
                    "type_filter": type_filter,
                    "total_results": len(exploits.get("RESULTS", [])),
                    "exploits": exploits.get("RESULTS", [])[:10],  # 返回前 10 个结果
                    "source": "searchsploit"
                }
            except json.JSONDecodeError:
                # 如果不是 JSON，返回原始输出
                return {
                    "query": query,
                    "output": result.stdout,
                    "source": "searchsploit_text"
                }
        else:
            return {
                "error": "searchsploit 执行失败",
                "stderr": result.stderr,
                "installation_hint": "sudo apt install exploitdb  # Kali/Debian"
            }
    
    except FileNotFoundError:
        return {
            "error": "searchsploit 未安装",
            "installation": [
                "Kali/Debian: sudo apt install exploitdb",
                "通用方法: git clone https://github.com/offensive-security/exploitdb.git"
            ],
            "query": query
        }
    
    except Exception as e:
        logger.error(f"search_exploit 失败: {str(e)}")
        return {
            "error": str(e),
            "query": query
        }

async def cvss_calculator(**kwargs) -> dict:
    """计算 CVSS v3.1 评分（简化实现）"""
    # CVSS v3.1 评分算法简化实现
    # 完整实现请参考：https://www.first.org/cvss/v3.1/specification-document
    
    # 评分映射
    av_map = {"NETWORK": 0.85, "ADJACENT_NETWORK": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
    ac_map = {"LOW": 0.77, "HIGH": 0.44}
    pr_map = {
        "NONE": {"UNCHANGED": 0.85, "CHANGED": 0.85},
        "LOW": {"UNCHANGED": 0.62, "CHANGED": 0.68},
        "HIGH": {"UNCHANGED": 0.27, "CHANGED": 0.50}
    }
    ui_map = {"NONE": 0.85, "REQUIRED": 0.62}
    cia_map = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}
    
    # 计算基础评分
    av = av_map.get(kwargs.get("attack_vector"), 0)
    ac = ac_map.get(kwargs.get("attack_complexity"), 0)
    pr = pr_map.get(kwargs.get("privileges_required"), {}).get(kwargs.get("scope"), 0)
    ui = ui_map.get(kwargs.get("user_interaction"), 0)
    
    c = cia_map.get(kwargs.get("confidentiality"), 0)
    i = cia_map.get(kwargs.get("integrity"), 0)
    a = cia_map.get(kwargs.get("availability"), 0)
    
    # 简化计算（完整实现需要更多逻辑）
    base_score = av * ac * pr * ui  # 这是简化版本
    
    # 确定严重等级
    if base_score >= 9.0:
        severity = "CRITICAL"
    elif base_score >= 7.0:
        severity = "HIGH"
    elif base_score >= 4.0:
        severity = "MEDIUM"
    elif base_score > 0:
        severity = "LOW"
    else:
        severity = "NONE"
    
    return {
        "base_score": round(base_score, 1),
        "severity": severity,
        "vector": {
            "AV": kwargs.get("attack_vector")[0],
            "AC": kwargs.get("attack_complexity")[0],
            "PR": kwargs.get("privileges_required")[0],
            "UI": kwargs.get("user_interaction")[0],
            "S": kwargs.get("scope")[0],
            "C": kwargs.get("confidentiality")[0],
            "I": kwargs.get("integrity")[0],
            "A": kwargs.get("availability")[0]
        },
        "note": "这是简化实现，完整实现请参考 CVSS v3.1 规范"
    }

async def cwe_mapping(cwe_id: str) -> dict:
    """查询 CWE 信息（简化实现）"""
    # 简化实现：返回常见 CWE 信息
    # 完整实现应该调用 MITRE CWE API 或本地数据库
    
    common_cwe = {
        "CWE-79": {
            "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "weakness_type": "Class",
            "status": "Incomplete",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page."
        },
        "CWE-89": {
            "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "weakness_type": "Class",
            "status": "Draft",
            "description": "The software constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements."
        },
        "CWE-287": {
            "name": "Improper Authentication",
            "weakness_type": "Class",
            "status": "Draft",
            "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct."
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "weakness_type": "Compound",
            "status": "Incomplete",
            "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request."
        },
        "CWE-434": {
            "name": "Unrestricted File Upload with Dangerous Type",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The application allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment."
        }
    }
    
    if cwe_id in common_cwe:
        return common_cwe[cwe_id]
    else:
        return {
            "note": f"CWE {cwe_id} 详细信息需要查询 MITRE CWE 数据库",
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
            "suggestion": "考虑下载完整 CWE 数据库: https://cwe.mitre.org/data/downloads.html"
        }

async def find_nuclei_template(tags: str, severity: str = None) -> dict:
    """查找 Nuclei 模板（需要本地克隆仓库）"""
    # 检查本地是否有 nuclei-templates 仓库
    templates_dir = os.path.expanduser("~/.local/share/nuclei-templates")
    
    if not os.path.exists(templates_dir):
        return {
            "error": "nuclei-templates 仓库未找到",
            "installation": [
                "方法1: nuclei -update-templates",
                "方法2: git clone https://github.com/projectdiscovery/nuclei-templates.git ~/.local/share/nuclei-templates"
            ],
            "tags": tags,
            "severity": severity
        }
    
    # 搜索模板
    try:
        import glob
        
        # 构建搜索命令
        search_pattern = os.path.join(templates_dir, "**", "*.yaml")
        all_templates = glob.glob(search_pattern, recursive=True)
        
        # 过滤包含指定标签的模板
        matched_templates = []
        for template_path in all_templates:
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if all(tag.strip() in content for tag in tags.split(',')):
                    if severity is None or severity in content:
                        matched_templates.append(template_path)
        
        return {
            "tags": tags,
            "severity": severity,
            "total_matched": len(matched_templates),
            "templates": matched_templates[:10],  # 返回前 10 个
            "search_dir": templates_dir
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "tags": tags,
            "severity": severity
        }



# ---------- 新增工具实现 ----------

async def scan_ports(target: str, ports: str = None, scan_type: str = "quick") -> dict:
    """端口扫描（集成 nmap）"""
    try:
        # 构建 nmap 命令
        cmd = ["nmap"]
        
        # 根据扫描类型设置参数
        if scan_type == "quick":
            cmd.extend(["-T4", "-F"])  # 快速扫描常见端口
        elif scan_type == "full":
            cmd.extend(["-T4", "-p", "1-65535"])  # 全端口扫描
        elif scan_type == "stealth":
            cmd.extend(["-sS", "-T2"])  # SYN 隐蔽扫描
        elif scan_type == "version":
            cmd.extend(["-sV", "-T4"])  # 版本检测
        
        # 添加端口参数（如果指定）
        if ports:
            cmd.extend(["-p", ports])
        
        # 添加目标
        cmd.append(target)
        
        # 执行 nmap
        logger.info(f"执行 nmap 命令: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return {
                "target": target,
                "scan_type": scan_type,
                "ports": ports or "default",
                "output": result.stdout,
                "status": "success"
            }
        else:
            return {
                "target": target,
                "error": "nmap 执行失败",
                "stderr": result.stderr,
                "installation_hint": "sudo apt install nmap  # Kali/Debian"
            }
    
    except FileNotFoundError:
        return {
            "error": "nmap 未安装",
            "installation": [
                "Kali/Debian: sudo apt install nmap",
                "macOS: brew install nmap",
                "Windows: https://nmap.org/download.html"
            ],
            "target": target
        }
    
    except subprocess.TimeoutExpired:
        return {
            "error": "nmap 扫描超时（5分钟）",
            "target": target,
            "suggestion": "尝试减少端口范围或使用 quick 扫描类型"
        }
    
    except Exception as e:
        logger.error(f"scan_ports 失败: {str(e)}")
        return {
            "error": str(e),
            "target": target
        }


async def enumerate_subdomains(domain: str, tool: str = "sublist3r") -> dict:
    """子域名枚举（集成 sublist3r 或 amass）"""
    try:
        if tool == "sublist3r":
            # 使用 sublist3r
            cmd = ["sublist3r", "-d", domain, "-o", "/tmp/subdomains.txt"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # 读取结果文件
            subdomains = []
            if os.path.exists("/tmp/subdomains.txt"):
                with open("/tmp/subdomains.txt", "r") as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            return {
                "domain": domain,
                "tool": tool,
                "total_found": len(subdomains),
                "subdomains": subdomains[:50],  # 返回前 50 个
                "output": result.stdout,
                "source": "sublist3r"
            }
        
        elif tool == "amass":
            # 使用 amass（被动枚举）
            cmd = ["amass", "enum", "-passive", "-d", domain]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            return {
                "domain": domain,
                "tool": tool,
                "total_found": len(subdomains),
                "subdomains": subdomains[:50],
                "source": "amass"
            }
    
    except FileNotFoundError:
        install_cmds = {
            "sublist3r": [
                "pip install sublist3r",
                "或使用: git clone https://github.com/aboul3la/Sublist3r.git"
            ],
            "amass": [
                "Kali/Debian: sudo apt install amass",
                "macOS: brew install amass",
                "或其他方式: https://github.com/OWASP/Amass"
            ]
        }
        return {
            "error": f"{tool} 未安装",
            "installation": install_cmds.get(tool, ["请查看工具官方文档"]),
            "domain": domain
        }
    
    except subprocess.TimeoutExpired:
        return {
            "error": f"{tool} 枚举超时（5分钟）",
            "domain": domain,
            "suggestion": "尝试使用 passive 模式或减少数据源"
        }
    
    except Exception as e:
        logger.error(f"enumerate_subdomains 失败: {str(e)}")
        return {
            "error": str(e),
            "domain": domain
        }


async def check_http_headers(url: str) -> dict:
    """HTTP 安全头检查"""
    # 定义重要的安全头
    security_headers = {
        "Strict-Transport-Security": {
            "description": "强制 HTTPS 连接",
            "recommendation": "max-age=31536000; includeSubDomains"
        },
        "Content-Security-Policy": {
            "description": "防止 XSS 和内容注入",
            "recommendation": "default-src 'self'"
        },
        "X-Frame-Options": {
            "description": "防止点击劫持",
            "recommendation": "DENY 或 SAMEORIGIN"
        },
        "X-Content-Type-Options": {
            "description": "防止 MIME 类型嗅探",
            "recommendation": "nosniff"
        },
        "Referrer-Policy": {
            "description": "控制 Referer 头",
            "recommendation": "strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "description": "控制浏览器功能权限",
            "recommendation": "限制敏感 API（如摄像头、麦克风）"
        },
        "X-XSS-Protection": {
            "description": "XSS 过滤器（已弃用，建议使用 CSP）",
            "recommendation": "0（禁用，依赖 CSP）"
        }
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=30.0, follow_redirects=True)
            headers = response.headers
            
            # 检查安全头
            results = {
                "url": str(response.url),
                "status_code": response.status_code,
                "headers_analysis": {}
            }
            
            present_count = 0
            missing_count = 0
            
            for header, info in security_headers.items():
                if header in headers:
                    results["headers_analysis"][header] = {
                        "status": "✓ 存在",
                        "value": headers[header],
                        "description": info["description"]
                    }
                    present_count += 1
                else:
                    results["headers_analysis"][header] = {
                        "status": "✗ 缺失",
                        "description": info["description"],
                        "recommendation": info["recommendation"]
                    }
                    missing_count += 1
            
            # 总结
            results["summary"] = {
                "total_checked": len(security_headers),
                "present": present_count,
                "missing": missing_count,
                "score": f"{int(present_count / len(security_headers) * 100)}%"
            }
            
            return results
    
    except httpx.TimeoutException:
        return {
            "error": "请求超时",
            "url": url
        }
    
    except httpx.ConnectError:
        return {
            "error": "连接失败（目标不可达或 URL 错误）",
            "url": url
        }
    
    except Exception as e:
        logger.error(f"check_http_headers 失败: {str(e)}")
        return {
            "error": str(e),
            "url": url
        }


async def query_dns(domain: str, record_type: str = "A") -> dict:
    """DNS 记录查询"""
    results = {
        "domain": domain,
        "records": {}
    }
    
    try:
        # 如果请求所有记录类型
        if record_type == "ALL":
            types_to_query = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        else:
            types_to_query = [record_type]
        
        for rtype in types_to_query:
            try:
                # 使用 dnspython
                answers = dns.resolver.resolve(domain, rtype)
                records = [str(rdata) for rdata in answers]
                
                results["records"][rtype] = {
                    "status": "success",
                    "count": len(records),
                    "values": records
                }
            
            except dns.resolver.NXDOMAIN:
                results["records"][rtype] = {
                    "status": "error",
                    "error": "域名不存在"
                }
                break
            
            except dns.resolver.NoAnswer:
                results["records"][rtype] = {
                    "status": "no_record",
                    "message": f"该域名没有 {rtype} 记录"
                }
            
            except Exception as e:
                results["records"][rtype] = {
                    "status": "error",
                    "error": str(e)
                }
        
        return results
    
    except Exception as e:
        logger.error(f"query_dns 失败: {str(e)}")
        return {
            "error": str(e),
            "domain": domain,
            "record_type": record_type
        }


async def geolocate_ip(ip: str) -> dict:
    """IP 地理位置查询"""
    # 使用 ip-api.com 的免费 API（无需 API key）
    api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(api_url, timeout=10.0)
            response.raise_for_status()
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "zip": data.get("zip"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "as": data.get("as"),
                    "source": "ip-api.com"
                }
            else:
                return {
                    "error": data.get("message", "查询失败"),
                    "ip": ip
                }
    
    except httpx.TimeoutException:
        return {
            "error": "API 请求超时",
            "ip": ip,
            "fallback_api": "可以尝试其他 API（如 ipinfo.io）"
        }
    
    except Exception as e:
        logger.error(f"geolocate_ip 失败: {str(e)}")
        return {
            "error": str(e),
            "ip": ip
        }




# ---------- 主函数 ----------

async def main():
    """启动 MCP 服务器"""
    logger.info("Vulnerability Research MCP Server 启动中...")
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
