#!/usr/bin/env python3
"""
Vulnerability Research MCP Server
一个用于渗透测试的漏洞研究 MCP 服务器
整合 CVE、CWE、Exploit-DB、Nuclei 模板等数据源
"""

import asyncio
import json
import logging
import math
import os
import re
import subprocess
from typing import Any

import dns.resolver
import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import EmbeddedResource, TextContent, Tool

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
            description="计算 CVSS v3.1 评分（支持完整 vector 字符串或分解参数）",
            inputSchema={
                "type": "object",
                "properties": {
                    "vector": {
                        "type": "string",
                        "description": "完整 CVSS v3.1 vector 字符串（如：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H），如提供此项，其他参数可不填。"
                    },
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
                "required": []
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
        
        response = await client.get(f"{NVD_API_BASE}/cves/2.0", params=params, timeout=10.0)
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
        response = await client.get(f"{NVD_API_BASE}/cves/2.0", params=params, timeout=10.0)
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
    """计算 CVSS v3.1 评分（符合 FIRST 规范）"""
    # 支持两种输入方式：
    # 1. 完整 vector 字符串：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    # 2. 分开参数：attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability
    
    vector = kwargs.get("vector")
    if vector and isinstance(vector, str) and vector.startswith("CVSS:3.1/"):
        kwargs = _parse_cvss_vector(vector)
    elif kwargs.get("vector"):
        return {"error": "vector 格式不正确，必须以 CVSS:3.1/ 开头"}
    
    # 校验必需参数
    required = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope", "confidentiality", "integrity", "availability"]
    missing = [p for p in required if p not in kwargs or kwargs[p] is None]
    if missing:
        return {"error": f"缺少参数: {', '.join(missing)}。或者传入完整 vector 字符串"}
    
    result = _compute_cvss_v3_1(kwargs)
    return result

def _parse_cvss_vector(vector: str) -> dict:
    """解析 CVSS v3.1 vector 字符串为参数字典"""
    metrics = {}
    parts = vector.replace("CVSS:3.1/", "").split("/")
    mapping = {
        "AV": "attack_vector",
        "AC": "attack_complexity",
        "PR": "privileges_required",
        "UI": "user_interaction",
        "S": "scope",
        "C": "confidentiality",
        "I": "integrity",
        "A": "availability"
    }
    value_map = {
        "attack_vector": {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
        "attack_complexity": {"L": "LOW", "H": "HIGH"},
        "privileges_required": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "user_interaction": {"N": "NONE", "R": "REQUIRED"},
        "scope": {"U": "UNCHANGED", "C": "CHANGED"},
        "confidentiality": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "integrity": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "availability": {"N": "NONE", "L": "LOW", "H": "HIGH"}
    }
    for part in parts:
        if ":" not in part:
            continue
        metric, value = part.split(":", 1)
        key = mapping.get(metric)
        if key:
            metrics[key] = value_map[key].get(value, value)
    return metrics

def _compute_cvss_v3_1(metrics: dict) -> dict:
    """按 FIRST CVSS v3.1 规范计算基础分数"""
    # 参考: https://www.first.org/cvss/v3.1/specification-document
    
    av_map = {"NETWORK": 0.85, "ADJACENT_NETWORK": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
    ac_map = {"LOW": 0.77, "HIGH": 0.44}
    pr_map = {
        "NONE": {"UNCHANGED": 0.85, "CHANGED": 0.85},
        "LOW": {"UNCHANGED": 0.62, "CHANGED": 0.68},
        "HIGH": {"UNCHANGED": 0.27, "CHANGED": 0.50}
    }
    ui_map = {"NONE": 0.85, "REQUIRED": 0.62}
    cia_map = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}
    
    # 获取数值
    av = av_map.get(metrics.get("attack_vector"), 0)
    ac = ac_map.get(metrics.get("attack_complexity"), 0)
    pr = pr_map.get(metrics.get("privileges_required"), {}).get(metrics.get("scope"), 0)
    ui = ui_map.get(metrics.get("user_interaction"), 0)
    scope_changed = metrics.get("scope") == "CHANGED"
    c = cia_map.get(metrics.get("confidentiality"), 0)
    i = cia_map.get(metrics.get("integrity"), 0)
    a = cia_map.get(metrics.get("availability"), 0)
    
    # 1. 计算 Impact Sub-Score (ISS)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    # 2. 计算 Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    
    # 3. 计算 Exploitability
    exploitability = 8.22 * av * ac * pr * ui
    
    # 4. 计算 Base Score
    if impact <= 0:
        base_score = 0.0
    else:
        if scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10)
        else:
            base_score = min(impact + exploitability, 10)
    
    # 5. 向上取整到小数点后一位
    base_score = round_up(base_score, 1)
    
    # 6. 严重等级
    if base_score == 0.0:
        severity = "NONE"
    elif base_score < 4.0:
        severity = "LOW"
    elif base_score < 7.0:
        severity = "MEDIUM"
    elif base_score < 9.0:
        severity = "HIGH"
    else:
        severity = "CRITICAL"
    
    # 生成标准 vector 字符串
    vector = (
        f"CVSS:3.1/AV:{metrics.get('attack_vector')[0]}/"
        f"AC:{metrics.get('attack_complexity')[0]}/"
        f"PR:{metrics.get('privileges_required')[0]}/"
        f"UI:{metrics.get('user_interaction')[0]}/"
        f"S:{metrics.get('scope')[0]}/"
        f"C:{metrics.get('confidentiality')[0]}/"
        f"I:{metrics.get('integrity')[0]}/"
        f"A:{metrics.get('availability')[0]}"
    )
    
    return {
        "base_score": base_score,
        "severity": severity,
        "impact": round(impact, 3),
        "exploitability": round(exploitability, 3),
        "vector": vector,
        "metrics": {
            "AV": metrics.get("attack_vector"),
            "AC": metrics.get("attack_complexity"),
            "PR": metrics.get("privileges_required"),
            "UI": metrics.get("user_interaction"),
            "S": metrics.get("scope"),
            "C": metrics.get("confidentiality"),
            "I": metrics.get("integrity"),
            "A": metrics.get("availability")
        },
        "note": "基于 FIRST CVSS v3.1 规范计算（完整 Base Score 算法）"
    }

def round_up(value: float, precision: int) -> float:
    """按 CVSS 规范向上取整"""
    multiplier = 10 ** precision
    return math.ceil(value * multiplier - 0.0000005) / multiplier

async def cwe_mapping(cwe_id: str) -> dict:
    """查询 CWE 信息（本地常见漏洞类型库）"""
    normalized = cwe_id.strip().upper()
    
    # CWE ID 格式校验
    if not re.match(r"^CWE-\d{1,6}$", normalized):
        return {
            "error": "CWE ID 格式不正确",
            "expected": "CWE-XX 格式（如 CWE-89、CWE-079）",
            "received": cwe_id
        }
    
    cwe_number = int(normalized.split("-", 1)[1])
    
    common_cwe = {
        22: {
            "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."
        },
        79: {
            "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "weakness_type": "Class",
            "status": "Incomplete",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page."
        },
        89: {
            "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "weakness_type": "Class",
            "status": "Draft",
            "description": "The software constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements."
        },
        94: {
            "name": "Improper Control of Generation of Code ('Code Injection')",
            "weakness_type": "Class",
            "status": "Incomplete",
            "description": "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment."
        },
        200: {
            "name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "weakness_type": "Class",
            "status": "Stable",
            "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information."
        },
        287: {
            "name": "Improper Authentication",
            "weakness_type": "Class",
            "status": "Draft",
            "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct."
        },
        306: {
            "name": "Missing Authentication for Critical Function",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources."
        },
        311: {
            "name": "Missing Encryption of Sensitive Data",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The product does not encrypt sensitive or critical information before storage or transmission."
        },
        319: {
            "name": "Cleartext Transmission of Sensitive Information",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors."
        },
        352: {
            "name": "Cross-Site Request Forgery (CSRF)",
            "weakness_type": "Compound",
            "status": "Incomplete",
            "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request."
        },
        434: {
            "name": "Unrestricted File Upload with Dangerous Type",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The application allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment."
        },
        502: {
            "name": "Deserialization of Untrusted Data",
            "weakness_type": "Class",
            "status": "Incomplete",
            "description": "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid."
        },
        522: {
            "name": "Insufficiently Protected Credentials",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The product transmits or stores authentication credentials, but uses an insecure method that is susceptible to unauthorized interception and/or retrieval."
        },
        732: {
            "name": "Incorrect Permission Assignment for Critical Resource",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors."
        },
        798: {
            "name": "Use of Hard-coded Credentials",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data."
        },
        918: {
            "name": "Server-Side Request Forgery (SSRF)",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The web server receives a URL or similar request from an upstream component, but the server does not sufficiently ensure that the request is being sent to the expected destination."
        },
        1035: {
            "name": "Insufficient Authorization of DNS Query by Source Port Randomization",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "A device uses an insufficient source port randomization algorithm for DNS queries, making DNS spoofing more likely."
        },
        1174: {
            "name": "Improper Validation of Integrity Check Value",
            "weakness_type": "Base",
            "status": "Draft",
            "description": "The product does not validate or incorrectly validates the integrity check values."
        }
    }
    
    if cwe_number in common_cwe:
        data = common_cwe[cwe_number].copy()
        data["cwe_id"] = normalized
        data["mitre_url"] = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        data["source"] = "vuln-research-mcp local database"
        return data
    else:
        return {
            "cwe_id": normalized,
            "found": False,
            "note": f"本地数据库未收录 {normalized}。",
            "mitre_url": f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",
            "suggestion": "可访问 MITRE CWE 官方数据库获取完整信息。"
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
