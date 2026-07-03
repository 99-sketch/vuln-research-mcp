# src/tools/cwe_tool.py
"""CWE 漏洞类型查询"""

import re
from ..validators import validate_cwe_id

# 内置 CWE 数据库（20 条常见漏洞类型）
CWE_DATABASE = {
    22: {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
    },
    78: {
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The software constructs all or part of an OS command using externally-influenced input, but does not neutralize special elements that could modify the intended OS command.",
    },
    79: {
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "weakness_type": "Class",
        "status": "Incomplete",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.",
    },
    89: {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "weakness_type": "Class",
        "status": "Draft",
        "description": "The software constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements.",
    },
    94: {
        "name": "Improper Control of Generation of Code ('Code Injection')",
        "weakness_type": "Class",
        "status": "Incomplete",
        "description": "The software constructs all or part of a code segment using externally-influenced input, but does not neutralize special elements that could modify the syntax or behavior of the intended code segment.",
    },
    125: {
        "name": "Out-of-bounds Read",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The software reads data past the end, or before the beginning, of the intended buffer.",
    },
    119: {
        "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
    },
    200: {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "weakness_type": "Class",
        "status": "Stable",
        "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access.",
    },
    287: {
        "name": "Improper Authentication",
        "weakness_type": "Class",
        "status": "Draft",
        "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
    },
    306: {
        "name": "Missing Authentication for Critical Function",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
    },
    311: {
        "name": "Missing Encryption of Sensitive Data",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The product does not encrypt sensitive or critical information before storage or transmission.",
    },
    319: {
        "name": "Cleartext Transmission of Sensitive Information",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
    },
    327: {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The product uses a broken or risky cryptographic algorithm or protocol.",
    },
    352: {
        "name": "Cross-Site Request Forgery (CSRF)",
        "weakness_type": "Compound",
        "status": "Incomplete",
        "description": "The web application does not sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user.",
    },
    434: {
        "name": "Unrestricted File Upload with Dangerous Type",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The application allows the attacker to upload or transfer files of dangerous types that can be automatically processed.",
    },
    502: {
        "name": "Deserialization of Untrusted Data",
        "weakness_type": "Class",
        "status": "Incomplete",
        "description": "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
    },
    522: {
        "name": "Insufficiently Protected Credentials",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The product transmits or stores authentication credentials, but uses an insecure method that is susceptible to unauthorized interception.",
    },
    798: {
        "name": "Use of Hard-coded Credentials",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication, or encryption of internal data.",
    },
    862: {
        "name": "Missing Authorization",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The product does not perform an authorization check when an actor attempts to access a resource or perform an action.",
    },
    918: {
        "name": "Server-Side Request Forgery (SSRF)",
        "weakness_type": "Base",
        "status": "Draft",
        "description": "The web server receives a URL or similar request from an upstream component, but the server does not sufficiently ensure that the request is being sent to the expected destination.",
    },
}


async def cwe_mapping(cwe_id: str) -> dict:
    """查询 CWE 信息"""
    cwe_id = validate_cwe_id(cwe_id)
    cwe_number = int(cwe_id.split("-", 1)[1])

    if cwe_number in CWE_DATABASE:
        data = CWE_DATABASE[cwe_number].copy()
        data["cwe_id"] = cwe_id
        data["mitre_url"] = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        data["source"] = "vuln-research-mcp local database"
        return data
    else:
        return {
            "cwe_id": cwe_id,
            "found": False,
            "note": f"本地数据库未收录 {cwe_id}（共收录 {len(CWE_DATABASE)} 条）。",
            "mitre_url": f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",
            "suggestion": "可访问 MITRE CWE 官方数据库获取完整信息。",
        }
