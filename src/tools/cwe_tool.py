# src/tools/cwe_tool.py
"""CWE 漏洞类型查询 - 40 条本地数据库 + 在线 MITRE API fallback"""

import logging
import httpx
from ..validators import validate_cwe_id

logger = logging.getLogger("vuln-research-mcp")

# 内置 CWE 数据库（40 条常见漏洞类型，覆盖 OWASP Top 10 + 常见渗透发现）
CWE_DATABASE = {
    20: {"name": "Improper Input Validation", "weakness_type": "Base", "status": "Draft", "description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program."},
    22: {"name": "Path Traversal", "weakness_type": "Base", "status": "Draft", "description": "The software uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize special elements."},
    77: {"name": "Command Injection", "weakness_type": "Class", "status": "Draft", "description": "The software constructs all or part of a command using externally-influenced input, but does not neutralize special elements that could modify the intended command."},
    78: {"name": "OS Command Injection", "weakness_type": "Base", "status": "Draft", "description": "The software constructs all or part of an OS command using externally-influenced input, but does not neutralize special elements."},
    79: {"name": "Cross-site Scripting (XSS)", "weakness_type": "Class", "status": "Incomplete", "description": "The software does not neutralize user-controllable input before placing it in output used as a web page."},
    89: {"name": "SQL Injection", "weakness_type": "Class", "status": "Draft", "description": "The software constructs all or part of an SQL command using externally-influenced input, but does not neutralize special elements."},
    90: {"name": "LDAP Injection", "weakness_type": "Base", "status": "Draft", "description": "The software constructs all or part of an LDAP query using externally-influenced input, but does not neutralize special elements."},
    94: {"name": "Code Injection", "weakness_type": "Class", "status": "Incomplete", "description": "The software constructs all or part of a code segment using externally-influenced input, but does not neutralize special elements."},
    95: {"name": "Eval Injection", "weakness_type": "Base", "status": "Draft", "description": "The software receives input from an upstream component, but it does not sanitize or incorrectly sanitizes special elements before using the input in an evaluation call."},
    98: {"name": "PHP File Inclusion", "weakness_type": "Base", "status": "Draft", "description": "The PHP application receives input from an upstream component, but it does not sanitize or incorrectly sanitizes special elements before using the input in a file inclusion call."},
    100: {"name": "Deprecated: OWASP Top Ten 2004 Category", "weakness_type": "Category", "status": "Deprecated", "description": "Deprecated OWASP Top Ten 2004 entry."},
    113: {"name": "HTTP Response Splitting", "weakness_type": "Base", "status": "Draft", "description": "The software receives data from an HTTP agent/component, but it does not sanitize or incorrectly sanitizes CRLF sequences before including the data in HTTP headers."},
    119: {"name": "Buffer Overflow", "weakness_type": "Base", "status": "Draft", "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location outside the intended boundary."},
    125: {"name": "Out-of-bounds Read", "weakness_type": "Base", "status": "Draft", "description": "The software reads data past the end, or before the beginning, of the intended buffer."},
    190: {"name": "Integer Overflow or Wraparound", "weakness_type": "Base", "status": "Draft", "description": "The software performs a calculation that can produce an integer overflow or wraparound."},
    200: {"name": "Information Exposure", "weakness_type": "Class", "status": "Stable", "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access."},
    209: {"name": "Generation of Error Message Containing Sensitive Information", "weakness_type": "Base", "status": "Draft", "description": "The software generates an error message that includes sensitive information."},
    269: {"name": "Improper Privilege Management", "weakness_type": "Base", "status": "Draft", "description": "The software does not properly assign, modify, track, or check privileges for an actor."},
    287: {"name": "Improper Authentication", "weakness_type": "Class", "status": "Draft", "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct."},
    288: {"name": "Authentication Bypass Using an Alternate Path or Channel", "weakness_type": "Base", "status": "Draft", "description": "A product requires authentication, but the product has an alternate path or channel that does not require authentication."},
    290: {"name": "Authentication Bypass by Spoofing", "weakness_type": "Base", "status": "Draft", "description": "This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks."},
    294: {"name": "Authentication Bypass by Capture-replay", "weakness_type": "Base", "status": "Draft", "description": "A capture-replay flaw exists when it is possible for a malicious user to sniff network traffic and replay it."},
    306: {"name": "Missing Authentication for Critical Function", "weakness_type": "Base", "status": "Draft", "description": "The product does not perform any authentication for functionality that requires a provable user identity."},
    311: {"name": "Missing Encryption of Sensitive Data", "weakness_type": "Base", "status": "Draft", "description": "The product does not encrypt sensitive or critical information before storage or transmission."},
    319: {"name": "Cleartext Transmission of Sensitive Information", "weakness_type": "Base", "status": "Draft", "description": "The product transmits sensitive data in cleartext in a communication channel that can be sniffed."},
    326: {"name": "Inadequate Encryption Strength", "weakness_type": "Base", "status": "Draft", "description": "The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required."},
    327: {"name": "Use of Broken or Risky Cryptographic Algorithm", "weakness_type": "Base", "status": "Draft", "description": "The product uses a broken or risky cryptographic algorithm or protocol."},
    328: {"name": "Use of Weak Hash", "weakness_type": "Base", "status": "Draft", "description": "The product uses a weak cryptographic hash function."},
    352: {"name": "Cross-Site Request Forgery (CSRF)", "weakness_type": "Compound", "status": "Incomplete", "description": "The web application does not sufficiently verify whether a valid request was intentionally provided by the user."},
    400: {"name": "Uncontrolled Resource Consumption", "weakness_type": "Base", "status": "Draft", "description": "The software does not properly control the allocation and maintenance of a limited resource."},
    434: {"name": "Unrestricted File Upload", "weakness_type": "Base", "status": "Draft", "description": "The application allows the attacker to upload or transfer files of dangerous types."},
    444: {"name": "Inconsistent Interpretation of HTTP Requests", "weakness_type": "Base", "status": "Draft", "description": "The software parses HTTP requests but does not consistently interpret the boundaries of the request."},
    451: {"name": "User Interface (UI) Misrepresentation of Critical Information", "weakness_type": "Base", "status": "Draft", "description": "The user interface provides critical information in a way that is misleading or can be misinterpreted."},
    502: {"name": "Deserialization of Untrusted Data", "weakness_type": "Class", "status": "Incomplete", "description": "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid."},
    522: {"name": "Insufficiently Protected Credentials", "weakness_type": "Base", "status": "Draft", "description": "The product transmits or stores authentication credentials using an insecure method."},
    601: {"name": "URL Redirection to Untrusted Site (Open Redirect)", "weakness_type": "Base", "status": "Draft", "description": "A web application accepts a user-controlled input that specifies a link to an external site."},
    611: {"name": "Improper Restriction of XML External Entity Reference", "weakness_type": "Base", "status": "Draft", "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control."},
    639: {"name": "Authorization Bypass Through User-Controlled Key", "weakness_type": "Base", "status": "Draft", "description": "The system's authorization functionality does not prevent one user from gaining access to another user's data by modifying the key value."},
    732: {"name": "Incorrect Permission Assignment for Critical Resource", "weakness_type": "Base", "status": "Draft", "description": "The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors."},
    798: {"name": "Use of Hard-coded Credentials", "weakness_type": "Base", "status": "Draft", "description": "The product contains hard-coded credentials, such as a password or cryptographic key."},
    862: {"name": "Missing Authorization", "weakness_type": "Base", "status": "Draft", "description": "The product does not perform an authorization check when an actor attempts to access a resource."},
    863: {"name": "Incorrect Authorization", "weakness_type": "Base", "status": "Draft", "description": "The product performs an authorization check, but the check is incorrect."},
    918: {"name": "Server-Side Request Forgery (SSRF)", "weakness_type": "Base", "status": "Draft", "description": "The web server receives a URL or similar request from an upstream component, but the server does not sufficiently ensure that the request is being sent to the expected destination."},
}


async def _query_mitre_cwe_online(cwe_number: int) -> dict | None:
    """在线查询 MITRE CWE API（fallback）"""
    try:
        async with httpx.AsyncClient() as client:
            url = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
            response = await client.get(url, timeout=10.0, follow_redirects=True)
            if response.status_code == 200:
                # MITRE 页面没有 JSON API，但能确认条目存在
                text = response.text
                # 提取标题
                title_start = text.find("<title>")
                title_end = text.find("</title>")
                title = text[title_start+7:title_end].strip() if title_start > 0 else f"CWE-{cwe_number}"
                return {
                    "cwe_id": f"CWE-{cwe_number}",
                    "name": title.replace(f"CWE-{cwe_number}:", "").strip(),
                    "mitre_url": url,
                    "source": "MITRE CWE (online)",
                    "found": True,
                    "note": "本地数据库未收录此条目，已从 MITRE 在线查询。",
                }
    except Exception as e:
        logger.warning(f"MITRE CWE 在线查询失败: {e}")
    return None


async def cwe_mapping(cwe_id: str) -> dict:
    """查询 CWE 信息（本地 40 条优先 + 在线 MITRE fallback）"""
    cwe_id = validate_cwe_id(cwe_id)
    cwe_number = int(cwe_id.split("-", 1)[1])

    # 1. 先查本地数据库
    if cwe_number in CWE_DATABASE:
        data = CWE_DATABASE[cwe_number].copy()
        data["cwe_id"] = cwe_id
        data["mitre_url"] = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        data["source"] = "local database (40 entries)"
        return data

    # 2. 本地没有，在线查 MITRE
    online_result = await _query_mitre_cwe_online(cwe_number)
    if online_result:
        return online_result

    # 3. 在线也失败
    return {
        "cwe_id": cwe_id,
        "found": False,
        "note": f"本地数据库（{len(CWE_DATABASE)} 条）和 MITRE 在线查询均未找到 {cwe_id}。",
        "mitre_url": f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",
        "suggestion": "请访问 MITRE CWE 官方数据库手动查询。",
    }
