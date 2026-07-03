#!/usr/bin/env python3
"""CPE 工具 — 产品指纹匹配 + 服务 Banner 识别"""

import logging

logger = logging.getLogger("vuln-research-mcp")

# 常见产品 → CPE 映射表
CPE_PRODUCT_MAP = {
    "apache": "cpe:2.3:a:apache",
    "nginx": "cpe:2.3:a:nginx",
    "tomcat": "cpe:2.3:a:apache:tomcat",
    "log4j": "cpe:2.3:a:apache:log4j",
    "log4j2": "cpe:2.3:a:apache:log4j",
    "openssh": "cpe:2.3:a:openbsd:openssh",
    "openssl": "cpe:2.3:a:openssl:openssl",
    "mysql": "cpe:2.3:a:oracle:mysql",
    "mariadb": "cpe:2.3:a:mariadb:mariadb",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "redis": "cpe:2.3:a:redis:redis",
    "mongodb": "cpe:2.3:a:mongodb:mongodb",
    "node.js": "cpe:2.3:a:nodejs:node.js",
    "python": "cpe:2.3:a:python:python",
    "django": "cpe:2.3:a:djangoproject:django",
    "flask": "cpe:2.3:a:palletsprojects:flask",
    "spring": "cpe:2.3:a:vmware:spring_framework",
    "struts": "cpe:2.3:a:apache:struts",
    "jquery": "cpe:2.3:a:jquery:jquery",
    "wordpress": "cpe:2.3:a:wordpress:wordpress",
    "joomla": "cpe:2.3:a:joomla:joomla",
    "drupal": "cpe:2.3:a:drupal:drupal",
    "jenkins": "cpe:2.3:a:jenkins:jenkins",
    "kubernetes": "cpe:2.3:a:kubernetes:kubernetes",
    "docker": "cpe:2.3:a:docker:docker",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    "kibana": "cpe:2.3:a:elastic:kibana",
    "grafana": "cpe:2.3:a:grafana:grafana",
    "gitlab": "cpe:2.3:a:gitlab:gitlab",
    "vscode": "cpe:2.3:a:microsoft:visual_studio_code",
    "iis": "cpe:2.3:a:microsoft:iis",
    "exchange": "cpe:2.3:a:microsoft:exchange_server",
    "windows": "cpe:2.3:o:microsoft:windows",
    "linux": "cpe:2.3:o:linux:linux_kernel",
    "php": "cpe:2.3:a:php:php",
}

# Banner 指纹识别模式
SERVICE_PATTERNS = [
    ("OpenSSH", r"OpenSSH[_ ]([\d.]+[a-z]*)", "ssh"),
    ("Apache httpd", r"Apache/([\d.]+)", "http"),
    ("nginx", r"nginx/([\d.]+)", "http"),
    ("Tomcat", r"Apache Tomcat/([\d.]+)", "http"),
    ("IIS", r"Microsoft-IIS/([\d.]+)", "http"),
    ("PHP", r"PHP/([\d.]+)", "http"),
    ("MySQL", r"MySQL[ -]([\d.]+)", "database"),
    ("MariaDB", r"MariaDB[ -]([\d.]+)", "database"),
    ("PostgreSQL", r"PostgreSQL[ -]([\d.]+)", "database"),
    ("Redis", r"redis_version:([\d.]+)", "database"),
    ("MongoDB", r"MongoDB[ -]([\d.]+)", "database"),
    ("ProFTPD", r"ProFTPD[ -]([\d.]+)", "ftp"),
    ("vsftpd", r"vsftpd[ -]([\d.]+)", "ftp"),
    ("Sendmail", r"Sendmail[ -]([\d.]+)", "smtp"),
    ("Postfix", r"Postfix[ -]([\d.]+)", "smtp"),
    ("Exim", r"Exim[ -]([\d.]+)", "smtp"),
    ("Bind", r"BIND[ -]([\d.]+)", "dns"),
]


async def cpe_lookup(product: str) -> dict:
    """产品名 → CPE 字符串匹配"""
    import re
    product_lower = product.lower().strip()

    matches = []
    for key, cpe in CPE_PRODUCT_MAP.items():
        if key in product_lower or product_lower in key:
            matches.append({"product": key, "cpe": cpe})

    # 如果没有精确匹配，尝试模糊匹配
    if not matches:
        for key, cpe in CPE_PRODUCT_MAP.items():
            if any(word in product_lower for word in key.split()):
                matches.append({"product": key, "cpe": cpe})

    return {
        "query": product,
        "matches": matches[:20],
        "total": len(matches),
    }


async def service_fingerprint(banner: str) -> dict:
    """从 Banner 文本提取服务指纹"""
    import re

    results = []
    for name, pattern, category in SERVICE_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            results.append({
                "service": name,
                "version": m.group(1),
                "category": category,
            })

    return {
        "banner": banner[:500],
        "identified_services": results,
        "total": len(results),
    }


async def cpe_to_cve_search(cpe_string: str, max_results: int = 20) -> dict:
    """CPE → CVE 搜索"""
    try:
        from src.tools.cve_tools import search_cve
        keyword = cpe_string.split(":")[-1] if ":" in cpe_string else cpe_string
        return await search_cve(keyword=keyword, max_results=max_results)
    except Exception as e:
        return {"error": str(e), "cpe": cpe_string}
