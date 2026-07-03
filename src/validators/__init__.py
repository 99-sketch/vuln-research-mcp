# src/validators/__init__.py
"""输入验证模块 - 防止命令注入、SSRF、格式校验"""

import re
import ipaddress
from urllib.parse import urlparse


def validate_ip(ip: str) -> str:
    """验证 IP 地址格式，返回规范化 IP 或抛出 ValueError"""
    if not ip or not isinstance(ip, str):
        raise ValueError("IP 地址不能为空")
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValueError(f"无效的 IP 地址: {ip}")


def validate_domain(domain: str) -> str:
    """验证域名格式，返回规范化域名或抛出 ValueError"""
    if not domain or not isinstance(domain, str):
        raise ValueError("域名不能为空")
    domain = domain.strip().lower()
    # 域名格式：labels 用 . 分隔，每段 1-63 字符，只能含字母数字和连字符
    pattern = r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    if not re.match(pattern, domain):
        raise ValueError(f"无效的域名: {domain}")
    return domain


def validate_url(url: str) -> str:
    """验证 URL 格式，返回规范化 URL 或抛出 ValueError"""
    if not url or not isinstance(url, str):
        raise ValueError("URL 不能为空")
    url = url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        raise ValueError(f"URL 必须包含协议 (http/https): {url}")
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"只支持 http/https 协议: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError(f"URL 必须包含主机名: {url}")
    return url


def is_private_ip(ip: str) -> bool:
    """检查是否为内网/私有 IP 地址"""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True  # 无效 IP 视为私有（安全侧）


def validate_target(target: str) -> str:
    """验证扫描目标（IP 或域名），返回规范化目标或抛出 ValueError"""
    if not target or not isinstance(target, str):
        raise ValueError("目标不能为空")
    target = target.strip()
    # 尝试作为 IP 验证
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    # 作为域名验证
    return validate_domain(target)


def validate_ports(ports: str) -> str:
    """验证端口范围字符串格式"""
    if not ports:
        return ""
    ports = ports.strip()
    # 允许格式：80  或  80,443,8080  或  1-1000  或  80,443,1000-2000
    pattern = r'^(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?)*$'
    if not re.match(pattern, ports):
        raise ValueError(f"无效的端口格式: {ports}（示例: 80,443 或 1-1000）")
    # 校验端口范围
    for part in ports.split(','):
        nums = part.split('-')
        for n in nums:
            port = int(n)
            if port < 1 or port > 65535:
                raise ValueError(f"端口超出范围 (1-65535): {port}")
        if len(nums) == 2 and int(nums[0]) > int(nums[1]):
            raise ValueError(f"端口范围无效（起始 > 结束）: {part}")
    return ports


def validate_cve_id(cve_id: str) -> str:
    """验证 CVE ID 格式"""
    if not cve_id or not isinstance(cve_id, str):
        raise ValueError("CVE ID 不能为空")
    cve_id = cve_id.strip().upper()
    pattern = r'^CVE-\d{4}-\d{4,7}$'
    if not re.match(pattern, cve_id):
        raise ValueError(f"无效的 CVE ID: {cve_id}（格式: CVE-2021-44228）")
    return cve_id


def validate_cwe_id(cwe_id: str) -> str:
    """验证 CWE ID 格式"""
    if not cwe_id or not isinstance(cwe_id, str):
        raise ValueError("CWE ID 不能为空")
    cwe_id = cwe_id.strip().upper()
    pattern = r'^CWE-\d{1,6}$'
    if not re.match(pattern, cwe_id):
        raise ValueError(f"无效的 CWE ID: {cwe_id}（格式: CWE-89）")
    return cwe_id


def sanitize_subprocess_arg(arg: str) -> str:
    """净化 subprocess 参数 - 防止命令注入
    
    只允许字母、数字、点、连字符、下划线、斜杠、冒号
    任何 shell 元字符都直接拒绝
    """
    if not arg:
        raise ValueError("参数不能为空")
    # 允许的字符：字母数字 . - _ / : 和端口格式
    if not re.match(r'^[a-zA-Z0-9._\-/:,]+$', arg):
        raise ValueError(f"参数包含非法字符: {arg}")
    # 检查是否有常见的注入模式
    dangerous_patterns = ['..', '&&', '||', ';', '|', '`', '$', '()', '{}', '\n', '\r']
    lowered = arg.lower()
    for pattern in dangerous_patterns:
        if pattern in lowered:
            raise ValueError(f"参数包含危险模式: {pattern}")
    return arg
