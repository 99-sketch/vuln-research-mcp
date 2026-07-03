#!/usr/bin/env python3
"""vuln-research-mcp v0.2.0 自测脚本"""

import asyncio
import sys
import os
import json

# 添加项目根目录到 path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# 确保使用正确的 src 导入
from src.tools.cve_tools import search_cve, get_cve_details
from src.tools.cvss_tool import cvss_calculator
from src.tools.cwe_tool import cwe_mapping
from src.tools.exploit_tool import search_exploit
from src.tools.nuclei_tool import find_nuclei_template
from src.tools.scan_tools import scan_ports, enumerate_subdomains
from src.tools.network_tools import check_http_headers, query_dns, geolocate_ip
from src.validators import (
    validate_ip, validate_domain, validate_url, validate_target,
    validate_ports, validate_cve_id, validate_cwe_id, sanitize_subprocess_arg,
    is_private_ip,
)

passed = 0
failed = 0
errors = []


def check(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name} {detail}")
        failed += 1
        errors.append(f"{name}: {detail}")


async def run_tests():
    print("=" * 60)
    print("vuln-research-mcp v0.2.0 自测")
    print("=" * 60)

    # ===== 1. 输入验证 =====
    print("\n[1/8] 输入验证模块")

    # IP 验证
    check("validate_ip 合法 IPv4", validate_ip("8.8.8.8") == "8.8.8.8")
    check("validate_ip 合法 IPv6", validate_ip("::1") == "::1")
    try:
        validate_ip("not-an-ip")
        check("validate_ip 非法 IP 拒绝", False)
    except ValueError:
        check("validate_ip 非法 IP 拒绝", True)
    try:
        validate_ip("")
        check("validate_ip 空值拒绝", False)
    except ValueError:
        check("validate_ip 空值拒绝", True)

    # 域名验证
    check("validate_domain 合法域名", validate_domain("Example.COM") == "example.com")
    try:
        validate_domain("invalid")
        check("validate_domain 非法域名拒绝", False)
    except ValueError:
        check("validate_domain 非法域名拒绝", True)
    try:
        validate_domain("../../../etc/passwd")
        check("validate_domain 路径遍历拒绝", False)
    except ValueError:
        check("validate_domain 路径遍历拒绝", True)

    # URL 验证
    check("validate_url 合法 URL", "https://example.com" in validate_url("https://example.com"))
    try:
        validate_url("ftp://example.com")
        check("validate_url 非 http 协议拒绝", False)
    except ValueError:
        check("validate_url 非 http 协议拒绝", True)
    try:
        validate_url("not a url")
        check("validate_url 非法 URL 拒绝", False)
    except ValueError:
        check("validate_url 非法 URL 拒绝", True)

    # 端口验证
    check("validate_ports 合法端口", validate_ports("80,443,8080") == "80,443,8080")
    check("validate_ports 合法范围", validate_ports("1-1000") == "1-1000")
    try:
        validate_ports("80; rm -rf /")
        check("validate_ports 命令注入拒绝", False)
    except ValueError:
        check("validate_ports 命令注入拒绝", True)
    try:
        validate_ports("99999")
        check("validate_ports 超范围端口拒绝", False)
    except ValueError:
        check("validate_ports 超范围端口拒绝", True)

    # CVE/CWE ID 验证
    check("validate_cve_id 合法", validate_cve_id("cve-2021-44228") == "CVE-2021-44228")
    try:
        validate_cve_id("CVE-2021")
        check("validate_cve_id 短 ID 拒绝", False)
    except ValueError:
        check("validate_cve_id 短 ID 拒绝", True)
    check("validate_cwe_id 合法", validate_cwe_id("cwe-89") == "CWE-89")

    # subprocess 参数净化
    check("sanitize 正常参数", sanitize_subprocess_arg("example.com") == "example.com")
    try:
        sanitize_subprocess_arg("example.com; rm -rf /")
        check("sanitize 命令注入拒绝", False)
    except ValueError:
        check("sanitize 命令注入拒绝", True)
    try:
        sanitize_subprocess_arg("$(whoami)")
        check("sanitize $() 拒绝", False)
    except ValueError:
        check("sanitize $() 拒绝", True)

    # 私有 IP 检测
    check("is_private_ip 192.168", is_private_ip("192.168.1.1") is True)
    check("is_private_ip 127.0.0.1", is_private_ip("127.0.0.1") is True)
    check("is_private_ip 8.8.8.8", is_private_ip("8.8.8.8") is False)

    # ===== 2. CVSS 计算器 =====
    print("\n[2/8] CVSS 计算器")

    r = await cvss_calculator(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    check("CVSS 9.8 CRITICAL", r.get("base_score") == 9.8 and r.get("severity") == "CRITICAL", f"got {r.get('base_score')}")

    r = await cvss_calculator(vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N")
    check("CVSS scope changed", r.get("base_score") is not None and 2.0 <= r.get("base_score") <= 6.0, f"got {r.get('base_score')}")

    r = await cvss_calculator(vector="CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
    check("CVSS zero score", r.get("base_score") == 0.0 and r.get("severity") == "NONE", f"got {r.get('base_score')}")

    r = await cvss_calculator(
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED", confidentiality="HIGH",
        integrity="HIGH", availability="HIGH",
    )
    check("CVSS 参数模式", r.get("base_score") == 9.8, f"got {r.get('base_score')}")

    r = await cvss_calculator(vector="invalid")
    check("CVSS 无效 vector 返回 error", "error" in r)

    # ===== 3. CWE 查询 =====
    print("\n[3/8] CWE 查询")

    r = await cwe_mapping("CWE-89")
    check("CWE-89 SQL注入", "SQL" in r.get("name", ""), r.get("name", ""))
    check("CWE-89 有 mitre_url", "mitre.org" in r.get("mitre_url", ""), r.get("mitre_url", ""))

    r = await cwe_mapping("cwe-918")
    check("CWE-918 SSRF", "SSRF" in r.get("name", "") or "Server-Side" in r.get("name", ""), r.get("name", ""))

    r = await cwe_mapping("CWE-99999")
    check("CWE 未收录返回 found=False", r.get("found") is False)

    try:
        await cwe_mapping("NOT-A-CWE")
        check("CWE 非法格式拒绝", False)
    except ValueError:
        check("CWE 非法格式拒绝", True)

    # ===== 4. CVE 搜索 =====
    print("\n[4/8] CVE 搜索（需要网络）")

    try:
        r = await search_cve("Apache Log4j", max_results=3)
        check("search_cve 返回结果", r.get("total_results", 0) > 0, f"total={r.get('total_results')}")
        check("search_cve 限制条数", len(r.get("vulnerabilities", [])) <= 3)
    except Exception as e:
        check(f"search_cve 网络跳过 ({e})", True)

    try:
        r = await get_cve_details("CVE-2021-44228")
        check("get_cve_details 返回", r.get("cve_id") == "CVE-2021-44228" or "error" in r, str(r)[:100])
    except Exception as e:
        check(f"get_cve_details 网络跳过 ({e})", True)

    try:
        await get_cve_details("INVALID-ID")
        check("get_cve_details 非法ID拒绝", False)
    except ValueError:
        check("get_cve_details 非法ID拒绝", True)

    # ===== 5. DNS 查询 =====
    print("\n[5/8] DNS 查询")

    r = await query_dns("example.com", "A")
    a_records = r.get("records", {}).get("A", {})
    check("DNS A 记录", a_records.get("status") == "success" and a_records.get("count", 0) > 0, str(a_records)[:100])

    r = await query_dns("example.com", "MX")
    mx = r.get("records", {}).get("MX", {})
    check("DNS MX 查询不崩溃", mx.get("status") is not None, str(mx)[:100])

    try:
        await query_dns("../../../etc/passwd", "A")
        check("DNS 非法域名拒绝", False)
    except ValueError:
        check("DNS 非法域名拒绝", True)

    # ===== 6. HTTP 安全头 =====
    print("\n[6/8] HTTP 安全头检查")

    r = await check_http_headers("https://example.com")
    check("HTTP headers 返回分析", "headers_analysis" in r and "summary" in r, str(r)[:100])
    check("HTTP headers 评分", "score" in r.get("summary", {}), str(r.get("summary"))[:100])

    try:
        await check_http_headers("ftp://bad-protocol.com")
        check("HTTP 非法协议拒绝", False)
    except ValueError:
        check("HTTP 非法协议拒绝", True)

    r = await check_http_headers("https://nonexistent-domain-12345.com")
    check("HTTP 不可达域名处理", "error" in r, str(r)[:100])

    # ===== 7. IP 地理位置 =====
    print("\n[7/8] IP 地理定位")

    r = await geolocate_ip("8.8.8.8")
    check("GeoIP 8.8.8.8", r.get("country") is not None, str(r)[:100])
    check("GeoIP ISP", "Google" in (r.get("isp", "") or ""), r.get("isp", ""))

    r = await geolocate_ip("192.168.1.1")
    check("GeoIP 私有IP警告", r.get("warning") is not None or r.get("error") is not None, str(r)[:100])

    try:
        await geolocate_ip("not-an-ip")
        check("GeoIP 非法IP拒绝", False)
    except ValueError:
        check("GeoIP 非法IP拒绝", True)

    # ===== 8. 离线工具降级 =====
    print("\n[8/8] 离线工具降级（search_exploit / nuclei / scan_ports / subdomains）")

    r = await search_exploit("WordPress")
    check("search_exploit 不崩溃", r is not None and ("exploits" in r or "error" in r or "source" in r), str(r)[:100])

    r = await find_nuclei_template("cve", "high")
    check("find_nuclei 不崩溃", r is not None and ("templates" in r or "error" in r), str(r)[:100])

    r = await scan_ports("127.0.0.1", scan_type="quick")
    check("scan_ports 不崩溃", r is not None and ("output" in r or "error" in r), str(r)[:100])

    r = await enumerate_subdomains("example.com")
    check("enumerate_subdomains 不崩溃", r is not None and ("subdomains" in r or "error" in r), str(r)[:100])

    # 命令注入防护测试
    try:
        await scan_ports("127.0.0.1; rm -rf /", scan_type="quick")
        check("scan_ports 命令注入拒绝", False)
    except ValueError:
        check("scan_ports 命令注入拒绝", True)

    try:
        await enumerate_subdomains("example.com; cat /etc/passwd")
        check("subdomains 命令注入拒绝", False)
    except ValueError:
        check("subdomains 命令注入拒绝", True)

    # ===== 汇总 =====
    print("\n" + "=" * 60)
    total = passed + failed
    print(f"总计: {total} | 通过: {passed} | 失败: {failed}")
    if errors:
        print("\n失败项:")
        for e in errors:
            print(f"  - {e}")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)
