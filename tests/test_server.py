"""
vuln-research-mcp v1.0.0 测试套件 (pytest)
覆盖全部 11 个工具 + 输入验证 + 安全防护 + 版本检测
"""

import asyncio
import sys
import os
import json
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.validators import (
    validate_ip, validate_domain, validate_url, validate_target,
    validate_ports, validate_cve_id, validate_cwe_id, sanitize_subprocess_arg,
    is_private_ip,
)
from src.tools.cvss_tool import cvss_calculator, _compute_cvss_v3_1
from src.tools.cwe_tool import cwe_mapping, CWE_DATABASE
from src.tools.cve_tools import search_cve, get_cve_details
from src.tools.network_tools import check_http_headers, query_dns, geolocate_ip
from src.tools.exploit_tool import search_exploit, _check_searchsploit
from src.tools.nuclei_tool import find_nuclei_template
from src.tools.scan_tools import scan_ports, enumerate_subdomains, _check_tool_version
from src.tools.poc_archive_tool import search_poc_archive, list_poc_archive, clone_archive, update_archive
from src.rate_limiter import NVD_API_KEY


# ========== 输入验证 (22 项) ==========

class TestInputValidation:

    def test_validate_ip_valid_v4(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    def test_validate_ip_valid_v6(self):
        assert validate_ip("::1") == "::1"

    def test_validate_ip_invalid(self):
        with pytest.raises(ValueError):
            validate_ip("not-an-ip")

    def test_validate_ip_empty(self):
        with pytest.raises(ValueError):
            validate_ip("")

    def test_validate_domain_valid(self):
        assert validate_domain("Example.COM") == "example.com"

    def test_validate_domain_invalid(self):
        with pytest.raises(ValueError):
            validate_domain("invalid")

    def test_validate_domain_path_traversal(self):
        with pytest.raises(ValueError):
            validate_domain("../../../etc/passwd")

    def test_validate_url_valid(self):
        assert "https://example.com" in validate_url("https://example.com")

    def test_validate_url_rejects_ftp(self):
        with pytest.raises(ValueError):
            validate_url("ftp://example.com")

    def test_validate_url_rejects_garbage(self):
        with pytest.raises(ValueError):
            validate_url("not a url")

    def test_validate_ports_valid_list(self):
        assert validate_ports("80,443,8080") == "80,443,8080"

    def test_validate_ports_valid_range(self):
        assert validate_ports("1-1000") == "1-1000"

    def test_validate_ports_rejects_injection(self):
        with pytest.raises(ValueError):
            validate_ports("80; rm -rf /")

    def test_validate_ports_rejects_out_of_range(self):
        with pytest.raises(ValueError):
            validate_ports("99999")

    def test_validate_cve_id_valid(self):
        assert validate_cve_id("cve-2021-44228") == "CVE-2021-44228"

    def test_validate_cve_id_short(self):
        with pytest.raises(ValueError):
            validate_cve_id("CVE-2021")

    def test_validate_cwe_id_valid(self):
        assert validate_cwe_id("cwe-89") == "CWE-89"

    def test_sanitize_normal(self):
        assert sanitize_subprocess_arg("example.com") == "example.com"

    def test_sanitize_rejects_semicolon(self):
        with pytest.raises(ValueError):
            sanitize_subprocess_arg("example.com; rm -rf /")

    def test_sanitize_rejects_dollar(self):
        with pytest.raises(ValueError):
            sanitize_subprocess_arg("$(whoami)")

    def test_is_private_192168(self):
        assert is_private_ip("192.168.1.1") is True

    def test_is_private_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_is_private_public(self):
        assert is_private_ip("8.8.8.8") is False


# ========== CVSS 计算器 (5 项) ==========

class TestCVSS:

    @pytest.mark.asyncio
    async def test_cvss_98_critical(self):
        r = await cvss_calculator(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r["base_score"] == 9.8
        assert r["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_cvss_scope_changed(self):
        r = await cvss_calculator(vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N")
        assert r["base_score"] is not None
        assert 2.0 <= r["base_score"] <= 6.0

    @pytest.mark.asyncio
    async def test_cvss_zero(self):
        r = await cvss_calculator(vector="CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
        assert r["base_score"] == 0.0
        assert r["severity"] == "NONE"

    @pytest.mark.asyncio
    async def test_cvss_params_mode(self):
        r = await cvss_calculator(
            attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
            user_interaction="NONE", scope="UNCHANGED", confidentiality="HIGH",
            integrity="HIGH", availability="HIGH",
        )
        assert r["base_score"] == 9.8

    @pytest.mark.asyncio
    async def test_cvss_invalid_vector(self):
        r = await cvss_calculator(vector="invalid")
        assert "error" in r


# ========== CWE 查询 (6 项) ==========

class TestCWE:

    @pytest.mark.asyncio
    async def test_cwe_89_sql(self):
        r = await cwe_mapping("CWE-89")
        assert "SQL" in r["name"]

    @pytest.mark.asyncio
    async def test_cwe_89_mitre_url(self):
        r = await cwe_mapping("CWE-89")
        assert "mitre.org" in r["mitre_url"]

    @pytest.mark.asyncio
    async def test_cwe_918_ssrf(self):
        r = await cwe_mapping("cwe-918")
        assert "SSRF" in r["name"] or "Server-Side" in r["name"]

    @pytest.mark.asyncio
    async def test_cwe_611_xxe(self):
        r = await cwe_mapping("CWE-611")
        assert "XML" in r["name"]

    @pytest.mark.asyncio
    async def test_cwe_not_found_local(self):
        """本地没有但应尝试在线 fallback"""
        r = await cwe_mapping("CWE-999")
        # 在线 fallback 可能成功也可能失败，但不应崩溃
        assert r is not None
        assert "cwe_id" in r or "found" in r

    @pytest.mark.asyncio
    async def test_cwe_invalid_format(self):
        with pytest.raises(ValueError):
            await cwe_mapping("NOT-A-CWE")

    def test_cwe_database_size(self):
        """CWE 数据库至少 40 条"""
        assert len(CWE_DATABASE) >= 40


# ========== CVE 搜索 (4 项) ==========

class TestCVE:

    @pytest.mark.asyncio
    async def test_search_cve_returns_results(self):
        r = await search_cve("Apache Log4j", max_results=3)
        assert r["total_results"] > 0

    @pytest.mark.asyncio
    async def test_search_cve_limits_results(self):
        r = await search_cve("Apache Log4j", max_results=3)
        assert len(r["vulnerabilities"]) <= 3

    @pytest.mark.asyncio
    async def test_search_cve_reports_api_key_status(self):
        """搜索结果应包含 API Key 使用状态"""
        r = await search_cve("Apache", max_results=1)
        assert "api_key_used" in r
        assert "rate_limit" in r

    @pytest.mark.asyncio
    async def test_get_cve_invalid_id(self):
        with pytest.raises(ValueError):
            await get_cve_details("INVALID-ID")


# ========== DNS 查询 (3 项) ==========

class TestDNS:

    @pytest.mark.asyncio
    async def test_dns_a_record(self):
        r = await query_dns("example.com", "A")
        a = r["records"]["A"]
        assert a["status"] == "success"
        assert a["count"] > 0

    @pytest.mark.asyncio
    async def test_dns_mx_no_crash(self):
        r = await query_dns("example.com", "MX")
        assert "records" in r

    @pytest.mark.asyncio
    async def test_dns_invalid_domain(self):
        with pytest.raises(ValueError):
            await query_dns("../../../etc/passwd", "A")


# ========== HTTP 安全头 (4 项) ==========

class TestHTTPHeaders:

    @pytest.mark.asyncio
    async def test_returns_analysis(self):
        r = await check_http_headers("https://example.com")
        assert "headers_analysis" in r
        assert "summary" in r

    @pytest.mark.asyncio
    async def test_score_present(self):
        r = await check_http_headers("https://example.com")
        assert "score" in r["summary"]

    @pytest.mark.asyncio
    async def test_rejects_ftp(self):
        with pytest.raises(ValueError):
            await check_http_headers("ftp://bad-protocol.com")

    @pytest.mark.asyncio
    async def test_unreachable_domain(self):
        r = await check_http_headers("https://nonexistent-domain-12345.com")
        assert "error" in r


# ========== IP 地理定位 (4 项) ==========

class TestGeoIP:

    @pytest.mark.asyncio
    async def test_8888(self):
        r = await geolocate_ip("8.8.8.8")
        assert r.get("country") is not None

    @pytest.mark.asyncio
    async def test_isp(self):
        r = await geolocate_ip("8.8.8.8")
        assert "Google" in (r.get("isp") or "")

    @pytest.mark.asyncio
    async def test_private_ip_warning(self):
        r = await geolocate_ip("192.168.1.1")
        assert r.get("warning") is not None or r.get("error") is not None

    @pytest.mark.asyncio
    async def test_invalid_ip(self):
        with pytest.raises(ValueError):
            await geolocate_ip("not-an-ip")


# ========== Exploit 搜索 + 版本检测 (4 项) ==========

class TestExploitSearch:

    @pytest.mark.asyncio
    async def test_search_exploit_no_crash(self):
        r = await search_exploit("WordPress")
        assert r is not None
        assert "exploits" in r or "error" in r or "source" in r

    @pytest.mark.asyncio
    async def test_search_exploit_empty_query(self):
        with pytest.raises(ValueError):
            await search_exploit("")

    def test_check_searchsploit_installed(self):
        """版本检测不应崩溃"""
        result = _check_searchsploit()
        assert "installed" in result
        assert isinstance(result["installed"], bool)

    @pytest.mark.asyncio
    async def test_search_exploit_type_filter(self):
        r = await search_exploit("Apache", type_filter="remote")
        assert r is not None


# ========== Nuclei 模板搜索 (3 项) ==========

class TestNucleiSearch:

    @pytest.mark.asyncio
    async def test_find_nuclei_no_crash(self):
        r = await find_nuclei_template("cve", "high")
        assert r is not None
        assert "templates" in r or "error" in r

    @pytest.mark.asyncio
    async def test_find_nuclei_empty_tags(self):
        with pytest.raises(ValueError):
            await find_nuclei_template("")

    @pytest.mark.asyncio
    async def test_find_nuclei_invalid_severity(self):
        with pytest.raises(ValueError):
            await find_nuclei_template("cve", "super-critical")


# ========== 端口扫描 + 版本检测 (5 项) ==========

class TestScanPorts:

    @pytest.mark.asyncio
    async def test_scan_ports_no_crash(self):
        """即使 nmap 未安装也不应崩溃"""
        r = await scan_ports("127.0.0.1", scan_type="quick")
        assert r is not None
        assert "output" in r or "error" in r

    @pytest.mark.asyncio
    async def test_scan_ports_injection_rejected(self):
        with pytest.raises(ValueError):
            await scan_ports("127.0.0.1; rm -rf /", scan_type="quick")

    @pytest.mark.asyncio
    async def test_scan_ports_invalid_type(self):
        """无效扫描类型应回退到 quick"""
        r = await scan_ports("127.0.0.1", scan_type="invalid-type")
        assert r is not None  # 不崩溃，回退到 quick

    def test_check_tool_version_nmap(self):
        """版本检测不应崩溃"""
        result = _check_tool_version("nmap")
        assert "installed" in result
        assert isinstance(result["installed"], bool)

    def test_check_tool_version_nonexistent(self):
        """不存在的工具应返回 installed=False"""
        result = _check_tool_version("nonexistent-tool-xyz")
        assert result["installed"] is False


# ========== 子域名枚举 (4 项) ==========

class TestEnumerateSubdomains:

    @pytest.mark.asyncio
    async def test_enumerate_no_crash(self):
        r = await enumerate_subdomains("example.com")
        assert r is not None
        assert "subdomains" in r or "error" in r

    @pytest.mark.asyncio
    async def test_enumerate_injection_rejected(self):
        with pytest.raises(ValueError):
            await enumerate_subdomains("example.com; cat /etc/passwd")

    @pytest.mark.asyncio
    async def test_enumerate_invalid_tool(self):
        """无效工具名应回退到 sublist3r"""
        r = await enumerate_subdomains("example.com", tool="invalid-tool")
        assert r is not None  # 不崩溃，回退到 sublist3r

    @pytest.mark.asyncio
    async def test_enumerate_amass_no_crash(self):
        r = await enumerate_subdomains("example.com", tool="amass")
        assert r is not None
        assert "subdomains" in r or "error" in r


# ========== 速率限制器 (2 项) ==========

class TestRateLimiter:

    def test_nvd_api_key_env(self):
        """NVD_API_KEY 应从环境变量读取"""
        # 不设环境变量时应为空字符串
        import importlib
        import src.rate_limiter
        # 值取决于测试时环境是否有 NVD_API_KEY
        assert isinstance(NVD_API_KEY, str)

    @pytest.mark.asyncio
    async def test_nvd_request_no_crash_on_network_error(self):
        """网络错误不应导致崩溃"""
        import httpx
        from src.rate_limiter import nvd_rate_limited_request
        client = httpx.AsyncClient()
        try:
            with pytest.raises((httpx.HTTPStatusError, httpx.RequestError, Exception)):
                await nvd_rate_limited_request(
                    client,
                    "https://invalid-url-that-does-not-exist-12345.com/api",
                    {},
                    max_retries=1,
                )
        finally:
            await client.aclose()


# ========== PoC 档案库搜索 (6 项) ==========

class TestPoCArchive:

    @pytest.mark.asyncio
    async def test_search_not_cloned(self):
        """未克隆时应返回错误，不应崩溃"""
        r = await search_poc_archive(query="test", custom_path="/nonexistent/path/12345")
        assert "error" in r
        assert "suggestion" in r or "repo_url" in r

    @pytest.mark.asyncio
    async def test_list_not_cloned(self):
        r = await list_poc_archive(custom_path="/nonexistent/path/12345")
        assert "error" in r

    @pytest.mark.asyncio
    async def test_search_empty_query_no_crash(self):
        """空查询不应崩溃"""
        r = await search_poc_archive(custom_path="/nonexistent/path/12345")
        assert r is not None

    @pytest.mark.asyncio
    async def test_search_invalid_cve(self):
        r = await search_poc_archive(cve_id="INVALID", custom_path="/nonexistent/path/12345")
        # 未克隆时先返回克隆错误，或返回 CVE 格式错误
        assert r is not None

    def test_clone_archive_no_git(self):
        """clone_archive 函数应存在且可调用"""
        # 只验证函数存在，不实际克隆
        assert callable(clone_archive)

    def test_update_archive_no_git(self):
        """update_archive 函数应存在且可调用"""
        assert callable(update_archive)
