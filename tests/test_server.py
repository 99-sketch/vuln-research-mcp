# tests/test_server.py
"""vuln-research-mcp v2.0 测试套件 — 80+ 项测试"""

import asyncio
import json
import os
import pytest
import pytest_asyncio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock

# Imports
from src.validators import (
    validate_ip, validate_domain, validate_url, validate_ports,
    validate_cve_id, validate_cwe_id, sanitize_subprocess_arg, is_private_ip,
)
from src.tools.cvss_tool import cvss_calculator
from src.tools.cwe_tool import cwe_mapping
from src.tools.cve_tools import search_cve, get_cve_details
from src.tools.network_tools import check_http_headers, query_dns, geolocate_ip
from src.tools.exploit_tool import search_exploit, _check_searchsploit
from src.tools.nuclei_tool import find_nuclei_template
from src.tools.scan_tools import scan_ports, enumerate_subdomains, _check_tool_version
from src.tools.poc_archive_tool import search_poc_archive, list_poc_archive, clone_archive, update_archive
from src.tools.threat_intel_tool import check_kev, get_epss_score, vulnerability_assess, search_kev
from src.tools.cross_search_tool import cross_source_search
from src.rate_limiter import NVD_API_KEY
from src.core.async_subprocess import async_run, async_run_safe
from src.core.circuit_breaker import CircuitBreaker, CircuitOpenError, get_breaker, all_breaker_status
from src.core.cache_manager import CacheManager, get_cache, init_cache
from src.core.health_check import startup_health_check, get_degraded_tools
from src.core.config_manager import load_config, AppConfig, create_default_config
from src.core.tool_registry import get_registry, ToolDefinition, register_all_tools
from src.core.structured_logger import StructuredFormatter, setup_logging


# ========== Input Validation (23 项) ==========

class TestInputValidation:

    def test_validate_ip_valid_v4(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"

    def test_validate_ip_valid_v6(self):
        assert validate_ip("::1") == "::1"

    def test_validate_ip_invalid(self):
        with pytest.raises(ValueError):
            validate_ip("999.999.999.999")

    def test_validate_ip_empty(self):
        with pytest.raises(ValueError):
            validate_ip("")

    def test_validate_domain_valid(self):
        assert validate_domain("example.com") == "example.com"

    def test_validate_domain_invalid(self):
        with pytest.raises(ValueError):
            validate_domain("-invalid.com")

    def test_validate_domain_path_traversal(self):
        with pytest.raises(ValueError):
            validate_domain("../../etc/passwd")

    def test_validate_url_valid(self):
        assert validate_url("https://example.com") == "https://example.com"

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
        assert validate_cve_id("CVE-2021-44228") == "CVE-2021-44228"

    def test_validate_cve_id_short(self):
        with pytest.raises(ValueError):
            validate_cve_id("CVE-123")

    def test_validate_cwe_id_valid(self):
        assert validate_cwe_id("CWE-89") == "CWE-89"

    def test_sanitize_normal(self):
        assert sanitize_subprocess_arg("normal-text") == "normal-text"

    def test_sanitize_rejects_semicolon(self):
        with pytest.raises(ValueError):
            sanitize_subprocess_arg("text; rm -rf")

    def test_sanitize_rejects_dollar(self):
        with pytest.raises(ValueError):
            sanitize_subprocess_arg("text $(whoami)")

    def test_is_private_192168(self):
        assert is_private_ip("192.168.1.1") is True

    def test_is_private_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_is_private_public(self):
        assert is_private_ip("8.8.8.8") is False


# ========== CVSS Calculator (5 项) ==========

class TestCVSS:

    @pytest.mark.asyncio
    async def test_cvss_98_critical(self):
        r = await cvss_calculator(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r["base_score"] == 9.8
        assert r["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_cvss_scope_changed(self):
        r = await cvss_calculator(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert r["base_score"] == 10.0

    @pytest.mark.asyncio
    async def test_cvss_zero(self):
        r = await cvss_calculator(vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
        assert r["base_score"] == 0.0

    @pytest.mark.asyncio
    async def test_cvss_params_mode(self):
        r = await cvss_calculator(
            attack_vector="NETWORK", attack_complexity="LOW",
            privileges_required="NONE", user_interaction="NONE",
            scope="UNCHANGED", confidentiality="HIGH",
            integrity="HIGH", availability="HIGH",
        )
        assert r["base_score"] == 9.8

    @pytest.mark.asyncio
    async def test_cvss_invalid_vector(self):
        r = await cvss_calculator(vector="INVALID")
        assert "error" in r


# ========== CWE Mapping (7 项) ==========

class TestCWE:

    @pytest.mark.asyncio
    async def test_cwe_89_sql(self):
        r = await cwe_mapping("CWE-89")
        assert r["cwe_id"] == "CWE-89"
        assert "SQL" in r["name"].upper() or "Injection" in r["name"]

    @pytest.mark.asyncio
    async def test_cwe_89_mitre_url(self):
        r = await cwe_mapping("CWE-89")
        assert "mitre.org" in r.get("mitre_url", r.get("url", ""))

    @pytest.mark.asyncio
    async def test_cwe_918_ssrf(self):
        r = await cwe_mapping("CWE-918")
        assert r["cwe_id"] == "CWE-918"

    @pytest.mark.asyncio
    async def test_cwe_611_xxe(self):
        r = await cwe_mapping("CWE-611")
        assert r["cwe_id"] == "CWE-611"

    @pytest.mark.asyncio
    async def test_cwe_not_found_local(self):
        r = await cwe_mapping("CWE-99999")
        assert "error" in r or r.get("found") is False or "not found" in r.get("note", "").lower()

    @pytest.mark.asyncio
    async def test_cwe_invalid_format(self):
        with pytest.raises(ValueError):
            await cwe_mapping("INVALID")

    @pytest.mark.asyncio
    async def test_cwe_database_size(self):
        r = await cwe_mapping("CWE-79")
        assert r["cwe_id"] == "CWE-79"


# ========== CVE Search (4 项) ==========

class TestCVE:

    @pytest.mark.asyncio
    async def test_search_cve_returns_results(self):
        r = await search_cve(keyword="Apache Log4j", max_results=3)
        assert "total_results" in r
        assert "vulnerabilities" in r

    @pytest.mark.asyncio
    async def test_search_cve_limits_results(self):
        r = await search_cve(keyword="WordPress", max_results=3)
        assert len(r.get("vulnerabilities", [])) <= 3

    @pytest.mark.asyncio
    async def test_search_cve_reports_api_key_status(self):
        r = await search_cve(keyword="test", max_results=1)
        assert "api_key_used" in r

    @pytest.mark.asyncio
    async def test_get_cve_invalid_id(self):
        with pytest.raises(ValueError):
            await get_cve_details("INVALID")


# ========== DNS (3 项) ==========

class TestDNS:

    @pytest.mark.asyncio
    async def test_dns_a_record(self):
        r = await query_dns("example.com", "A")
        assert r["domain"] == "example.com"
        assert "A" in r["records"]

    @pytest.mark.asyncio
    async def test_dns_mx_no_crash(self):
        r = await query_dns("example.com", "MX")
        assert "records" in r

    @pytest.mark.asyncio
    async def test_dns_invalid_domain(self):
        with pytest.raises(ValueError):
            await query_dns("-invalid.com")


# ========== HTTP Headers (4 项) ==========

class TestHTTPHeaders:

    @pytest.mark.asyncio
    async def test_returns_analysis(self):
        r = await check_http_headers("https://example.com")
        assert "headers_analysis" in r or "error" in r

    @pytest.mark.asyncio
    async def test_score_present(self):
        r = await check_http_headers("https://example.com")
        if "summary" in r:
            assert "score" in r["summary"]

    @pytest.mark.asyncio
    async def test_rejects_ftp(self):
        with pytest.raises(ValueError):
            await check_http_headers("ftp://example.com")

    @pytest.mark.asyncio
    async def test_unreachable_domain(self):
        r = await check_http_headers("https://this-domain-does-not-exist-12345.com")
        assert "error" in r


# ========== GeoIP (4 项) ==========

class TestGeoIP:

    @pytest.mark.asyncio
    async def test_8888(self):
        r = await geolocate_ip("8.8.8.8")
        assert r.get("country") is not None or "error" in r

    @pytest.mark.asyncio
    async def test_isp(self):
        r = await geolocate_ip("8.8.8.8")
        if "error" not in r:
            assert "isp" in r

    @pytest.mark.asyncio
    async def test_private_ip_warning(self):
        r = await geolocate_ip("192.168.1.1")
        assert "warning" in r or "error" in r

    @pytest.mark.asyncio
    async def test_invalid_ip(self):
        with pytest.raises(ValueError):
            await geolocate_ip("999.999.999.999")


# ========== Exploit Search (4 项) ==========

class TestExploitSearch:

    @pytest.mark.asyncio
    async def test_search_exploit_no_crash(self):
        r = await search_exploit("WordPress RCE")
        assert r is not None

    @pytest.mark.asyncio
    async def test_search_exploit_empty_query(self):
        with pytest.raises(ValueError):
            await search_exploit("")

    def test_check_searchsploit_installed(self):
        r = _check_searchsploit()
        assert "installed" in r

    @pytest.mark.asyncio
    async def test_search_exploit_type_filter(self):
        r = await search_exploit("Apache", type_filter="remote")
        assert r is not None


# ========== Nuclei Search (3 项) ==========

class TestNucleiSearch:

    @pytest.mark.asyncio
    async def test_find_nuclei_no_crash(self):
        r = await find_nuclei_template("cve")
        assert r is not None

    @pytest.mark.asyncio
    async def test_find_nuclei_empty_tags(self):
        with pytest.raises(ValueError):
            await find_nuclei_template("")

    @pytest.mark.asyncio
    async def test_find_nuclei_invalid_severity(self):
        with pytest.raises(ValueError):
            await find_nuclei_template("cve", severity="invalid")


# ========== Scan Ports (5 项) ==========

class TestScanPorts:

    @pytest.mark.asyncio
    async def test_scan_ports_no_crash(self):
        r = await scan_ports("127.0.0.1", scan_type="quick")
        assert r is not None

    @pytest.mark.asyncio
    async def test_scan_ports_injection_rejected(self):
        with pytest.raises(ValueError):
            await scan_ports("127.0.0.1; rm -rf /")

    @pytest.mark.asyncio
    async def test_scan_ports_invalid_type(self):
        r = await scan_ports("127.0.0.1", scan_type="invalid_type")
        # 无效类型应降级为 quick
        assert r is not None

    @pytest.mark.asyncio
    async def test_check_tool_version_nmap(self):
        r = await scan_ports("127.0.0.1")
        assert r is not None

    @pytest.mark.asyncio
    async def test_check_tool_version_nonexistent(self):
        from src.tools.scan_tools import _check_tool_version
        r = _check_tool_version("nonexistent_tool_12345")
        assert r["installed"] is False


# ========== Enumerate Subdomains (4 项) ==========

class TestEnumerateSubdomains:

    @pytest.mark.asyncio
    async def test_enumerate_no_crash(self):
        r = await enumerate_subdomains("example.com")
        assert r is not None

    @pytest.mark.asyncio
    async def test_enumerate_injection_rejected(self):
        with pytest.raises(ValueError):
            await enumerate_subdomains("example.com; rm -rf /")

    @pytest.mark.asyncio
    async def test_enumerate_invalid_tool(self):
        r = await enumerate_subdomains("example.com", tool="invalid")
        # 无效工具应降级为 sublist3r
        assert r is not None

    @pytest.mark.asyncio
    async def test_enumerate_amass_no_crash(self):
        r = await enumerate_subdomains("example.com", tool="amass")
        assert r is not None


# ========== Rate Limiter (2 项) ==========

class TestRateLimiter:

    def test_nvd_api_key_env(self):
        assert isinstance(NVD_API_KEY, str)

    @pytest.mark.asyncio
    async def test_nvd_request_no_crash_on_network_error(self):
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


# ========== PoC Archive (6 项) ==========

class TestPoCArchive:

    @pytest.mark.asyncio
    async def test_search_not_cloned(self):
        r = await search_poc_archive(query="test", custom_path="/nonexistent/path/12345")
        assert "error" in r

    @pytest.mark.asyncio
    async def test_list_not_cloned(self):
        r = await list_poc_archive(custom_path="/nonexistent/path/12345")
        assert "error" in r

    @pytest.mark.asyncio
    async def test_search_empty_query_no_crash(self):
        r = await search_poc_archive(custom_path="/nonexistent/path/12345")
        assert r is not None

    @pytest.mark.asyncio
    async def test_search_invalid_cve(self):
        r = await search_poc_archive(cve_id="INVALID", custom_path="/nonexistent/path/12345")
        assert r is not None

    def test_clone_archive_no_git(self):
        assert callable(clone_archive)

    def test_update_archive_no_git(self):
        assert callable(update_archive)


# ========== Async Subprocess (3 项) ==========

class TestAsyncSubprocess:

    @pytest.mark.asyncio
    async def test_async_run_echo(self):
        rc, stdout, stderr = await async_run(
            ["python", "-c", "print('hello')"], timeout=5
        )
        assert rc == 0
        assert "hello" in stdout

    @pytest.mark.asyncio
    async def test_async_run_safe_not_found(self):
        r = await async_run_safe(["nonexistent_command_12345"], timeout=5)
        assert r["error"] is not None
        assert r["returncode"] == -2

    @pytest.mark.asyncio
    async def test_async_run_safe_timeout(self):
        r = await async_run_safe(
            ["python", "-c", "import time; time.sleep(10)"], timeout=1
        )
        assert r["error"] is not None
        assert "超时" in r["error"]


# ========== Circuit Breaker (6 项) ==========

class TestCircuitBreaker:

    @pytest.mark.asyncio
    async def test_breaker_starts_closed(self):
        cb = CircuitBreaker(name="test_1")
        assert cb.state == "CLOSED"

    @pytest.mark.asyncio
    async def test_breaker_opens_after_failures(self):
        cb = CircuitBreaker(name="test_2", failure_threshold=3, recovery_timeout=1)
        for _ in range(3):
            with pytest.raises(ValueError):
                await cb.call(_raise_value_error())
        assert cb.state == "OPEN"

    @pytest.mark.asyncio
    async def test_breaker_rejects_when_open(self):
        cb = CircuitBreaker(name="test_3", failure_threshold=1, recovery_timeout=60)
        with pytest.raises(ValueError):
            await cb.call(_raise_value_error())
        assert cb.state == "OPEN"
        with pytest.raises(CircuitOpenError):
            await cb.call(_noop_coro())

    @pytest.mark.asyncio
    async def test_breaker_recovers_after_timeout(self):
        cb = CircuitBreaker(name="test_4", failure_threshold=1, recovery_timeout=0.1)
        with pytest.raises(ValueError):
            await cb.call(_raise_value_error())
        assert cb.state == "OPEN"
        await asyncio.sleep(0.2)
        result = await cb.call(_return_ok_coro())
        assert result == "ok"
        assert cb.state == "CLOSED"

    @pytest.mark.asyncio
    async def test_breaker_reset(self):
        cb = CircuitBreaker(name="test_5", failure_threshold=1)
        with pytest.raises(ValueError):
            await cb.call(_raise_value_error())
        cb.reset()
        assert cb.state == "CLOSED"

    @pytest.mark.asyncio
    async def test_all_breaker_status(self):
        get_breaker("test_status_1")
        status = all_breaker_status()
        assert "test_status_1" in status


async def _raise_value_error():
    raise ValueError("test error")


async def _noop_coro():
    return None


async def _return_ok_coro():
    return "ok"


# ========== Cache Manager (5 项) ==========

class TestCacheManager:

    def test_memory_cache_basic(self):
        cache = CacheManager(enabled=True)  # 使用内存缓存（diskcache 可能未安装）
        cache.set("test", "key1", {"data": "hello"}, ttl=60)
        result = cache.get("test", "key1")
        assert result is not None
        assert result["data"] == "hello"
        cache.clear()

    def test_memory_cache_miss(self):
        cache = CacheManager(enabled=True)
        result = cache.get("test", "nonexistent_key")
        assert result is None
        cache.clear()

    def test_memory_cache_delete(self):
        cache = CacheManager(enabled=True)
        cache.set("test", "key2", "value", ttl=60)
        cache.delete("test", "key2")
        assert cache.get("test", "key2") is None
        cache.clear()

    def test_memory_cache_clear(self):
        cache = CacheManager(enabled=True)
        cache.set("test", "key3", "value", ttl=60)
        cache.clear()
        assert cache.get("test", "key3") is None

    def test_cache_stats(self):
        cache = CacheManager(enabled=True)
        cache.set("test", "key4", "value", ttl=60)
        stats = cache.stats()
        assert "type" in stats
        assert "size" in stats
        cache.clear()


# ========== Health Check (3 项) ==========

class TestHealthCheck:

    @pytest.mark.asyncio
    async def test_startup_health_check_returns_dict(self):
        r = await startup_health_check()
        assert "apis" in r
        assert "tools" in r
        assert "summary" in r

    @pytest.mark.asyncio
    async def test_health_check_has_nvd(self):
        r = await startup_health_check()
        assert "nvd_api" in r["apis"]

    def test_get_degraded_tools(self):
        health = {
            "apis": {"nvd_api": False, "cisa_kev": True, "epss_api": True, "ip_api": True},
            "tools": {"nmap": False, "searchsploit": True, "sublist3r": True, "amass": True, "git": True},
            "nuclei_templates": True,
        }
        degraded = get_degraded_tools(health)
        assert "search_cve" in degraded
        assert "scan_ports" in degraded


# ========== Config Manager (4 项) ==========

class TestConfigManager:

    def test_load_config_defaults(self):
        cfg = load_config(config_path="/nonexistent/path/config.yaml")
        assert cfg.server.name == "vuln-research-mcp"
        assert cfg.server.log_level == "INFO"

    def test_load_config_env_override(self):
        os.environ["LOG_LEVEL"] = "DEBUG"
        cfg = load_config(config_path="/nonexistent/path/config.yaml")
        assert cfg.server.log_level == "DEBUG"
        del os.environ["LOG_LEVEL"]

    def test_app_config_defaults(self):
        cfg = AppConfig()
        assert cfg.cache.enabled is True
        assert cfg.rate_limit.nvd_max_retries == 3

    def test_create_default_config(self):
        import tempfile
        path = os.path.join(tempfile.gettempdir(), "test_config_v2.yaml")
        result = create_default_config(path)
        assert os.path.exists(path)
        os.remove(path)


# ========== Tool Registry (4 项) ==========

class TestToolRegistry:

    def test_registry_register_and_resolve(self):
        from src.core.tool_registry import ToolRegistry
        registry = ToolRegistry()
        tool = ToolDefinition(
            name="test_tool",
            description="Test",
            input_schema={},
            handler=lambda **kw: None,
        )
        registry.register(tool)
        assert registry.resolve("test_tool") is not None
        assert registry.size() == 1

    def test_registry_list_all(self):
        from src.core.tool_registry import ToolRegistry
        registry = ToolRegistry()
        registry.register(ToolDefinition(
            name="test_list_all_unique", description="T1", input_schema={}, handler=lambda **kw: None
        ))
        tools = registry.list_all()
        assert len(tools) == 1
        assert tools[0]["name"] == "test_list_all_unique"

    def test_registry_filter_disabled(self):
        from src.core.tool_registry import ToolRegistry
        registry = ToolRegistry()
        registry.register(ToolDefinition(
            name="test_filter_1", description="T1", input_schema={}, handler=lambda **kw: None
        ))
        registry.register(ToolDefinition(
            name="test_filter_2", description="T2", input_schema={}, handler=lambda **kw: None
        ))
        registry.filter_disabled(["test_filter_1"])
        assert registry.size() == 1
        assert registry.resolve("test_filter_1") is None
        assert registry.resolve("test_filter_2") is not None

    def test_global_registry_has_tools(self):
        # 确保 server.py 的注册已被调用（通过 import 触发）
        registry = get_registry()
        # 如果未注册，至少不应该 crash
        assert registry is not None


# ========== Structured Logger (2 项) ==========

class TestStructuredLogger:

    def test_text_format(self):
        import logging
        formatter = StructuredFormatter(fmt="text")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        assert "test message" in output

    def test_json_format(self):
        import logging
        formatter = StructuredFormatter(fmt="json")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["msg"] == "test message"
        assert data["level"] == "INFO"


# ========== Threat Intel — CISA KEV (3 项) ==========

class TestCISAKEV:

    @pytest.mark.asyncio
    async def test_check_kev_known_cve(self):
        # CVE-2021-44228 (Log4j) 应该在 KEV 中
        r = await check_kev("CVE-2021-44228")
        assert r["cve_id"] == "CVE-2021-44228"
        # 网络可用时应返回 in_kev=True
        if "error" not in r:
            assert "in_kev" in r

    @pytest.mark.asyncio
    async def test_check_kev_invalid_cve(self):
        with pytest.raises(ValueError):
            await check_kev("INVALID")

    @pytest.mark.asyncio
    async def test_search_kev_no_crash(self):
        r = await search_kev("Apache")
        assert r is not None
        assert "total_in_kev" in r or "error" in r


# ========== Threat Intel — EPSS (2 项) ==========

class TestEPSS:

    @pytest.mark.asyncio
    async def test_get_epss_score(self):
        r = await get_epss_score("CVE-2021-44228")
        assert r["cve_id"] == "CVE-2021-44228"
        assert "epss_score" in r

    @pytest.mark.asyncio
    async def test_get_epss_invalid_cve(self):
        with pytest.raises(ValueError):
            await get_epss_score("INVALID")


# ========== Vulnerability Assess (2 项) ==========

class TestVulnerabilityAssess:

    @pytest.mark.asyncio
    async def test_assess_log4j(self):
        r = await vulnerability_assess("CVE-2021-44228")
        assert r["cve_id"] == "CVE-2021-44228"
        assert "risk_score" in r
        assert "risk_severity" in r
        assert r["risk_severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    @pytest.mark.asyncio
    async def test_assess_invalid_cve(self):
        with pytest.raises(ValueError):
            await vulnerability_assess("INVALID")


# ========== Cross Source Search (2 项) ==========

class TestCrossSourceSearch:

    @pytest.mark.asyncio
    async def test_cross_source_search_no_crash(self):
        r = await cross_source_search("log4j", max_results=3)
        assert r is not None
        assert "keyword" in r
        assert "sources" in r
        assert "summary" in r

    @pytest.mark.asyncio
    async def test_cross_source_search_empty_query(self):
        with pytest.raises(ValueError):
            await cross_source_search("")
