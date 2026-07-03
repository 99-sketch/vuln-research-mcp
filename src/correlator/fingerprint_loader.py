# src/correlator/fingerprint_loader.py
"""动态指纹加载器 v5.1 — 从 JSON 文件动态加载 550+ 产品指纹

使用:
    loader = FingerprintLoader()
    loader.load_all()  # 加载 fingerprints.json
    product = loader.match_banner("Apache/2.4.57 (Unix)")  # → "apache_httpd"
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vuln-research-mcp.correlator.fingerprint")

# 默认位置
DEFAULT_FINGERPRINT_PATH = Path(__file__).parent / "fingerprints.json"


class FingerprintLoader:
    """动态指纹加载器"""

    def __init__(self, fingerprint_path: Optional[str] = None):
        self._path = fingerprint_path or str(DEFAULT_FINGERPRINT_PATH)
        self._data: Dict[str, Any] = {}
        self._banner_patterns: Dict[str, str] = {}
        self._cpe_map: Dict[str, str] = {}
        self._known_vulns: Dict[str, List[Dict[str, Any]]] = {}
        self._product_aliases: Dict[str, str] = {}
        self._version_regex = re.compile(r'(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)')
        self._loaded = False

    def load_all(self) -> bool:
        """加载所有指纹数据"""
        if self._loaded:
            return True

        if not os.path.exists(self._path):
            logger.warning(f"指纹文件不存在: {self._path}")
            return False

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                self._data = json.load(f)

            meta = self._data.get("_meta", {})
            logger.info(f"指纹库 v{meta.get('version')}: {meta.get('total_products', 0)} 产品, "
                       f"{meta.get('total_banner_patterns', 0)} banner 模式")

            self._load_banner_patterns()
            self._load_cpe_map()
            self._load_known_vulns()
            self._build_aliases()

            self._loaded = True
            return True
        except Exception as e:
            logger.error(f"指纹加载失败: {e}")
            return False

    def reload(self) -> bool:
        """重新加载指纹"""
        self._loaded = False
        self._banner_patterns.clear()
        self._cpe_map.clear()
        self._known_vulns.clear()
        self._product_aliases.clear()
        return self.load_all()

    # ===================================================================
    # Banner 匹配
    # ===================================================================

    def match_banner(self, banner: str) -> Optional[Tuple[str, Optional[str]]]:
        """根据服务 banner 匹配产品名和版本

        返回: (product_name, version_or_none)
        """
        if not banner:
            return None

        if not self._loaded:
            self.load_all()

        # 按 banner 模式匹配 (更具体的先匹配)
        for pattern, product in self._banner_patterns.items():
            if self._pattern_matches(banner, pattern):
                ver = self._extract_version(banner)
                return (product, ver)

        return None

    def match_product(self, banner: str) -> Optional[str]:
        """只返回产品名, 不提取版本"""
        result = self.match_banner(banner)
        return result[0] if result else None

    def match_version(self, banner: str) -> Optional[str]:
        """从 banner 提取版本号"""
        if not banner:
            return None
        match = self._version_regex.search(banner)
        return match.group(1) if match else None

    # ===================================================================
    # CPE 查询
    # ===================================================================

    def get_cpe(self, product: str, version: str = "") -> Optional[str]:
        """根据产品名获取 CPE 模板"""
        if not self._loaded:
            self.load_all()

        product = product.lower()
        cpe_template = self._cpe_map.get(product)
        if not cpe_template:
            # 尝试别名
            alias = self._product_aliases.get(product)
            if alias:
                cpe_template = self._cpe_map.get(alias)

        if cpe_template and version:
            return cpe_template.replace("{version}", version)
        return cpe_template

    # ===================================================================
    # 已知漏洞查询
    # ===================================================================

    def get_known_vulns(self, product: str, version: str = "") -> List[Dict[str, Any]]:
        """查询已知漏洞"""
        if not self._loaded:
            self.load_all()

        product = product.lower()

        # 精确匹配
        if version:
            key = f"{product}:{version}"
            if key in self._known_vulns:
                return self._known_vulns[key]

        # 前缀匹配 (同产品, 大版本)
        results = []
        for k, vulns in self._known_vulns.items():
            k_product = k.split(":")[0] if ":" in k else ""
            if k_product == product:
                results.extend(vulns)

        return results

    # ===================================================================
    # 统计
    # ===================================================================

    @property
    def total_products(self) -> int:
        return self._data.get("_meta", {}).get("total_products", 0)

    @property
    def total_banner_patterns(self) -> int:
        return len(self._banner_patterns)

    @property
    def total_categories(self) -> int:
        return len(self._data.get("banner_patterns", {}))

    def get_categories(self) -> List[str]:
        return list(self._data.get("banner_patterns", {}).keys())

    def search_product(self, keyword: str) -> List[str]:
        """按关键词搜索产品"""
        if not self._loaded:
            self.load_all()

        keyword = keyword.lower()
        results = set()
        for product in self._cpe_map:
            if keyword in product:
                results.add(product)
        return sorted(results)

    # ===================================================================
    # 内部方法
    # ===================================================================

    def _load_banner_patterns(self) -> None:
        """加载所有 banner 模式"""
        categories = self._data.get("banner_patterns", {})
        for category_name, patterns in categories.items():
            if isinstance(patterns, dict) and not category_name.startswith("_"):
                for pattern, product in patterns.items():
                    if product and not pattern.startswith("_"):
                        # 保持原始顺序 (JSON 保留插入顺序)
                        self._banner_patterns[pattern] = product

    def _load_cpe_map(self) -> None:
        """构建产品到 CPE 的映射"""
        # 从 banner 模式推断产品列表, 配合已知 CPE 数据库
        cpe_base = {
            # Web Servers
            "apache_httpd": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
            "apache_tomcat": "cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*",
            "nginx": "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
            "caddy": "cpe:2.3:a:caddyserver:caddy:{version}:*:*:*:*:*:*:*",
            "litespeed": "cpe:2.3:a:litespeedtech:litespeed_web_server:{version}:*:*:*:*:*:*:*",
            "openlitespeed": "cpe:2.3:a:litespeedtech:openlitespeed:{version}:*:*:*:*:*:*:*",
            "microsoft_iis": "cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*",
            "gunicorn": "cpe:2.3:a:gunicorn:gunicorn:{version}:*:*:*:*:*:*:*",
            "uwsgi": "cpe:2.3:a:unbit:uwsgi:{version}:*:*:*:*:*:*:*",
            "cherokee": "cpe:2.3:a:cherokee-project:cherokee:{version}:*:*:*:*:*:*:*",
            "lighttpd": "cpe:2.3:a:lighttpd:lighttpd:{version}:*:*:*:*:*:*:*",
            "tengine": "cpe:2.3:a:alibaba:tengine:{version}:*:*:*:*:*:*:*",
            "eclipse_jetty": "cpe:2.3:a:eclipse:jetty:{version}:*:*:*:*:*:*:*",
            "undertow": "cpe:2.3:a:redhat:undertow:{version}:*:*:*:*:*:*:*",
            "wildfly": "cpe:2.3:a:redhat:wildfly:{version}:*:*:*:*:*:*:*",
            "jboss": "cpe:2.3:a:redhat:jboss_enterprise_application_platform:{version}:*:*:*:*:*:*:*",
            "glassfish": "cpe:2.3:a:oracle:glassfish_server:{version}:*:*:*:*:*:*:*",
            "oracle_weblogic": "cpe:2.3:a:oracle:weblogic_server:{version}:*:*:*:*:*:*:*",
            "ibm_websphere": "cpe:2.3:a:ibm:websphere_application_server:{version}:*:*:*:*:*:*:*",

            # Databases
            "mysql": "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
            "mariadb": "cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*",
            "postgresql": "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*",
            "redis": "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*",
            "mongodb": "cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*",
            "microsoft_sql_server": "cpe:2.3:a:microsoft:sql_server:{version}:*:*:*:*:*:*:*",
            "oracle_database": "cpe:2.3:a:oracle:database_server:{version}:*:*:*:*:*:*:*",
            "elasticsearch": "cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*",
            "apache_cassandra": "cpe:2.3:a:apache:cassandra:{version}:*:*:*:*:*:*:*",
            "apache_couchdb": "cpe:2.3:a:apache:couchdb:{version}:*:*:*:*:*:*:*",
            "couchbase": "cpe:2.3:a:couchbase:couchbase_server:{version}:*:*:*:*:*:*:*",
            "neo4j": "cpe:2.3:a:neo4j:neo4j:{version}:*:*:*:*:*:*:*",
            "influxdb": "cpe:2.3:a:influxdata:influxdb:{version}:*:*:*:*:*:*:*",
            "clickhouse": "cpe:2.3:a:clickhouse:clickhouse:{version}:*:*:*:*:*:*:*",
            "memcached": "cpe:2.3:a:memcached:memcached:{version}:*:*:*:*:*:*:*",
            "sqlite": "cpe:2.3:a:sqlite:sqlite:{version}:*:*:*:*:*:*:*",

            # Frameworks & CMS
            "wordpress": "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
            "drupal": "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
            "joomla": "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*",
            "magento": "cpe:2.3:a:magento:magento:{version}:*:*:*:*:*:*:*",
            "prestashop": "cpe:2.3:a:prestashop:prestashop:{version}:*:*:*:*:*:*:*",
            "django": "cpe:2.3:a:djangoproject:django:{version}:*:*:*:*:*:*:*",
            "flask": "cpe:2.3:a:palletsprojects:flask:{version}:*:*:*:*:*:*:*",
            "fastapi": "cpe:2.3:a:tiangolo:fastapi:{version}:*:*:*:*:*:*:*",
            "spring_boot": "cpe:2.3:a:vmware:spring_boot:{version}:*:*:*:*:*:*:*",
            "spring_framework": "cpe:2.3:a:vmware:spring_framework:{version}:*:*:*:*:*:*:*",
            "laravel": "cpe:2.3:a:laravel:laravel:{version}:*:*:*:*:*:*:*",
            "symfony": "cpe:2.3:a:sensiolabs:symfony:{version}:*:*:*:*:*:*:*",
            "ruby_on_rails": "cpe:2.3:a:rubyonrails:rails:{version}:*:*:*:*:*:*:*",
            "aspnet_core": "cpe:2.3:a:microsoft:asp.net_core:{version}:*:*:*:*:*:*:*",
            "vuejs": "cpe:2.3:a:vuejs:vue:{version}:*:*:*:*:*:*:*",
            "angular": "cpe:2.3:a:angular:angular:{version}:*:*:*:*:*:*:*",
            "nextjs": "cpe:2.3:a:vercel:next.js:{version}:*:*:*:*:*:*:*",

            # DevOps
            "jenkins": "cpe:2.3:a:jenkins:jenkins:{version}:*:*:*:*:*:*:*",
            "gitlab": "cpe:2.3:a:gitlab:gitlab:{version}:*:*:*:*:*:*:*",
            "sonarqube": "cpe:2.3:a:sonarsource:sonarqube:{version}:*:*:*:*:*:*:*",
            "grafana": "cpe:2.3:a:grafana:grafana:{version}:*:*:*:*:*:*:*",
            "prometheus": "cpe:2.3:a:prometheus:prometheus:{version}:*:*:*:*:*:*:*",
            "kibana": "cpe:2.3:a:elastic:kibana:{version}:*:*:*:*:*:*:*",

            # Languages
            "python": "cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
            "php": "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*",
            "nodejs": "cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*",
            "ruby": "cpe:2.3:a:ruby-lang:ruby:{version}:*:*:*:*:*:*:*",
            "java": "cpe:2.3:a:oracle:jdk:{version}:*:*:*:*:*:*:*",

            # Container & Orchestration
            "kubernetes": "cpe:2.3:a:kubernetes:kubernetes:{version}:*:*:*:*:*:*:*",
            "docker_engine": "cpe:2.3:a:docker:docker:{version}:*:*:*:*:*:*:*",
            "helm": "cpe:2.3:a:helm:helm:{version}:*:*:*:*:*:*:*",

            # Mail
            "microsoft_exchange": "cpe:2.3:a:microsoft:exchange_server:{version}:*:*:*:*:*:*:*",
            "postfix": "cpe:2.3:a:postfix:postfix:{version}:*:*:*:*:*:*:*",
            "exim": "cpe:2.3:a:exim:exim:{version}:*:*:*:*:*:*:*",
            "zimbra": "cpe:2.3:a:zimbra:collaboration:{version}:*:*:*:*:*:*:*",

            # Network
            "haproxy": "cpe:2.3:a:haproxy:haproxy:{version}:*:*:*:*:*:*:*",
            "traefik": "cpe:2.3:a:traefik:traefik:{version}:*:*:*:*:*:*:*",
            "squid_proxy": "cpe:2.3:a:squid-cache:squid:{version}:*:*:*:*:*:*:*",
            "rabbitmq": "cpe:2.3:a:vmware:rabbitmq:{version}:*:*:*:*:*:*:*",
            "apache_kafka": "cpe:2.3:a:apache:kafka:{version}:*:*:*:*:*:*:*",
            "apache_activemq": "cpe:2.3:a:apache:activemq:{version}:*:*:*:*:*:*:*",

            # Virtualization
            "vmware_esxi": "cpe:2.3:a:vmware:esxi:{version}:*:*:*:*:*:*:*",
            "vmware_vcenter": "cpe:2.3:a:vmware:vcenter_server:{version}:*:*:*:*:*:*:*",
            "virtualbox": "cpe:2.3:a:oracle:vm_virtualbox:{version}:*:*:*:*:*:*:*",

            # Security
            "atlassian_confluence": "cpe:2.3:a:atlassian:confluence:{version}:*:*:*:*:*:*:*",
            "atlassian_jira": "cpe:2.3:a:atlassian:jira:{version}:*:*:*:*:*:*:*",
            "fortinet_fortios": "cpe:2.3:o:fortinet:fortios:{version}:*:*:*:*:*:*:*",
            "cisco_ios": "cpe:2.3:o:cisco:ios:{version}:*:*:*:*:*:*:*",
            "palo_alto_panos": "cpe:2.3:o:paloaltonetworks:pan-os:{version}:*:*:*:*:*:*:*",
        }

        self._cpe_map = cpe_base

    def _load_known_vulns(self) -> None:
        """加载已知漏洞数据库 (从 JSON 或硬编码)"""
        # 扩展版 (partial, 完整从 NVD CPE 字典加载)
        self._known_vulns = {
            # Apache HTTPD
            "apache_httpd:2.4.49": [
                {"cve": "CVE-2021-41773", "cvss": 7.5, "epss": 97.5, "kev": True, "desc": "Path traversal/RCE"},
            ],
            "apache_httpd:2.4.50": [
                {"cve": "CVE-2021-42013", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Path traversal/RCE"},
            ],
            "apache_httpd:2.4.52": [
                {"cve": "CVE-2022-22720", "cvss": 9.8, "epss": 60.0, "kev": True, "desc": "HTTP Request Smuggling"},
            ],

            # OpenSSH
            "openssh:7.4": [{"cve": "CVE-2018-15473", "cvss": 5.3, "epss": 97.5, "kev": False, "desc": "User enumeration"}],
            "openssh:8.5": [{"cve": "CVE-2021-41617", "cvss": 7.0, "epss": 50.0, "kev": False, "desc": "Privilege escalation"}],
            "openssh:9.0": [{"cve": "CVE-2023-25136", "cvss": 6.5, "epss": 30.0, "kev": False, "desc": "Pre-auth double free"}],

            # Spring
            "spring_framework:5.2": [{"cve": "CVE-2022-22965", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Spring4Shell RCE"}],
            "spring_framework:5.3.18": [{"cve": "CVE-2022-22965", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Spring4Shell RCE"}],

            # WordPress
            "wordpress:5.7": [{"cve": "CVE-2021-29447", "cvss": 6.5, "epss": 20.0, "kev": False, "desc": "XXE vulnerability"}],
            "wordpress:6.1": [{"cve": "CVE-2023-2745", "cvss": 7.2, "epss": 15.0, "kev": False, "desc": "Unauthenticated SQLi"}],

            # Tomcat
            "apache_tomcat:9.0.31": [{"cve": "CVE-2020-9484", "cvss": 7.0, "epss": 85.0, "kev": False, "desc": "Session persistence RCE"}],
            "apache_tomcat:8.5.60": [{"cve": "CVE-2021-25329", "cvss": 7.0, "epss": 40.0, "kev": False, "desc": "Incomplete fix for CVE-2020-9484"}],

            # Weblogic
            "oracle_weblogic:12.2.1.3": [
                {"cve": "CVE-2020-14882", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Remote code execution"},
            ],
            "oracle_weblogic:14.1.1": [
                {"cve": "CVE-2023-21839", "cvss": 7.5, "epss": 40.0, "kev": False, "desc": "Unauthenticated RCE via IIOP"},
            ],

            # FortiOS
            "fortinet_fortios:7.0": [{"cve": "CVE-2023-27997", "cvss": 9.8, "epss": 95.0, "kev": True, "desc": "SSL-VPN heap overflow RCE"}],
            "fortinet_fortios:6.0": [{"cve": "CVE-2018-13379", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "SSL-VPN path traversal"}],

            # Exchange
            "microsoft_exchange:2016": [
                {"cve": "CVE-2021-26855", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "ProxyLogon SSRF → RCE"},
            ],
            "microsoft_exchange:2019": [
                {"cve": "CVE-2022-41082", "cvss": 8.0, "epss": 90.0, "kev": True, "desc": "ProxyNotShell RCE"},
            ],

            # VMware
            "vmware_esxi:7.0": [
                {"cve": "CVE-2021-21972", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "vCenter unauthenticated RCE"},
                {"cve": "CVE-2021-21985", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "vSphere Client RCE"},
            ],
            "vmware_vcenter:7.0": [
                {"cve": "CVE-2021-21972", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Unauthenticated RCE (vCenter)"},
            ],

            # Jenkins
            "jenkins:2.263": [{"cve": "CVE-2021-21605", "cvss": 9.8, "epss": 30.0, "kev": False, "desc": "Arbitrary file read"}],

            # GitLab
            "gitlab:14.0": [{"cve": "CVE-2021-22205", "cvss": 10.0, "epss": 97.5, "kev": True, "desc": "Unauthenticated RCE (ExifTool)"}],

            # Confluence
            "atlassian_confluence:7.13": [
                {"cve": "CVE-2022-26134", "cvss": 9.8, "epss": 97.5, "kev": True, "desc": "Unauthenticated OGNL injection RCE"},
            ],
            "atlassian_confluence:8.0": [
                {"cve": "CVE-2023-22518", "cvss": 9.1, "epss": 85.0, "kev": True, "desc": "Improper authorization → RCE"},
            ],

            # Log4j
            "apache_log4j:2.14.1": [{"cve": "CVE-2021-44228", "cvss": 10.0, "epss": 97.5, "kev": True, "desc": "Log4Shell RCE"}],
            "apache_log4j:2.15.0": [{"cve": "CVE-2021-45046", "cvss": 9.0, "epss": 97.5, "kev": True, "desc": "Log4Shell incomplete fix"}],
        }

    def _build_aliases(self) -> None:
        """构建产品名别名映射"""
        aliases = {
            "apache": "apache_httpd",
            "httpd": "apache_httpd",
            "tomcat": "apache_tomcat",
            "iis": "microsoft_iis",
            "weblogic": "oracle_weblogic",
            "websphere": "ibm_websphere",
            "ms-sql": "microsoft_sql_server",
            "sqlserver": "microsoft_sql_server",
            "mssql": "microsoft_sql_server",
            "oracle": "oracle_database",
            "oracledb": "oracle_database",
            "es": "elasticsearch",
            "elastic": "elasticsearch",
            "cassandra": "apache_cassandra",
            "couch": "apache_couchdb",
            "spring": "spring_framework",
            "springboot": "spring_boot",
            "rails": "ruby_on_rails",
            "dotnet": "aspnet_core",
            "aspnet": "aspnet_core",
            "next": "nextjs",
            "nuxt": "nuxtjs",
            "sanity": "sanity_cms",
            "exchange": "microsoft_exchange",
            "exch": "microsoft_exchange",
            "squid": "squid_proxy",
            "activemq": "apache_activemq",
            "kafka": "apache_kafka",
            "esxi": "vmware_esxi",
            "vcenter": "vmware_vcenter",
            "vsphere": "vmware_vsphere",
            "confluence": "atlassian_confluence",
            "jira": "atlassian_jira",
            "fortios": "fortinet_fortios",
            "fortigate": "fortinet_fortios",
            "panos": "palo_alto_panos",
            "pan": "palo_alto_panos",
            "ios": "cisco_ios",
            "cisco": "cisco_ios",
        }
        self._product_aliases = aliases

    @staticmethod
    def _pattern_matches(banner: str, pattern: str) -> bool:
        """检查 banner 是否匹配 pattern (大小写不敏感)"""
        return pattern.lower() in banner.lower() or banner.lower().startswith(pattern.lower())

    def _extract_version(self, text: str) -> Optional[str]:
        """提取版本号 (支持多种格式)"""
        # 优先匹配紧随产品名后的版本: "Apache/2.4.57"
        match = re.search(r'(?:/|[-_\s])(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)', text)
        if match:
            return match.group(1)

        # 回退: 任何位置
        match = self._version_regex.search(text)
        if match:
            return match.group(1)

        return None


# ===================================================================
# 全局单例
# ===================================================================

_global_loader: Optional[FingerprintLoader] = None


def get_fingerprint_loader() -> FingerprintLoader:
    global _global_loader
    if _global_loader is None:
        _global_loader = FingerprintLoader()
    return _global_loader
