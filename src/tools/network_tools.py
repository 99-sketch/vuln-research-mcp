# src/tools/network_tools.py
"""网络工具：HTTP 安全头检查、DNS 查询、IP 地理定位 — v2.0: 缓存"""

import logging
import ipaddress

import httpx
import dns.resolver

from ..validators import validate_url, validate_domain, validate_ip, is_private_ip
from ..core.cache_manager import get_cache

logger = logging.getLogger("vuln-research-mcp")


async def check_http_headers(url: str) -> dict:
    """HTTP 安全头检查"""
    url = validate_url(url)

    security_headers = {
        "Strict-Transport-Security": {
            "description": "强制 HTTPS 连接",
            "recommendation": "max-age=31536000; includeSubDomains",
        },
        "Content-Security-Policy": {
            "description": "防止 XSS 和内容注入",
            "recommendation": "default-src 'self'",
        },
        "X-Frame-Options": {
            "description": "防止点击劫持",
            "recommendation": "DENY 或 SAMEORIGIN",
        },
        "X-Content-Type-Options": {
            "description": "防止 MIME 类型嗅探",
            "recommendation": "nosniff",
        },
        "Referrer-Policy": {
            "description": "控制 Referer 头",
            "recommendation": "strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "description": "控制浏览器功能权限",
            "recommendation": "限制敏感 API（如摄像头、麦克风）",
        },
        "X-XSS-Protection": {
            "description": "XSS 过滤器（已弃用，建议使用 CSP）",
            "recommendation": "0（禁用，依赖 CSP）",
        },
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=30.0, follow_redirects=True)
            headers = response.headers

            results = {
                "url": str(response.url),
                "status_code": response.status_code,
                "headers_analysis": {},
            }

            present_count = 0
            missing_count = 0

            for header, info in security_headers.items():
                if header in headers:
                    results["headers_analysis"][header] = {
                        "status": "present",
                        "value": headers[header],
                        "description": info["description"],
                    }
                    present_count += 1
                else:
                    results["headers_analysis"][header] = {
                        "status": "missing",
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                    }
                    missing_count += 1

            results["summary"] = {
                "total_checked": len(security_headers),
                "present": present_count,
                "missing": missing_count,
                "score": f"{int(present_count / len(security_headers) * 100)}%",
            }

            return results

    except httpx.TimeoutException:
        return {"error": "请求超时", "url": url}
    except httpx.ConnectError:
        return {"error": "连接失败（目标不可达或 URL 错误）", "url": url}
    except ValueError as e:
        return {"error": f"输入验证失败: {str(e)}", "url": url}
    except Exception as e:
        logger.error(f"check_http_headers 失败: {e}")
        return {"error": str(e), "url": url}


async def query_dns(domain: str, record_type: str = "A") -> dict:
    """DNS 记录查询 — v2.0: 缓存"""
    domain = validate_domain(domain)

    valid_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "ALL"]
    if record_type.upper() not in valid_types:
        raise ValueError(f"无效的记录类型: {record_type}（支持: {', '.join(valid_types)}）")

    # 缓存
    cache = get_cache()
    cache_key = f"{domain}:{record_type}"
    cached = cache.get("dns_lookup", cache_key)
    if cached is not None:
        return cached

    results = {"domain": domain, "records": {}}

    if record_type.upper() == "ALL":
        types_to_query = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    else:
        types_to_query = [record_type.upper()]

    for rtype in types_to_query:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = [str(rdata) for rdata in answers]

            results["records"][rtype] = {
                "status": "success",
                "count": len(records),
                "values": records,
            }
        except dns.resolver.NXDOMAIN:
            results["records"][rtype] = {"status": "error", "error": "域名不存在"}
            break
        except dns.resolver.NoAnswer:
            results["records"][rtype] = {
                "status": "no_record",
                "message": f"该域名没有 {rtype} 记录",
            }
        except dns.resolver.NoNameservers:
            results["records"][rtype] = {
                "status": "error",
                "error": "无法找到权威 DNS 服务器",
            }
        except Exception as e:
            results["records"][rtype] = {"status": "error", "error": str(e)}

    cache.set("dns_lookup", cache_key, results, ttl=300)
    return results


async def geolocate_ip(ip: str) -> dict:
    """IP 地理位置查询 — v2.0: 缓存"""
    ip = validate_ip(ip)

    # 缓存
    cache = get_cache()
    cached = cache.get("ip_geolocation", ip)
    if cached is not None:
        return cached

    private_warning = None
    if is_private_ip(ip):
        private_warning = f"注意: {ip} 是私有/内网 IP，可能无法获取地理位置信息"

    api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(api_url, timeout=10.0)
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                result = {
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
                    "source": "ip-api.com",
                }
                if private_warning:
                    result["warning"] = private_warning

                cache.set("ip_geolocation", ip, result, ttl=86400)
                return result
            else:
                return {"error": data.get("message", "查询失败"), "ip": ip}
    except httpx.TimeoutException:
        return {
            "error": "API 请求超时",
            "ip": ip,
            "fallback_api": "可以尝试其他 API（如 ipinfo.io）",
        }
    except ValueError as e:
        return {"error": f"输入验证失败: {str(e)}", "ip": ip}
    except Exception as e:
        logger.error(f"geolocate_ip 失败: {e}")
        return {"error": str(e), "ip": ip}
