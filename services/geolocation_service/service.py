import ipaddress
import json
import os
import threading
import time
import urllib.parse
import urllib.error
import urllib.request


_cache_lock = threading.Lock()
_cache: dict[str, dict] = {}


def get_geolocation_provider_url() -> str:
    return os.getenv(
        "GEOLOCATION_PROVIDER_URL",
        "https://ipwho.is/{ip}"
    )


def get_cache_ttl_seconds() -> int:
    return int(os.getenv("GEOLOCATION_CACHE_TTL_SECONDS", "3600"))


def is_private_or_reserved_ip(ip: str) -> tuple[bool, str | None]:
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return True, "invalid_ip"

    if parsed_ip.is_loopback:
        return True, "loopback_ip"
    if parsed_ip.is_private:
        return True, "private_ip"
    if parsed_ip.is_reserved:
        return True, "reserved_ip"
    if parsed_ip.is_multicast:
        return True, "multicast_ip"
    if parsed_ip.is_unspecified:
        return True, "unspecified_ip"

    return False, None


def get_cached_result(ip: str):
    with _cache_lock:
        cached = _cache.get(ip)
        if not cached:
            return None
        if time.time() - cached["cached_at"] > get_cache_ttl_seconds():
            _cache.pop(ip, None)
            return None
        return cached["value"]


def set_cached_result(ip: str, value: dict):
    with _cache_lock:
        _cache[ip] = {
            "cached_at": time.time(),
            "value": value
        }


def build_not_found_result(ip: str, reason: str) -> dict:
    return {
        "ip": ip,
        "found": False,
        "reason": reason,
        "latitude": None,
        "longitude": None,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None
    }


def normalize_provider_payload(ip: str, payload: dict) -> dict:
    ipwho_success = payload.get("success")
    ip_api_status = payload.get("status")

    if ipwho_success is False or (ip_api_status is not None and ip_api_status != "success"):
        return build_not_found_result(
            ip,
            payload.get("message")
            or payload.get("reason")
            or payload.get("error", {}).get("message")
            or "lookup_failed"
        )

    latitude = payload.get("latitude", payload.get("lat"))
    longitude = payload.get("longitude", payload.get("lon"))

    if latitude is None or longitude is None:
        return build_not_found_result(ip, "missing_coordinates")

    return {
        "ip": ip,
        "found": True,
        "reason": None,
        "latitude": latitude,
        "longitude": longitude,
        "country": payload.get("country"),
        "country_code": payload.get("country_code", payload.get("countryCode")),
        "region": payload.get("region", payload.get("regionName")),
        "city": payload.get("city")
    }


def fetch_ip_geolocation(ip: str) -> dict:
    private_or_reserved, reason = is_private_or_reserved_ip(ip)
    if private_or_reserved:
        return build_not_found_result(ip, reason)

    cached = get_cached_result(ip)
    if cached:
        return cached

    url = get_geolocation_provider_url().format(ip=urllib.parse.quote(ip, safe=""))

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (TimeoutError, urllib.error.URLError, json.JSONDecodeError):
        result = build_not_found_result(ip, "provider_unreachable")
        set_cached_result(ip, result)
        return result

    result = normalize_provider_payload(ip, payload)
    set_cached_result(ip, result)
    return result


def batch_lookup(ips: list[str]) -> list[dict]:
    unique_ips = []
    seen = set()

    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    return [fetch_ip_geolocation(ip) for ip in unique_ips]
