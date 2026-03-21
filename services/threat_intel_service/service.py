import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from services.geolocation_service.service import fetch_ip_geolocation
from shared.config import BASE_DIR


def get_provider_url() -> str:
    return os.getenv("THREAT_INTEL_PROVIDER_URL", "https://ipwho.is/{ip}")


def get_tor_nodes_file() -> Path:
    return Path(os.getenv("TOR_EXIT_NODES_FILE", BASE_DIR / "configs" / "tor_exit_nodes.txt"))


def load_tor_exit_nodes() -> set[str]:
    path = get_tor_nodes_file()
    if not path.exists():
        return set()
    with path.open(encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


TOR_EXIT_NODES = load_tor_exit_nodes()


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def fetch_provider_payload(ip: str) -> dict:
    url = get_provider_url().format(ip=urllib.parse.quote(ip, safe=""))
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {}


def enrich_event(route_payload: dict) -> dict:
    route = route_payload.get("route")
    event = dict(route_payload.get("event") or route_payload)
    ip = event.get("ip")
    geo = fetch_ip_geolocation(ip) if ip else {}
    provider_payload = fetch_provider_payload(ip) if is_public_ip(ip) else {}
    security = provider_payload.get("security", {})
    connection = provider_payload.get("connection", {})

    is_tor = bool(security.get("tor")) or ip in TOR_EXIT_NODES
    is_proxy = bool(
        security.get("proxy")
        or security.get("vpn")
        or provider_payload.get("proxy")
        or provider_payload.get("is_proxy")
    )
    asn = connection.get("asn") or provider_payload.get("asn")
    reputation_score = 10
    if geo.get("found"):
        reputation_score += 15
    if is_proxy:
        reputation_score += 30
    if is_tor:
        reputation_score += 45
    if event.get("status") == "failed":
        reputation_score += 10

    enriched = dict(event)
    enriched.update(
        {
            "route": route,
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
            "region": geo.get("region"),
            "city": geo.get("city"),
            "latitude": geo.get("latitude"),
            "longitude": geo.get("longitude"),
            "asn": asn,
            "is_tor": is_tor,
            "is_proxy": is_proxy,
            "reputation_score": min(reputation_score, 100),
        }
    )
    return enriched
