from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


SEVERITY_SCORES = {
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}

CRITICALITY_SCORES = {
    "low": 0,
    "medium": 10,
    "high": 25,
}

ENTITY_FIELDS = {
    "ip": ("source_ip", "ip", "src_ip", "client_ip"),
    "user": ("user_id", "username", "account", "account_name", "principal", "email", "user_email"),
    "host": ("hostname", "host", "device_id", "device_hash", "device", "endpoint", "endpoint_name"),
}


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _get_details(alert: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(alert, dict):
        return {}
    details = alert.get("details")
    return details if isinstance(details, dict) else {}


def _pick_value(alert: dict[str, Any], *keys: str) -> str:
    details = _get_details(alert)
    for key in keys:
        value = _safe_text(alert.get(key))
        if value:
            return value
        value = _safe_text(details.get(key))
        if value:
            return value
    return ""


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    text = _safe_text(value)
    if not text:
        return datetime.now(timezone.utc)
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def normalize_asset_criticality(value: Any, alert: dict[str, Any] | None = None, entity_type: str | None = None) -> str:
    direct = _safe_text(value).lower()
    if direct in CRITICALITY_SCORES:
        return direct

    alert = alert or {}
    details = _get_details(alert)
    candidate_values = [
        _safe_text(details.get("asset_criticality")).lower(),
        _safe_text(details.get(f"{entity_type}_criticality")).lower() if entity_type else "",
        _safe_text(details.get("criticality")).lower(),
        _safe_text(alert.get("asset_criticality")).lower(),
    ]
    for candidate in candidate_values:
        if candidate in CRITICALITY_SCORES:
            return candidate

    heuristics = " ".join([
        _pick_value(alert, "hostname", "host", "device", "device_id", "device_hash"),
        _pick_value(alert, "username", "user_id", "account", "email"),
        _pick_value(alert, "attack_type", "rule"),
    ]).lower()
    if any(token in heuristics for token in ("prod", "dc-", "domain", "admin", "finance", "payroll", "crown")):
        return "high"
    if any(token in heuristics for token in ("server", "vpn", "laptop", "workstation", "employee")):
        return "medium"
    return "low"


def extract_entities(alert: dict[str, Any] | None) -> list[dict[str, str]]:
    if not isinstance(alert, dict):
        return []
    entities: list[dict[str, str]] = []
    for entity_type, keys in ENTITY_FIELDS.items():
        value = _pick_value(alert, *keys)
        if value:
            entities.append({
                "type": entity_type,
                "value": value,
                "asset_criticality": normalize_asset_criticality(None, alert, entity_type),
            })
    return entities


def build_entity_enrichment(entity_type: str, entity_value: str, alert: dict[str, Any] | None = None) -> dict[str, Any]:
    alert = alert or {}
    details = _get_details(alert)
    if entity_type == "ip":
        geo_parts = [_safe_text(details.get("city")), _safe_text(details.get("region")), _safe_text(details.get("country"))]
        return {
            "geo": {
                "country": _safe_text(details.get("country") or alert.get("country")),
                "region": _safe_text(details.get("region")),
                "city": _safe_text(details.get("city")),
                "location": ", ".join([part for part in geo_parts if part]),
            },
            "asn": _safe_text(details.get("asn") or details.get("asn_org") or alert.get("asn")),
            "reputation": {
                "score": int(float(details.get("reputation_score") or details.get("risk_score") or alert.get("risk_score") or 0)),
                "label": _safe_text(details.get("threat_level") or alert.get("threat_level")),
                "is_tor": bool(details.get("is_tor") or alert.get("is_tor")),
                "is_proxy": bool(details.get("is_proxy") or alert.get("is_proxy")),
            },
        }
    if entity_type == "user":
        return {
            "geo": {
                "country": _safe_text(details.get("country") or alert.get("country")),
            },
            "asn": _safe_text(details.get("asn") or details.get("asn_org")),
            "reputation": {
                "score": int(float(details.get("risk_score") or alert.get("risk_score") or 0)),
                "label": _safe_text(details.get("threat_level") or alert.get("threat_level")),
                "department": _safe_text(details.get("department")),
                "email": _pick_value(alert, "email", "user_email"),
            },
        }
    return {
        "geo": {
            "country": _safe_text(details.get("country") or alert.get("country")),
        },
        "asn": _safe_text(details.get("asn") or details.get("asn_org")),
        "reputation": {
            "score": int(float(details.get("risk_score") or alert.get("risk_score") or 0)),
            "label": _safe_text(details.get("threat_level") or alert.get("threat_level")),
            "os": _safe_text(details.get("os") or details.get("device_os")),
            "managed": bool(details.get("managed") or details.get("is_managed")),
        },
    }


def compute_alert_risk(alert: dict[str, Any] | None, entity_type: str | None = None) -> int:
    alert = alert or {}
    details = _get_details(alert)
    base_risk = int(float(
        details.get("risk_score")
        or alert.get("risk_score")
        or details.get("reputation_score")
        or alert.get("reputation_score")
        or SEVERITY_SCORES.get(_safe_text(alert.get("severity") or details.get("severity")).lower(), 35)
    ))
    criticality = normalize_asset_criticality(None, alert, entity_type)
    behavior_bonus = 0
    sequence = alert.get("sequence") or details.get("sequence") or {}
    if isinstance(sequence, dict):
        seq_type = _safe_text(sequence.get("sequence_type") or sequence.get("type")).lower()
        if seq_type == "coordinated":
            behavior_bonus += 12
        elif seq_type == "critical":
            behavior_bonus += 20
    if bool(details.get("is_honeypot") or alert.get("is_honeypot")):
        behavior_bonus += 15
    if bool(details.get("coordinated_attack") or alert.get("coordinated_attack")):
        behavior_bonus += 10
    return max(0, min(100, base_risk + CRITICALITY_SCORES[criticality] + behavior_bonus))


def adjust_severity_for_criticality(severity: Any, asset_criticality: Any) -> str:
    normalized = _safe_text(severity).lower() or "medium"
    severity_order = ["low", "medium", "high", "critical"]
    if normalized not in severity_order:
        normalized = "medium"
    criticality = normalize_asset_criticality(asset_criticality)
    if criticality != "high":
        return normalized
    index = severity_order.index(normalized)
    return severity_order[min(index + 1, len(severity_order) - 1)]


def summarize_recent_alert(alert: dict[str, Any] | None) -> dict[str, Any]:
    alert = alert or {}
    details = _get_details(alert)
    return {
        "id": _safe_text(alert.get("id") or details.get("id")),
        "rule": _safe_text(alert.get("rule") or alert.get("attack_type") or details.get("rule") or details.get("attack_type")),
        "severity": _safe_text(alert.get("severity") or details.get("severity") or "medium").lower(),
        "risk_score": compute_alert_risk(alert),
        "timestamp": _parse_timestamp(alert.get("timestamp") or details.get("timestamp")).isoformat(),
    }


def merge_related_attack_types(existing: list[Any] | None, alerts: list[dict[str, Any]]) -> list[str]:
    seen = set()
    merged: list[str] = []
    for value in list(existing or []):
        text = _safe_text(value)
        if text and text.lower() not in seen:
            seen.add(text.lower())
            merged.append(text)
    for alert in alerts:
        rule = _safe_text(alert.get("rule") or alert.get("attack_type") or _get_details(alert).get("rule"))
        if rule and rule.lower() not in seen:
            seen.add(rule.lower())
            merged.append(rule)
    return merged


def build_activity_summary(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    severities = Counter(_safe_text(alert.get("severity") or _get_details(alert).get("severity") or "medium").lower() for alert in alerts)
    rules = Counter(_safe_text(alert.get("rule") or alert.get("attack_type") or _get_details(alert).get("rule")) for alert in alerts)
    return {
        "total_alerts": len(alerts),
        "severity_breakdown": {key: value for key, value in severities.items() if key},
        "top_attack_types": [rule for rule, _ in rules.most_common(3) if rule],
    }


def build_entity_profile(
    entity_type: str,
    entity_value: str,
    alerts: list[dict[str, Any]],
    cases: list[dict[str, Any]] | None = None,
    base_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_alerts = sorted(
        list(alerts or []),
        key=lambda item: _parse_timestamp(item.get("timestamp") or _get_details(item).get("timestamp")),
    )
    if not normalized_alerts:
        return {
            "entity_type": entity_type,
            "entity_key": entity_value,
            "display_name": entity_value,
            "first_seen": None,
            "last_seen": None,
            "alert_count": 0,
            "case_count": 0,
            "related_attack_types": [],
            "risk_score": 0,
            "asset_criticality": normalize_asset_criticality((base_profile or {}).get("asset_criticality")),
            "enrichment": (base_profile or {}).get("enrichment") or {},
            "activity_summary": {"total_alerts": 0, "severity_breakdown": {}, "top_attack_types": []},
            "recent_alerts": [],
        }

    first_seen = _parse_timestamp(normalized_alerts[0].get("timestamp") or _get_details(normalized_alerts[0]).get("timestamp"))
    last_seen = _parse_timestamp(normalized_alerts[-1].get("timestamp") or _get_details(normalized_alerts[-1]).get("timestamp"))
    asset_criticality = max(
        (normalize_asset_criticality(None, alert, entity_type) for alert in normalized_alerts),
        key=lambda value: CRITICALITY_SCORES[value],
        default=normalize_asset_criticality((base_profile or {}).get("asset_criticality")),
    )
    max_alert_risk = max(compute_alert_risk(alert, entity_type) for alert in normalized_alerts)
    aggregate_bonus = min(25, max(0, len(normalized_alerts) - 1) * 4)
    case_records = list(cases or [])
    case_count = len(case_records)
    case_bonus = min(15, case_count * 5)
    profile = {
        "entity_type": entity_type,
        "entity_key": entity_value,
        "display_name": entity_value,
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "alert_count": len(normalized_alerts),
        "case_count": case_count,
        "related_attack_types": merge_related_attack_types((base_profile or {}).get("related_attack_types"), normalized_alerts),
        "risk_score": min(100, max_alert_risk + aggregate_bonus + case_bonus),
        "asset_criticality": asset_criticality,
        "enrichment": ((base_profile or {}).get("enrichment") or {}) | build_entity_enrichment(entity_type, entity_value, normalized_alerts[-1]),
        "activity_summary": build_activity_summary(normalized_alerts),
        "recent_alerts": [summarize_recent_alert(alert) for alert in normalized_alerts[-5:]][::-1],
    }
    return profile
