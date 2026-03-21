import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request
try:
    from flask_sock import Sock
except ImportError:
    class Sock:
        def __init__(self, app):
            self.app = app

        def route(self, path):
            def decorator(func):
                return func
            return decorator

from services.geolocation_service.service import fetch_ip_geolocation
from services.investigation_api.database import get_connection
from services.investigation_api.graph import investigate_account, investigate_device, investigate_ip
from services.investigation_api.models import get_alerts_by_ip, get_all_alerts, get_entity_profile
from shared.api_security import (
    enforce_rate_limit,
    get_rate_limit_identifier,
    issue_jwt,
    require_admin,
    require_api_key,
    require_jwt,
    require_user,
)
from shared.alert_state import (
    acknowledge_alert,
    add_note,
    assign_analyst,
    can_transition_disposition,
    get_state,
    link_case,
    lock_alert,
    merge_into_case,
    normalize_alert_disposition,
    normalize_alert_status,
    reopen_alert,
    set_case_id,
    set_disposition,
    set_false_positive,
    set_status,
    suppress_alert,
)
from shared.audit_log import get_logs, log_action
from shared.blocklist import block_ip, is_blocked
from shared.config import get_geolocation_target
from shared.entity_context import build_entity_profile, compute_alert_risk, extract_entities
from shared.incident_records import (
    create_case,
    get_case,
    get_investigation,
    link_cases,
    list_cases,
    list_investigations,
    merge_cases,
    split_case,
    update_case,
    update_investigation,
    upsert_investigation,
)
from shared.ioc_utils import (
    IOC_MAX_TEXT_VALUES,
    IOC_SUPPORTED_TYPES,
    extract_iocs_from_alert,
    flatten_text_values,
    is_valid_ip,
    iter_ioc_items,
    normalize_ioc_type,
    normalize_ioc_value,
    safe_string,
    validate_ioc_value,
)
from shared.kafka_utils import create_consumer, ensure_topics
from shared.mitre_mapping import MITRE_MAP, classify_threat
from shared.metrics import metrics_response
from shared.presence import get_online_users, remove_presence, update_presence
from shared.playbook_engine import (
    build_playbook_payload,
    execute_playbook,
    list_playbook_executions,
    list_playbooks,
)
from shared.rule_config import get_all_rule_config, update_rule_section
from shared.rule_config import get_detection_rule, list_detection_rules, update_detection_rule
from shared.topics import CANONICAL_TOPICS
from shared.users import USERS
from shared.watchlist_store import add_watchlist_entry, list_watchlist_entries, remove_watchlist_entry

app = Flask(__name__)
sock = Sock(app)
ws_clients = set()
ws_lock = threading.Lock()
stream_thread_started = False
ALLOWED_CORS_ORIGINS = {
    "http://localhost:63342",
    "http://localhost:8080",
    "http://127.0.0.1:63342",
    "http://127.0.0.1:8080",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://localhost:53390",
}
IOC_INDEX_CACHE = {
    "signature": None,
    "index": None,
    "typed_index": None,
    "alerts": [],
    "cases": [],
    "activity": [],
}
WATCHLIST_CACHE = {
    "signature": None,
    "entries": [],
    "stats": {},
}


def is_allowed_cors_origin(origin):
    if origin in ALLOWED_CORS_ORIGINS:
        return True
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and parsed.hostname in {"localhost", "127.0.0.1"}


@app.before_request
def handle_cors_preflight():
    if request.method == "OPTIONS":
        return ("", 204)


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and is_allowed_cors_origin(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, X-User, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


def authorize_request():
    identifier = get_rate_limit_identifier(dict(request.headers), request.remote_addr)
    try:
        auth_header = request.headers.get("Authorization", "")
        bearer_token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else None
        if bearer_token:
            require_jwt(bearer_token)
        else:
            require_api_key(request.headers.get("X-API-Key"))
        enforce_rate_limit(identifier)
    except PermissionError as exc:
        return jsonify({"detail": str(exc)}), 401
    except RuntimeError as exc:
        return jsonify({"detail": str(exc)}), 429
    return None


def get_authenticated_user(requirement: str = "user"):
    try:
        if requirement == "admin":
            return require_admin(dict(request.headers)), None
        return require_user(dict(request.headers)), None
    except PermissionError as exc:
        return None, (jsonify({"detail": str(exc)}), 403)


AUTH_ACTIVITY_TYPES = {"auth_login", "auth_logout", "auth_session_expired"}


def _filter_audit_logs_for_user(user: dict, logs: list[dict]) -> list[dict]:
    if user.get("role") == "admin":
        return logs
    return [
        entry for entry in logs
        if str(entry.get("actionType") or entry.get("action") or "").strip().lower() not in AUTH_ACTIVITY_TYPES
    ]


def broadcast_payload(payload: dict) -> None:
    dead_clients = []
    encoded = json.dumps(payload)
    with ws_lock:
        for client in ws_clients:
            try:
                client.send(encoded)
            except Exception:
                dead_clients.append(client)
        for client in dead_clients:
            ws_clients.discard(client)


def _build_entity_alert_summary(alert: dict) -> dict:
    details = alert.get("details") or {}
    return {
        "id": alert.get("id"),
        "rule": alert.get("rule") or alert.get("attack_type") or details.get("rule"),
        "severity": alert.get("severity") or details.get("severity") or "medium",
        "risk_score": details.get("risk_score") or alert.get("risk_score") or 0,
        "timestamp": alert.get("timestamp") or details.get("timestamp"),
    }


def _entity_matches_alert(alert: dict, entity_type: str, entity_key: str) -> bool:
    normalized = safe_string(entity_key).lower()
    if not normalized:
        return False
    return any(
        safe_string(entity.get("value")).lower() == normalized and safe_string(entity.get("type")).lower() == entity_type
        for entity in extract_entities(alert)
    )


def _get_alert_entity_context(alert: dict) -> dict:
    details = alert.get("details") or {}
    provided_context = details.get("entity_context") if isinstance(details.get("entity_context"), dict) else {}
    profiles = {}
    for entity in extract_entities(alert):
        entity_type = safe_string(entity.get("type")).lower()
        entity_key = safe_string(entity.get("value"))
        if not entity_type or not entity_key:
            continue
        stored = provided_context.get(entity_type) if isinstance(provided_context.get(entity_type), dict) else {}
        profiles[entity_type] = {
            "entity_type": entity_type,
            "entity_key": entity_key,
            "display_name": stored.get("display_name") or entity_key,
            "first_seen": stored.get("first_seen") or alert.get("timestamp") or details.get("timestamp"),
            "last_seen": stored.get("last_seen") or alert.get("timestamp") or details.get("timestamp"),
            "alert_count": stored.get("alert_count") or 1,
            "case_count": stored.get("case_count") or (1 if alert.get("case_id") else 0),
            "related_attack_types": stored.get("related_attack_types") or [alert.get("rule") or alert.get("attack_type")],
            "risk_score": stored.get("risk_score") or compute_alert_risk(alert, entity_type),
            "asset_criticality": stored.get("asset_criticality") or entity.get("asset_criticality") or "medium",
            "enrichment": stored.get("enrichment") or {},
            "activity_summary": stored.get("activity_summary") or {"total_alerts": stored.get("alert_count") or 1},
            "recent_alerts": stored.get("recent_alerts") or [_build_entity_alert_summary(alert)],
        }
    return profiles


def build_stream_payload(alert: dict) -> dict:
    details = alert.get("details") or {}
    entity_context = _get_alert_entity_context({**alert, "details": details})
    state = get_state(str(alert.get("id"))) if alert.get("id") is not None else {}
    iocs = _extract_iocs_from_alert({**alert, "details": details})
    explanation = alert.get("explanation") or details.get("explanation")
    risk_history = alert.get("risk_history") or details.get("risk_history")
    geo = fetch_ip_geolocation(alert.get("ip")) if alert.get("ip") else {}
    target = get_geolocation_target()
    rule = alert.get("rule")
    risk_score = details.get("risk_score") or details.get("reputation_score") or alert.get("risk_score") or 0
    is_honeypot = rule == "honeypot_access"
    coordinated_attack = rule == "coordinated_attack" or bool(details.get("coordinated_attack"))
    sequence = alert.get("sequence") or details.get("sequence")
    severity = "critical" if is_honeypot else alert.get("severity")
    mitre = alert.get("mitre") or details.get("mitre") or MITRE_MAP.get(rule)
    threat_level = alert.get("threat_level") or details.get("threat_level") or classify_threat(risk_score)
    blocked = bool(alert.get("is_blocked") or details.get("is_blocked") or is_blocked(alert.get("ip")))
    status = normalize_alert_status(alert.get("status") or details.get("status") or state.get("status") or "new")
    false_positive = bool(alert.get("false_positive") or details.get("false_positive") or state.get("false_positive"))
    disposition = normalize_alert_disposition(alert.get("disposition") or details.get("disposition") or state.get("disposition") or "new")
    analyst = (
        alert.get("analyst")
        or alert.get("assigned_to")
        or details.get("analyst")
        or details.get("assigned_to")
        or state.get("analyst")
        or state.get("assigned_to")
    )
    notes = alert.get("notes") or details.get("notes") or state.get("notes", [])
    locked_by = (
        alert.get("locked_by")
        or details.get("locked_by")
        or state.get("locked_by")
    )
    created_at = (
        alert.get("created_at")
        or details.get("created_at")
        or state.get("created_at")
        or alert.get("timestamp")
    )
    updated_at = (
        alert.get("updated_at")
        or details.get("updated_at")
        or state.get("updated_at")
        or created_at
    )
    acknowledged_at = (
        alert.get("acknowledged_at")
        or details.get("acknowledged_at")
        or state.get("acknowledged_at")
    )
    closed_at = (
        alert.get("closed_at")
        or details.get("closed_at")
        or state.get("closed_at")
    )
    sla_fields = _compute_sla_fields(created_at, acknowledged_at, closed_at, severity, risk_score)
    watchlist_meta = _get_alert_watchlist_metadata({"iocs": iocs})
    playbook = build_playbook_payload({**alert, "details": details, "attack_type": alert.get("attack_type") or rule})
    payload = {
        "id": alert.get("id"),
        "ip": alert.get("ip"),
        "source_ip": alert.get("ip"),
        "country": details.get("country") or geo.get("country"),
        "attack_type": rule,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "severity": severity,
        "mitre": mitre,
        "is_blocked": blocked,
            "status": status,
            "lifecycle": status,
        "false_positive": false_positive,
        "disposition": disposition,
        "analyst": analyst,
        "assigned_to": analyst,
        "iocs": iocs,
        "watchlist_hit": watchlist_meta["watchlist_hit"],
        "watchlist_hits_count": watchlist_meta["watchlist_hits_count"],
        "watchlist_matches": watchlist_meta["watchlist_matches"],
        "playbook": playbook,
        "recommended_actions": list((playbook or {}).get("recommended_actions") or []),
        "playbook_tags": list((playbook or {}).get("auto_tags") or []),
        "merged_into_case_id": alert.get("merged_into_case_id") or details.get("merged_into_case_id") or state.get("merged_into_case_id"),
        "notes": notes,
        "locked_by": locked_by,
        "created_at": created_at,
        "updated_at": updated_at,
        "acknowledged_at": acknowledged_at,
        "closed_at": closed_at,
        "time_to_ack": sla_fields["time_to_ack"],
        "time_to_close": sla_fields["time_to_close"],
        "sla_thresholds": sla_fields["sla_thresholds"],
        "sla_breaches": sla_fields["sla_breaches"],
        "overdue": sla_fields["overdue"],
        "urgency_score": sla_fields["urgency_score"],
        "is_honeypot": is_honeypot,
        "coordinated_attack": coordinated_attack,
        "confidence_label": "High confidence threat" if is_honeypot else ("Multi-stage attack detected" if coordinated_attack else None),
        "timestamp": alert.get("timestamp"),
        "entity_context": entity_context,
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
        "source_lat": geo.get("latitude"),
        "source_lon": geo.get("longitude"),
        "target_latitude": target["latitude"],
        "target_longitude": target["longitude"],
        "target_lat": target["latitude"],
        "target_lon": target["longitude"],
        "details": {
            **details,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "severity": severity,
            "rule": rule,
            "mitre": mitre,
            "is_blocked": blocked,
            "status": status,
            "lifecycle": status,
            "false_positive": false_positive,
            "disposition": disposition,
            "analyst": analyst,
            "assigned_to": analyst,
            "iocs": iocs,
            "watchlist_hit": watchlist_meta["watchlist_hit"],
            "watchlist_hits_count": watchlist_meta["watchlist_hits_count"],
            "watchlist_matches": watchlist_meta["watchlist_matches"],
            "playbook": playbook,
            "recommended_actions": list((playbook or {}).get("recommended_actions") or []),
            "playbook_tags": list((playbook or {}).get("auto_tags") or []),
            "merged_into_case_id": alert.get("merged_into_case_id") or details.get("merged_into_case_id") or state.get("merged_into_case_id"),
            "notes": notes,
            "updated_at": updated_at,
            "acknowledged_at": acknowledged_at,
            "closed_at": closed_at,
            "time_to_ack": sla_fields["time_to_ack"],
            "time_to_close": sla_fields["time_to_close"],
            "sla_thresholds": sla_fields["sla_thresholds"],
            "sla_breaches": sla_fields["sla_breaches"],
            "overdue": sla_fields["overdue"],
            "urgency_score": sla_fields["urgency_score"],
            "is_honeypot": is_honeypot,
            "coordinated_attack": coordinated_attack,
            "confidence_label": "High confidence threat" if is_honeypot else ("Multi-stage attack detected" if coordinated_attack else None),
            "entity_context": entity_context,
        },
    }
    if sequence:
        payload["sequence"] = {
            "type": sequence.get("sequence_type"),
            "attack_types": sequence.get("attack_types", []),
            "events": sequence.get("events", []),
        }
    if risk_history:
        payload["risk_history"] = risk_history
    if explanation:
        payload["explanation"] = explanation
    return payload


def serialize_alert(alert: dict) -> dict:
    details = alert.get("details") or {}
    entity_context = _get_alert_entity_context({**alert, "details": details})
    state = get_state(str(alert.get("id"))) if alert.get("id") is not None else {}
    iocs = _extract_iocs_from_alert({**alert, "details": details})
    explanation = alert.get("explanation") or details.get("explanation")
    risk_history = alert.get("risk_history") or details.get("risk_history")
    rule = alert.get("rule")
    risk_score = details.get("risk_score") or details.get("reputation_score") or alert.get("risk_score") or 0
    is_honeypot = rule == "honeypot_access" or bool(details.get("is_honeypot"))
    coordinated_attack = rule == "coordinated_attack" or bool(details.get("coordinated_attack"))
    sequence = alert.get("sequence") or details.get("sequence")
    severity = "critical" if is_honeypot else (alert.get("severity") or details.get("severity") or "medium")
    mitre = alert.get("mitre") or details.get("mitre") or MITRE_MAP.get(rule)
    threat_level = alert.get("threat_level") or details.get("threat_level") or classify_threat(risk_score)
    blocked = bool(alert.get("is_blocked") or details.get("is_blocked") or is_blocked(alert.get("ip")))
    status = normalize_alert_status(alert.get("status") or details.get("status") or state.get("status") or "new")
    false_positive = bool(alert.get("false_positive") or details.get("false_positive") or state.get("false_positive"))
    disposition = normalize_alert_disposition(alert.get("disposition") or details.get("disposition") or state.get("disposition") or "new")
    analyst = (
        alert.get("analyst")
        or alert.get("assigned_to")
        or details.get("analyst")
        or details.get("assigned_to")
        or state.get("analyst")
        or state.get("assigned_to")
    )
    notes = alert.get("notes") or details.get("notes") or state.get("notes", [])
    locked_by = (
        alert.get("locked_by")
        or details.get("locked_by")
        or state.get("locked_by")
    )
    created_at = (
        alert.get("created_at")
        or details.get("created_at")
        or state.get("created_at")
        or alert.get("timestamp")
    )
    updated_at = (
        alert.get("updated_at")
        or details.get("updated_at")
        or state.get("updated_at")
        or created_at
    )
    acknowledged_at = (
        alert.get("acknowledged_at")
        or details.get("acknowledged_at")
        or state.get("acknowledged_at")
    )
    closed_at = (
        alert.get("closed_at")
        or details.get("closed_at")
        or state.get("closed_at")
    )
    sla_fields = _compute_sla_fields(created_at, acknowledged_at, closed_at, severity, risk_score)
    watchlist_meta = _get_alert_watchlist_metadata({"iocs": iocs})
    playbook = build_playbook_payload({**alert, "details": details, "attack_type": alert.get("attack_type") or rule})

    payload = {
        **alert,
        "source_ip": alert.get("source_ip") or alert.get("ip"),
        "attack_type": alert.get("attack_type") or rule,
        "severity": severity,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "mitre": mitre,
        "is_blocked": blocked,
        "status": status,
        "lifecycle": status,
        "alert_lifecycle": status,
        "country": alert.get("country") or details.get("country"),
        "iocs": iocs,
        "watchlist_hit": watchlist_meta["watchlist_hit"],
        "watchlist_hits_count": watchlist_meta["watchlist_hits_count"],
        "watchlist_matches": watchlist_meta["watchlist_matches"],
        "playbook": playbook,
        "recommended_actions": list((playbook or {}).get("recommended_actions") or []),
        "playbook_tags": list((playbook or {}).get("auto_tags") or []),
        "false_positive": false_positive,
        "disposition": disposition,
        "analyst": analyst,
        "assigned_to": analyst,
        "merged_into_case_id": alert.get("merged_into_case_id") or details.get("merged_into_case_id") or state.get("merged_into_case_id"),
        "notes": notes,
        "locked_by": locked_by,
        "created_at": created_at,
        "updated_at": updated_at,
        "acknowledged_at": acknowledged_at,
        "closed_at": closed_at,
        "time_to_ack": sla_fields["time_to_ack"],
        "time_to_close": sla_fields["time_to_close"],
        "sla_thresholds": sla_fields["sla_thresholds"],
        "sla_breaches": sla_fields["sla_breaches"],
        "overdue": sla_fields["overdue"],
        "urgency_score": sla_fields["urgency_score"],
        "investigation_id": alert.get("investigation_id"),
        "case_id": alert.get("case_id") or state.get("case_id"),
        "is_honeypot": is_honeypot,
        "coordinated_attack": coordinated_attack,
        "confidence_label": "High confidence threat" if is_honeypot else ("Multi-stage attack detected" if coordinated_attack else None),
        "entity_context": entity_context,
        "details": {
            **details,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "severity": severity,
            "rule": rule,
            "mitre": mitre,
            "is_blocked": blocked,
            "status": status,
            "lifecycle": status,
            "false_positive": false_positive,
            "disposition": disposition,
            "analyst": analyst,
            "assigned_to": analyst,
            "iocs": iocs,
            "watchlist_hit": watchlist_meta["watchlist_hit"],
            "watchlist_hits_count": watchlist_meta["watchlist_hits_count"],
            "watchlist_matches": watchlist_meta["watchlist_matches"],
            "playbook": playbook,
            "recommended_actions": list((playbook or {}).get("recommended_actions") or []),
            "playbook_tags": list((playbook or {}).get("auto_tags") or []),
            "merged_into_case_id": alert.get("merged_into_case_id") or details.get("merged_into_case_id") or state.get("merged_into_case_id"),
            "notes": notes,
            "updated_at": updated_at,
            "acknowledged_at": acknowledged_at,
            "closed_at": closed_at,
            "time_to_ack": sla_fields["time_to_ack"],
            "time_to_close": sla_fields["time_to_close"],
            "sla_thresholds": sla_fields["sla_thresholds"],
            "sla_breaches": sla_fields["sla_breaches"],
            "overdue": sla_fields["overdue"],
            "urgency_score": sla_fields["urgency_score"],
            "is_honeypot": is_honeypot,
            "coordinated_attack": coordinated_attack,
            "entity_context": entity_context,
            "confidence_label": "High confidence threat" if is_honeypot else ("Multi-stage attack detected" if coordinated_attack else None),
        },
    }
    if sequence:
        payload["sequence"] = {
            "type": sequence.get("sequence_type"),
            "attack_types": sequence.get("attack_types", []),
            "events": sequence.get("events", []),
        }
    if risk_history:
        payload["risk_history"] = risk_history
    if explanation:
        payload["explanation"] = explanation
    return payload


def _serialize_alerts_with_correlation(raw_alerts: list[dict]) -> list[dict]:
    serialized_alerts = [_attach_incident_links(serialize_alert(alert)) for alert in raw_alerts]
    return [_attach_correlation_metadata(alert, serialized_alerts) for alert in serialized_alerts]


def _safe_string(value) -> str:
    return safe_string(value)


def _dedupe_preserve(values):
    seen = set()
    deduped = []
    for value in values:
        normalized = _safe_string(value)
        if not normalized:
            continue
        marker = normalized.lower()
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(normalized)
    return deduped


def _flatten_text_values(value, bucket: list[str], limit: int = IOC_MAX_TEXT_VALUES):
    flatten_text_values(value, bucket, limit)


def _is_valid_ip(value: str) -> bool:
    return is_valid_ip(value)


def _looks_like_hostname(value: str) -> bool:
    normalized = normalize_ioc_value("hostname", value)
    return validate_ioc_value("hostname", normalized)


def _extract_iocs_from_alert(alert: dict) -> dict:
    return extract_iocs_from_alert(alert)


def _collect_alert_ioc_terms(alert: dict) -> list[str]:
    return _dedupe_preserve([
        normalized_value
        for _, _, _, normalized_value in iter_ioc_items(alert.get("iocs") or {})
    ])


def _build_ioc_index(alerts: list[dict], cases: list[dict], activity: list[dict]) -> dict:
    index: dict[str, dict[str, list]] = {}
    typed_index: dict[str, dict[str, dict[str, list]]] = {
        ioc_type: {}
        for ioc_type in IOC_SUPPORTED_TYPES
    }

    def ensure_entry(key: str) -> dict[str, list]:
        normalized_key = _safe_string(key).lower()
        if not normalized_key:
            return {"alerts": [], "cases": [], "activity": []}
        if normalized_key not in index:
            index[normalized_key] = {"alerts": [], "cases": [], "activity": []}
        return index[normalized_key]

    def ensure_typed_entry(ioc_type: str, key: str) -> dict[str, list]:
        normalized_type = normalize_ioc_type(ioc_type)
        normalized_key = normalize_ioc_value(normalized_type, key)
        if not normalized_type or not normalized_key:
            return {"alerts": [], "cases": [], "activity": []}
        bucket = typed_index.setdefault(normalized_type, {})
        if normalized_key not in bucket:
            bucket[normalized_key] = {"alerts": [], "cases": [], "activity": []}
        return bucket[normalized_key]

    for alert in alerts:
        alert_ioc_items = iter_ioc_items(alert.get("iocs") or {})
        for ioc_type, _, _, normalized_value in alert_ioc_items:
            ensure_entry(normalized_value)["alerts"].append(alert)
            ensure_typed_entry(ioc_type, normalized_value)["alerts"].append(alert)

    for case in cases:
        case_ioc_terms = set()
        case_ioc_items: set[tuple[str, str]] = set()
        source_alert = case.get("alert") or {}
        case_ioc_terms.update(_collect_alert_ioc_terms(source_alert))
        case_ioc_items.update(
            (ioc_type, normalized_value)
            for ioc_type, _, _, normalized_value in iter_ioc_items(source_alert.get("iocs") or {})
        )
        for linked_alert in case.get("linked_alerts") or []:
            case_ioc_terms.update(_collect_alert_ioc_terms(linked_alert))
            case_ioc_items.update(
                (ioc_type, normalized_value)
                for ioc_type, _, _, normalized_value in iter_ioc_items(linked_alert.get("iocs") or {})
            )
        for term in case_ioc_terms:
            ensure_entry(term)["cases"].append(case)
        for ioc_type, normalized_value in case_ioc_items:
            ensure_typed_entry(ioc_type, normalized_value)["cases"].append(case)

    for entry in activity:
        haystack = "\n".join([
            _safe_string(entry.get("target")),
            _safe_string(entry.get("message")),
            _safe_string(entry.get("details")),
            _safe_string(entry.get("target_id")),
            _safe_string(entry.get("related_alert_id")),
            _safe_string(entry.get("related_case_id")),
        ]).lower()
        for key, bucket in index.items():
            if key and key in haystack:
                bucket["activity"].append(entry)
        for ioc_type, buckets in typed_index.items():
            for key, bucket in buckets.items():
                if key and key in haystack:
                    bucket["activity"].append(entry)

    for bucket in index.values():
        bucket["alerts"] = list({str(item.get("id")): item for item in bucket["alerts"]}.values())
        bucket["cases"] = list({str(item.get("id")): item for item in bucket["cases"]}.values())
        bucket["activity"] = list({
            f"{_safe_string(item.get('target_id'))}|{_safe_string(item.get('action'))}|{_safe_string(item.get('timestamp'))}": item
            for item in bucket["activity"]
        }.values())
    for buckets in typed_index.values():
        for bucket in buckets.values():
            bucket["alerts"] = list({str(item.get("id")): item for item in bucket["alerts"]}.values())
            bucket["cases"] = list({str(item.get("id")): item for item in bucket["cases"]}.values())
            bucket["activity"] = list({
                f"{_safe_string(item.get('target_id'))}|{_safe_string(item.get('action'))}|{_safe_string(item.get('timestamp'))}": item
                for item in bucket["activity"]
            }.values())
    return {
        "by_value": index,
        "by_type": typed_index,
    }


def _get_cached_ioc_index():
    alerts = [_attach_incident_links(serialize_alert(alert)) for alert in get_all_alerts()]
    cases = [serialize_case(record) for record in list_cases()]
    activity = get_logs()
    signature = json.dumps({
        "alerts": [
            {
                "id": alert.get("id"),
                "updated_at": alert.get("updated_at"),
                "timestamp": alert.get("timestamp"),
                "case_id": alert.get("case_id"),
            }
            for alert in alerts
        ],
        "cases": [
            {
                "id": case.get("id"),
                "updated_at": case.get("updated_at"),
                "linked_alert_ids": case.get("linked_alert_ids"),
            }
            for case in cases
        ],
        "activity": len(activity),
    }, sort_keys=True)
    if IOC_INDEX_CACHE["signature"] != signature:
        IOC_INDEX_CACHE["signature"] = signature
        IOC_INDEX_CACHE["alerts"] = alerts
        IOC_INDEX_CACHE["cases"] = cases
        IOC_INDEX_CACHE["activity"] = activity
        built_index = _build_ioc_index(alerts, cases, activity)
        IOC_INDEX_CACHE["index"] = built_index.get("by_value") or {}
        IOC_INDEX_CACHE["typed_index"] = built_index.get("by_type") or {}
    return IOC_INDEX_CACHE


def _get_watchlist_cache():
    cache = _get_cached_ioc_index()
    entries = list_watchlist_entries()
    signature = json.dumps({
        "entries": [
            {
                "type": _safe_string(entry.get("type")).lower(),
                "value": _safe_string(entry.get("value")).lower(),
                "created_at": entry.get("created_at"),
            }
            for entry in entries
        ],
        "ioc_signature": cache.get("signature"),
    }, sort_keys=True)
    if WATCHLIST_CACHE["signature"] != signature:
        stats = {}
        index = cache.get("index") or {}
        for entry in entries:
            entry_type = _safe_string(entry.get("type")).lower()
            entry_value = _safe_string(entry.get("value"))
            bucket = index.get(entry_value.lower(), {"alerts": [], "cases": [], "activity": []})
            last_seen_ts = max(
                [
                    _to_timestamp_seconds(alert.get("updated_at") or alert.get("timestamp"))
                    for alert in bucket["alerts"]
                    if _to_timestamp_seconds(alert.get("updated_at") or alert.get("timestamp")) is not None
                ] or [0]
            )
            stats[(entry_type, entry_value.lower())] = {
                "type": entry_type,
                "value": entry_value,
                "created_at": entry.get("created_at"),
                "created_by": entry.get("created_by"),
                "hits_count": len(bucket["alerts"]),
                "cases_count": len(bucket["cases"]),
                "activity_count": len(bucket["activity"]),
                "last_seen_at": datetime.fromtimestamp(last_seen_ts).isoformat() if last_seen_ts else None,
            }
        WATCHLIST_CACHE["signature"] = signature
        WATCHLIST_CACHE["entries"] = entries
        WATCHLIST_CACHE["stats"] = stats
    return WATCHLIST_CACHE


def _get_alert_watchlist_metadata(alert: dict) -> dict:
    iocs = alert.get("iocs") or {}
    watchlist = _get_watchlist_cache()
    stats = watchlist.get("stats") or {}
    matches = []
    for entry_type, values in (
        ("ip", iocs.get("ips") or []),
        ("domain", iocs.get("domains") or []),
        ("email", iocs.get("emails") or []),
        ("hash", iocs.get("hashes") or []),
        ("username", iocs.get("usernames") or []),
        ("hostname", iocs.get("hostnames") or []),
    ):
        for value in values:
            stat = stats.get((entry_type, _safe_string(value).lower()))
            if stat:
                matches.append(stat)
    deduped = list({
        f"{item['type']}|{item['value'].lower()}": item
        for item in matches
    }.values())
    return {
        "watchlist_matches": deduped,
        "watchlist_hit": bool(deduped),
        "watchlist_hits_count": sum(item.get("hits_count", 0) for item in deduped),
    }


def _build_correlation_explanation(base_alert: dict, candidate_alert: dict) -> dict | None:
    base_iocs = base_alert.get("iocs") or {}
    candidate_iocs = candidate_alert.get("iocs") or {}
    matched_fields = []
    if set(base_iocs.get("ips") or []).intersection(candidate_iocs.get("ips") or []):
        matched_fields.append("ip")
    if set(base_iocs.get("usernames") or []).intersection(candidate_iocs.get("usernames") or []):
        matched_fields.append("user")
    if set(base_iocs.get("hostnames") or []).intersection(candidate_iocs.get("hostnames") or []):
        matched_fields.append("device")
    if not matched_fields:
        return None

    if "ip" in matched_fields and "user" in matched_fields:
        rule_source = "multi_signal_ip_user"
    elif "device" in matched_fields:
        rule_source = "device_identity_overlap"
    else:
        rule_source = "shared_entity_signal"

    score = 0.2
    if "ip" in matched_fields:
        score += 0.34
    if "user" in matched_fields:
        score += 0.24
    if "device" in matched_fields:
        score += 0.18
    confidence_score = min(round(score, 2), 0.99)

    fragments = []
    if "ip" in matched_fields:
        ip_value = next(iter(set(base_iocs.get("ips") or []).intersection(candidate_iocs.get("ips") or [])), "")
        fragments.append(f"same source IP ({ip_value})")
    if "user" in matched_fields:
        user_value = next(iter(set(base_iocs.get("usernames") or []).intersection(candidate_iocs.get("usernames") or [])), "")
        fragments.append(f"same user ({user_value})")
    if "device" in matched_fields:
        device_value = next(iter(set(base_iocs.get("hostnames") or []).intersection(candidate_iocs.get("hostnames") or [])), "")
        fragments.append(f"same device/host ({device_value})")
    correlation_reason = f"Related because both alerts share {', '.join(fragments)}."

    return {
        "matched_fields": matched_fields,
        "correlation_reason": correlation_reason,
        "confidence_score": confidence_score,
        "rule_source": rule_source,
    }


def _attach_correlation_metadata(alert: dict, alerts: list[dict]) -> dict:
    explanations = []
    for candidate in alerts:
        if str(candidate.get("id")) == str(alert.get("id")):
            continue
        explanation = _build_correlation_explanation(alert, candidate)
        if not explanation:
            continue
        explanations.append({
            "alert_id": candidate.get("id"),
            **explanation,
        })
    explanations.sort(key=lambda entry: entry.get("confidence_score", 0), reverse=True)
    top = explanations[0] if explanations else None
    return {
        **alert,
        "correlation": {
            "matched_fields": top.get("matched_fields", []) if top else [],
            "correlation_reason": top.get("correlation_reason", "") if top else "",
            "confidence_score": top.get("confidence_score", 0.0) if top else 0.0,
            "rule_source": top.get("rule_source", "") if top else "",
            "related": explanations[:8],
        }
    }


SLA_THRESHOLDS_SECONDS = {
    "critical": {"ack": 5 * 60, "close": 30 * 60},
    "high": {"ack": 15 * 60, "close": 2 * 60 * 60},
    "medium": {"ack": 60 * 60, "close": 8 * 60 * 60},
    "low": {"ack": 60 * 60, "close": 8 * 60 * 60},
}


def _to_timestamp_seconds(value):
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        return numeric / 1000 if numeric > 9999999999 else numeric
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.timestamp()
    except Exception:
        return None


def _compute_sla_fields(created_at, acknowledged_at, closed_at, severity, risk_score):
    created_ts = _to_timestamp_seconds(created_at)
    ack_ts = _to_timestamp_seconds(acknowledged_at)
    close_ts = _to_timestamp_seconds(closed_at)
    severity_key = str(severity or "medium").strip().lower()
    thresholds = SLA_THRESHOLDS_SECONDS.get(severity_key, SLA_THRESHOLDS_SECONDS["medium"])

    time_to_ack = max(0, ack_ts - created_ts) if created_ts and ack_ts else None
    time_to_close = max(0, close_ts - created_ts) if created_ts and close_ts else None
    now_ts = time.time()
    ack_overdue = bool(
        created_ts and (
            (ack_ts and ack_ts - created_ts > thresholds["ack"])
            or (not ack_ts and now_ts - created_ts > thresholds["ack"])
        )
    )
    close_overdue = bool(
        created_ts and (
            (close_ts and close_ts - created_ts > thresholds["close"])
            or (not close_ts and now_ts - created_ts > thresholds["close"])
        )
    )
    overdue = ack_overdue or close_overdue

    severity_weight = {
        "critical": 40,
        "high": 28,
        "medium": 16,
        "low": 8,
    }.get(severity_key, 16)
    risk_value = float(risk_score or 0)
    age_seconds = max(0, now_ts - created_ts) if created_ts else 0
    age_factor = min(40, age_seconds / 300)
    breach_factor = 20 if overdue else 0
    urgency_score = round(severity_weight + min(40, risk_value / 3) + age_factor + breach_factor, 2)

    return {
        "created_at": created_ts or created_at,
        "acknowledged_at": ack_ts,
        "closed_at": close_ts,
        "time_to_ack": time_to_ack,
        "time_to_close": time_to_close,
        "sla_thresholds": thresholds,
        "overdue": overdue,
        "sla_breaches": {
            "ack": ack_overdue,
            "close": close_overdue,
        },
        "urgency_score": urgency_score,
    }


def _find_serialized_alert(alert_id: str) -> dict | None:
    normalized = _safe_string(alert_id)
    if not normalized:
        return None

    try:
        alerts = get_all_alerts()
    except Exception:
        return None

    for alert in alerts:
        serialized = serialize_alert(alert)
        if str(serialized.get("id")) == normalized:
            return serialized
    return None


def _find_linked_investigation_by_alert(alert_id: str) -> dict | None:
    normalized = _safe_string(alert_id)
    if not normalized:
        return None
    return next(
        (record for record in list_investigations() if _safe_string(record.get("alert_id")) == normalized),
        None,
    )


def _find_linked_case(alert_id: str | None = None, investigation_id: str | None = None) -> dict | None:
    normalized_alert_id = _safe_string(alert_id)
    normalized_investigation_id = _safe_string(investigation_id)
    return next(
        (
            record for record in list_cases()
            if (
                normalized_alert_id
                and (
                    _safe_string(record.get("source_alert_id")) == normalized_alert_id
                    or _safe_string(record.get("alert_id")) == normalized_alert_id
                    or normalized_alert_id in [_safe_string(value) for value in (record.get("linked_alert_ids") or [])]
                )
            )
            or (
                normalized_investigation_id
                and (
                    _safe_string(record.get("source_investigation_id")) == normalized_investigation_id
                    or _safe_string(record.get("investigation_id")) == normalized_investigation_id
                )
            )
        ),
        None,
    )


def _broadcast_alert_state(alert_id: str) -> None:
    state = get_state(alert_id)
    broadcast_payload({
        "type": "alert_update",
        "alert_id": alert_id,
        "assigned_to": state.get("assigned_to") or state.get("analyst"),
        "status": state.get("status"),
        "disposition": state.get("disposition"),
        "merged_into_case_id": state.get("merged_into_case_id"),
        "updated_at": state.get("updated_at"),
    })


def _alert_action_response(alert_id: str, action: str):
    serialized = _find_serialized_alert(alert_id)
    return jsonify({
        "status": "success",
        "id": alert_id,
        "action": action,
        "alert": _attach_incident_links(serialized) if serialized else None,
    })


def _collect_related_alert_ids(entity_key: str | None, fallback_alert_id: str) -> list[str]:
    normalized_entity_key = _safe_string(entity_key)
    normalized_alert_id = _safe_string(fallback_alert_id)
    related_alert_ids: list[str] = []
    try:
        alerts = get_all_alerts()
    except Exception:
        alerts = []

    for alert in alerts:
        serialized = serialize_alert(alert)
        if normalized_entity_key and _safe_string(serialized.get("source_ip")) != normalized_entity_key:
            continue
        serialized_id = _safe_string(serialized.get("id"))
        if serialized_id:
            related_alert_ids.append(serialized_id)

    if normalized_alert_id and normalized_alert_id not in related_alert_ids:
        related_alert_ids.append(normalized_alert_id)
    return sorted(set(related_alert_ids))


def _attach_incident_links(alert: dict) -> dict:
    linked_investigation = _find_linked_investigation_by_alert(str(alert.get("id")))
    linked_case = _find_linked_case(alert_id=str(alert.get("id")))
    alert["investigation_id"] = linked_investigation.get("id") if linked_investigation else None
    alert["case_id"] = linked_case.get("id") if linked_case else None
    return alert


def serialize_investigation(record: dict) -> dict:
    investigation = dict(record)
    linked_case = _find_linked_case(
        alert_id=investigation.get("alert_id"),
        investigation_id=investigation.get("id"),
    )
    investigation["alert"] = investigation.get("alert") or _find_serialized_alert(investigation.get("alert_id"))
    related_alert_ids = investigation.get("related_alert_ids") or []
    investigation["related_alerts"] = [
        alert
        for alert in (_find_serialized_alert(alert_id) for alert_id in related_alert_ids)
        if alert is not None
    ]
    investigation["case_id"] = linked_case.get("id") if linked_case else None
    investigation["entity_key"] = investigation.get("entity_key") or investigation.get("alert", {}).get("source_ip")
    investigation["created_by"] = investigation.get("created_by") or investigation.get("analyst")
    investigation["status"] = investigation.get("status") or "open"
    investigation["created_at"] = investigation.get("created_at")
    investigation["updated_at"] = investigation.get("updated_at")
    investigation["notes"] = investigation.get("notes") or []
    investigation["actions"] = investigation.get("actions") or []
    return investigation


def serialize_case(record: dict) -> dict:
    case = dict(record)
    investigation_id = case.get("source_investigation_id") or case.get("investigation_id")
    source_alert_id = case.get("source_alert_id") or case.get("alert_id")
    investigation = get_investigation(investigation_id) if investigation_id else None
    case["alert"] = case.get("alert") or _find_serialized_alert(source_alert_id)
    case["investigation"] = serialize_investigation(investigation) if investigation else None
    case["source_alert_id"] = source_alert_id
    case["source_investigation_id"] = investigation_id
    case["linked_alert_ids"] = case.get("linked_alert_ids") or ([source_alert_id] if source_alert_id else [])
    case["parent_case_id"] = case.get("parent_case_id")
    case["linked_cases"] = [str(case_id) for case_id in (case.get("linked_cases") or []) if case_id]
    case["linked_alerts"] = [
        alert
        for alert in (_find_serialized_alert(alert_id) for alert_id in case["linked_alert_ids"])
        if alert is not None
    ]
    case["related_cases"] = [
        {
            "id": related_case.get("id"),
            "title": related_case.get("title"),
            "status": related_case.get("status"),
            "priority": related_case.get("priority"),
            "severity": related_case.get("severity"),
            "parent_case_id": related_case.get("parent_case_id"),
        }
        for related_case in (get_case(case_id) for case_id in case["linked_cases"])
        if related_case is not None
    ]
    case["notes"] = case.get("notes") or []
    case["actions"] = case.get("actions") or []
    evidence = case.get("evidence") if isinstance(case.get("evidence"), dict) else {}
    timeline = list(evidence.get("timeline") or [])
    enrichments = list(evidence.get("enrichments") or [])
    analyst_notes = list(evidence.get("analyst_notes") or [])
    seen_timeline = set()
    seen_notes = set()
    deduped_timeline = []
    deduped_notes = []
    for action in case["actions"]:
        if isinstance(action, dict):
            timeline.append(dict(action))
    for note in case["notes"]:
        if isinstance(note, dict):
            analyst_notes.append(dict(note))
    if not enrichments and case.get("alert"):
        enrichments.append({
            "timestamp": case.get("created_at") or time.time(),
            "source": "source_alert",
            "snapshot": {
                "id": case["alert"].get("id"),
                "source_ip": case["alert"].get("source_ip") or case["alert"].get("ip"),
                "attack_type": case["alert"].get("attack_type") or case["alert"].get("attackType") or case["alert"].get("rule"),
                "severity": case["alert"].get("severity"),
                "risk_score": case["alert"].get("risk_score"),
                "country": case["alert"].get("country"),
                "disposition": case["alert"].get("disposition"),
                "watchlist_hit": case["alert"].get("watchlist_hit"),
            },
        })
    for entry in timeline:
        if not isinstance(entry, dict):
            continue
        key = (
            str(entry.get("timestamp") or ""),
            str(entry.get("type") or entry.get("actionType") or ""),
            str(entry.get("text") or entry.get("message") or entry.get("label") or ""),
        )
        if key in seen_timeline:
            continue
        seen_timeline.add(key)
        deduped_timeline.append(entry)
    for entry in analyst_notes:
        if not isinstance(entry, dict):
            continue
        key = (
            str(entry.get("timestamp") or ""),
            str(entry.get("text") or entry.get("message") or ""),
        )
        if key in seen_notes:
            continue
        seen_notes.add(key)
        deduped_notes.append(entry)
    case["evidence"] = {
        "timeline": deduped_timeline,
        "enrichments": enrichments,
        "analyst_notes": deduped_notes,
    }
    case["severity"] = case.get("severity") or case.get("alert", {}).get("severity") or "medium"
    return case


def _build_case_report_payload(case: dict) -> dict:
    source_alert = case.get("alert") or {}
    linked_alerts = case.get("linked_alerts") or []
    evidence = case.get("evidence") or {}
    timeline = sorted(
        [entry for entry in evidence.get("timeline", []) if isinstance(entry, dict)],
        key=lambda item: float(item.get("timestamp") or 0),
        reverse=True,
    )
    analyst_notes = sorted(
        [entry for entry in evidence.get("analyst_notes", []) if isinstance(entry, dict)],
        key=lambda item: float(item.get("timestamp") or 0),
        reverse=True,
    )
    enrichments = [entry for entry in evidence.get("enrichments", []) if isinstance(entry, dict)]

    return {
        "case_id": case.get("id"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "overview": {
            "title": case.get("title"),
            "status": case.get("status"),
            "priority": case.get("priority"),
            "severity": case.get("severity"),
            "assignee": case.get("assignee"),
            "created_at": case.get("created_at"),
            "updated_at": case.get("updated_at"),
            "source_alert_id": case.get("source_alert_id"),
            "source_investigation_id": case.get("source_investigation_id"),
        },
        "alerts": [
            {
                "id": alert.get("id"),
                "attack_type": alert.get("attack_type") or alert.get("attackType") or alert.get("rule"),
                "source_ip": alert.get("source_ip") or alert.get("sourceIp") or alert.get("ip"),
                "severity": alert.get("severity"),
                "country": alert.get("country"),
                "disposition": alert.get("disposition"),
            }
            for alert in linked_alerts
        ],
        "timeline": [
            {
                "timestamp": entry.get("timestamp"),
                "actor": entry.get("actor") or entry.get("author"),
                "action": entry.get("actionType") or entry.get("type"),
                "message": entry.get("message") or entry.get("label"),
                "status": entry.get("status"),
                "target_id": entry.get("targetId") or entry.get("target_id"),
            }
            for entry in timeline
        ],
        "evidence": {
            "enrichments": enrichments,
            "analyst_notes": analyst_notes,
        },
        "conclusion": {
            "summary": case.get("summary") or "No summary provided.",
            "linked_alert_count": len(linked_alerts),
            "timeline_entries": len(timeline),
            "latest_note": analyst_notes[0].get("text") if analyst_notes else "",
            "primary_source_ip": source_alert.get("source_ip") or source_alert.get("sourceIp") or source_alert.get("ip"),
        },
        "technical_summary": {
            "source_ip": source_alert.get("source_ip") or source_alert.get("sourceIp") or source_alert.get("ip"),
            "attack_type": source_alert.get("attack_type") or source_alert.get("attackType") or source_alert.get("rule"),
            "severity": source_alert.get("severity") or case.get("severity"),
            "risk_score": source_alert.get("risk_score"),
            "mitre": source_alert.get("mitre"),
            "ioc_count": sum(len((alert.get("iocs") or {}).get(key, [])) for alert in linked_alerts for key in ["ips", "domains", "emails", "hashes", "usernames", "hostnames"]),
        },
        "analyst_timeline": [
            {
                "timestamp": entry.get("timestamp"),
                "author": entry.get("actor") or entry.get("author"),
                "message": entry.get("message") or entry.get("label"),
            }
            for entry in timeline
        ],
    }


def _pdf_escape(text: str) -> str:
    return str(text or "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_pdf_text(text: str, limit: int = 92) -> list[str]:
    words = str(text or "").split()
    if not words:
        return [""]
    lines = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= limit:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _build_case_report_pdf(payload: dict) -> bytes:
    lines = [
        f"Case Report - {payload['overview'].get('title') or payload.get('case_id')}",
        f"Case ID: {payload.get('case_id')}",
        f"Status: {payload['overview'].get('status')} | Priority: {payload['overview'].get('priority')} | Severity: {payload['overview'].get('severity')}",
        f"Assignee: {payload['overview'].get('assignee') or 'Unassigned'}",
        f"Created: {payload['overview'].get('created_at')} | Updated: {payload['overview'].get('updated_at')}",
        "",
        "Overview",
        payload["conclusion"].get("summary") or "No summary provided.",
        "",
        "Alerts",
    ]
    for alert in payload.get("alerts", []):
        lines.append(f"- {alert.get('id')} | {alert.get('attack_type')} | {alert.get('source_ip')} | {alert.get('severity')}")
    lines.extend(["", "Timeline"])
    for entry in payload.get("timeline", []):
        lines.append(f"- {entry.get('timestamp')} | {entry.get('actor') or 'Unknown'} | {entry.get('action')} | {entry.get('message')}")
    lines.extend(["", "Evidence"])
    for note in payload.get("evidence", {}).get("analyst_notes", []):
        lines.append(f"- Note {note.get('timestamp')} | {note.get('text') or note.get('message') or ''}")
    lines.extend(["", "Conclusion"])
    lines.append(f"Primary source IP: {payload['conclusion'].get('primary_source_ip') or 'Unknown'}")
    lines.append(f"Linked alerts: {payload['conclusion'].get('linked_alert_count')}")
    lines.append(f"Timeline entries: {payload['conclusion'].get('timeline_entries')}")

    wrapped_lines = []
    for line in lines:
        wrapped_lines.extend(_wrap_pdf_text(line))

    page_height = 792
    line_height = 14
    start_y = 760
    content_stream = ["BT", "/F1 11 Tf"]
    y = start_y
    for line in wrapped_lines:
        if y < 40:
            break
        content_stream.append(f"72 {y} Td ({_pdf_escape(line)}) Tj")
        y -= line_height
    content_stream.append("ET")
    content_bytes = "\n".join(content_stream).encode("latin-1", errors="replace")

    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
        f"4 0 obj << /Length {len(content_bytes)} >> stream\n".encode("latin-1") + content_bytes + b"\nendstream endobj",
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    ]
    buffer = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(buffer))
        buffer.extend(obj)
        buffer.extend(b"\n")
    xref_offset = len(buffer)
    buffer.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    buffer.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    buffer.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("latin-1"))
    return bytes(buffer)


def build_search_results(query: str) -> dict:
    normalized_query = _safe_string(query).lower()
    alerts = [_attach_incident_links(serialize_alert(alert)) for alert in get_all_alerts()]
    investigations = [serialize_investigation(record) for record in list_investigations()]
    cases = [serialize_case(record) for record in list_cases()]

    if not normalized_query:
        return {
            "query": "",
            "alerts": [],
            "investigations": investigations[:5],
            "cases": cases[:5],
            "total": len(investigations[:5]) + len(cases[:5]),
        }

    def matches(value) -> bool:
        if value is None:
            return False
        if isinstance(value, (list, tuple, set)):
            return any(matches(item) for item in value)
        if isinstance(value, dict):
            return any(matches(item) for item in value.values())
        return normalized_query in str(value).lower()

    matched_alerts = [
        alert for alert in alerts
        if matches([
            alert.get("id"),
            alert.get("ip"),
            alert.get("source_ip"),
            alert.get("rule"),
            alert.get("severity"),
            alert.get("status"),
            alert.get("country"),
            alert.get("analyst"),
            alert.get("details"),
        ])
    ][:20]
    matched_investigations = [
        record for record in investigations
        if matches(record)
    ][:10]
    matched_cases = [
        record for record in cases
        if matches(record)
    ][:10]

    return {
        "query": query,
        "alerts": matched_alerts,
        "investigations": matched_investigations,
        "cases": matched_cases,
        "total": len(matched_alerts) + len(matched_investigations) + len(matched_cases),
    }


HUNTABLE_FIELDS = {
    "ip": ("ip", "source_ip", "sourceIp"),
    "user": ("user_id", "userId", "username", "analyst"),
    "attack": ("attack_type", "attackType", "rule"),
    "country": ("country",),
    "severity": ("severity",),
    "status": ("status", "lifecycle"),
}

TIME_RANGE_ALIASES = {
    "5m": 5 * 60,
    "5min": 5 * 60,
    "5mins": 5 * 60,
    "1h": 60 * 60,
    "1hr": 60 * 60,
    "24h": 24 * 60 * 60,
}


def parse_hunt_query(query: str, explicit_time_range: str | None = None) -> dict:
    raw_query = _safe_string(query)
    lowered = raw_query.lower()
    resolved_time_range = _safe_string(explicit_time_range).lower()
    time_clause = re.search(r"\blast\s+(5\s*(?:m|min|mins|minute|minutes)|1\s*(?:h|hr|hour|hours)|24\s*(?:h|hr|hour|hours))\b", lowered)
    if time_clause and not resolved_time_range:
        time_token = re.sub(r"\s+", "", time_clause.group(1))
        if time_token.startswith("5"):
            resolved_time_range = "5m"
        elif time_token.startswith("1"):
            resolved_time_range = "1h"
        elif time_token.startswith("24"):
            resolved_time_range = "24h"
        raw_query = raw_query[:time_clause.start()].strip()

    if resolved_time_range not in TIME_RANGE_ALIASES:
        resolved_time_range = "24h"

    or_groups = [segment.strip() for segment in re.split(r"\s+OR\s+", raw_query, flags=re.IGNORECASE) if segment.strip()]
    parsed_groups = []
    free_text_terms = []
    for group in or_groups or [raw_query]:
        and_terms = [term.strip() for term in re.split(r"\s+AND\s+", group, flags=re.IGNORECASE) if term.strip()]
        parsed_terms = []
        for term in and_terms:
            if ":" in term:
                field, value = term.split(":", 1)
                normalized_field = _safe_string(field).lower()
                normalized_value = _safe_string(value)
                if normalized_field in HUNTABLE_FIELDS and normalized_value:
                    parsed_terms.append({
                        "field": normalized_field,
                        "value": normalized_value,
                    })
                    continue
            text_value = _safe_string(term)
            if text_value:
                parsed_terms.append({
                    "field": "text",
                    "value": text_value,
                })
                free_text_terms.append(text_value)
        if parsed_terms:
            parsed_groups.append(parsed_terms)

    return {
        "query": raw_query,
        "groups": parsed_groups,
        "time_range": resolved_time_range,
        "has_structured_terms": any(
            term.get("field") != "text"
            for group in parsed_groups
            for term in group
        ),
        "free_text_terms": free_text_terms,
    }


def _hunt_field_values(alert: dict, field: str) -> list[str]:
    values = []
    if field == "text":
        values.extend([
            _safe_string(alert.get("id")),
            _safe_string(alert.get("source_ip")),
            _safe_string(alert.get("country")),
            _safe_string(alert.get("severity")),
            _safe_string(alert.get("attack_type")),
            _safe_string(alert.get("rule")),
            _safe_string(alert.get("status")),
            _safe_string(alert.get("details")),
        ])
        return [value.lower() for value in values if value]

    for key in HUNTABLE_FIELDS.get(field, ()):
        value = alert.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            values.extend(_safe_string(item) for item in value if _safe_string(item))
        else:
            text = _safe_string(value)
            if text:
                values.append(text)
    if field == "user":
        details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
        values.extend([
            _safe_string(details.get("user_id")),
            _safe_string(details.get("username")),
            _safe_string(details.get("account")),
            _safe_string(details.get("email")),
        ])
    return [value.lower() for value in values if value]


def _matches_hunt_term(alert: dict, term: dict) -> bool:
    field = term.get("field")
    expected = _safe_string(term.get("value")).lower()
    if not expected:
        return True
    values = _hunt_field_values(alert, field)
    return any(expected in value for value in values)


def _matches_hunt_query(alert: dict, parsed_query: dict) -> bool:
    groups = parsed_query.get("groups") or []
    if not groups:
        return True
    return any(all(_matches_hunt_term(alert, term) for term in group) for group in groups)


def _time_range_cutoff_seconds(time_range: str) -> float:
    return time.time() - TIME_RANGE_ALIASES.get(_safe_string(time_range).lower(), 24 * 60 * 60)


def build_hunt_results(query: str, time_range: str | None = None) -> dict:
    parsed = parse_hunt_query(query, explicit_time_range=time_range)
    cutoff = _time_range_cutoff_seconds(parsed["time_range"])
    alerts = [_attach_incident_links(serialize_alert(alert)) for alert in get_all_alerts()]
    matched_alerts = [
        alert for alert in alerts
        if (_to_timestamp_seconds(alert.get("timestamp")) or 0) >= cutoff and _matches_hunt_query(alert, parsed)
    ]
    matched_alerts.sort(
        key=lambda alert: (
            _to_timestamp_seconds(alert.get("timestamp")) or 0,
            int(alert.get("risk_score") or 0),
        ),
        reverse=True,
    )
    severity_counts = {}
    for alert in matched_alerts:
        severity = _safe_string(alert.get("severity") or "medium").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "query": query,
        "parsed_query": parsed,
        "time_range": parsed["time_range"],
        "alerts": matched_alerts[:200],
        "total": len(matched_alerts),
        "stats": {
            "unique_ips": len({_safe_string(alert.get("source_ip")) for alert in matched_alerts if _safe_string(alert.get("source_ip"))}),
            "unique_users": len({
                _safe_string((alert.get("details") or {}).get("user_id") or alert.get("user_id"))
                for alert in matched_alerts
                if _safe_string((alert.get("details") or {}).get("user_id") or alert.get("user_id"))
            }),
            "severity_breakdown": severity_counts,
        },
    }


def _build_rule_test_payload(rule_key: str) -> dict:
    rule = get_detection_rule(rule_key)
    cutoff = time.time() - int(rule.get("time_window_seconds") or 60)
    alerts = [_attach_incident_links(serialize_alert(alert)) for alert in get_all_alerts()]
    matching_alerts = [
        alert for alert in alerts
        if _safe_string(alert.get("attack_type") or alert.get("rule")).lower() == _safe_string(rule.get("attack_type")).lower()
        and (_to_timestamp_seconds(alert.get("timestamp")) or 0) >= cutoff
    ]
    return {
        "rule": rule,
        "matches": len(matching_alerts),
        "alerts": matching_alerts[:25],
    }


def build_ioc_search_results(ioc_value: str) -> dict:
    normalized_ioc = _safe_string(ioc_value).lower()
    if not normalized_ioc:
        return {
            "ioc": "",
            "alerts": [],
            "cases": [],
            "activity": [],
            "pivot": {
                "alerts_seen": 0,
                "cases_seen": 0,
                "activity_seen": 0,
            },
            "total": 0,
        }

    cache = _get_cached_ioc_index()
    bucket = (cache.get("index") or {}).get(normalized_ioc, {"alerts": [], "cases": [], "activity": []})
    alerts = bucket["alerts"][:50]
    cases = bucket["cases"][:25]
    activity = sorted(
        bucket["activity"],
        key=lambda entry: _to_timestamp_seconds(entry.get("timestamp")) or 0,
        reverse=True,
    )[:50]
    return {
        "ioc": ioc_value,
        "alerts": alerts,
        "cases": cases,
        "activity": activity,
        "pivot": {
            "alerts_seen": len(bucket["alerts"]),
            "cases_seen": len(bucket["cases"]),
            "activity_seen": len(bucket["activity"]),
        },
        "total": len(alerts) + len(cases) + len(activity),
    }


def _serialize_pivot_alert(alert: dict) -> dict:
    linked_case = _find_linked_case(
        alert_id=alert.get("id"),
        investigation_id=alert.get("investigation_id"),
    )
    return {
        "id": alert.get("id"),
        "attack_type": alert.get("attack_type") or alert.get("attackType") or alert.get("rule"),
        "severity": alert.get("severity"),
        "timestamp": alert.get("timestamp"),
        "status": alert.get("status"),
        "case_id": (linked_case or {}).get("id") or alert.get("case_id"),
        "case_name": (linked_case or {}).get("title"),
    }


def _serialize_pivot_case(case: dict) -> dict:
    return {
        "id": case.get("id"),
        "case_id": case.get("id"),
        "case_name": case.get("title"),
        "priority": case.get("priority"),
        "assignee": case.get("assignee"),
        "status": case.get("status"),
        "updated_at": case.get("updated_at"),
    }


def _serialize_pivot_activity(entry: dict) -> dict:
    return {
        "timestamp": entry.get("timestamp"),
        "action": entry.get("actionType") or entry.get("action"),
        "actor": entry.get("actor") or entry.get("user"),
        "object_type": entry.get("targetType") or entry.get("target_type"),
        "object_id": entry.get("targetId") or entry.get("target_id"),
        "message": entry.get("message"),
        "related_alert_id": entry.get("related_alert_id"),
        "related_case_id": entry.get("related_case_id"),
    }


def _find_watchlist_entry(ioc_type: str, normalized_value: str) -> dict | None:
    watchlist = _get_watchlist_cache()
    stats = watchlist.get("stats") or {}
    exact = stats.get((ioc_type, normalized_value))
    if exact:
        return exact
    return next(
        (
            entry for (entry_type, entry_value), entry in stats.items()
            if entry_value == normalized_value and (entry_type == ioc_type or not ioc_type)
        ),
        None,
    )


def build_ioc_pivot_payload(ioc_type: str, ioc_value: str) -> dict:
    normalized_type = normalize_ioc_type(ioc_type)
    normalized_value = normalize_ioc_value(normalized_type, ioc_value)
    if normalized_type not in IOC_SUPPORTED_TYPES:
        raise ValueError("Unsupported IOC type")
    if not validate_ioc_value(normalized_type, normalized_value):
        raise ValueError("Invalid IOC value")

    cache = _get_cached_ioc_index()
    typed_bucket = ((cache.get("typed_index") or {}).get(normalized_type) or {}).get(
        normalized_value,
        {"alerts": [], "cases": [], "activity": []},
    )
    related_alerts = sorted(
        typed_bucket["alerts"],
        key=lambda alert: _to_timestamp_seconds(alert.get("updated_at") or alert.get("timestamp")) or 0,
        reverse=True,
    )
    related_cases = sorted(
        typed_bucket["cases"],
        key=lambda case: _to_timestamp_seconds(case.get("updated_at") or case.get("created_at")) or 0,
        reverse=True,
    )
    recent_activity = sorted(
        typed_bucket["activity"],
        key=lambda entry: _to_timestamp_seconds(entry.get("timestamp")) or 0,
        reverse=True,
    )
    watchlist_entry = _find_watchlist_entry(normalized_type, normalized_value)

    return {
        "ioc": {
            "type": normalized_type,
            "value": _safe_string(ioc_value),
            "normalized_value": normalized_value,
        },
        "summary": {
            "related_alerts_count": len(related_alerts),
            "related_cases_count": len(related_cases),
            "activity_count": len(recent_activity),
            "recurrence_count": len(related_alerts),
            "watchlist_hit": bool(watchlist_entry),
        },
        "watchlist_entry": watchlist_entry,
        "related_alerts": [_serialize_pivot_alert(alert) for alert in related_alerts[:50]],
        "related_cases": [_serialize_pivot_case(case) for case in related_cases[:25]],
        "recent_activity": [_serialize_pivot_activity(entry) for entry in recent_activity[:50]],
    }


def build_watchlist_payload() -> dict:
    watchlist = _get_watchlist_cache()
    entries = sorted(
        (watchlist.get("stats") or {}).values(),
        key=lambda entry: (
            -int(entry.get("hits_count") or 0),
            -int(entry.get("cases_count") or 0),
            str(entry.get("value") or "").lower(),
        ),
    )
    return {
        "entries": entries,
        "total": len(entries),
    }


def build_event_payload(alert: dict) -> dict | None:
    ip = alert.get("ip")
    if not ip:
        return None

    geo = fetch_ip_geolocation(ip)
    latitude = geo.get("latitude")
    longitude = geo.get("longitude")

    if latitude is None or longitude is None:
        return None

    return {
        "ip": ip,
        "lat": latitude,
        "lon": longitude,
        "country": (alert.get("details") or {}).get("country") or geo.get("country_code") or geo.get("country"),
        "severity": alert.get("severity", "low"),
    }


def stream_generated_alerts():
    ensure_topics()
    consumer = create_consumer(CANONICAL_TOPICS["alerts_generated"], group_id="investigation-api-stream")
    for message in consumer:
        payload = build_stream_payload(message.value)
        dead_clients = []
        with ws_lock:
            for client in ws_clients:
                try:
                    client.send(json.dumps(payload))
                except Exception:
                    dead_clients.append(client)
            for client in dead_clients:
                ws_clients.discard(client)


def ensure_stream_thread():
    global stream_thread_started
    if stream_thread_started:
        return
    thread = threading.Thread(target=stream_generated_alerts, daemon=True)
    thread.start()
    stream_thread_started = True


@app.get("/health")
def health():
    try:
        conn = get_connection()
        conn.close()
        return jsonify({"status": "ok", "service": "investigation_api", "database": "reachable"})
    except Exception as exc:
        return jsonify({"status": "degraded", "service": "investigation_api", "database": str(exc)}), 503


@app.get("/metrics")
def metrics():
    return metrics_response()


@app.post("/auth/token")
def auth_token():
    try:
        require_api_key(request.headers.get("X-API-Key"))
    except PermissionError as exc:
        return jsonify({"detail": str(exc)}), 401
    return jsonify({"token": issue_jwt("dashboard-user")})


@app.post("/auth/login")
def auth_login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    user = USERS.get(username)

    if not user or user["password"] != password:
      return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    update_presence(username, role=user.get("role"), current_page="dashboard")
    log_action(
        username,
        "auth_login",
        username,
        target_type="auth",
        target_id=username,
        status="success",
        message=f"{username} logged in",
    )

    return jsonify({
        "status": "success",
        "username": username,
        "role": user["role"],
        "assignable_users": [
            {
                "username": available_username,
                "role": available_record.get("role", "analyst"),
            }
            for available_username, available_record in sorted(USERS.items())
        ] if user.get("role") == "admin" else [],
    })


@app.get("/users")
def users_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user("admin")
    if auth_response:
        return auth_response
    return jsonify({
        "users": [
            {
                "username": username,
                "role": record.get("role", "analyst"),
            }
            for username, record in sorted(USERS.items())
        ]
    })


@app.get("/playbooks")
def playbooks_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response
    return jsonify({
        "playbooks": list_playbooks(),
        "executions": list_playbook_executions() if user.get("role") == "admin" else [],
    })


@app.get("/alerts")
def list_alerts():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    alerts = _serialize_alerts_with_correlation(get_all_alerts())
    return jsonify({"alerts": alerts})


@app.post("/alerts/<alert_id>/acknowledge")
def acknowledge_alert_route(alert_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    try:
        acknowledge_alert(alert_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 409

    state = get_state(alert_id)
    log_action(
        user["username"],
        "acknowledge_alert",
        alert_id,
        target_type="alert",
        target_id=alert_id,
        related_alert_id=alert_id,
        status="success",
        result={"disposition": state.get("disposition")},
        message=f"{user['username']} acknowledged alert {alert_id}",
    )
    _broadcast_alert_state(alert_id)
    return _alert_action_response(alert_id, "acknowledge")


@app.post("/alerts/<alert_id>/suppress")
def suppress_alert_route(alert_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    try:
        suppress_alert(alert_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 409

    state = get_state(alert_id)
    log_action(
        user["username"],
        "suppress_alert",
        alert_id,
        target_type="alert",
        target_id=alert_id,
        related_alert_id=alert_id,
        status="success",
        result={"disposition": state.get("disposition")},
        message=f"{user['username']} suppressed alert {alert_id}",
    )
    _broadcast_alert_state(alert_id)
    return _alert_action_response(alert_id, "suppress")


@app.post("/alerts/<alert_id>/reopen")
def reopen_alert_route(alert_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    try:
        reopen_alert(alert_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 409

    state = get_state(alert_id)
    log_action(
        user["username"],
        "reopen_alert",
        alert_id,
        target_type="alert",
        target_id=alert_id,
        related_alert_id=alert_id,
        status="success",
        result={"disposition": state.get("disposition")},
        message=f"{user['username']} reopened alert {alert_id}",
    )
    _broadcast_alert_state(alert_id)
    return _alert_action_response(alert_id, "reopen")


@app.post("/alerts/<alert_id>/assign")
def assign_alert_route(alert_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    user_id = _safe_string(payload.get("user_id"))
    if not user_id:
        return jsonify({"status": "error", "message": "Missing user_id"}), 400
    if user.get("role") != "admin" and user_id != user["username"]:
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    assign_analyst(alert_id, user_id)
    state = get_state(alert_id)
    log_action(
        user["username"],
        "assign_alert",
        alert_id,
        target_type="alert",
        target_id=alert_id,
        related_alert_id=alert_id,
        status="success",
        result={"assigned_to": state.get("assigned_to")},
        message=f"{user['username']} assigned alert {alert_id} to {user_id}",
    )
    _broadcast_alert_state(alert_id)
    return _alert_action_response(alert_id, "assign")


@app.post("/alerts/<alert_id>/merge")
def merge_alert_route(alert_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    case_id = _safe_string(payload.get("case_id"))
    if not case_id:
        return jsonify({"status": "error", "message": "Missing case_id"}), 400
    case_record = get_case(case_id)
    if not case_record:
        return jsonify({"status": "error", "message": "Case not found"}), 404

    merge_into_case(alert_id, case_id)
    linked_alert_ids = case_record.get("linked_alert_ids") or []
    if alert_id not in linked_alert_ids:
        linked_alert_ids = [*linked_alert_ids, alert_id]
    update_case(case_id, linked_alert_ids=linked_alert_ids)
    state = get_state(alert_id)
    log_action(
        user["username"],
        "merge_alert",
        alert_id,
        target_type="alert",
        target_id=alert_id,
        related_alert_id=alert_id,
        related_case_id=case_id,
        status="success",
        result={"merged_into_case_id": case_id, "status": state.get("status")},
        message=f"{user['username']} merged alert {alert_id} into case {case_id}",
    )
    _broadcast_alert_state(alert_id)
    return _alert_action_response(alert_id, "merge")


@app.get("/search")
def search_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error

    ioc_query = request.args.get("ioc", "")
    if _safe_string(ioc_query):
        return jsonify(build_ioc_search_results(ioc_query))

    query = request.args.get("q", "")
    mode = _safe_string(request.args.get("mode")).lower()
    time_range = request.args.get("time_range")
    if mode == "hunt" or ":" in _safe_string(query) or " last " in f" {_safe_string(query).lower()} ":
        return jsonify(build_hunt_results(query, time_range=time_range))
    return jsonify(build_search_results(query))


@app.post("/playbooks/run")
def run_playbook_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response
    payload = request.get_json(silent=True) or {}
    alert_id = _safe_string(payload.get("alert_id"))
    playbook_key = _safe_string(payload.get("playbook_key")) or None
    alert = _find_serialized_alert(alert_id)
    if not alert:
        return jsonify({"detail": "Alert not found"}), 404
    execution = execute_playbook(alert, playbook_key, actor=user["username"], automatic=False)
    if not execution:
        return jsonify({"detail": "Playbook not found"}), 404
    log_action(
        user["username"],
        "run_playbook",
        execution["playbook_id"],
        target_type="playbook",
        target_id=execution["playbook_id"],
        related_alert_id=alert_id,
        status="success",
        message=f"{user['username']} manually ran playbook {execution['playbook_id']} for alert {alert_id}",
    )
    return jsonify({
        "status": "success",
        "execution": execution,
        "alert": _attach_incident_links(_find_serialized_alert(alert_id) or alert),
    })


@app.get("/iocs/pivot")
def ioc_pivot_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error

    ioc_type = _safe_string(request.args.get("type")).lower()
    ioc_value = _safe_string(request.args.get("value"))
    if not ioc_type or not ioc_value:
        return jsonify({"detail": "Missing IOC type or value"}), 400

    try:
        return jsonify(build_ioc_pivot_payload(ioc_type, ioc_value))
    except ValueError as exc:
        return jsonify({"detail": str(exc)}), 400


@app.get("/watchlist")
def list_watchlist_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    return jsonify(build_watchlist_payload())


@app.post("/watchlist/add")
def add_watchlist_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response
    payload = request.get_json(silent=True) or {}
    entry_type = normalize_ioc_type(payload.get("type"))
    value = _safe_string(payload.get("value"))
    normalized_value = normalize_ioc_value(entry_type, value)
    if entry_type not in IOC_SUPPORTED_TYPES:
        return jsonify({"status": "error", "message": "Invalid watchlist type"}), 400
    if not validate_ioc_value(entry_type, normalized_value):
        return jsonify({"status": "error", "message": "Missing watchlist value"}), 400
    entry = add_watchlist_entry(entry_type, normalized_value, user["username"])
    WATCHLIST_CACHE["signature"] = None
    log_action(
        user["username"],
        "add_watchlist",
        normalized_value,
        target_type="watchlist",
        target_id=normalized_value,
        status="success",
        result={"type": entry_type, "value": normalized_value},
        message=f"{user['username']} added {normalized_value} to watchlist",
    )
    return jsonify({"status": "success", "entry": entry, **build_watchlist_payload()})


@app.delete("/watchlist/remove")
def remove_watchlist_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response
    payload = request.get_json(silent=True) or {}
    entry_type = normalize_ioc_type(payload.get("type"))
    value = _safe_string(payload.get("value"))
    normalized_value = normalize_ioc_value(entry_type, value)
    if not entry_type or not validate_ioc_value(entry_type, normalized_value):
        return jsonify({"status": "error", "message": "Missing watchlist entry"}), 400
    removed = remove_watchlist_entry(entry_type, normalized_value)
    if not removed:
        return jsonify({"status": "error", "message": "Watchlist entry not found"}), 404
    WATCHLIST_CACHE["signature"] = None
    log_action(
        user["username"],
        "remove_watchlist",
        normalized_value,
        target_type="watchlist",
        target_id=normalized_value,
        status="success",
        result={"type": entry_type, "value": normalized_value},
        message=f"{user['username']} removed {normalized_value} from watchlist",
    )
    return jsonify({"status": "success", **build_watchlist_payload()})


@app.post("/actions/block-ip")
def block_ip_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "Missing IP"}), 400

    if is_blocked(ip):
        log_action(
            user["username"],
            "block_ip",
            ip,
            target_type="network",
            target_id=ip,
            status="success",
            result={"action": "already_blocked"},
            message=f"{user['username']} attempted to block IP {ip} - already blocked",
        )
        return jsonify({
            "status": "success",
            "ip": ip,
            "action": "already_blocked"
        })

    block_ip(ip)
    log_action(
        user["username"],
        "block_ip",
        ip,
        target_type="network",
        target_id=ip,
        status="success",
        result={"action": "blocked"},
        message=f"{user['username']} blocked IP {ip}",
    )
    return jsonify({
        "status": "success",
        "ip": ip,
        "action": "blocked"
    })


@app.post("/actions/set-status")
def set_status_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    alert_id = str(payload.get("id") or "").strip()
    status = str(payload.get("status") or "").strip().lower()
    if not alert_id or not status:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    normalized_status = normalize_alert_status(status)
    set_status(alert_id, normalized_status)
    log_action(
        user["username"],
        "set_status",
        alert_id,
        target_type="alert",
        target_id=alert_id,
        related_alert_id=alert_id,
        status="success",
        result={"status": normalized_status},
        message=f"{user['username']} changed alert {alert_id} to {normalized_status}",
    )
    _broadcast_alert_state(alert_id)
    return jsonify({"status": "success", "id": alert_id, "new_status": normalized_status})


@app.post("/actions/false-positive")
def false_positive_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    alert_id = str(payload.get("id") or "").strip()
    if not alert_id:
        return jsonify({"status": "error", "message": "Missing alert ID"}), 400

    set_false_positive(alert_id)
    log_action(
        user["username"],
        "mark_false_positive",
        alert_id,
        target_type="alert",
        target_id=alert_id,
        related_alert_id=alert_id,
        status="success",
        result={"status": "false_positive"},
        message=f"{user['username']} marked alert {alert_id} as false positive",
    )
    _broadcast_alert_state(alert_id)
    return jsonify({"status": "success", "id": alert_id, "flagged": "false_positive"})


@app.post("/actions/assign")
def assign_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    alert_id = str(payload.get("id") or "").strip()
    analyst = str(payload.get("analyst") or "").strip()
    if not alert_id or not analyst:
        return jsonify({"status": "error"}), 400

    if user.get("role") != "admin" and analyst != user["username"]:
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    state = get_state(alert_id)
    assigned_to = state.get("assigned_to") or state.get("analyst")
    if assigned_to and assigned_to != analyst and user.get("role") != "admin":
        return jsonify({"status": "error", "message": f"Already assigned to {assigned_to}"}), 409

    assign_analyst(alert_id, analyst)
    log_action(user["username"], "assign_alert", f"{alert_id}:{analyst}")
    _broadcast_alert_state(alert_id)
    return jsonify({"status": "success", "assigned_to": analyst, "status_value": "assigned"})


@app.post("/actions/add-note")
def add_note_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    alert_id = str(payload.get("id") or "").strip()
    note = str(payload.get("note") or "").strip()
    if not alert_id or not note:
        return jsonify({"status": "error"}), 400

    add_note(alert_id, note)
    log_action(user["username"], "add_note", alert_id)
    return jsonify({"status": "success"})


@app.get("/audit")
def audit_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response
    return jsonify({"logs": _filter_audit_logs_for_user(user, get_logs())})


@app.post("/auth/heartbeat")
def auth_heartbeat_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    current_page = _safe_string(payload.get("current_page")) or None
    update_presence(user["username"], role=user.get("role"), current_page=current_page)
    return jsonify({"status": "success", "username": user["username"], "current_page": current_page})


@app.post("/auth/logout")
def auth_logout_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    reason = _safe_string(payload.get("reason")).lower()
    event_type = "auth_session_expired" if reason == "session_expired" else "auth_logout"
    message = "session expired" if event_type == "auth_session_expired" else f"{user['username']} logged out"
    log_action(
        user["username"],
        event_type,
        user["username"],
        target_type="auth",
        target_id=user["username"],
        status="success",
        message=message,
    )
    remove_presence(user["username"])
    return jsonify({"status": "success"})


@app.get("/activity/online-users")
def online_users_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    current_page = _safe_string(request.args.get("current_page")) or None
    update_presence(user["username"], role=user.get("role"), current_page=current_page)
    return jsonify({"users": get_online_users()})


@app.post("/presence")
def presence_route():
    return auth_heartbeat_route()


@app.get("/admin/presence")
def admin_presence_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user("admin")
    if auth_response:
        return auth_response

    update_presence(user["username"], role=user.get("role"), current_page="admin")
    return jsonify({"users": get_online_users()})


@app.get("/rules")
def rules_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    _, auth_response = get_authenticated_user("admin")
    if auth_response:
        return auth_response

    return jsonify(get_all_rule_config())


@app.get("/rules/detection")
def detection_rules_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    _, auth_response = get_authenticated_user("admin")
    if auth_response:
        return auth_response
    return jsonify({"rules": list_detection_rules()})


@app.post("/rules/update")
def rules_update_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user("admin")
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    rule = str(payload.get("rule") or "").strip()
    updates = payload.get("config")

    if not rule:
        return jsonify({"status": "error", "message": "Missing rule"}), 400
    if not isinstance(updates, dict) or not updates:
        return jsonify({"status": "error", "message": "Missing config"}), 400

    sanitized = {
        key: value
        for key, value in updates.items()
        if isinstance(key, str) and isinstance(value, (int, float, str, bool))
    }
    if not sanitized:
        return jsonify({"status": "error", "message": "No valid updates"}), 400

    section = update_rule_section(rule, sanitized)
    log_action(user["username"], "update_rule", rule)
    return jsonify({"status": "success", "rule": rule, "config": section})


@app.post("/rules/detection/update")
def detection_rules_update_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user("admin")
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    rule_key = _safe_string(payload.get("rule_key"))
    rule_payload = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    if not rule_key:
        return jsonify({"status": "error", "message": "Missing rule_key"}), 400

    updated_rule = update_detection_rule(rule_key, rule_payload)
    log_action(
        user["username"],
        "update_detection_rule",
        rule_key,
        target_type="rule",
        target_id=rule_key,
        result=updated_rule,
        message=f"{user['username']} updated detection rule {rule_key}",
    )
    return jsonify({"status": "success", "rule": updated_rule})


@app.post("/rules/test")
def rule_test_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user("admin")
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    rule_key = _safe_string(payload.get("rule_key"))
    if not rule_key:
        return jsonify({"status": "error", "message": "Missing rule_key"}), 400

    result = _build_rule_test_payload(rule_key)
    log_action(
        user["username"],
        "test_detection_rule",
        rule_key,
        target_type="rule",
        target_id=rule_key,
        result={"matches": result["matches"]},
        message=f"{user['username']} tested detection rule {rule_key}",
    )
    return jsonify({"status": "success", **result})


@app.post("/investigate")
def investigate_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    alert_id = str(payload.get("alert_id") or payload.get("id") or "").strip()
    if not alert_id:
        return jsonify({"status": "error", "message": "Missing alert ID"}), 400

    alert = _find_serialized_alert(alert_id)
    if not alert:
        return jsonify({"status": "error", "message": "Alert not found"}), 404

    state = get_state(alert_id)
    locked_by = state.get("locked_by")
    if locked_by and locked_by != user["username"]:
        return jsonify({"status": "error", "message": f"Locked by {locked_by}"}), 409

    lock_alert(alert_id, user["username"])
    set_status(alert_id, "new")
    related_alert_ids = _collect_related_alert_ids(alert.get("source_ip"), alert_id)
    existing_case = _find_linked_case(alert_id=alert_id)
    investigation = upsert_investigation(
        alert_id=alert_id,
        title=f"Investigation for alert {alert_id}",
        entity_key=alert.get("source_ip"),
        created_by=user["username"],
        analyst=user["username"],
        status="investigating",
        case_id=existing_case.get("id") if existing_case else None,
        related_alert_ids=related_alert_ids,
        actions=[log_action(
            user["username"],
            "investigate",
            alert_id,
            target_type="investigation",
            target_id=alert_id,
            related_alert_id=alert_id,
            status="success",
            message=f"{user['username']} opened investigation on alert {alert_id}",
        )],
        source="alert_lock",
    )
    broadcast_payload({
        "type": "investigating",
        "alert_id": alert_id,
        "user": user["username"],
        "locked_by": user["username"],
    })
    return jsonify({"status": "success", "locked_by": user["username"], "investigation": serialize_investigation(investigation)})


@app.get("/investigations")
def investigations_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    return jsonify({"investigations": [serialize_investigation(record) for record in list_investigations()]})


@app.post("/investigations")
def create_investigation_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    alert_id = _safe_string(payload.get("alert_id") or payload.get("id"))
    if not alert_id:
        return jsonify({"status": "error", "message": "Missing alert ID"}), 400
    alert = _find_serialized_alert(alert_id)
    if not alert:
        return jsonify({"status": "error", "message": "Alert not found"}), 404

    entity_key = _safe_string(payload.get("entity_key")) or _safe_string(alert.get("source_ip"))
    related_alert_ids = payload.get("related_alert_ids") if isinstance(payload.get("related_alert_ids"), list) else None
    existing_case = _find_linked_case(alert_id=alert_id)

    investigation = upsert_investigation(
        alert_id=alert_id,
        entity_key=entity_key or None,
        created_by=_safe_string(payload.get("created_by")) or user["username"],
        title=_safe_string(payload.get("title")) or f"Investigation for alert {alert_id}",
        summary=_safe_string(payload.get("summary")),
        analyst=_safe_string(payload.get("analyst")) or user["username"],
        status=_safe_string(payload.get("status")) or "investigating",
        case_id=_safe_string(payload.get("case_id")) or (existing_case.get("id") if existing_case else None),
        notes=payload.get("notes") if isinstance(payload.get("notes"), list) else None,
        actions=[payload.get("action")] if isinstance(payload.get("action"), dict) else None,
        related_alert_ids=related_alert_ids or _collect_related_alert_ids(entity_key, alert_id),
        source="manual",
    )
    set_status(alert_id, "new")
    log_action(
        user["username"],
        "create_investigation",
        investigation["id"],
        target_type="investigation",
        target_id=investigation["id"],
        related_alert_id=alert_id,
        status="success",
        message=f"{user['username']} created investigation {investigation['id']} from alert {alert_id}",
    )
    return jsonify({"status": "success", "investigation": serialize_investigation(investigation)})


@app.get("/investigations/<investigation_id>")
def investigation_detail_route(investigation_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    investigation = get_investigation(investigation_id)
    if not investigation:
        return jsonify({"detail": "Investigation not found"}), 404
    return jsonify({"investigation": serialize_investigation(investigation)})


@app.post("/investigations/<investigation_id>")
def investigation_update_route(investigation_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    updated = update_investigation(
        investigation_id,
        title=payload.get("title"),
        summary=payload.get("summary"),
        analyst=payload.get("analyst"),
        created_by=payload.get("created_by"),
        entity_key=payload.get("entity_key"),
        status=payload.get("status"),
        case_id=payload.get("case_id"),
        related_alert_ids=payload.get("related_alert_ids"),
        note=payload.get("note"),
        notes=payload.get("notes"),
        action=payload.get("action") if isinstance(payload.get("action"), dict) else None,
        actions=payload.get("actions") if isinstance(payload.get("actions"), list) else None,
    )
    if not updated:
        return jsonify({"detail": "Investigation not found"}), 404
    log_action(
        user["username"],
        "update_investigation",
        investigation_id,
        target_type="investigation",
        target_id=investigation_id,
        related_alert_id=updated.get("alert_id"),
        related_case_id=updated.get("case_id"),
        status="success",
        message=f"{user['username']} updated investigation {investigation_id}",
    )
    return jsonify({"status": "success", "investigation": serialize_investigation(updated)})


@app.get("/cases")
def cases_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    return jsonify({"cases": [serialize_case(record) for record in list_cases()]})


@app.post("/cases")
def create_case_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    alert_id = _safe_string(payload.get("alert_id"))
    investigation_id = _safe_string(payload.get("investigation_id"))

    if not alert_id and not investigation_id:
        return jsonify({"status": "error", "message": "Missing alert_id or investigation_id"}), 400

    linked_investigation = None
    linked_alert = None
    if investigation_id:
        linked_investigation = get_investigation(investigation_id)
        if not linked_investigation:
            return jsonify({"detail": "Investigation not found"}), 404
        alert_id = alert_id or _safe_string(linked_investigation.get("alert_id"))
    elif alert_id:
        linked_alert = _find_serialized_alert(alert_id)
        if not linked_alert:
            return jsonify({"status": "error", "message": "Alert not found"}), 404
        linked_investigation = _find_linked_investigation_by_alert(alert_id)
        if not linked_investigation:
            linked_investigation = upsert_investigation(
                alert_id=alert_id,
                entity_key=linked_alert.get("source_ip"),
                created_by=user["username"],
                analyst=user["username"],
                status="investigating",
                related_alert_ids=_collect_related_alert_ids(linked_alert.get("source_ip"), alert_id),
                source="case_escalation",
            )
        investigation_id = linked_investigation.get("id")

    if not linked_alert and alert_id:
        linked_alert = _find_serialized_alert(alert_id)

    linked_alert_ids = []
    if linked_investigation:
        linked_alert_ids = linked_investigation.get("related_alert_ids") or []
    if not linked_alert_ids and alert_id:
        linked_alert_ids = _collect_related_alert_ids((linked_alert or {}).get("source_ip"), alert_id)

    case_action = payload.get("action") if isinstance(payload.get("action"), dict) else None
    evidence = {
        "timeline": [case_action] if case_action else [],
        "enrichments": [{
            "timestamp": time.time(),
            "source": "source_alert",
            "snapshot": {
                "id": linked_alert.get("id") if linked_alert else alert_id,
                "source_ip": (linked_alert or {}).get("source_ip"),
                "attack_type": (linked_alert or {}).get("attack_type"),
                "severity": (linked_alert or {}).get("severity"),
                "risk_score": (linked_alert or {}).get("risk_score"),
                "country": (linked_alert or {}).get("country"),
                "disposition": (linked_alert or {}).get("disposition"),
                "watchlist_hit": (linked_alert or {}).get("watchlist_hit"),
            },
        }] if linked_alert else [],
        "analyst_notes": list(payload.get("notes") if isinstance(payload.get("notes"), list) else []),
    }
    case = create_case(
        title=_safe_string(payload.get("title")) or f"Case for alert {alert_id or investigation_id}",
        alert_id=alert_id or None,
        investigation_id=investigation_id or None,
        priority=_safe_string(payload.get("priority")) or "medium",
        status=_safe_string(payload.get("status")) or "open",
        severity=_safe_string(payload.get("severity")) or ((linked_alert or {}).get("severity")) or "medium",
        assignee=_safe_string(payload.get("assignee")) or user["username"],
        summary=_safe_string(payload.get("summary")),
        linked_alert_ids=linked_alert_ids,
        notes=payload.get("notes") if isinstance(payload.get("notes"), list) else None,
        actions=[case_action] if case_action else None,
        evidence=evidence,
        parent_case_id=_safe_string(payload.get("parent_case_id")) or None,
        linked_cases=payload.get("linked_cases") if isinstance(payload.get("linked_cases"), list) else None,
        source="manual",
    )
    if investigation_id:
        update_investigation(
            investigation_id,
            status="in_case",
            analyst=case.get("assignee"),
            case_id=case.get("id"),
            related_alert_ids=linked_alert_ids,
        )
    if alert_id:
        link_case(alert_id, case.get("id"))
        set_case_id(alert_id, case.get("id"))
    log_action(
        user["username"],
        "create_case",
        case["id"],
        target_type="case",
        target_id=case["id"],
        related_case_id=case["id"],
        related_alert_id=alert_id or None,
        status="success",
        message=f"{user['username']} created case {case['id']} from alert {alert_id or '-'}",
    )
    return jsonify({"status": "success", "case": serialize_case(case)})


@app.get("/cases/<case_id>")
def case_detail_route(case_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    case = get_case(case_id)
    if not case:
        return jsonify({"detail": "Case not found"}), 404
    return jsonify({"case": serialize_case(case)})


@app.get("/cases/<case_id>/report")
def case_report_route(case_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    case = get_case(case_id)
    if not case:
        return jsonify({"detail": "Case not found"}), 404

    serialized_case = serialize_case(case)
    report_payload = _build_case_report_payload(serialized_case)
    section = _safe_string(request.args.get("section")) or "full"
    output_format = (_safe_string(request.args.get("format")) or "json").lower()

    if section == "summary":
        body = {
            "case_id": report_payload["case_id"],
            "overview": report_payload["overview"],
            "technical_summary": report_payload["technical_summary"],
            "conclusion": report_payload["conclusion"],
        }
    elif section == "timeline":
        body = {
            "case_id": report_payload["case_id"],
            "overview": report_payload["overview"],
            "timeline": report_payload["timeline"],
            "analyst_timeline": report_payload["analyst_timeline"],
        }
    else:
        body = report_payload

    if output_format == "pdf":
        pdf_bytes = _build_case_report_pdf(report_payload if section == "full" else {
            **report_payload,
            **body,
        })
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={case_id}-{section}-report.pdf",
            },
        )

    return Response(
        json.dumps(body, indent=2),
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={case_id}-{section}.json",
        },
    )


@app.post("/cases/<case_id>")
def update_case_route(case_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    if "assignee" in payload and user.get("role") != "admin":
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    updated = update_case(
        case_id,
        title=payload.get("title"),
        summary=payload.get("summary"),
        priority=payload.get("priority"),
        status=payload.get("status"),
        severity=payload.get("severity"),
        assignee=payload.get("assignee"),
        parent_case_id=payload.get("parent_case_id"),
        linked_cases=payload.get("linked_cases"),
        linked_alert_ids=payload.get("linked_alert_ids"),
        note=payload.get("note"),
        action=payload.get("action") if isinstance(payload.get("action"), dict) else None,
        actions=payload.get("actions") if isinstance(payload.get("actions"), list) else None,
    )
    if not updated:
        return jsonify({"detail": "Case not found"}), 404

    linked_alert_id = updated.get("source_alert_id") or updated.get("alert_id")
    linked_investigation_id = updated.get("source_investigation_id") or updated.get("investigation_id")
    if linked_investigation_id:
        update_investigation(
            linked_investigation_id,
            status=payload.get("status") or None,
            case_id=case_id,
            action=payload.get("action") if isinstance(payload.get("action"), dict) else None,
        )
    normalized_case_status = normalize_alert_status(payload.get("status"))
    if linked_alert_id and _safe_string(payload.get("status")):
        if normalized_case_status == "closed":
            set_status(linked_alert_id, "closed")
        elif normalized_case_status == "new":
            link_case(linked_alert_id, case_id)
        elif normalized_case_status == "in_case":
            link_case(linked_alert_id, case_id)
    log_action(
        user["username"],
        "update_case",
        case_id,
        target_type="case",
        target_id=case_id,
        related_case_id=case_id,
        related_alert_id=linked_alert_id or None,
        status="success",
        message=f"{user['username']} updated case {case_id}",
    )
    return jsonify({"status": "success", "case": serialize_case(updated)})


@app.patch("/cases/<case_id>/assignee")
def update_case_assignee_route(case_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response
    if user.get("role") != "admin":
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    assignee = _safe_string(payload.get("assignee"))
    if not assignee:
        return jsonify({"status": "error", "message": "Missing assignee"}), 400
    if assignee not in USERS:
        return jsonify({"status": "error", "message": "Unknown assignee"}), 400

    existing_case = get_case(case_id)
    if not existing_case:
        return jsonify({"detail": "Case not found"}), 404

    previous_assignee = _safe_string(existing_case.get("assignee"))
    updated = update_case(case_id, assignee=assignee)
    if not updated:
        return jsonify({"detail": "Case not found"}), 404

    log_action(
        user["username"],
        "reassign_case",
        case_id,
        target_type="case",
        target_id=case_id,
        related_case_id=case_id,
        input={"previous_assignee": previous_assignee or None, "assignee": assignee},
        result={"assignee": assignee},
        status="success",
        message=f"{user['username']} reassigned case {case_id} from {previous_assignee or 'Unassigned'} to {assignee}",
    )
    return jsonify({"status": "success", "case": serialize_case(updated)})


@app.post("/cases/link")
def link_cases_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    case_id = _safe_string(payload.get("case_id"))
    linked_case_id = _safe_string(payload.get("linked_case_id"))
    relationship_action = payload.get("action") if isinstance(payload.get("action"), dict) else None
    if not case_id or not linked_case_id:
        return jsonify({"status": "error", "message": "Missing case_id or linked_case_id"}), 400

    try:
        primary, secondary = link_cases(case_id, linked_case_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    if relationship_action:
        primary = update_case(case_id, action=relationship_action) or primary
        secondary = update_case(linked_case_id, action=relationship_action) or secondary

    log_action(
        user["username"],
        "link_cases",
        case_id,
        target_type="case",
        target_id=case_id,
        related_case_id=linked_case_id,
        status="success",
        result={"linked_case_id": linked_case_id},
        message=f"{user['username']} linked case {case_id} to case {linked_case_id}",
    )
    return jsonify({
        "status": "success",
        "case": serialize_case(primary),
        "linked_case": serialize_case(secondary),
    })


@app.post("/cases/merge")
def merge_cases_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    primary_case_id = _safe_string(payload.get("primary_case_id"))
    secondary_case_id = _safe_string(payload.get("secondary_case_id"))
    relationship_action = payload.get("action") if isinstance(payload.get("action"), dict) else None
    if not primary_case_id or not secondary_case_id:
        return jsonify({"status": "error", "message": "Missing primary_case_id or secondary_case_id"}), 400

    try:
        primary, secondary = merge_cases(primary_case_id, secondary_case_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    for linked_alert_id in primary.get("linked_alert_ids") or []:
        link_case(linked_alert_id, primary_case_id)
        set_case_id(linked_alert_id, primary_case_id)
    if relationship_action:
        primary = update_case(primary_case_id, action=relationship_action) or primary
        secondary = update_case(secondary_case_id, action=relationship_action) or secondary

    log_action(
        user["username"],
        "merge_cases",
        primary_case_id,
        target_type="case",
        target_id=primary_case_id,
        related_case_id=secondary_case_id,
        status="success",
        result={"merged_case_id": secondary_case_id},
        message=f"{user['username']} merged case {secondary_case_id} into case {primary_case_id}",
    )
    return jsonify({
        "status": "success",
        "case": serialize_case(primary),
        "merged_case": serialize_case(secondary),
    })


@app.post("/cases/split")
def split_case_route():
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    user, auth_response = get_authenticated_user()
    if auth_response:
        return auth_response

    payload = request.get_json(silent=True) or {}
    case_id = _safe_string(payload.get("case_id"))
    alert_ids = payload.get("alert_ids") if isinstance(payload.get("alert_ids"), list) else []
    title = _safe_string(payload.get("title")) or None
    relationship_action = payload.get("action") if isinstance(payload.get("action"), dict) else None
    if not case_id or not alert_ids:
        return jsonify({"status": "error", "message": "Missing case_id or alert_ids"}), 400

    try:
        source_case, child_case = split_case(case_id, alert_ids, title=title)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    for linked_alert_id in child_case.get("linked_alert_ids") or []:
        link_case(linked_alert_id, child_case.get("id"))
        set_case_id(linked_alert_id, child_case.get("id"))
    if relationship_action:
        source_case = update_case(case_id, action=relationship_action) or source_case
        child_case = update_case(child_case.get("id"), action=relationship_action) or child_case

    log_action(
        user["username"],
        "split_case",
        case_id,
        target_type="case",
        target_id=case_id,
        related_case_id=child_case.get("id"),
        status="success",
        result={"new_case_id": child_case.get("id"), "alert_ids": alert_ids},
        message=f"{user['username']} split alerts from case {case_id} into case {child_case.get('id')}",
    )
    return jsonify({
        "status": "success",
        "case": serialize_case(source_case),
        "split_case": serialize_case(child_case),
    })


@app.get("/api/events")
def list_event_map_data():
    auth_error = authorize_request()
    if auth_error:
        return auth_error

    alerts = get_all_alerts()
    events = []

    for alert in alerts:
        payload = build_event_payload(alert)
        if payload:
            events.append(payload)
        if len(events) >= 500:
            break

    return jsonify(events)


@app.get("/entities/<entity_type>/<path:entity_key>")
def entity_profile_route(entity_type: str, entity_key: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error

    normalized_type = safe_string(entity_type).lower()
    normalized_key = safe_string(entity_key)
    if normalized_type not in {"ip", "user", "host"} or not normalized_key:
        return jsonify({"detail": "Unsupported entity"}), 400

    matching_alerts = [
        alert
        for alert in get_all_alerts()
        if _entity_matches_alert(alert, normalized_type, normalized_key)
    ]
    linked_alert_ids = {safe_string(alert.get("id")) for alert in matching_alerts if alert.get("id") is not None}
    related_cases = [
        record for record in list_cases()
        if (
            safe_string(record.get("alert_id")) in linked_alert_ids
            or safe_string(record.get("source_alert_id")) in linked_alert_ids
            or any(safe_string(value) in linked_alert_ids for value in (record.get("linked_alert_ids") or []))
        )
    ]
    stored_profile = get_entity_profile(normalized_type, normalized_key) or {}
    profile = build_entity_profile(
        normalized_type,
        normalized_key,
        alerts=matching_alerts,
        cases=related_cases,
        base_profile=stored_profile,
    )
    return jsonify({
        "profile": profile,
        "recent_alerts": [_build_entity_alert_summary(alert) | {
            "id": alert.get("id"),
            "attackType": alert.get("rule") or alert.get("attack_type"),
        } for alert in matching_alerts[:8]],
    })


@app.get("/alerts/ip/<ip>")
def alerts_by_ip(ip: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    alerts = _serialize_alerts_with_correlation(get_alerts_by_ip(ip))
    return jsonify({"alerts": alerts})


@app.get("/investigate/ip/<ip>")
def investigate_ip_route(ip: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    return jsonify(investigate_ip(ip))


@app.get("/investigate/account/<account_id>")
def investigate_account_route(account_id: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    return jsonify(investigate_account(account_id))


@app.get("/investigate/device/<device_hash>")
def investigate_device_route(device_hash: str):
    auth_error = authorize_request()
    if auth_error:
        return auth_error
    return jsonify(investigate_device(device_hash))


def handle_alerts_socket(ws):
    auth_token = ws.receive()
    try:
        require_jwt(auth_token)
    except PermissionError:
        ws.close()
        return

    ensure_stream_thread()
    with ws_lock:
        ws_clients.add(ws)

    try:
        while True:
            message = ws.receive()
            if message is None:
                break
    finally:
        with ws_lock:
            ws_clients.discard(ws)


@sock.route("/ws")
def attacks_socket(ws):
    handle_alerts_socket(ws)


@sock.route("/ws/alerts")
def alerts_socket(ws):
    handle_alerts_socket(ws)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
