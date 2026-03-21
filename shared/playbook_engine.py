from __future__ import annotations

import time
import uuid
from copy import deepcopy

from services.geolocation_service.service import fetch_ip_geolocation
from services.threat_intel_service.service import fetch_provider_payload
from shared.alert_state import assign_analyst, get_state, link_case, set_case_id, suppress_alert
from shared.audit_log import log_action
from shared.blocklist import block_ip
from shared.entity_context import compute_alert_risk
from shared.incident_records import create_case, list_cases, update_case
from shared.users import USERS


PLAYBOOK_EXECUTIONS: list[dict] = []
_PLAYBOOK_ASSIGNMENT_CURSOR = 0

PLAYBOOK_DEFINITIONS = {
    "credential_containment": {
        "playbook_id": "playbook-credential-containment",
        "title": "Credential Containment",
        "summary": "Enrich hostile IP context, verify reputation, open a case, and assign an analyst automatically.",
        "trigger": {
            "attack_types": ["credential_stuffing", "honeypot_access", "high_risk_actor"],
            "severity": ["high", "critical"],
        },
        "conditions": {
            "min_risk_score": 70,
            "min_reputation_score": 40,
        },
        "auto_tags": ["automation", "identity", "containment"],
        "recommended_actions": ["create_case", "assign_analyst", "block_ip"],
        "actions": [
            {"type": "enrich_ip"},
            {"type": "check_threat_intel"},
            {"type": "create_case"},
            {"type": "assign_analyst"},
            {"type": "block_ip"},
        ],
    },
    "benign_login_suppression": {
        "playbook_id": "playbook-benign-login-suppression",
        "title": "Benign Login Suppression",
        "summary": "Enrich suspicious login context and suppress low-risk alerts that look benign.",
        "trigger": {
            "attack_types": ["suspicious_login", "anomaly_spike"],
            "severity": ["low", "medium"],
        },
        "conditions": {
            "max_risk_score": 45,
        },
        "auto_tags": ["automation", "triage"],
        "recommended_actions": ["suppress_alert"],
        "actions": [
            {"type": "enrich_ip"},
            {"type": "suppress_alert"},
        ],
    },
}

ATTACK_TYPE_MAP = {
    "phishing": "credential_containment",
    "credential_stuffing": "credential_containment",
    "suspicious_login": "benign_login_suppression",
    "honeypot_access": "credential_containment",
    "honeypot_hit": "credential_containment",
    "high_risk_actor": "credential_containment",
    "anomaly_spike": "benign_login_suppression",
}


def _safe_string(value) -> str:
    return str(value or "").strip()


def _safe_number(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _details(alert: dict | None) -> dict:
    return alert.get("details") if isinstance(alert, dict) and isinstance(alert.get("details"), dict) else {}


def _attack_type(alert: dict | None) -> str:
    payload = alert if isinstance(alert, dict) else {}
    details = _details(payload)
    return _safe_string(
        payload.get("attack_type")
        or payload.get("attackType")
        or payload.get("rule")
        or details.get("attack_type")
        or details.get("rule")
    ).lower()


def _severity(alert: dict | None) -> str:
    payload = alert if isinstance(alert, dict) else {}
    details = _details(payload)
    return _safe_string(payload.get("severity") or details.get("severity") or "medium").lower()


def _alert_id(alert: dict | None) -> str:
    return _safe_string((alert or {}).get("id") or _details(alert or {}).get("id"))


def _source_ip(alert: dict | None) -> str:
    payload = alert if isinstance(alert, dict) else {}
    details = _details(payload)
    return _safe_string(payload.get("source_ip") or payload.get("ip") or details.get("ip") or details.get("source_ip"))


def resolve_playbook_key(alert: dict | None) -> str | None:
    attack_type = _attack_type(alert)
    if not attack_type:
        return None
    return ATTACK_TYPE_MAP.get(attack_type)


def list_playbooks() -> list[dict]:
    return [
        {
            **deepcopy(definition),
            "id": definition.get("playbook_id") or key,
            "key": key,
        }
        for key, definition in PLAYBOOK_DEFINITIONS.items()
    ]


def list_playbook_executions(limit: int = 50) -> list[dict]:
    return [deepcopy(entry) for entry in PLAYBOOK_EXECUTIONS[-limit:]][::-1]


def build_playbook_payload(alert: dict | None) -> dict | None:
    key = resolve_playbook_key(alert)
    if not key:
        return None
    definition = PLAYBOOK_DEFINITIONS.get(key)
    if not definition:
        return None
    payload = deepcopy(definition)
    payload["id"] = payload.get("playbook_id") or key
    payload["key"] = key
    payload["triggered_by"] = _attack_type(alert) or key
    return payload


def _select_analyst() -> str:
    global _PLAYBOOK_ASSIGNMENT_CURSOR
    analysts = sorted([username for username, record in USERS.items() if record.get("role") == "analyst"])
    if not analysts:
        return "analyst"
    analyst = analysts[_PLAYBOOK_ASSIGNMENT_CURSOR % len(analysts)]
    _PLAYBOOK_ASSIGNMENT_CURSOR += 1
    return analyst


def _find_case_for_alert(alert_id: str) -> dict | None:
    normalized = _safe_string(alert_id)
    if not normalized:
        return None
    return next(
        (
            case for case in list_cases()
            if normalized in [_safe_string(case.get("alert_id")), _safe_string(case.get("source_alert_id")), *[_safe_string(value) for value in (case.get("linked_alert_ids") or [])]]
        ),
        None,
    )


def _timeline_entry(step: str, message: str, actor: str, status: str = "success", metadata: dict | None = None) -> dict:
    return {
        "type": "playbook_step",
        "label": message,
        "author": actor,
        "timestamp": time.time(),
        "step": step,
        "status": status,
        "metadata": metadata or {},
    }


def _case_action(case_record: dict | None, action_type: str, actor: str, message: str, result: dict | None = None) -> dict:
    case_id = _safe_string((case_record or {}).get("id"))
    return {
        "id": f"playbook-action-{uuid.uuid4().hex[:8]}",
        "type": "playbook_action",
        "actionType": action_type,
        "label": message,
        "author": actor,
        "timestamp": time.time(),
        "caseId": case_id or None,
        "status": "success",
        "result": result or {},
    }


def _record_case_artifacts(alert: dict, actor: str, step_name: str, message: str, snapshot: dict | None = None) -> dict | None:
    alert_id = _alert_id(alert)
    if not alert_id:
        return None
    case_record = _find_case_for_alert(alert_id)
    if not case_record:
        return None
    timeline_entry = _timeline_entry(step_name, message, actor, metadata=snapshot or {})
    action_entry = _case_action(case_record, step_name, actor, message, snapshot or {})
    updated = update_case(
        case_record["id"],
        action=action_entry,
        timeline_entry=timeline_entry,
        enrichment_snapshot={
            "type": "playbook_snapshot",
            "timestamp": time.time(),
            "source": step_name,
            "snapshot": snapshot or {"message": message},
        },
    )
    return updated or case_record


def _matches_conditions(alert: dict, definition: dict) -> bool:
    conditions = definition.get("conditions") or {}
    risk_score = _safe_number(_details(alert).get("risk_score") or alert.get("risk_score") or compute_alert_risk(alert))
    reputation_score = _safe_number(_details(alert).get("reputation_score") or alert.get("reputation_score") or risk_score)
    if "min_risk_score" in conditions and risk_score < _safe_number(conditions.get("min_risk_score")):
        return False
    if "max_risk_score" in conditions and risk_score > _safe_number(conditions.get("max_risk_score"), 10**9):
        return False
    if "min_reputation_score" in conditions and reputation_score < _safe_number(conditions.get("min_reputation_score")):
        return False
    return True


def should_auto_execute(alert: dict | None, playbook_key: str | None = None) -> bool:
    key = playbook_key or resolve_playbook_key(alert)
    if not key:
        return False
    definition = PLAYBOOK_DEFINITIONS.get(key) or {}
    trigger = definition.get("trigger") or {}
    attack_types = [value.lower() for value in trigger.get("attack_types", [])]
    severities = [value.lower() for value in trigger.get("severity", [])]
    if attack_types and _attack_type(alert) not in attack_types:
        return False
    if severities and _severity(alert) not in severities:
        return False
    return _matches_conditions(alert or {}, definition)


def _action_enrich_ip(alert: dict, actor: str) -> dict:
    ip = _source_ip(alert)
    geo = fetch_ip_geolocation(ip) if ip else {}
    result = {
        "ip": ip,
        "country": geo.get("country") or geo.get("country_code"),
        "region": geo.get("region"),
        "city": geo.get("city"),
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
    }
    _record_case_artifacts(alert, actor, "enrich_ip", f"{actor} enriched IP context for {ip or 'unknown'}", result)
    log_action(actor, "playbook_enrich_ip", ip or _alert_id(alert), target_type="alert", related_alert_id=_alert_id(alert), result=result, message=f"{actor} enriched IP context via playbook")
    return result


def _action_check_threat_intel(alert: dict, actor: str) -> dict:
    ip = _source_ip(alert)
    provider = fetch_provider_payload(ip) if ip else {}
    result = {
        "ip": ip,
        "provider": provider,
        "reputation_score": _safe_number(_details(alert).get("reputation_score") or alert.get("reputation_score")),
    }
    _record_case_artifacts(alert, actor, "check_threat_intel", f"{actor} checked threat intel for {ip or 'unknown'}", result)
    log_action(actor, "playbook_check_threat_intel", ip or _alert_id(alert), target_type="alert", related_alert_id=_alert_id(alert), result=result, message=f"{actor} checked threat intel via playbook")
    return result


def _action_create_case(alert: dict, actor: str) -> dict:
    alert_id = _alert_id(alert)
    existing_case = _find_case_for_alert(alert_id)
    if existing_case:
        _record_case_artifacts(alert, actor, "create_case", f"{actor} reused case {existing_case['id']} during playbook execution", {"case_id": existing_case["id"]})
        return {"case_id": existing_case["id"], "created": False}
    case_record = create_case(
        title=f"Automated case for {_attack_type(alert) or alert_id}",
        alert_id=alert_id or None,
        priority="high" if _severity(alert) in {"high", "critical"} else "medium",
        status="open",
        severity=_severity(alert) or "medium",
        assignee=None,
        summary=f"Created automatically by playbook for {_attack_type(alert) or 'alert'}",
        linked_alert_ids=[alert_id] if alert_id else None,
        actions=[_case_action(None, "playbook_create_case", actor, f"{actor} created a case via playbook", {"alert_id": alert_id})],
        evidence={
            "timeline": [_timeline_entry("playbook_create_case", f"{actor} created case automatically", actor, metadata={"alert_id": alert_id})],
            "enrichments": [],
            "analyst_notes": [],
        },
        source="playbook",
    )
    if alert_id:
        link_case(alert_id, case_record["id"])
        set_case_id(alert_id, case_record["id"])
    log_action(actor, "playbook_create_case", case_record["id"], target_type="case", target_id=case_record["id"], related_alert_id=alert_id or None, related_case_id=case_record["id"], result={"case_id": case_record["id"]}, message=f"{actor} created case {case_record['id']} via playbook")
    return {"case_id": case_record["id"], "created": True}


def _action_assign_analyst(alert: dict, actor: str) -> dict:
    alert_id = _alert_id(alert)
    analyst = _select_analyst()
    if alert_id:
        assign_analyst(alert_id, analyst)
    case_record = _find_case_for_alert(alert_id)
    if case_record:
        update_case(
            case_record["id"],
            assignee=analyst,
            action=_case_action(case_record, "playbook_assign_analyst", actor, f"{actor} assigned case to {analyst}", {"assignee": analyst}),
            timeline_entry=_timeline_entry("playbook_assign_analyst", f"{actor} assigned analyst {analyst}", actor, metadata={"assignee": analyst}),
        )
    log_action(actor, "playbook_assign_analyst", alert_id or analyst, target_type="alert", related_alert_id=alert_id or None, related_case_id=(case_record or {}).get("id"), result={"assigned_to": analyst}, message=f"{actor} assigned analyst {analyst} via playbook")
    return {"assigned_to": analyst}


def _action_block_ip(alert: dict, actor: str) -> dict:
    ip = _source_ip(alert)
    if ip:
        block_ip(ip)
    case_record = _record_case_artifacts(alert, actor, "block_ip", f"{actor} blocked IP {ip or 'unknown'} via playbook", {"ip": ip, "blocked": bool(ip)})
    log_action(actor, "playbook_block_ip", ip or _alert_id(alert), target_type="alert", related_alert_id=_alert_id(alert), related_case_id=(case_record or {}).get("id"), result={"ip": ip, "blocked": bool(ip)}, message=f"{actor} blocked IP {ip or 'unknown'} via playbook")
    return {"ip": ip, "blocked": bool(ip)}


def _action_suppress_alert(alert: dict, actor: str) -> dict:
    alert_id = _alert_id(alert)
    if alert_id:
        suppress_alert(alert_id)
    case_record = _record_case_artifacts(alert, actor, "suppress_alert", f"{actor} suppressed alert {alert_id or 'unknown'} via playbook", {"alert_id": alert_id})
    log_action(actor, "playbook_suppress_alert", alert_id or "-", target_type="alert", related_alert_id=alert_id or None, related_case_id=(case_record or {}).get("id"), result={"suppressed": bool(alert_id)}, message=f"{actor} suppressed alert {alert_id or 'unknown'} via playbook")
    return {"suppressed": bool(alert_id)}


ACTION_EXECUTORS = {
    "enrich_ip": _action_enrich_ip,
    "check_threat_intel": _action_check_threat_intel,
    "create_case": _action_create_case,
    "assign_analyst": _action_assign_analyst,
    "block_ip": _action_block_ip,
    "suppress_alert": _action_suppress_alert,
}


def execute_playbook(alert: dict | None, playbook_key: str | None = None, *, actor: str = "system", automatic: bool = False) -> dict | None:
    payload = deepcopy(alert or {})
    key = playbook_key or resolve_playbook_key(payload)
    definition = PLAYBOOK_DEFINITIONS.get(key or "")
    if not definition:
        return None
    if automatic and not should_auto_execute(payload, key):
        return None

    execution = {
        "execution_id": f"pbx-{uuid.uuid4().hex[:10]}",
        "playbook_id": definition.get("playbook_id") or key,
        "playbook_key": key,
        "alert_id": _alert_id(payload) or None,
        "attack_type": _attack_type(payload),
        "automatic": automatic,
        "actor": actor,
        "started_at": time.time(),
        "status": "success",
        "steps": [],
    }

    for action in definition.get("actions", []):
        action_type = _safe_string(action.get("type")).lower()
        executor = ACTION_EXECUTORS.get(action_type)
        if not executor:
            execution["steps"].append({
                "type": action_type,
                "status": "skipped",
                "result": {"reason": "unsupported_action"},
            })
            continue
        try:
            result = executor(payload, actor)
            execution["steps"].append({
                "type": action_type,
                "status": "success",
                "result": result,
            })
        except Exception as exc:
            execution["status"] = "partial_failure"
            execution["steps"].append({
                "type": action_type,
                "status": "failed",
                "result": {"error": str(exc)},
            })

    execution["completed_at"] = time.time()
    PLAYBOOK_EXECUTIONS.append(deepcopy(execution))
    case_record = _find_case_for_alert(_alert_id(payload))
    log_action(
        actor,
        "playbook_execution",
        execution["playbook_id"],
        target_type="playbook",
        target_id=execution["playbook_id"],
        related_alert_id=execution.get("alert_id"),
        related_case_id=(case_record or {}).get("id"),
        result={"status": execution["status"], "automatic": automatic, "steps": execution["steps"]},
        message=f"{actor} {'automatically ' if automatic else ''}executed playbook {execution['playbook_id']}",
    )
    return execution
