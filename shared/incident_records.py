import time
import uuid
from copy import deepcopy


INVESTIGATIONS: dict[str, dict] = {}
CASES: dict[str, dict] = {}


def _now() -> float:
    return time.time()


def _build_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _copy(record: dict | None) -> dict | None:
    if record is None:
        return None
    return deepcopy(record)


def _normalize_evidence(evidence: dict | None = None) -> dict:
    payload = evidence if isinstance(evidence, dict) else {}
    return {
        "timeline": list(payload.get("timeline") or []),
        "enrichments": list(payload.get("enrichments") or []),
        "analyst_notes": list(payload.get("analyst_notes") or []),
    }


def _normalize_case_ids(values: list[str] | None = None) -> list[str]:
    seen = set()
    normalized = []
    for value in values or []:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def _append_unique_entry(entries: list[dict], entry: dict | None) -> list[dict]:
    if not isinstance(entry, dict) or not entry:
        return entries
    candidate = dict(entry)
    key = (
        str(candidate.get("timestamp") or ""),
        str(candidate.get("type") or ""),
        str(candidate.get("text") or candidate.get("message") or candidate.get("label") or ""),
    )
    if any(
        (
            str(existing.get("timestamp") or ""),
            str(existing.get("type") or ""),
            str(existing.get("text") or existing.get("message") or existing.get("label") or ""),
        ) == key
        for existing in entries
        if isinstance(existing, dict)
    ):
        return entries
    return [*entries, candidate]


def reset_records() -> None:
    INVESTIGATIONS.clear()
    CASES.clear()


def list_investigations() -> list[dict]:
    return [
        _copy(record)
        for record in sorted(
            INVESTIGATIONS.values(),
            key=lambda item: (float(item.get("updated_at") or 0), float(item.get("created_at") or 0)),
            reverse=True,
        )
    ]


def get_investigation(investigation_id: str) -> dict | None:
    return _copy(INVESTIGATIONS.get(str(investigation_id)))


def upsert_investigation(
    *,
    alert_id: str,
    entity_key: str | None = None,
    created_by: str | None = None,
    status: str = "open",
    case_id: str | None = None,
    notes: list[dict] | None = None,
    title: str = "",
    summary: str = "",
    analyst: str | None = None,
    related_alert_ids: list[str] | None = None,
    actions: list[dict] | None = None,
    source: str = "manual",
) -> dict:
    normalized_alert_id = str(alert_id)
    existing = next(
        (record for record in INVESTIGATIONS.values() if record.get("alert_id") == normalized_alert_id),
        None,
    )
    now = _now()
    if existing:
        merged_notes = existing.get("notes") or []
        if isinstance(notes, list) and notes:
            merged_notes = [*merged_notes, *notes]
        merged_actions = existing.get("actions") or []
        if isinstance(actions, list) and actions:
            merged_actions = [*merged_actions, *actions]
        existing.update({
            "title": title or existing.get("title") or f"Investigation for {normalized_alert_id}",
            "summary": summary if summary != "" else existing.get("summary", ""),
            "analyst": analyst or existing.get("analyst"),
            "created_by": created_by or existing.get("created_by") or analyst or existing.get("analyst"),
            "entity_key": entity_key or existing.get("entity_key"),
            "status": str(status or existing.get("status") or "open").lower(),
            "case_id": case_id if case_id is not None else existing.get("case_id"),
            "notes": merged_notes,
            "actions": merged_actions,
            "related_alert_ids": sorted(set(related_alert_ids or existing.get("related_alert_ids") or [normalized_alert_id])),
            "source": source or existing.get("source") or "manual",
            "updated_at": now,
        })
        return _copy(existing)

    record = {
        "id": _build_id("inv"),
        "alert_id": normalized_alert_id,
        "title": title or f"Investigation for {normalized_alert_id}",
        "summary": summary,
        "analyst": analyst,
        "created_by": created_by or analyst,
        "entity_key": entity_key,
        "status": str(status or "open").lower(),
        "case_id": case_id,
        "notes": list(notes or []),
        "actions": list(actions or []),
        "related_alert_ids": sorted(set(related_alert_ids or [normalized_alert_id])),
        "source": source or "manual",
        "created_at": now,
        "updated_at": now,
    }
    INVESTIGATIONS[record["id"]] = record
    return _copy(record)


def update_investigation(investigation_id: str, **updates) -> dict | None:
    record = INVESTIGATIONS.get(str(investigation_id))
    if not record:
        return None

    if "title" in updates and updates["title"]:
        record["title"] = str(updates["title"])
    if "summary" in updates and updates["summary"] is not None:
        record["summary"] = str(updates["summary"])
    if "analyst" in updates and updates["analyst"] is not None:
        record["analyst"] = str(updates["analyst"]) or None
    if "created_by" in updates and updates["created_by"] is not None:
        record["created_by"] = str(updates["created_by"]) or None
    if "entity_key" in updates and updates["entity_key"] is not None:
        record["entity_key"] = str(updates["entity_key"]) or None
    if "status" in updates and updates["status"]:
        record["status"] = str(updates["status"]).lower()
    if "case_id" in updates:
        record["case_id"] = str(updates["case_id"]) if updates["case_id"] else None
    if "related_alert_ids" in updates and updates["related_alert_ids"] is not None:
        record["related_alert_ids"] = sorted(set(str(value) for value in updates["related_alert_ids"] if value))
    if "note" in updates and updates["note"]:
        record.setdefault("notes", []).append({
            "text": str(updates["note"]),
            "timestamp": _now(),
        })
    if "notes" in updates and isinstance(updates["notes"], list):
        record["notes"] = list(updates["notes"])
    if "action" in updates and isinstance(updates["action"], dict):
        record.setdefault("actions", []).append(dict(updates["action"]))
    if "actions" in updates and isinstance(updates["actions"], list):
        record["actions"] = list(updates["actions"])
    record["updated_at"] = _now()
    return _copy(record)


def list_cases() -> list[dict]:
    return [
        _copy(record)
        for record in sorted(
            CASES.values(),
            key=lambda item: (float(item.get("updated_at") or 0), float(item.get("created_at") or 0)),
            reverse=True,
        )
    ]


def get_case(case_id: str) -> dict | None:
    return _copy(CASES.get(str(case_id)))


def create_case(
    *,
    title: str,
    alert_id: str | None = None,
    investigation_id: str | None = None,
    priority: str = "medium",
    status: str = "open",
    severity: str | None = None,
    assignee: str | None = None,
    summary: str = "",
    linked_alert_ids: list[str] | None = None,
    notes: list[dict] | None = None,
    actions: list[dict] | None = None,
    evidence: dict | None = None,
    parent_case_id: str | None = None,
    linked_cases: list[str] | None = None,
    source: str = "manual",
) -> dict:
    normalized_alert_id = str(alert_id) if alert_id else None
    normalized_investigation_id = str(investigation_id) if investigation_id else None
    for record in CASES.values():
        if normalized_alert_id and (
            record.get("source_alert_id") == normalized_alert_id
            or record.get("alert_id") == normalized_alert_id
            or normalized_alert_id in (record.get("linked_alert_ids") or [])
        ):
            return _copy(record)
        if normalized_investigation_id and (
            record.get("source_investigation_id") == normalized_investigation_id
            or record.get("investigation_id") == normalized_investigation_id
        ):
            return _copy(record)

    now = _now()
    normalized_linked_alert_ids = sorted(set(
        str(value) for value in (linked_alert_ids or []) if value
    ))
    if normalized_alert_id and normalized_alert_id not in normalized_linked_alert_ids:
        normalized_linked_alert_ids.append(normalized_alert_id)
    normalized_evidence = _normalize_evidence(evidence)
    for note in list(notes or []):
        normalized_evidence["analyst_notes"] = _append_unique_entry(normalized_evidence["analyst_notes"], note)
    for action in list(actions or []):
        normalized_evidence["timeline"] = _append_unique_entry(normalized_evidence["timeline"], action)

    record = {
        "id": _build_id("case"),
        "title": title,
        "summary": summary,
        "source_alert_id": normalized_alert_id,
        "source_investigation_id": normalized_investigation_id,
        "linked_alert_ids": normalized_linked_alert_ids,
        "alert_id": normalized_alert_id,
        "investigation_id": normalized_investigation_id,
        "priority": str(priority or "medium").lower(),
        "status": str(status or "open").lower(),
        "severity": str(severity or "medium").lower(),
        "assignee": assignee,
        "source": source or "manual",
        "created_at": now,
        "updated_at": now,
        "notes": list(notes or []),
        "actions": list(actions or []),
        "evidence": normalized_evidence,
        "parent_case_id": str(parent_case_id).strip() if parent_case_id else None,
        "linked_cases": _normalize_case_ids(linked_cases),
    }
    CASES[record["id"]] = record
    return _copy(record)


def update_case(case_id: str, **updates) -> dict | None:
    record = CASES.get(str(case_id))
    if not record:
        return None

    evidence = _normalize_evidence(record.get("evidence"))
    if "title" in updates and updates["title"]:
        record["title"] = str(updates["title"])
    if "summary" in updates and updates["summary"] is not None:
        record["summary"] = str(updates["summary"])
    if "priority" in updates and updates["priority"]:
        record["priority"] = str(updates["priority"]).lower()
    if "status" in updates and updates["status"]:
        record["status"] = str(updates["status"]).lower()
    if "severity" in updates and updates["severity"]:
        record["severity"] = str(updates["severity"]).lower()
    if "assignee" in updates and updates["assignee"] is not None:
        record["assignee"] = str(updates["assignee"]) or None
    if "parent_case_id" in updates:
        record["parent_case_id"] = str(updates["parent_case_id"]).strip() if updates["parent_case_id"] else None
    if "linked_cases" in updates and updates["linked_cases"] is not None:
        record["linked_cases"] = _normalize_case_ids(updates["linked_cases"])
    if "linked_alert_ids" in updates and updates["linked_alert_ids"] is not None:
        record["linked_alert_ids"] = sorted(set(str(value) for value in updates["linked_alert_ids"] if value))
    if "note" in updates and updates["note"]:
        note_entry = {
            "text": str(updates["note"]),
            "timestamp": _now(),
        }
        record.setdefault("notes", []).append(note_entry)
        evidence["analyst_notes"] = _append_unique_entry(evidence["analyst_notes"], note_entry)
    if "action" in updates and isinstance(updates["action"], dict):
        action_entry = dict(updates["action"])
        record.setdefault("actions", []).append(action_entry)
        evidence["timeline"] = _append_unique_entry(evidence["timeline"], action_entry)
    if "actions" in updates and isinstance(updates["actions"], list):
        for action_entry in updates["actions"]:
            evidence["timeline"] = _append_unique_entry(
                evidence["timeline"],
                action_entry if isinstance(action_entry, dict) else None,
            )
        record["actions"] = list(updates["actions"])
    if "evidence" in updates and isinstance(updates["evidence"], dict):
        incoming = _normalize_evidence(updates["evidence"])
        for note_entry in incoming["analyst_notes"]:
            evidence["analyst_notes"] = _append_unique_entry(evidence["analyst_notes"], note_entry)
        for timeline_entry in incoming["timeline"]:
            evidence["timeline"] = _append_unique_entry(evidence["timeline"], timeline_entry)
        for enrichment_entry in incoming["enrichments"]:
            evidence["enrichments"] = _append_unique_entry(evidence["enrichments"], enrichment_entry)
    if "analyst_note" in updates and isinstance(updates["analyst_note"], dict):
        evidence["analyst_notes"] = _append_unique_entry(evidence["analyst_notes"], updates["analyst_note"])
    if "timeline_entry" in updates and isinstance(updates["timeline_entry"], dict):
        evidence["timeline"] = _append_unique_entry(evidence["timeline"], updates["timeline_entry"])
    if "enrichment_snapshot" in updates and isinstance(updates["enrichment_snapshot"], dict):
        evidence["enrichments"] = _append_unique_entry(evidence["enrichments"], updates["enrichment_snapshot"])
    record["evidence"] = evidence
    record["updated_at"] = _now()
    return _copy(record)


def link_cases(case_id: str, other_case_id: str) -> tuple[dict, dict]:
    primary = CASES.get(str(case_id))
    secondary = CASES.get(str(other_case_id))
    if not primary or not secondary:
        raise ValueError("Case not found")
    if primary["id"] == secondary["id"]:
        raise ValueError("Cannot link a case to itself")

    primary_links = _normalize_case_ids([*(primary.get("linked_cases") or []), secondary["id"]])
    secondary_links = _normalize_case_ids([*(secondary.get("linked_cases") or []), primary["id"]])
    now = _now()
    primary["linked_cases"] = primary_links
    secondary["linked_cases"] = secondary_links
    primary["updated_at"] = now
    secondary["updated_at"] = now
    return _copy(primary), _copy(secondary)


def merge_cases(primary_case_id: str, secondary_case_id: str) -> tuple[dict, dict]:
    primary = CASES.get(str(primary_case_id))
    secondary = CASES.get(str(secondary_case_id))
    if not primary or not secondary:
        raise ValueError("Case not found")
    if primary["id"] == secondary["id"]:
        raise ValueError("Cannot merge a case into itself")

    primary_evidence = _normalize_evidence(primary.get("evidence"))
    secondary_evidence = _normalize_evidence(secondary.get("evidence"))
    for entry in secondary_evidence["timeline"]:
        primary_evidence["timeline"] = _append_unique_entry(primary_evidence["timeline"], entry)
    for entry in secondary_evidence["enrichments"]:
        primary_evidence["enrichments"] = _append_unique_entry(primary_evidence["enrichments"], entry)
    for entry in secondary_evidence["analyst_notes"]:
        primary_evidence["analyst_notes"] = _append_unique_entry(primary_evidence["analyst_notes"], entry)

    primary["linked_alert_ids"] = sorted(set([
        *[str(value) for value in (primary.get("linked_alert_ids") or []) if value],
        *[str(value) for value in (secondary.get("linked_alert_ids") or []) if value],
    ]))
    primary["linked_cases"] = [
        value for value in _normalize_case_ids([
        *(primary.get("linked_cases") or []),
        secondary["id"],
        *(secondary.get("linked_cases") or []),
    ]) if value != primary["id"]]
    primary["notes"] = [*(primary.get("notes") or []), *(secondary.get("notes") or [])]
    primary["actions"] = [*(primary.get("actions") or []), *(secondary.get("actions") or [])]
    primary["evidence"] = primary_evidence

    secondary["parent_case_id"] = primary["id"]
    secondary["linked_cases"] = [
        value for value in _normalize_case_ids([
        *(secondary.get("linked_cases") or []),
        primary["id"],
        *(primary.get("linked_cases") or []),
    ]) if value != secondary["id"]]
    secondary["status"] = "closed"

    now = _now()
    primary["updated_at"] = now
    secondary["updated_at"] = now
    return _copy(primary), _copy(secondary)


def split_case(case_id: str, alert_ids: list[str] | None = None, title: str | None = None) -> tuple[dict, dict]:
    source_case = CASES.get(str(case_id))
    if not source_case:
        raise ValueError("Case not found")

    selected_alert_ids = _normalize_case_ids(alert_ids)
    if not selected_alert_ids:
        raise ValueError("Missing alert IDs")
    source_linked_alerts = [str(value) for value in (source_case.get("linked_alert_ids") or []) if value]
    if any(alert_id not in source_linked_alerts for alert_id in selected_alert_ids):
        raise ValueError("Split alerts must belong to the source case")
    if len(selected_alert_ids) >= len(source_linked_alerts):
        raise ValueError("Cannot split all alerts out of a case")

    remaining_alert_ids = [alert_id for alert_id in source_linked_alerts if alert_id not in set(selected_alert_ids)]
    source_case["linked_alert_ids"] = remaining_alert_ids
    source_case["updated_at"] = _now()

    child_case = create_case(
        title=title or f"{source_case.get('title') or 'Case'} split",
        alert_id=selected_alert_ids[0],
        investigation_id=source_case.get("source_investigation_id") or source_case.get("investigation_id"),
        priority=source_case.get("priority") or "medium",
        status="open",
        severity=source_case.get("severity") or "medium",
        assignee=source_case.get("assignee"),
        summary=source_case.get("summary") or "",
        linked_alert_ids=selected_alert_ids,
        notes=[],
        actions=[],
        evidence=None,
        parent_case_id=source_case["id"],
        linked_cases=[source_case["id"], *(source_case.get("linked_cases") or [])],
        source="split",
    )
    source_case["linked_cases"] = [value for value in _normalize_case_ids([*(source_case.get("linked_cases") or []), child_case["id"]]) if value != source_case["id"]]
    source_case["updated_at"] = _now()
    return _copy(source_case), _copy(CASES.get(child_case["id"]))
