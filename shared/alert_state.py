import time

ALERT_STATE = {}

ALERT_LIFECYCLE_VALUES = {"new", "in_case", "closed", "false_positive"}
ALERT_DISPOSITION_VALUES = {"new", "acknowledged", "suppressed", "reopened"}


def normalize_alert_status(status: str | None) -> str:
    value = str(status or "").strip().lower()
    mapping = {
        "open": "new",
        "assigned": "new",
        "investigating": "new",
        "in_case": "in_case",
        "escalated": "in_case",
        "converted_to_case": "in_case",
        "processed": "in_case",
        "closed": "closed",
        "false_positive": "false_positive",
    }
    normalized = mapping.get(value, value or "new")
    return normalized if normalized in ALERT_LIFECYCLE_VALUES else "new"


def normalize_alert_disposition(disposition: str | None) -> str:
    value = str(disposition or "").strip().lower()
    mapping = {
        "new": "new",
        "ack": "acknowledged",
        "acknowledge": "acknowledged",
        "acknowledged": "acknowledged",
        "suppress": "suppressed",
        "suppressed": "suppressed",
        "reopen": "reopened",
        "reopened": "reopened",
    }
    normalized = mapping.get(value, value or "new")
    return normalized if normalized in ALERT_DISPOSITION_VALUES else "new"


def _touch(alert_id: str):
    ALERT_STATE.setdefault(alert_id, {})
    ALERT_STATE[alert_id]["updated_at"] = time.time()


def _ensure_defaults(alert_id: str):
    ALERT_STATE.setdefault(alert_id, {})
    ALERT_STATE[alert_id].setdefault("created_at", time.time())
    ALERT_STATE[alert_id].setdefault("disposition", "new")
    ALERT_STATE[alert_id].setdefault("assigned_to", None)
    ALERT_STATE[alert_id].setdefault("merged_into_case_id", None)
    ALERT_STATE[alert_id].setdefault("acknowledged_at", None)
    ALERT_STATE[alert_id].setdefault("closed_at", None)
    ALERT_STATE[alert_id].setdefault("updated_at", time.time())


def can_transition_disposition(current: str | None, target: str | None) -> bool:
    normalized_current = normalize_alert_disposition(current)
    normalized_target = normalize_alert_disposition(target)
    allowed = {
        "new": {"acknowledged", "suppressed"},
        "acknowledged": {"suppressed"},
        "suppressed": {"reopened"},
        "reopened": {"acknowledged", "suppressed"},
    }
    if normalized_current == normalized_target:
        return True
    return normalized_target in allowed.get(normalized_current, set())


def set_disposition(alert_id: str, disposition: str):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id]["disposition"] = normalize_alert_disposition(disposition)
    _touch(alert_id)


def acknowledge_alert(alert_id: str):
    _ensure_defaults(alert_id)
    current = ALERT_STATE[alert_id].get("disposition")
    if not can_transition_disposition(current, "acknowledged"):
        raise ValueError(f"Invalid disposition transition: {current} -> acknowledged")
    ALERT_STATE[alert_id]["disposition"] = "acknowledged"
    ALERT_STATE[alert_id]["acknowledged_at"] = ALERT_STATE[alert_id].get("acknowledged_at") or time.time()
    _touch(alert_id)


def suppress_alert(alert_id: str):
    _ensure_defaults(alert_id)
    current = ALERT_STATE[alert_id].get("disposition")
    if not can_transition_disposition(current, "suppressed"):
        raise ValueError(f"Invalid disposition transition: {current} -> suppressed")
    ALERT_STATE[alert_id]["disposition"] = "suppressed"
    _touch(alert_id)


def reopen_alert(alert_id: str):
    _ensure_defaults(alert_id)
    current = ALERT_STATE[alert_id].get("disposition")
    if not can_transition_disposition(current, "reopened"):
        raise ValueError(f"Invalid disposition transition: {current} -> reopened")
    ALERT_STATE[alert_id]["disposition"] = "reopened"
    ALERT_STATE[alert_id]["closed_at"] = None
    _touch(alert_id)


def set_status(alert_id: str, status: str):
    _ensure_defaults(alert_id)
    normalized = normalize_alert_status(status)
    ALERT_STATE[alert_id]["status"] = normalized
    if normalized == "closed":
        ALERT_STATE[alert_id]["closed_at"] = time.time()
    elif normalized != "closed":
        ALERT_STATE[alert_id]["closed_at"] = None
    _touch(alert_id)


def set_false_positive(alert_id: str):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id]["false_positive"] = True
    ALERT_STATE[alert_id]["status"] = "false_positive"
    ALERT_STATE[alert_id]["closed_at"] = None
    _touch(alert_id)


def link_case(alert_id: str, case_id: str | None = None):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id]["status"] = "in_case"
    if case_id:
        ALERT_STATE[alert_id]["case_id"] = case_id
        ALERT_STATE[alert_id]["merged_into_case_id"] = case_id
    _touch(alert_id)


def set_case_id(alert_id: str, case_id: str | None = None):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id]["case_id"] = case_id
    ALERT_STATE[alert_id]["merged_into_case_id"] = case_id
    _touch(alert_id)


def merge_into_case(alert_id: str, case_id: str):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id]["merged_into_case_id"] = case_id
    ALERT_STATE[alert_id]["case_id"] = case_id
    ALERT_STATE[alert_id]["status"] = "in_case"
    _touch(alert_id)


def assign_analyst(alert_id: str, analyst: str):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id]["analyst"] = analyst
    ALERT_STATE[alert_id]["assigned_to"] = analyst
    ALERT_STATE[alert_id]["status"] = ALERT_STATE[alert_id].get("status") or "new"
    _touch(alert_id)


def lock_alert(alert_id: str, username: str):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id]["locked_by"] = username
    _touch(alert_id)


def add_note(alert_id: str, note: str):
    _ensure_defaults(alert_id)
    ALERT_STATE[alert_id].setdefault("notes", [])
    ALERT_STATE[alert_id]["notes"].append({
        "text": note,
        "timestamp": time.time()
    })
    _touch(alert_id)


def get_state(alert_id: str):
    _ensure_defaults(alert_id)
    return ALERT_STATE.get(alert_id, {})
