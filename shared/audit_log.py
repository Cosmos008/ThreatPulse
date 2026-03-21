import time
import uuid


AUDIT_LOG = []


def log_action(
    user,
    action,
    target=None,
    *,
    target_type="system",
    target_id=None,
    related_case_id=None,
    related_alert_id=None,
    input=None,
    result=None,
    status="success",
    message="",
):
    timestamp = time.time()
    record = {
        "actionId": f"act-{uuid.uuid4().hex[:10]}",
        "actionType": str(action or "").strip().lower(),
        "actor": user,
        "timestamp": timestamp,
        "targetType": str(target_type or "system").strip().lower(),
        "targetId": str(target_id or target or "-"),
        "relatedCaseId": str(related_case_id) if related_case_id else None,
        "relatedAlertId": str(related_alert_id) if related_alert_id else None,
        "input": input,
        "result": result,
        "status": str(status or "success").strip().lower(),
        "message": message or "",
        # Backwards-compatible fields
        "user": user,
        "username": user,
        "action": str(action or "").strip().lower(),
        "target": str(target or target_id or "-"),
        "details": message or "",
    }
    AUDIT_LOG.append(record)
    return record


def get_logs():
    return AUDIT_LOG[-100:]
