from services.detection_engine.counters import login_failures
from shared.rule_config import get_detection_rule


def check_credential_stuffing(event):
    rule = get_detection_rule("credential_stuffing")
    if not rule.get("enabled", True):
        return None
    ip = event.get("ip")
    status = event.get("status")
    threshold = int(rule.get("threshold", 10))

    if status != "failed":
        return None

    login_failures[ip] = login_failures.get(ip, 0) + 1

    if login_failures[ip] > threshold and (
        login_failures[ip] == threshold + 1 or login_failures[ip] % 10 == 0
    ):

        return {
            "rule": "credential_stuffing",
            "severity": rule.get("severity", "high"),
            "ip": ip,
            "failed_attempts": login_failures[ip],
            "mitre": rule.get("mitre_mapping"),
            "explanation": [
                "Multiple failed login attempts",
                "Same IP targeting multiple users"
            ]
        }

    return None
