device_accounts = {}

from shared.rule_config import get_detection_rule

def check_device_abuse(event):
    rule = get_detection_rule("device_abuse")
    if not rule.get("enabled", True):
        return None
    device = event.get("device_hash") or event.get("device_id")
    user = event.get("user_id")
    threshold = int(rule.get("threshold", 5))

    if not device:
        return None

    if device not in device_accounts:
        device_accounts[device] = set()

    device_accounts[device].add(user)

    if len(device_accounts[device]) == threshold + 1:

        return {
            "rule": "device_abuse",
            "severity": rule.get("severity", "high"),
            "device_hash": device,
            "mitre": rule.get("mitre_mapping"),
            "accounts": len(device_accounts[device])
        }

    return None
