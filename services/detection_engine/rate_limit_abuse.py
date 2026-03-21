from shared.redis_utils import increment_counter
from shared.rule_config import get_detection_rule


def check_rate_limit_abuse(event: dict):
    rule = get_detection_rule("rate_limit_abuse")
    if not rule.get("enabled", True):
        return None
    window_seconds = int(rule.get("time_window_seconds", 60))
    ip_threshold = int(rule.get("threshold", 25))
    user_threshold = int(rule.get("user_threshold", 20))
    device_threshold = int(rule.get("device_threshold", 20))

    ip = event.get("ip")
    user_id = event.get("user_id")
    device_hash = event.get("device_hash") or event.get("device_id")

    if ip:
        ip_count = increment_counter(f"rate:ip:{ip}", window_seconds)
        if ip_count == ip_threshold or (ip_count > ip_threshold and ip_count % ip_threshold == 0):
            return {
                "rule": "rate_limit_abuse",
                "severity": rule.get("severity", "high"),
                "ip": ip,
                "dimension": "ip",
                "mitre": rule.get("mitre_mapping"),
                "requests": ip_count,
            }

    if user_id:
        user_count = increment_counter(f"rate:user:{user_id}", window_seconds)
        if user_count == user_threshold or (user_count > user_threshold and user_count % user_threshold == 0):
            return {
                "rule": "rate_limit_abuse",
                "severity": rule.get("severity", "high"),
                "ip": ip,
                "user_id": user_id,
                "dimension": "user",
                "mitre": rule.get("mitre_mapping"),
                "requests": user_count,
            }

    if device_hash:
        device_count = increment_counter(f"rate:device:{device_hash}", window_seconds)
        if device_count == device_threshold or (device_count > device_threshold and device_count % device_threshold == 0):
            return {
                "rule": "rate_limit_abuse",
                "severity": rule.get("severity", "high"),
                "ip": ip,
                "device_hash": device_hash,
                "dimension": "device",
                "mitre": rule.get("mitre_mapping"),
                "requests": device_count,
            }

    return None
