play_counts = {}

from shared.rule_config import get_detection_rule


def check_streaming_fraud(event):
    rule = get_detection_rule("streaming_fraud")
    if not rule.get("enabled", True):
        return None
    threshold = int(rule.get("threshold", 50))

    if event.get("event_type") != "music_play":
        return None

    ip = event.get("ip")

    play_counts[ip] = play_counts.get(ip, 0) + 1

    if play_counts[ip] > threshold and (
        play_counts[ip] == threshold + 1 or play_counts[ip] % 25 == 0
    ):

        return {
            "rule": "streaming_fraud",
            "severity": rule.get("severity", "medium"),
            "ip": ip,
            "mitre": rule.get("mitre_mapping"),
            "plays": play_counts[ip]
        }

    return None
