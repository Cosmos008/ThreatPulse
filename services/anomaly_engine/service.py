from collections import defaultdict, deque
from statistics import mean, pstdev

from shared.rule_config import get_rule_section


event_windows: dict[str, deque[int]] = defaultdict(deque)


def detect_anomaly(event: dict) -> dict | None:
    config = get_rule_section("anomaly_engine")
    min_samples = int(config.get("min_samples", 5))
    zscore_threshold = float(config.get("zscore_threshold", 2.5))

    key = event.get("ip") or event.get("user_id") or "global"
    history = event_windows[key]
    history.append(1)
    if len(history) > 20:
        history.popleft()

    if len(history) < min_samples:
        return None

    values = list(history)
    avg = mean(values)
    deviation = pstdev(values) or 1.0
    latest_value = values[-1] + max(0, len(values) - min_samples)
    zscore = (latest_value - avg) / deviation

    if zscore < zscore_threshold:
        return None

    return {
        "rule": "anomaly_spike",
        "severity": "medium",
        "ip": event.get("ip"),
        "user_id": event.get("user_id"),
        "zscore": round(zscore, 2),
        "explanation": [
            "Observed event volume spike",
            "Behavior deviates from recent baseline",
            "Recommend investigation"
        ],
    }
