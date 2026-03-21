from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from shared.rule_config import get_rule_section


signal_windows: dict[str, deque[dict]] = defaultdict(deque)


def _build_sequence(window: deque[dict]) -> list[dict]:
    return [
        {
            "rule": entry["rule"],
            "timestamp": entry["timestamp"].isoformat(),
            "severity": ((entry.get("alert") or entry).get("severity", "medium")),
        }
        for entry in window
    ]


def detect_attack_sequence(events: list[dict]) -> dict | None:
    grouped_events: dict[str, list[dict]] = defaultdict(list)

    for event in events:
        ip = event.get("source_ip") or event.get("ip")
        if not ip:
            continue
        grouped_events[ip].append(event)

    if not grouped_events:
        return None

    latest_ip, latest_events = max(
        grouped_events.items(),
        key=lambda item: max(
            entry.get("timestamp", datetime.min.replace(tzinfo=UTC))
            if isinstance(entry.get("timestamp"), datetime)
            else datetime.min.replace(tzinfo=UTC)
            for entry in item[1]
        )
    )

    sorted_events = sorted(
        latest_events,
        key=lambda event: event.get("timestamp", datetime.min.replace(tzinfo=UTC))
        if isinstance(event.get("timestamp"), datetime)
        else datetime.min.replace(tzinfo=UTC)
    )

    if not sorted_events:
        return None

    latest_timestamp = sorted_events[-1]["timestamp"]
    cutoff = latest_timestamp - timedelta(minutes=5)
    recent_events = [event for event in sorted_events if event["timestamp"] >= cutoff]
    attack_types = sorted({event.get("rule") or event.get("attack_type") or "alert" for event in recent_events})

    if not attack_types:
        return None

    sequence_type = "single"
    escalated = False

    if "honeypot_access" in attack_types:
        sequence_type = "critical"
        escalated = True
    elif len(attack_types) >= 3:
        sequence_type = "coordinated"
    elif len(attack_types) >= 2:
        sequence_type = "suspicious"

    return {
        "ip": latest_ip,
        "sequence_type": sequence_type,
        "attack_types": attack_types,
        "events": _build_sequence(deque(recent_events)),
        "escalated": escalated,
    }


def correlate_alert(alert: dict) -> dict | None:
    ip = alert.get("ip")
    if not ip:
        return None

    config = get_rule_section("correlation_engine")
    critical_rules = set(config.get("critical_rules", []))
    now = datetime.now(UTC)
    window = signal_windows[ip]
    window.append({"rule": alert.get("rule"), "timestamp": now, "alert": alert})

    cutoff = now - timedelta(minutes=15)
    while window and window[0]["timestamp"] < cutoff:
        window.popleft()

    coordinated_cutoff = now - timedelta(minutes=5)
    coordinated_window = [entry for entry in window if entry["timestamp"] >= coordinated_cutoff]
    coordinated_rules = {entry["rule"] for entry in coordinated_window}
    sequence = detect_attack_sequence(
        [
            {
                "ip": ip,
                "rule": entry["rule"],
                "timestamp": entry["timestamp"],
                "severity": (entry["alert"] or {}).get("severity", "medium"),
            }
            for entry in coordinated_window
        ]
    )

    if len(coordinated_rules) >= 3:
        correlated = {
            "rule": "coordinated_attack",
            "severity": "critical",
            "ip": ip,
            "signals": sorted(coordinated_rules),
            "risk_score": 220,
            "details": {
                "sequence": _build_sequence(deque(coordinated_window)),
                "coordinated_attack": True,
                "confidence_label": "Multi-stage attack detected",
            },
        }
        if sequence and sequence["sequence_type"] != "single":
            correlated["sequence"] = sequence
        return correlated

    rules = {entry["rule"] for entry in window}
    if len(rules & critical_rules) >= 2:
        correlated = {
            "rule": "correlated_attack_chain",
            "severity": "critical",
            "ip": ip,
            "signals": sorted(rules),
            "risk_score": 150,
            "details": {
                "sequence": _build_sequence(window),
            },
        }
        if sequence and sequence["sequence_type"] != "single":
            correlated["sequence"] = sequence
        return correlated

    return None
