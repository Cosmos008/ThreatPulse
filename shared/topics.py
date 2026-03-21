CANONICAL_TOPICS = {
    "events_raw": "events.raw",
    "events_parsed": "events.parsed",
    "events_routed": "events.routed",
    "events_enriched": "events.enriched",
    "detections_rules": "detections.rules",
    "detections_anomaly": "detections.anomaly",
    "risk_scores": "risk.scores",
    "alerts_correlated": "alerts.correlated",
    "alerts_generated": "alerts.generated",
}

LEGACY_TOPICS = {
    "raw_logs": "raw_logs",
    "parsed_events": "parsed_events",
    "auth_events": "auth_events",
    "stream_events": "stream_events",
    "session_events": "session_events",
    "security_alerts": "security_alerts",
    "risk_alerts": "risk_alerts",
}

TOPIC_ALIASES = {
    CANONICAL_TOPICS["events_raw"]: [LEGACY_TOPICS["raw_logs"]],
    CANONICAL_TOPICS["events_parsed"]: [LEGACY_TOPICS["parsed_events"]],
    CANONICAL_TOPICS["detections_rules"]: [LEGACY_TOPICS["security_alerts"]],
    CANONICAL_TOPICS["risk_scores"]: [LEGACY_TOPICS["risk_alerts"]],
}

ALL_TOPICS = sorted(
    {
        *CANONICAL_TOPICS.values(),
        *LEGACY_TOPICS.values(),
    }
)


def get_alias_topics(topic: str) -> list[str]:
    return TOPIC_ALIASES.get(topic, [])
