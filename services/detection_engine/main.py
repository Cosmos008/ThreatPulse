from shared.kafka_utils import create_consumer, ensure_topics
from shared.logging_utils import log_json
from shared.metrics import detections_total, events_processed_total, service_latency, start_metrics_server
from shared.topics import CANONICAL_TOPICS, LEGACY_TOPICS
from services.detection_engine.behavior_analytics import analyze_behavior
from services.detection_engine.credential_stuffing import check_credential_stuffing
from services.detection_engine.device_abuse import check_device_abuse
from services.detection_engine.device_fingerprint import build_device_hash
from services.detection_engine.honeypot_detection import check_honeypot
from services.detection_engine.producer import send_alert
from services.detection_engine.rate_limit_abuse import check_rate_limit_abuse
from services.detection_engine.streaming_fraud import check_streaming_fraud


SERVICE_NAME = "detection_engine"


def intel_alerts(event: dict) -> list[dict]:
    alerts = []
    if event.get("is_tor"):
        alerts.append(
            {
                "rule": "tor_exit_node",
                "severity": "high",
                "ip": event.get("ip"),
                "asn": event.get("asn"),
            }
        )
    if event.get("is_proxy"):
        alerts.append(
            {
                "rule": "proxy_usage",
                "severity": "medium",
                "ip": event.get("ip"),
                "asn": event.get("asn"),
            }
        )
    return alerts


def process_event(event: dict):
    event["device_hash"] = event.get("device_hash") or build_device_hash(event)

    alerts = [
        check_credential_stuffing(event),
        check_honeypot(event),
        check_streaming_fraud(event),
        check_device_abuse(event),
        check_rate_limit_abuse(event),
    ]
    alerts.extend(analyze_behavior(event))
    alerts.extend(intel_alerts(event))
    return [alert for alert in alerts if alert]


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    consumer = create_consumer(
        CANONICAL_TOPICS["events_enriched"],
        group_id="detection-engine",
    )

    log_json(SERVICE_NAME, "info", "service_started")

    for message in consumer:
        event = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume").inc()

        with service_latency.labels(service=SERVICE_NAME, operation="process").time():
            for alert in process_event(event):
                detections_total.labels(service=SERVICE_NAME, rule=alert["rule"]).inc()
                log_json(SERVICE_NAME, "warning", "detection_emitted", alert=alert)
                send_alert(alert)


if __name__ == "__main__":
    main()
