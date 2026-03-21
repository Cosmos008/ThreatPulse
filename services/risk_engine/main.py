from shared.kafka_utils import create_consumer, ensure_topics
from shared.logging_utils import log_json
from shared.metrics import alerts_generated_total, events_processed_total, service_latency, start_metrics_server
from shared.topics import CANONICAL_TOPICS, LEGACY_TOPICS
from services.risk_engine.producer import send_risk_alert
from services.risk_engine.scoring import update_score


SERVICE_NAME = "risk_engine"


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    consumer = create_consumer(
        CANONICAL_TOPICS["detections_rules"],
        CANONICAL_TOPICS["detections_anomaly"],
        group_id="risk-engine",
    )

    log_json(SERVICE_NAME, "info", "service_started")

    for message in consumer:
        alert = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="score").time():
            risk_alert = update_score(alert)
        if risk_alert:
            alerts_generated_total.labels(service=SERVICE_NAME, severity=risk_alert["severity"]).inc()
            log_json(SERVICE_NAME, "warning", "risk_alert_emitted", alert=risk_alert)
            send_risk_alert(risk_alert)


if __name__ == "__main__":
    main()
