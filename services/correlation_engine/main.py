from shared.kafka_utils import create_consumer, create_producer, ensure_topics
from shared.logging_utils import log_json
from shared.metrics import alerts_generated_total, events_processed_total, service_latency, start_metrics_server
from shared.topics import CANONICAL_TOPICS
from services.correlation_engine.service import correlate_alert


SERVICE_NAME = "correlation_engine"


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    consumer = create_consumer(
        CANONICAL_TOPICS["detections_rules"],
        CANONICAL_TOPICS["detections_anomaly"],
        group_id="correlation-engine",
    )
    producer = create_producer()

    log_json(SERVICE_NAME, "info", "service_started")

    for message in consumer:
        alert = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="correlate").time():
            correlated = correlate_alert(alert)
        if correlated:
            alerts_generated_total.labels(service=SERVICE_NAME, severity=correlated["severity"]).inc()
            producer.send(CANONICAL_TOPICS["alerts_correlated"], correlated)
            log_json(SERVICE_NAME, "warning", "correlated_alert_emitted", alert=correlated)


if __name__ == "__main__":
    main()
