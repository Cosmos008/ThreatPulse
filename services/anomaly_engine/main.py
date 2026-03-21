from shared.kafka_utils import create_consumer, create_producer, ensure_topics
from shared.logging_utils import log_json
from shared.metrics import detections_total, events_processed_total, service_latency, start_metrics_server
from shared.topics import CANONICAL_TOPICS
from services.anomaly_engine.service import detect_anomaly


SERVICE_NAME = "anomaly_engine"


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    consumer = create_consumer(CANONICAL_TOPICS["events_enriched"], group_id="anomaly-engine")
    producer = create_producer()

    log_json(SERVICE_NAME, "info", "service_started")

    for message in consumer:
        event = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="analyze").time():
            alert = detect_anomaly(event)
        if alert:
            detections_total.labels(service=SERVICE_NAME, rule=alert["rule"]).inc()
            producer.send(CANONICAL_TOPICS["detections_anomaly"], alert)
            log_json(SERVICE_NAME, "warning", "anomaly_emitted", alert=alert)


if __name__ == "__main__":
    main()
