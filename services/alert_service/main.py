from concurrent.futures import ThreadPoolExecutor

from shared.clickhouse_utils import store_event_log
from shared.kafka_utils import create_consumer, create_producer, ensure_topics
from shared.logging_utils import log_json
from shared.metrics import alerts_generated_total, events_processed_total, service_latency, start_metrics_server
from shared.neo4j_utils import sync_relationships
from shared.topics import CANONICAL_TOPICS, LEGACY_TOPICS
from services.alert_service.models import save_alert


SERVICE_NAME = "alert_service"


def persist_alerts():
    consumer = create_consumer(
        CANONICAL_TOPICS["detections_rules"],
        CANONICAL_TOPICS["detections_anomaly"],
        CANONICAL_TOPICS["risk_scores"],
        CANONICAL_TOPICS["alerts_correlated"],
        group_id="alert-service",
    )
    producer = create_producer()

    for message in consumer:
        alert = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume_alert").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="persist_alert").time():
            saved_alert = save_alert(alert)
        producer.send(CANONICAL_TOPICS["alerts_generated"], saved_alert)
        alerts_generated_total.labels(service=SERVICE_NAME, severity=saved_alert["severity"]).inc()
        log_json(SERVICE_NAME, "warning", "alert_persisted", alert=saved_alert)


def persist_event_logs():
    consumer = create_consumer(CANONICAL_TOPICS["events_enriched"], group_id="alert-service-storage")

    for message in consumer:
        event = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume_event").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="store_event").time():
            store_event_log(event)
            try:
                sync_relationships(event)
            except Exception as exc:
                log_json(SERVICE_NAME, "error", "graph_sync_failed", error=str(exc), ip=event.get("ip"))


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    log_json(SERVICE_NAME, "info", "service_started")
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(persist_alerts)
        executor.submit(persist_event_logs)
        executor.shutdown(wait=True)


if __name__ == "__main__":
    main()
