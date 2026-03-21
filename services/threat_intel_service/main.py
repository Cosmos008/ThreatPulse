from shared.kafka_utils import create_consumer, create_producer, ensure_topics
from shared.logging_utils import log_json
from shared.metrics import events_processed_total, service_latency, start_metrics_server
from shared.topics import CANONICAL_TOPICS
from services.threat_intel_service.service import enrich_event


SERVICE_NAME = "threat_intel_service"


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    consumer = create_consumer(CANONICAL_TOPICS["events_routed"], group_id="threat-intel-service")
    producer = create_producer()

    log_json(SERVICE_NAME, "info", "service_started")

    for message in consumer:
        route_payload = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="enrich").time():
            enriched_event = enrich_event(route_payload)
        producer.send(CANONICAL_TOPICS["events_enriched"], enriched_event)
        log_json(
            SERVICE_NAME,
            "info",
            "event_enriched",
            event_id=enriched_event.get("event_id"),
            ip=enriched_event.get("ip"),
        )


if __name__ == "__main__":
    main()
