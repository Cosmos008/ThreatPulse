from shared.kafka_utils import create_consumer, create_producer, ensure_topics, publish_with_aliases
from shared.logging_utils import log_json
from shared.metrics import events_processed_total, service_latency, start_metrics_server
from shared.topics import CANONICAL_TOPICS, LEGACY_TOPICS
from services.parser_service.parser import parse_event


SERVICE_NAME = "parser_service"


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    consumer = create_consumer(
        CANONICAL_TOPICS["events_raw"],
        group_id="parser-service",
    )
    producer = create_producer()

    log_json(SERVICE_NAME, "info", "service_started")

    for message in consumer:
        raw_event = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="parse").time():
            parsed_event = parse_event(raw_event)
        publish_with_aliases(producer, CANONICAL_TOPICS["events_parsed"], parsed_event)
        log_json(SERVICE_NAME, "info", "event_parsed", event_id=parsed_event.get("event_id"))


if __name__ == "__main__":
    main()
