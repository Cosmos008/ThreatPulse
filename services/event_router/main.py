from shared.kafka_utils import create_consumer, create_producer, ensure_topics
from shared.logging_utils import log_json
from shared.metrics import events_processed_total, service_latency, start_metrics_server
from shared.topics import CANONICAL_TOPICS, LEGACY_TOPICS
from services.event_router.router import route_event


SERVICE_NAME = "event_router"


def main():
    ensure_topics()
    start_metrics_server(SERVICE_NAME)
    consumer = create_consumer(
        CANONICAL_TOPICS["events_parsed"],
        group_id="event-router",
    )
    producer = create_producer()

    log_json(SERVICE_NAME, "info", "service_started")

    for message in consumer:
        event = message.value
        events_processed_total.labels(service=SERVICE_NAME, stage="consume").inc()
        with service_latency.labels(service=SERVICE_NAME, operation="route").time():
            route_topic = route_event(event)

        if route_topic:
            producer.send(route_topic, event)
            producer.send(
                CANONICAL_TOPICS["events_routed"],
                {
                    "route": route_topic,
                    "event": event,
                },
            )
            log_json(SERVICE_NAME, "info", "event_routed", route=route_topic, event_id=event.get("event_id"))


if __name__ == "__main__":
    main()
