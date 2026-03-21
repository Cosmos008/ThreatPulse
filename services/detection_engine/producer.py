from shared.kafka_utils import create_producer, publish_with_aliases
from shared.topics import CANONICAL_TOPICS

producer = create_producer()


def send_alert(alert):
    publish_with_aliases(producer, CANONICAL_TOPICS["detections_rules"], alert)
