import json
import time
from kafka import KafkaAdminClient, KafkaConsumer, KafkaProducer
from kafka.admin import NewTopic
from kafka.errors import TopicAlreadyExistsError

from shared.config import (
    get_kafka_bootstrap_servers,
    get_kafka_retry_attempts,
    get_kafka_retry_delay_seconds,
)
from shared.topics import ALL_TOPICS, get_alias_topics


def create_producer():
    last_error = None

    for _ in range(get_kafka_retry_attempts()):
        try:
            return KafkaProducer(
                bootstrap_servers=get_kafka_bootstrap_servers(),
                value_serializer=lambda v: json.dumps(v).encode("utf-8")
            )
        except Exception as exc:
            last_error = exc
            time.sleep(get_kafka_retry_delay_seconds())

    raise last_error


def create_admin_client():
    last_error = None

    for _ in range(get_kafka_retry_attempts()):
        try:
            return KafkaAdminClient(bootstrap_servers=get_kafka_bootstrap_servers())
        except Exception as exc:
            last_error = exc
            time.sleep(get_kafka_retry_delay_seconds())

    raise last_error


def ensure_topics(topics=None):
    topics = topics or ALL_TOPICS
    client = create_admin_client()
    existing = set(client.list_topics())
    missing = [topic for topic in topics if topic not in existing]

    if missing:
        try:
            client.create_topics(
                [NewTopic(name=topic, num_partitions=1, replication_factor=1) for topic in missing],
                validate_only=False,
            )
        except TopicAlreadyExistsError:
            pass

    client.close()


def create_consumer(*topics, group_id=None):
    last_error = None

    for _ in range(get_kafka_retry_attempts()):
        try:
            return KafkaConsumer(
                *topics,
                bootstrap_servers=get_kafka_bootstrap_servers(),
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                group_id=group_id
            )
        except Exception as exc:
            last_error = exc
            time.sleep(get_kafka_retry_delay_seconds())

    raise last_error


def publish_with_aliases(producer, topic: str, payload: dict):
    producer.send(topic, payload)
    for alias in get_alias_topics(topic):
        producer.send(alias, payload)
