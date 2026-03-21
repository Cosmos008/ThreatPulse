from flask import Flask, jsonify, request

from shared.api_security import enforce_rate_limit, get_rate_limit_identifier, require_api_key
from shared.blocklist import is_blocked
from shared.event_schema import create_event
from shared.kafka_utils import create_producer, publish_with_aliases
from shared.metrics import events_processed_total, metrics_response, service_latency
from shared.topics import CANONICAL_TOPICS

app = Flask(__name__)

producer = None


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


def authorize_request():
    try:
        require_api_key(request.headers.get("X-API-Key"))
        identifier = get_rate_limit_identifier(dict(request.headers), request.remote_addr)
        enforce_rate_limit(identifier)
    except PermissionError as exc:
        return jsonify({"detail": str(exc)}), 401
    except RuntimeError as exc:
        return jsonify({"detail": str(exc)}), 429
    return None


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "ingestion_service"})


@app.get("/metrics")
def metrics():
    return metrics_response()


@app.post("/log")
def receive_log():
    global producer

    auth_error = authorize_request()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    event_type = (data.get("event_type") or "").strip()
    metadata = data.get("metadata") or {}

    if not event_type:
        return jsonify({"detail": "event_type is required"}), 400
    if not isinstance(metadata, dict):
        return jsonify({"detail": "metadata must be an object"}), 400
    if is_blocked(data.get("ip")):
        return jsonify({"status": "blocked", "message": "IP is blocked"}), 202

    if producer is None:
        producer = create_producer()

    with service_latency.labels(service="ingestion_service", operation="ingest").time():
        event = create_event(
            event_type=event_type,
            user_id=data.get("user_id"),
            ip=data.get("ip"),
            device_id=data.get("device_id"),
            status=data.get("status"),
            metadata=metadata,
        )
        publish_with_aliases(producer, CANONICAL_TOPICS["events_raw"], event)
        producer.flush()

    events_processed_total.labels(service="ingestion_service", stage="ingest").inc()
    return jsonify({"status": "event sent", "event_id": event["event_id"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
