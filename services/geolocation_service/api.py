from flask import Flask, jsonify, request

from shared.api_security import enforce_rate_limit, get_rate_limit_identifier, require_api_key
from shared.metrics import metrics_response
from services.geolocation_service.service import batch_lookup

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
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
    return jsonify({"status": "ok", "service": "geolocation_service"})


@app.get("/metrics")
def metrics():
    return metrics_response()


@app.post("/lookup")
def lookup():
    auth_error = authorize_request()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    ips = payload.get("ips") or []

    if not isinstance(ips, list):
        return jsonify({"detail": "ips must be a list"}), 400

    return jsonify({"results": batch_lookup(ips)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8002)
