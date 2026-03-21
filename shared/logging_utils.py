import json
from datetime import UTC, datetime


def log_json(service: str, level: str, message: str, **fields):
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "service": service,
        "level": level,
        "message": message,
    }
    payload.update(fields)
    print(json.dumps(payload, default=str), flush=True)
