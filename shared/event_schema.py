import uuid
from datetime import UTC, datetime


def create_event(event_type, user_id=None, ip=None, device_id=None, status=None, metadata=None):

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
        "source_service": "ingestion_service",
        "user_id": user_id,
        "ip": ip,
        "device_id": device_id,
        "session_id": None,
        "status": status,
        "metadata": metadata or {}
    }
