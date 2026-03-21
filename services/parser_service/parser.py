def parse_event(event):

    parsed_event = {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "source_service": event.get("source_service", "ingestion_service"),
        "user_id": event.get("user_id"),
        "ip": event.get("ip"),
        "device_id": event.get("device_id"),
        "session_id": event.get("session_id"),
        "status": event.get("status"),
        "metadata": event.get("metadata", {})
    }

    return parsed_event
