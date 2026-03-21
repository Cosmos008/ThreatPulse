import hashlib


def build_device_hash(event: dict) -> str | None:
    metadata = event.get("metadata") or {}
    user_agent = metadata.get("user_agent", "")
    timezone = metadata.get("timezone", "")
    screen_resolution = metadata.get("screen_resolution", "")
    ip = event.get("ip", "")

    fingerprint_string = "|".join([user_agent, ip, timezone, screen_resolution])
    if not fingerprint_string.replace("|", ""):
        return None

    return hashlib.sha256(fingerprint_string.encode("utf-8")).hexdigest()
