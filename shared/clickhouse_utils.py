import json
import urllib.error
import urllib.request

from shared.config import get_clickhouse_config


def store_event_log(event: dict) -> bool:
    config = get_clickhouse_config()
    url = (
        f"http://{config['host']}:{config['port']}/"
        "?query=INSERT INTO security_events FORMAT JSONEachRow"
    )
    payload = json.dumps(event).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=2):
            return True
    except (urllib.error.URLError, TimeoutError):
        return False
