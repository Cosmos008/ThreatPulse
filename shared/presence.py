import time


ONLINE_USERS = {}
DEFAULT_PRESENCE_WINDOW_SECONDS = 90


def update_presence(username: str, *, role: str | None = None, current_page: str | None = None) -> None:
    if not username:
        return
    previous = ONLINE_USERS.get(username) or {}
    ONLINE_USERS[username] = {
        "username": username,
        "role": role or previous.get("role") or "analyst",
        "status": "online",
        "last_seen": time.time(),
        "current_page": current_page or previous.get("current_page") or None,
    }


def remove_presence(username: str) -> None:
    if username:
        ONLINE_USERS.pop(username, None)


def get_online_users(window_seconds: int = DEFAULT_PRESENCE_WINDOW_SECONDS) -> list[dict]:
    now = time.time()
    online_users = []
    stale_users = []

    for username, record in ONLINE_USERS.items():
        last_seen = float(record.get("last_seen") or 0)
        if now - last_seen < window_seconds:
            online_users.append({
                "username": username,
                "role": record.get("role") or "analyst",
                "status": "online",
                "last_seen": last_seen,
                "current_page": record.get("current_page") or None,
            })
        else:
            stale_users.append(username)

    for username in stale_users:
        ONLINE_USERS.pop(username, None)

    return sorted(online_users, key=lambda entry: (str(entry.get("role") or ""), str(entry.get("username") or "").lower()))
