import time

from shared.config import get_redis_config


_local_counters: dict[str, tuple[int, float]] = {}


def get_redis_client():
    try:
        import redis
    except ImportError:
        return None

    config = get_redis_config()
    try:
        client = redis.Redis(
            host=config["host"],
            port=int(config["port"]),
            db=int(config["db"]),
            password=config["password"] or None,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        client.ping()
        return client
    except Exception:
        return None


def increment_counter(key: str, window_seconds: int) -> int:
    client = get_redis_client()
    if client is not None:
        value = client.incr(key)
        if value == 1:
            client.expire(key, window_seconds)
        return int(value)

    count, expires_at = _local_counters.get(key, (0, 0.0))
    now = time.time()
    if now >= expires_at:
        count = 0
    count += 1
    _local_counters[key] = (count, now + window_seconds)
    return count
