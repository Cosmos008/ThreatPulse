from collections import defaultdict, deque
from datetime import datetime
from math import asin, cos, radians, sin, sqrt

from shared.rule_config import get_rule_section


user_login_history: dict[str, deque[dict]] = defaultdict(deque)
user_known_devices: dict[str, set[str]] = defaultdict(set)
user_known_countries: dict[str, set[str]] = defaultdict(set)
user_login_hours: dict[str, list[int]] = defaultdict(list)


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    if not timestamp:
        return None
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def _haversine_km(lat1, lon1, lat2, lon2):
    radius_km = 6371.0
    delta_lat = radians(lat2 - lat1)
    delta_lon = radians(lon2 - lon1)
    a = sin(delta_lat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(delta_lon / 2) ** 2
    return 2 * radius_km * asin(sqrt(a))


def analyze_behavior(event: dict) -> list[dict]:
    alerts = []
    user_id = event.get("user_id")
    country = event.get("country")
    latitude = event.get("latitude")
    longitude = event.get("longitude")
    device_hash = event.get("device_hash")
    timestamp = _parse_timestamp(event.get("timestamp"))
    event_type = event.get("event_type")

    if not user_id or event_type not in {"login_attempt", "login_success", "login_failed"}:
        return alerts

    config = get_rule_section("behavior_analytics")
    history = user_login_history[user_id]

    if country and user_known_countries[user_id] and country not in user_known_countries[user_id]:
        alerts.append(
            {
                "rule": "login_geo_anomaly",
                "severity": "medium",
                "ip": event.get("ip"),
                "user_id": user_id,
                "country": country,
            }
        )

    if device_hash and user_known_devices[user_id] and device_hash not in user_known_devices[user_id]:
        alerts.append(
            {
                "rule": "device_anomaly",
                "severity": "medium",
                "ip": event.get("ip"),
                "user_id": user_id,
                "device_hash": device_hash,
            }
        )

    if timestamp is not None and len(user_login_hours[user_id]) >= int(config.get("login_time_min_history", 5)):
        median_hour = sorted(user_login_hours[user_id])[len(user_login_hours[user_id]) // 2]
        if abs(timestamp.hour - median_hour) >= int(config.get("login_time_anomaly_hours", 6)):
            alerts.append(
                {
                    "rule": "login_time_anomaly",
                    "severity": "low",
                    "ip": event.get("ip"),
                    "user_id": user_id,
                    "hour": timestamp.hour,
                }
            )

    if history and timestamp is not None and latitude is not None and longitude is not None:
        last_event = history[-1]
        last_timestamp = last_event["timestamp"]
        if last_timestamp is not None:
            elapsed_seconds = (timestamp - last_timestamp).total_seconds()
            if 0 < elapsed_seconds <= int(config.get("impossible_travel_window_seconds", 600)):
                last_country = last_event["country"]
                last_latitude = last_event["latitude"]
                last_longitude = last_event["longitude"]
                if last_country and country and last_country != country:
                    distance_km = _haversine_km(last_latitude, last_longitude, latitude, longitude)
                    speed_kmh = distance_km / max(elapsed_seconds / 3600, 0.001)
                    if speed_kmh >= float(config.get("impossible_travel_min_kmh", 900)):
                        alerts.append(
                            {
                                "rule": "impossible_travel",
                                "severity": "high",
                                "ip": event.get("ip"),
                                "user_id": user_id,
                                "previous_country": last_country,
                                "current_country": country,
                                "estimated_speed_kmh": round(speed_kmh, 2),
                            }
                        )

    history.append(
        {
            "timestamp": timestamp,
            "country": country,
            "latitude": latitude,
            "longitude": longitude,
        }
    )
    if len(history) > 20:
        history.popleft()

    if device_hash:
        user_known_devices[user_id].add(device_hash)
    if country:
        user_known_countries[user_id].add(country)
    if timestamp is not None:
        user_login_hours[user_id].append(timestamp.hour)
        if len(user_login_hours[user_id]) > 50:
            user_login_hours[user_id] = user_login_hours[user_id][-50:]

    return alerts
