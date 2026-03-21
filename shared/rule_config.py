from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from time import time

from shared.config import get_rules_config_file


RULE_ACTIVITY: dict[str, dict] = {}

DETECTION_RULE_DEFAULTS = {
    "credential_stuffing": {
        "name": "Credential Stuffing",
        "attack_type": "credential_stuffing",
        "severity": "high",
        "enabled": True,
        "mitre_mapping": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        "threshold": 10,
        "time_window_seconds": 60,
        "condition_field": "failed_attempts",
    },
    "streaming_fraud": {
        "name": "Streaming Fraud",
        "attack_type": "streaming_fraud",
        "severity": "medium",
        "enabled": True,
        "mitre_mapping": {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        "threshold": 50,
        "time_window_seconds": 300,
        "condition_field": "plays",
    },
    "device_abuse": {
        "name": "Device Abuse",
        "attack_type": "device_abuse",
        "severity": "high",
        "enabled": True,
        "mitre_mapping": {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        "threshold": 5,
        "time_window_seconds": 600,
        "condition_field": "accounts",
    },
    "rate_limit_abuse": {
        "name": "Rate Limit Abuse",
        "attack_type": "rate_limit_abuse",
        "severity": "high",
        "enabled": True,
        "mitre_mapping": {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
        "threshold": 25,
        "time_window_seconds": 60,
        "condition_field": "requests",
        "user_threshold": 20,
        "device_threshold": 20,
    },
}

SECTION_TO_RULE_KEY = {
    "credential_stuffing": "credential_stuffing",
    "streaming_fraud": "streaming_fraud",
    "device_abuse": "device_abuse",
    "rate_limit": "rate_limit_abuse",
}

RULE_KEY_TO_SECTION = {value: key for key, value in SECTION_TO_RULE_KEY.items()}


@lru_cache(maxsize=1)
def load_rule_config() -> dict:
    try:
        import yaml
    except ImportError:
        return {}

    config_path = get_rules_config_file()

    if not config_path.exists():
        return {}

    with config_path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def reload_rule_config():
    load_rule_config.cache_clear()
    return load_rule_config()


def get_rule_section(name: str, default: dict | None = None) -> dict:
    config = load_rule_config()
    return deepcopy(config.get(name, default or {}))


def get_all_rule_config() -> dict:
    return deepcopy(load_rule_config())


def _normalize_mitre(value) -> dict:
    payload = value if isinstance(value, dict) else {}
    return {
        "id": str(payload.get("id") or payload.get("technique") or "").strip(),
        "name": str(payload.get("name") or "").strip(),
        "tactic": str(payload.get("tactic") or "").strip(),
    }


def get_detection_rule(rule_key: str) -> dict:
    defaults = deepcopy(DETECTION_RULE_DEFAULTS.get(rule_key, {}))
    section_name = RULE_KEY_TO_SECTION.get(rule_key, rule_key)
    section = get_rule_section(section_name, {})
    metadata = section.get("metadata") if isinstance(section.get("metadata"), dict) else {}

    normalized = {
        "key": rule_key,
        "section_name": section_name,
        "name": str(metadata.get("name") or defaults.get("name") or rule_key).strip(),
        "attack_type": str(metadata.get("attack_type") or defaults.get("attack_type") or rule_key).strip(),
        "severity": str(metadata.get("severity") or defaults.get("severity") or "medium").strip().lower(),
        "enabled": bool(metadata.get("enabled", defaults.get("enabled", True))),
        "mitre_mapping": _normalize_mitre(metadata.get("mitre_mapping") or defaults.get("mitre_mapping")),
        "threshold": int(section.get("threshold", metadata.get("threshold", defaults.get("threshold", 0))) or 0),
        "time_window_seconds": int(section.get("window_seconds", metadata.get("time_window_seconds", defaults.get("time_window_seconds", 60))) or 60),
        "user_threshold": int(section.get("user_threshold", metadata.get("user_threshold", defaults.get("user_threshold", defaults.get("threshold", 0)))) or 0),
        "device_threshold": int(section.get("device_threshold", metadata.get("device_threshold", defaults.get("device_threshold", defaults.get("threshold", 0)))) or 0),
        "condition_field": str(metadata.get("condition_field") or defaults.get("condition_field") or "count").strip(),
        "last_triggered": (RULE_ACTIVITY.get(rule_key) or {}).get("last_triggered"),
    }
    return normalized


def list_detection_rules() -> list[dict]:
    return [get_detection_rule(rule_key) for rule_key in DETECTION_RULE_DEFAULTS]


def update_rule_section(name: str, updates: dict) -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to update rules") from exc

    config_path = get_rules_config_file()
    config = get_all_rule_config()
    section = dict(config.get(name, {}))
    section.update(updates)
    config[name] = section

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)

    reload_rule_config()
    return get_rule_section(name, {})


def update_detection_rule(rule_key: str, payload: dict) -> dict:
    section_name = RULE_KEY_TO_SECTION.get(rule_key, rule_key)
    current_section = get_rule_section(section_name, {})
    metadata = dict(current_section.get("metadata") or {})
    defaults = get_detection_rule(rule_key)

    next_metadata = {
        **metadata,
        "name": str(payload.get("name") or defaults["name"]).strip(),
        "attack_type": str(payload.get("attack_type") or defaults["attack_type"]).strip(),
        "severity": str(payload.get("severity") or defaults["severity"]).strip().lower(),
        "enabled": bool(payload.get("enabled", defaults["enabled"])),
        "mitre_mapping": _normalize_mitre(payload.get("mitre_mapping") or defaults["mitre_mapping"]),
        "time_window_seconds": int(payload.get("time_window_seconds", defaults["time_window_seconds"]) or defaults["time_window_seconds"]),
        "condition_field": str(payload.get("condition_field") or defaults["condition_field"]).strip(),
        "threshold": int(payload.get("threshold", defaults["threshold"]) or defaults["threshold"]),
        "user_threshold": int(payload.get("user_threshold", defaults["user_threshold"]) or defaults["user_threshold"]),
        "device_threshold": int(payload.get("device_threshold", defaults["device_threshold"]) or defaults["device_threshold"]),
    }

    next_section = {
        **current_section,
        "metadata": next_metadata,
    }
    if rule_key == "rate_limit_abuse":
        next_section["window_seconds"] = next_metadata["time_window_seconds"]
        next_section["ip_threshold"] = next_metadata["threshold"]
        next_section["user_threshold"] = next_metadata["user_threshold"]
        next_section["device_threshold"] = next_metadata["device_threshold"]
    else:
        next_section["threshold"] = next_metadata["threshold"]
        next_section["window_seconds"] = next_metadata["time_window_seconds"]

    update_rule_section(section_name, next_section)
    return get_detection_rule(rule_key)


def note_rule_trigger(rule_name: str) -> None:
    rule_key = SECTION_TO_RULE_KEY.get(str(rule_name or "").strip(), str(rule_name or "").strip())
    RULE_ACTIVITY[rule_key] = {
        "last_triggered": time(),
    }
