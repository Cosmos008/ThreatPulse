import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def _resolve_config_path(env_key: str, default_relative_path: str) -> Path:
    default_path = BASE_DIR / default_relative_path
    configured_path = os.getenv(env_key)

    if not configured_path:
        return default_path

    candidate = Path(configured_path)

    if candidate.exists():
        return candidate

    normalized = configured_path.replace("\\", "/").lstrip("/")
    parts = normalized.split("/")

    if parts and parts[0] == "app":
        local_candidate = BASE_DIR.joinpath(*parts[1:])
        if local_candidate.exists():
            return local_candidate

    if not candidate.is_absolute():
        local_candidate = BASE_DIR / candidate
        if local_candidate.exists():
            return local_candidate

    return candidate


def get_kafka_bootstrap_servers() -> str:
    return os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")


def get_postgres_config() -> dict[str, str]:
    return {
        "host": os.getenv("POSTGRES_HOST", "postgres"),
        "port": os.getenv("POSTGRES_PORT", "5432"),
        "database": os.getenv("POSTGRES_DB", "alerts"),
        "user": os.getenv("POSTGRES_USER", "security"),
        "password": os.getenv("POSTGRES_PASSWORD", "change-me"),
    }


def get_honeypot_file() -> Path:
    return _resolve_config_path("HONEYPOT_FILE", "configs/honeypot_accounts.txt")


def get_kafka_retry_attempts() -> int:
    return int(os.getenv("KAFKA_CONNECT_RETRIES", "30"))


def get_kafka_retry_delay_seconds() -> float:
    return float(os.getenv("KAFKA_CONNECT_RETRY_DELAY_SECONDS", "2"))


def get_postgres_retry_attempts() -> int:
    return int(os.getenv("POSTGRES_CONNECT_RETRIES", "30"))


def get_postgres_retry_delay_seconds() -> float:
    return float(os.getenv("POSTGRES_CONNECT_RETRY_DELAY_SECONDS", "2"))


def get_rules_config_file() -> Path:
    return _resolve_config_path("RULES_CONFIG_FILE", "configs/rules.yaml")


def get_geolocation_target() -> dict[str, float]:
    return {
        "latitude": float(os.getenv("DEFAULT_TARGET_LATITUDE", "51.5074")),
        "longitude": float(os.getenv("DEFAULT_TARGET_LONGITUDE", "-0.1278")),
    }


def get_redis_config() -> dict[str, str]:
    return {
        "host": os.getenv("REDIS_HOST", "redis"),
        "port": os.getenv("REDIS_PORT", "6379"),
        "db": os.getenv("REDIS_DB", "0"),
        "password": os.getenv("REDIS_PASSWORD", ""),
    }


def get_clickhouse_config() -> dict[str, str]:
    return {
        "host": os.getenv("CLICKHOUSE_HOST", "clickhouse"),
        "port": os.getenv("CLICKHOUSE_PORT", "8123"),
        "database": os.getenv("CLICKHOUSE_DB", "default"),
    }


def get_neo4j_config() -> dict[str, str]:
    return {
        "uri": os.getenv("NEO4J_URI", "bolt://neo4j:7687"),
        "user": os.getenv("NEO4J_USER", "neo4j"),
        "password": os.getenv("NEO4J_PASSWORD", "change-me"),
    }


def get_jwt_secret() -> str:
    return os.getenv("JWT_SECRET", os.getenv("SECURITY_API_KEY", "change-this-api-key"))


def get_jwt_expiry_minutes() -> int:
    return int(os.getenv("JWT_EXPIRY_MINUTES", "60"))


def get_metrics_port(service_name: str) -> int:
    env_key = f"{service_name.upper()}_METRICS_PORT"
    default_ports = {
        "ingestion_service": 9100,
        "parser_service": 9101,
        "event_router": 9102,
        "threat_intel_service": 9103,
        "detection_engine": 9104,
        "anomaly_engine": 9105,
        "risk_engine": 9106,
        "correlation_engine": 9107,
        "alert_service": 9108,
        "investigation_api": 9109,
        "geolocation_service": 9110,
    }
    return int(os.getenv(env_key, str(default_ports[service_name])))
