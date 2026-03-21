from services.investigation_api.database import get_connection
from shared.database_utils import rows_to_dicts


def ensure_alerts_table():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            ip TEXT,
            details JSONB NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    conn.commit()
    cur.close()
    conn.close()


def ensure_entity_profiles_table():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_profiles (
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            display_name TEXT NOT NULL,
            first_seen TIMESTAMPTZ,
            last_seen TIMESTAMPTZ,
            alert_count INTEGER NOT NULL DEFAULT 0,
            case_count INTEGER NOT NULL DEFAULT 0,
            related_attack_types JSONB NOT NULL DEFAULT '[]'::jsonb,
            risk_score INTEGER NOT NULL DEFAULT 0,
            asset_criticality TEXT NOT NULL DEFAULT 'medium',
            enrichment JSONB NOT NULL DEFAULT '{}'::jsonb,
            activity_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
            recent_alerts JSONB NOT NULL DEFAULT '[]'::jsonb,
            PRIMARY KEY (entity_type, entity_key)
        )
        """
    )

    conn.commit()
    cur.close()
    conn.close()


def get_all_alerts():
    ensure_alerts_table()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, rule, severity, ip, details, timestamp FROM alerts ORDER BY timestamp DESC")

    rows = rows_to_dicts(cur, cur.fetchall())

    cur.close()
    conn.close()

    return rows


def get_alerts_by_ip(ip):
    ensure_alerts_table()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, rule, severity, ip, details, timestamp FROM alerts WHERE ip=%s ORDER BY timestamp DESC",
        (ip,)
    )

    rows = rows_to_dicts(cur, cur.fetchall())

    cur.close()
    conn.close()

    return rows


def get_entity_profile(entity_type, entity_key):
    ensure_entity_profiles_table()

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            entity_type,
            entity_key,
            display_name,
            first_seen,
            last_seen,
            alert_count,
            case_count,
            related_attack_types,
            risk_score,
            asset_criticality,
            enrichment,
            activity_summary,
            recent_alerts
        FROM entity_profiles
        WHERE entity_type=%s AND entity_key=%s
        """,
        (entity_type, entity_key),
    )
    rows = rows_to_dicts(cur, cur.fetchall())
    cur.close()
    conn.close()
    return rows[0] if rows else None
