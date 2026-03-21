import json

from services.alert_service.database import get_connection
from shared.entity_context import (
    adjust_severity_for_criticality,
    build_entity_profile,
    compute_alert_risk,
    extract_entities,
)
from shared.playbook_engine import execute_playbook
from shared.rule_config import note_rule_trigger


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


def _load_entity_profile(cur, entity_type, entity_key):
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
    row = cur.fetchone()
    if not row:
        return None
    return {
        "entity_type": row[0],
        "entity_key": row[1],
        "display_name": row[2],
        "first_seen": row[3].isoformat() if hasattr(row[3], "isoformat") and row[3] else row[3],
        "last_seen": row[4].isoformat() if hasattr(row[4], "isoformat") and row[4] else row[4],
        "alert_count": row[5],
        "case_count": row[6],
        "related_attack_types": row[7] or [],
        "risk_score": row[8] or 0,
        "asset_criticality": row[9] or "medium",
        "enrichment": row[10] or {},
        "activity_summary": row[11] or {},
        "recent_alerts": row[12] or [],
    }


def _upsert_entity_profiles(cur, alert_payload, saved_alert):
    ensure_entity_profiles_table()
    entities = extract_entities(alert_payload)
    timestamp = saved_alert["timestamp"]
    for entity in entities:
        entity_type = entity["type"]
        entity_key = entity["value"]
        existing = _load_entity_profile(cur, entity_type, entity_key)
        alerts = list(existing.get("recent_alerts") or []) if existing else []
        alerts.append(saved_alert)
        profile = build_entity_profile(
            entity_type,
            entity_key,
            alerts=alerts[-20:],
            cases=[],
            base_profile=existing,
        )
        cur.execute(
            """
            INSERT INTO entity_profiles (
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
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, CAST(%s AS JSONB), %s, %s, CAST(%s AS JSONB), CAST(%s AS JSONB), CAST(%s AS JSONB))
            ON CONFLICT (entity_type, entity_key)
            DO UPDATE SET
                display_name=EXCLUDED.display_name,
                first_seen=EXCLUDED.first_seen,
                last_seen=EXCLUDED.last_seen,
                alert_count=EXCLUDED.alert_count,
                case_count=EXCLUDED.case_count,
                related_attack_types=EXCLUDED.related_attack_types,
                risk_score=EXCLUDED.risk_score,
                asset_criticality=EXCLUDED.asset_criticality,
                enrichment=EXCLUDED.enrichment,
                activity_summary=EXCLUDED.activity_summary,
                recent_alerts=EXCLUDED.recent_alerts
            """,
            (
                profile["entity_type"],
                profile["entity_key"],
                profile["display_name"],
                profile["first_seen"],
                profile["last_seen"],
                profile["alert_count"],
                profile["case_count"],
                json.dumps(profile["related_attack_types"]),
                profile["risk_score"],
                profile["asset_criticality"],
                json.dumps(profile["enrichment"]),
                json.dumps(profile["activity_summary"]),
                json.dumps(profile["recent_alerts"]),
            ),
        )


def _enrich_alert(alert):
    enriched = dict(alert or {})
    details = dict(enriched.get("details") or {})
    entities = extract_entities(enriched)
    entity_map = {entity["type"]: {"value": entity["value"], "asset_criticality": entity["asset_criticality"]} for entity in entities}
    max_criticality = "low"
    for entity in entities:
        if entity["asset_criticality"] == "high":
            max_criticality = "high"
            break
        if entity["asset_criticality"] == "medium":
            max_criticality = "medium"

    adjusted_severity = adjust_severity_for_criticality(enriched.get("severity"), max_criticality)
    adjusted_risk = compute_alert_risk({**enriched, "severity": adjusted_severity, "details": details})
    details.update({
        "asset_criticality": max_criticality,
        "entity_context": entity_map,
        "risk_score": adjusted_risk,
        "original_severity": enriched.get("severity"),
        "perceived_severity": adjusted_severity,
    })
    enriched["severity"] = adjusted_severity
    enriched["details"] = details
    return enriched


def save_alert(alert):
    ensure_alerts_table()
    ensure_entity_profiles_table()
    alert = _enrich_alert(alert)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO alerts (rule, severity, ip, details)
        VALUES (%s, %s, %s, CAST(%s AS JSONB))
        RETURNING id, rule, severity, ip, details, timestamp
        """,
        (
            alert.get("rule"),
            alert.get("severity"),
            alert.get("ip"),
            json.dumps(alert)
        )
    )

    row = cur.fetchone()
    saved_alert = {
        "id": row[0],
        "rule": row[1],
        "severity": row[2],
        "ip": row[3],
        "details": row[4],
        "timestamp": row[5].isoformat() if hasattr(row[5], "isoformat") else row[5],
    }
    _upsert_entity_profiles(cur, alert, saved_alert)
    conn.commit()
    cur.close()
    conn.close()
    note_rule_trigger(saved_alert.get("rule"))
    try:
        execute_playbook({**saved_alert, "details": saved_alert.get("details") or {}}, actor="system", automatic=True)
    except Exception:
        pass
    return saved_alert
