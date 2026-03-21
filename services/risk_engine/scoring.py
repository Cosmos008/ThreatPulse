import time
from collections import defaultdict

risk_scores = {}
entity_risk_scores = defaultdict(dict)
last_emitted_bucket = {}
risk_history = defaultdict(list)

from shared.rule_config import get_rule_section
from shared.entity_context import compute_alert_risk, extract_entities


def update_score(alert):
    rule = alert.get("rule")
    config = get_rule_section("risk_engine")
    threshold = int(config.get("threshold", 120))
    weights = config.get("rule_weights", {})
    weight = weights.get(rule, 10)
    sequence = alert.get("sequence") or {}
    sequence_type = sequence.get("sequence_type")

    if sequence_type == "coordinated":
        weight += 50
    elif sequence_type == "critical":
        weight += 100

    entities = extract_entities(alert)
    ip = alert.get("ip")
    primary_entity = next((entity for entity in entities if entity.get("type") == "ip"), None)
    if not ip and primary_entity:
        ip = primary_entity.get("value")
    if not ip:
        return None

    risk_scores[ip] = risk_scores.get(ip, 0) + weight
    entity_profiles = {}
    for entity in entities:
        entity_type = entity.get("type")
        entity_value = entity.get("value")
        if not entity_type or not entity_value:
            continue
        updated_score = min(
            100,
            int(entity_risk_scores[entity_type].get(entity_value, 0)) + compute_alert_risk(alert, entity_type) // 4 + weight // 5,
        )
        entity_risk_scores[entity_type][entity_value] = updated_score
        entity_profiles[entity_type] = {
            "entity_type": entity_type,
            "entity_key": entity_value,
            "risk_score": updated_score,
            "asset_criticality": entity.get("asset_criticality") or "medium",
        }

    score = risk_scores[ip]
    risk_history[ip].append({
        "timestamp": time.time(),
        "score": score
    })
    risk_history[ip] = risk_history[ip][-10:]

    current_bucket = score // 50
    last_bucket = last_emitted_bucket.get(ip, 0)

    if score >= threshold and current_bucket > last_bucket:
        last_emitted_bucket[ip] = current_bucket

        return {
            "rule": "high_risk_actor",
            "severity": "critical",
            "ip": ip,
            "risk_score": score,
            "risk_history": risk_history[ip][-10:],
            "entity_context": entity_profiles,
        }

    return None
