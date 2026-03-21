from shared.entity_context import adjust_severity_for_criticality, compute_alert_risk, extract_entities


def test_asset_criticality_increases_alert_perception():
    alert = {
        "severity": "medium",
        "details": {
            "asset_criticality": "high",
            "user_id": "payroll-admin",
            "device_id": "srv-hr-02",
            "risk_score": 55,
        },
    }

    entities = extract_entities(alert)

    assert {entity["type"] for entity in entities} == {"user", "host"}
    assert adjust_severity_for_criticality("medium", "high") == "high"
    assert compute_alert_risk(alert, "host") > 55
