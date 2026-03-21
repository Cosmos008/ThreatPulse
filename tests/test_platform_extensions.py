from services.investigation_api import api as investigation_api
from services.threat_intel_service.service import enrich_event
from shared.alert_state import ALERT_STATE
from shared import api_security
from shared.audit_log import AUDIT_LOG
from shared.incident_records import reset_records
from shared.playbook_engine import PLAYBOOK_EXECUTIONS, execute_playbook


def setup_function():
    api_security._request_log.clear()
    reset_records()
    ALERT_STATE.clear()
    AUDIT_LOG.clear()
    PLAYBOOK_EXECUTIONS.clear()


def test_issue_and_validate_jwt():
    token = api_security.issue_jwt("tester")
    payload = api_security.require_jwt(token)

    assert payload["sub"] == "tester"
    assert payload["scope"] == "investigation"


def test_threat_intel_enriches_event(monkeypatch):
    monkeypatch.setattr(
        "services.threat_intel_service.service.fetch_ip_geolocation",
        lambda ip: {
            "found": True,
            "country": "Germany",
            "country_code": "DE",
            "region": "Berlin",
            "city": "Berlin",
            "latitude": 52.52,
            "longitude": 13.405,
        },
    )
    monkeypatch.setattr(
        "services.threat_intel_service.service.fetch_provider_payload",
        lambda ip: {
            "connection": {"asn": "AS1234"},
            "security": {"tor": True, "proxy": False},
        },
    )

    enriched = enrich_event(
        {
            "route": "auth_events",
            "event": {"event_id": "evt-1", "ip": "1.2.3.4", "status": "failed"},
        }
    )

    assert enriched["country_code"] == "DE"
    assert enriched["asn"] == "AS1234"
    assert enriched["is_tor"] is True
    assert enriched["reputation_score"] >= 70


def test_investigation_auth_token_endpoint(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post("/auth/token", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    assert "token" in response.get_json()


def test_investigation_events_endpoint(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(
        investigation_api,
        "get_all_alerts",
        lambda: [
            {
                "ip": "34.210.10.22",
                "severity": "high",
                "details": {"country": "US"},
            },
            {
                "ip": "10.0.0.1",
                "severity": "low",
                "details": {},
            },
        ],
    )
    monkeypatch.setattr(
        investigation_api,
        "fetch_ip_geolocation",
        lambda ip: (
            {"latitude": 47.6, "longitude": -122.3, "country_code": "US"}
            if ip == "34.210.10.22"
            else {"latitude": None, "longitude": None}
        ),
    )
    client = investigation_api.app.test_client()

    response = client.get("/api/events", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    assert response.get_json() == [
        {
            "ip": "34.210.10.22",
            "lat": 47.6,
            "lon": -122.3,
            "country": "US",
            "severity": "high",
        }
    ]


def test_entity_profile_endpoint_builds_history(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(
        investigation_api,
        "get_all_alerts",
        lambda: [
            {
                "id": "1",
                "ip": "8.8.8.8",
                "rule": "credential_stuffing",
                "severity": "high",
                "timestamp": "2026-03-20T10:00:00+00:00",
                "details": {
                    "user_id": "j.doe",
                    "device_id": "wkst-4471",
                    "asset_criticality": "medium",
                    "country": "US",
                },
            },
            {
                "id": "2",
                "ip": "8.8.8.8",
                "rule": "high_risk_actor",
                "severity": "critical",
                "timestamp": "2026-03-21T10:00:00+00:00",
                "details": {
                    "user_id": "j.doe",
                    "device_id": "wkst-4471",
                    "asset_criticality": "medium",
                    "country": "US",
                },
            },
        ],
    )
    monkeypatch.setattr(investigation_api, "get_entity_profile", lambda entity_type, entity_key: None)
    investigation_api.create_case(title="Case 1", alert_id="1", linked_alert_ids=["1", "2"])
    client = investigation_api.app.test_client()

    response = client.get("/entities/ip/8.8.8.8", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["profile"]["entity_type"] == "ip"
    assert payload["profile"]["alert_count"] == 2
    assert payload["profile"]["case_count"] == 1
    assert set(payload["profile"]["related_attack_types"]) == {"credential_stuffing", "high_risk_actor"}
    assert payload["profile"]["risk_score"] > 0


def test_hunt_search_supports_structured_query_and_time_range(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(
        investigation_api,
        "get_all_alerts",
        lambda: [
            {
                "id": "1",
                "ip": "172.16.10.25",
                "rule": "honeypot_access",
                "severity": "critical",
                "timestamp": "2026-03-21T11:58:00+00:00",
                "details": {
                    "country": "US",
                    "user_id": "svc-backup",
                    "risk_score": 90,
                },
            },
            {
                "id": "2",
                "ip": "172.16.10.25",
                "rule": "credential_stuffing",
                "severity": "high",
                "timestamp": "2026-03-21T10:10:00+00:00",
                "details": {
                    "country": "US",
                    "user_id": "svc-backup",
                    "risk_score": 70,
                },
            },
            {
                "id": "3",
                "ip": "8.8.8.8",
                "rule": "rate_limit_abuse",
                "severity": "medium",
                "timestamp": "2026-03-20T11:58:00+00:00",
                "details": {
                    "country": "DE",
                    "user_id": "j.doe",
                    "risk_score": 45,
                },
            },
        ],
    )
    monkeypatch.setattr(
        investigation_api,
        "_get_alert_watchlist_metadata",
        lambda alert: {"watchlist_hit": False, "watchlist_hits_count": 0, "watchlist_matches": []},
    )
    monkeypatch.setattr(
        investigation_api,
        "_time_range_cutoff_seconds",
        lambda time_range: 0 if time_range == "24h" else 1711022100,
    )
    client = investigation_api.app.test_client()

    response = client.get(
        "/search",
        query_string={
            "mode": "hunt",
            "q": "ip:172.16.10.25 AND severity:critical",
            "time_range": "1h",
        },
        headers={"X-API-Key": "secret-key"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 1
    assert payload["alerts"][0]["source_ip"] == "172.16.10.25"
    assert payload["alerts"][0]["severity"] == "critical"


def test_manual_playbook_run_executes_actions(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(
        investigation_api,
        "_get_alert_watchlist_metadata",
        lambda alert: {"watchlist_hit": False, "watchlist_hits_count": 0, "watchlist_matches": []},
    )
    monkeypatch.setattr(
        investigation_api,
        "get_all_alerts",
        lambda: [
            {
                "id": "55",
                "ip": "172.16.10.25",
                "rule": "credential_stuffing",
                "severity": "critical",
                "timestamp": "2026-03-21T11:58:00+00:00",
                "details": {
                    "country": "US",
                    "risk_score": 92,
                    "reputation_score": 88,
                    "user_id": "svc-backup",
                },
            }
        ],
    )
    monkeypatch.setattr("shared.playbook_engine.fetch_ip_geolocation", lambda ip: {"country": "US", "city": "Ashburn"})
    monkeypatch.setattr("shared.playbook_engine.fetch_provider_payload", lambda ip: {"security": {"tor": False}, "connection": {"asn": "AS7018"}})
    client = investigation_api.app.test_client()

    response = client.post(
        "/playbooks/run",
        json={"alert_id": "55", "playbook_key": "credential_containment"},
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["execution"]["playbook_key"] == "credential_containment"
    assert any(step["type"] == "create_case" for step in payload["execution"]["steps"])
    assert any(step["type"] == "assign_analyst" for step in payload["execution"]["steps"])
    assert len(PLAYBOOK_EXECUTIONS) == 1


def test_execute_playbook_auto_trigger_matches_conditions(monkeypatch):
    monkeypatch.setattr("shared.playbook_engine.fetch_ip_geolocation", lambda ip: {"country": "US"})
    monkeypatch.setattr("shared.playbook_engine.fetch_provider_payload", lambda ip: {"connection": {"asn": "AS7018"}})

    execution = execute_playbook(
        {
            "id": "77",
            "ip": "172.16.10.25",
            "rule": "credential_stuffing",
            "severity": "critical",
            "details": {
                "risk_score": 95,
                "reputation_score": 90,
            },
        },
        actor="system",
        automatic=True,
    )

    assert execution is not None
    assert execution["automatic"] is True
    assert execution["status"] == "success"
    assert any(step["type"] == "block_ip" for step in execution["steps"])


def test_rule_test_endpoint_returns_recent_matches(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(
        investigation_api,
        "_get_alert_watchlist_metadata",
        lambda alert: {"watchlist_hit": False, "watchlist_hits_count": 0, "watchlist_matches": []},
    )
    monkeypatch.setattr(
        investigation_api,
        "get_all_alerts",
        lambda: [
            {
                "id": "a1",
                "ip": "8.8.8.8",
                "rule": "credential_stuffing",
                "severity": "high",
                "timestamp": "2026-03-21T11:58:00+00:00",
                "details": {},
            },
            {
                "id": "a2",
                "ip": "8.8.4.4",
                "rule": "credential_stuffing",
                "severity": "high",
                "timestamp": "2026-03-21T11:57:00+00:00",
                "details": {},
            },
        ],
    )
    monkeypatch.setattr(investigation_api, "_to_timestamp_seconds", lambda value: 1711022280)
    monkeypatch.setattr(investigation_api.time, "time", lambda: 1711022340)
    client = investigation_api.app.test_client()

    response = client.post(
        "/rules/test",
        json={"rule_key": "credential_stuffing"},
        headers={"X-API-Key": "secret-key", "X-User": "admin"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["matches"] == 2
    assert payload["rule"]["key"] == "credential_stuffing"
