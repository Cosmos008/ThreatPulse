from services.ingestion_service import main as ingestion_main
from services.investigation_api import api as investigation_api
from shared import api_security
from shared import alert_state
from shared import audit_log
from shared import blocklist
from shared import incident_records
from shared import presence
from shared import rule_config


class FakeProducer:
    def __init__(self):
        self.messages = []

    def send(self, topic, payload):
        self.messages.append((topic, payload))

    def flush(self):
        return None


def setup_function():
    api_security._request_log.clear()
    ingestion_main.producer = None
    alert_state.ALERT_STATE.clear()
    audit_log.AUDIT_LOG.clear()
    blocklist.BLOCKED_IPS.clear()
    incident_records.reset_records()
    presence.ONLINE_USERS.clear()
    rule_config.reload_rule_config()


def test_ingestion_requires_api_key(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = ingestion_main.app.test_client()

    response = client.post("/log", json={"event_type": "login_attempt"})

    assert response.status_code == 401


def test_ingestion_accepts_valid_request(monkeypatch):
    fake_producer = FakeProducer()
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(ingestion_main, "create_producer", lambda: fake_producer)
    client = ingestion_main.app.test_client()

    response = client.post(
        "/log",
        headers={"X-API-Key": "secret-key"},
        json={"event_type": "login_attempt", "ip": "1.2.3.4"}
    )

    assert response.status_code == 200
    assert {message[0] for message in fake_producer.messages} >= {"events.raw", "raw_logs"}


def test_ingestion_rate_limit(monkeypatch):
    fake_producer = FakeProducer()
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "2")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    monkeypatch.setattr(ingestion_main, "create_producer", lambda: fake_producer)
    client = ingestion_main.app.test_client()
    headers = {"X-API-Key": "secret-key"}
    payload = {"event_type": "login_attempt", "ip": "1.2.3.4"}

    assert client.post("/log", headers=headers, json=payload).status_code == 200
    assert client.post("/log", headers=headers, json=payload).status_code == 200
    assert client.post("/log", headers=headers, json=payload).status_code == 429


def test_ingestion_drops_blocked_ip(monkeypatch):
    fake_producer = FakeProducer()
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(ingestion_main, "create_producer", lambda: fake_producer)
    blocklist.block_ip("9.9.9.9")
    client = ingestion_main.app.test_client()

    response = client.post(
        "/log",
        headers={"X-API-Key": "secret-key"},
        json={"event_type": "login_attempt", "ip": "9.9.9.9"}
    )

    assert response.status_code == 202
    assert response.get_json()["status"] == "blocked"
    assert fake_producer.messages == []


def test_investigation_requires_api_key(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [])
    client = investigation_api.app.test_client()

    response = client.get("/alerts")

    assert response.status_code == 401


def test_investigation_returns_alerts(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 1,
        "rule": "honeypot_access",
        "severity": "high",
        "ip": "10.0.0.9",
        "details": {},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    response = client.get("/alerts", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alerts"][0]["rule"] == "honeypot_access"
    assert payload["alerts"][0]["severity"] == "critical"
    assert payload["alerts"][0]["is_honeypot"] is True
    assert payload["alerts"][0]["confidence_label"] == "High confidence threat"
    assert payload["alerts"][0]["risk_score"] == 0
    assert payload["alerts"][0]["threat_level"] == "Low"
    assert payload["alerts"][0]["mitre"]["technique"] == "T1078"
    assert payload["alerts"][0]["status"] == "open"
    assert payload["alerts"][0]["false_positive"] is False


def test_investigation_adds_optional_mitre_and_threat_level(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 4,
        "rule": "credential_stuffing",
        "severity": "high",
        "ip": "10.0.0.10",
        "risk_score": 120,
        "details": {},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    response = client.get("/alerts", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alerts"][0]["threat_level"] == "High"
    assert payload["alerts"][0]["mitre"] == {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    }


def test_investigation_returns_optional_explanation(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 2,
        "rule": "credential_stuffing",
        "severity": "high",
        "ip": "10.0.0.8",
        "details": {
            "explanation": [
                "Multiple failed login attempts",
                "Same IP targeting multiple users"
            ]
        },
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    response = client.get("/alerts", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alerts"][0]["explanation"] == [
        "Multiple failed login attempts",
        "Same IP targeting multiple users"
    ]


def test_investigation_returns_optional_risk_history(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 3,
        "rule": "high_risk_actor",
        "severity": "critical",
        "ip": "10.0.0.7",
        "risk_history": [
            {"timestamp": 1710000000.0, "score": 50},
            {"timestamp": 1710000010.0, "score": 100},
        ],
        "details": {},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    response = client.get("/alerts", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alerts"][0]["risk_history"] == [
        {"timestamp": 1710000000.0, "score": 50},
        {"timestamp": 1710000010.0, "score": 100},
    ]


def test_block_ip_action_updates_blocklist(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/block-ip",
        headers={"X-API-Key": "secret-key", "X-User": "admin"},
        json={"ip": "10.0.0.55"}
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "ip": "10.0.0.55",
        "action": "blocked"
    }
    assert blocklist.is_blocked("10.0.0.55") is True
    assert audit_log.get_logs()[-1]["action"] == "block_ip"
    assert audit_log.get_logs()[-1]["user"] == "admin"


def test_block_ip_action_requires_admin(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/block-ip",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"ip": "10.0.0.56"}
    )

    assert response.status_code == 403
    assert response.get_json()["detail"] == "Forbidden"


def test_set_status_action_updates_alert_state(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/set-status",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"id": "alert-1", "status": "investigating"}
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "id": "alert-1",
        "new_status": "investigating"
    }
    assert alert_state.get_state("alert-1")["status"] == "investigating"
    assert audit_log.get_logs()[-1]["action"] == "set_status"


def test_false_positive_action_updates_alert_state(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/false-positive",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"id": "alert-2"}
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "id": "alert-2",
        "flagged": "false_positive"
    }
    assert alert_state.get_state("alert-2")["false_positive"] is True
    assert audit_log.get_logs()[-1]["action"] == "false_positive"


def test_assign_action_updates_alert_state(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/assign",
        headers={"X-API-Key": "secret-key", "X-User": "admin"},
        json={"id": "alert-3", "analyst": "Liloo_chi5a"}
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "assigned_to": "Liloo_chi5a",
        "status_value": "assigned"
    }
    assert alert_state.get_state("alert-3")["analyst"] == "Liloo_chi5a"
    assert alert_state.get_state("alert-3")["assigned_to"] == "Liloo_chi5a"
    assert alert_state.get_state("alert-3")["status"] == "assigned"
    assert audit_log.get_logs()[-1]["action"] == "assign_alert"


def test_add_note_action_updates_alert_state(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/add-note",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"id": "alert-4", "note": "Investigating user behavior"}
    )

    assert response.status_code == 200
    assert response.get_json() == {"status": "success"}
    state = alert_state.get_state("alert-4")
    assert len(state["notes"]) == 1
    assert state["notes"][0]["text"] == "Investigating user behavior"
    assert audit_log.get_logs()[-1]["action"] == "add_note"


def test_investigation_returns_alert_state(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    alert_state.set_status("9", "closed")
    alert_state.set_false_positive("9")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 9,
        "rule": "credential_stuffing",
        "severity": "high",
        "ip": "10.0.0.80",
        "details": {},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    response = client.get("/alerts", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alerts"][0]["status"] == "closed"
    assert payload["alerts"][0]["false_positive"] is True


def test_investigation_returns_assignment_and_notes(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    alert_state.assign_analyst("11", "Bob")
    alert_state.add_note("11", "Escalated to identity team")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 11,
        "rule": "credential_stuffing",
        "severity": "high",
        "ip": "10.0.0.81",
        "details": {},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    response = client.get("/alerts", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alerts"][0]["analyst"] == "Bob"
    assert payload["alerts"][0]["assigned_to"] == "Bob"
    assert payload["alerts"][0]["notes"][0]["text"] == "Escalated to identity team"


def test_investigation_returns_lock_and_created_at(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    alert_state.lock_alert("12", "analyst")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 12,
        "rule": "credential_stuffing",
        "severity": "high",
        "ip": "10.0.0.82",
        "details": {},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    response = client.get("/alerts", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alerts"][0]["locked_by"] == "analyst"
    assert payload["alerts"][0]["created_at"] == "2026-03-19T17:00:00+00:00"


def test_assign_action_rejects_different_existing_owner(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    alert_state.assign_analyst("alert-7", "Bob")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/assign",
        headers={"X-API-Key": "secret-key", "X-User": "admin"},
        json={"id": "alert-7", "analyst": "Alice"}
    )

    assert response.status_code == 200
    assert response.get_json()["assigned_to"] == "Alice"


def test_assign_action_allows_analyst_to_claim_self(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/assign",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"id": "alert-13", "analyst": "analyst"}
    )

    assert response.status_code == 200
    assert response.get_json()["assigned_to"] == "analyst"


def test_assign_action_rejects_analyst_assigning_other_user(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/actions/assign",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"id": "alert-14", "analyst": "Liloo_chi5a"}
    )

    assert response.status_code == 403
    assert response.get_json()["message"] == "Forbidden"


def test_investigate_locks_alert(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.post(
        "/investigate",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"alert_id": "alert-8"}
    )

    assert response.status_code == 200
    assert response.get_json()["locked_by"] == "analyst"
    assert alert_state.get_state("alert-8")["locked_by"] == "analyst"


def test_admin_presence_requires_admin(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.get("/admin/presence", headers={"X-API-Key": "secret-key", "X-User": "analyst"})

    assert response.status_code == 403
    assert response.get_json()["detail"] == "Forbidden"


def test_presence_tracks_online_users(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    heartbeat = client.post("/presence", headers={"X-API-Key": "secret-key", "X-User": "analyst"})
    assert heartbeat.status_code == 200

    response = client.get("/admin/presence", headers={"X-API-Key": "secret-key", "X-User": "admin"})

    assert response.status_code == 200
    assert "analyst" in response.get_json()["users"]


def test_rules_endpoint_requires_admin(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.get("/rules", headers={"X-API-Key": "secret-key", "X-User": "analyst"})

    assert response.status_code == 403
    assert response.get_json()["detail"] == "Forbidden"


def test_rules_update_persists_config(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text("credential_stuffing:\n  threshold: 10\n  window_seconds: 60\n", encoding="utf-8")
    monkeypatch.setenv("RULES_CONFIG_FILE", str(rules_file))
    rule_config.reload_rule_config()
    client = investigation_api.app.test_client()

    response = client.post(
        "/rules/update",
        headers={"X-API-Key": "secret-key", "X-User": "admin"},
        json={"rule": "credential_stuffing", "config": {"threshold": 25}}
    )

    assert response.status_code == 200
    assert response.get_json()["config"]["threshold"] == 25

    fetched = client.get("/rules", headers={"X-API-Key": "secret-key", "X-User": "admin"})
    assert fetched.status_code == 200
    assert fetched.get_json()["credential_stuffing"]["threshold"] == 25


def test_auth_login_returns_user_role():
    client = investigation_api.app.test_client()

    response = client.post("/auth/login", json={"username": "admin", "password": "admin123"})

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "username": "admin",
        "role": "admin"
    }


def test_auth_login_rejects_invalid_credentials():
    client = investigation_api.app.test_client()

    response = client.post("/auth/login", json={"username": "admin", "password": "wrong"})

    assert response.status_code == 401
    assert response.get_json()["status"] == "error"


def test_audit_endpoint_returns_recent_logs(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    audit_log.log_action("analyst", "set_status", "alert-9:closed")
    client = investigation_api.app.test_client()

    response = client.get("/audit", headers={"X-API-Key": "secret-key", "X-User": "analyst"})

    assert response.status_code == 200
    assert response.get_json()["logs"][-1]["user"] == "analyst"


def test_audit_endpoint_requires_known_user(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = investigation_api.app.test_client()

    response = client.get("/audit", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 403
    assert response.get_json()["detail"] == "Unauthorized"


def test_search_returns_alerts_cases_and_investigations(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 77,
        "rule": "credential_stuffing",
        "severity": "high",
        "ip": "10.0.0.77",
        "details": {"country": "GB"},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    investigation = incident_records.upsert_investigation(
        alert_id="77",
        title="Credential investigation",
        analyst="analyst",
        summary="Looking into repeated login failures",
        related_alert_ids=["77"],
    )
    incident_records.create_case(
        title="Identity abuse case",
        alert_id="77",
        investigation_id=investigation["id"],
        assignee="analyst",
        priority="high",
    )
    client = investigation_api.app.test_client()

    response = client.get("/search?q=credential", headers={"X-API-Key": "secret-key"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 3
    assert payload["alerts"][0]["id"] == 77
    assert payload["investigations"][0]["alert_id"] == "77"
    assert payload["cases"][0]["alert_id"] == "77"


def test_case_and_investigation_endpoints_round_trip(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(investigation_api, "get_all_alerts", lambda: [{
        "id": 88,
        "rule": "honeypot_access",
        "severity": "critical",
        "ip": "10.0.0.88",
        "details": {},
        "timestamp": "2026-03-19T17:00:00+00:00",
    }])
    client = investigation_api.app.test_client()

    investigation_response = client.post(
        "/investigations",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"alert_id": "88", "title": "Honeypot review", "summary": "Escalating high-confidence signal"}
    )
    assert investigation_response.status_code == 200
    investigation_payload = investigation_response.get_json()["investigation"]
    assert investigation_payload["alert_id"] == "88"

    case_response = client.post(
        "/cases",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"investigation_id": investigation_payload["id"], "title": "Escalated honeypot case", "priority": "critical"}
    )
    assert case_response.status_code == 200
    case_payload = case_response.get_json()["case"]
    assert case_payload["investigation_id"] == investigation_payload["id"]
    assert case_payload["alert_id"] == "88"

    update_response = client.post(
        f"/cases/{case_payload['id']}",
        headers={"X-API-Key": "secret-key", "X-User": "analyst"},
        json={"status": "closed", "note": "Contained and closed"}
    )
    assert update_response.status_code == 200
    assert update_response.get_json()["case"]["status"] == "closed"
    assert alert_state.get_state("88")["status"] == "closed"
