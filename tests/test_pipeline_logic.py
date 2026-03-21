from services.detection_engine import counters, credential_stuffing, device_abuse, streaming_fraud, honeypot_detection
from services.correlation_engine import service as correlation_service
from services.risk_engine import scoring
from services.event_router.router import route_event
from shared.event_schema import create_event
from shared.rule_config import update_detection_rule


def setup_function():
    counters.login_failures.clear()
    device_abuse.device_accounts.clear()
    streaming_fraud.play_counts.clear()
    scoring.risk_scores.clear()
    scoring.risk_history.clear()
    scoring.last_emitted_bucket.clear()
    correlation_service.signal_windows.clear()
    update_detection_rule("credential_stuffing", {"enabled": True, "threshold": 10, "severity": "high", "time_window_seconds": 60})


def test_event_routing_and_credential_stuffing():
    event = create_event("login_attempt", user_id="user-1", ip="10.0.0.5", device_id="device-1", status="failed")

    assert route_event(event) == "auth_events"

    alert = None
    for _ in range(11):
        alert = credential_stuffing.check_credential_stuffing(event)

    assert alert is not None
    assert alert["rule"] == "credential_stuffing"


def test_streaming_fraud_and_risk_scoring():
    event = create_event("music_play", user_id="listener-1", ip="10.0.0.9", device_id="speaker-1")

    assert route_event(event) == "stream_events"

    alert = None
    for _ in range(51):
        alert = streaming_fraud.check_streaming_fraud(event)

    assert alert is not None
    assert alert["rule"] == "streaming_fraud"
    assert scoring.update_score(alert) is None

    assert scoring.update_score(alert) is None
    risk_alert = scoring.update_score(alert)

    assert risk_alert is not None
    assert risk_alert["rule"] == "high_risk_actor"


def test_device_abuse_detection():
    alert = None

    for index in range(6):
        event = create_event(
            "login_success",
            user_id=f"user-{index}",
            ip=f"10.0.0.{index}",
            device_id="shared-device",
            status="success"
        )
        alert = device_abuse.check_device_abuse(event)

    assert alert is not None
    assert alert["rule"] == "device_abuse"


def test_honeypot_detection_is_critical():
    honeypot_user = next(iter(honeypot_detection.honeypot_accounts))
    event = create_event("login_attempt", user_id=honeypot_user, ip="10.0.0.77", status="failed")

    alert = honeypot_detection.check_honeypot(event)

    assert alert is not None
    assert alert["rule"] == "honeypot_access"
    assert alert["severity"] == "critical"


def test_correlation_detects_multi_stage_attack():
    ip = "10.0.0.88"
    alerts = [
        {"rule": "credential_stuffing", "severity": "high", "ip": ip},
        {"rule": "anomaly_spike", "severity": "medium", "ip": ip},
        {"rule": "honeypot_access", "severity": "critical", "ip": ip},
    ]

    correlated = None
    for alert in alerts:
        correlated = correlation_service.correlate_alert(alert)

    assert correlated is not None
    assert correlated["rule"] == "coordinated_attack"
    assert correlated["severity"] == "critical"
    assert correlated["sequence"]["sequence_type"] == "critical"
    assert correlated["sequence"]["escalated"] is True
    assert correlated["details"]["coordinated_attack"] is True
    assert correlated["details"]["confidence_label"] == "Multi-stage attack detected"


def test_detect_attack_sequence_returns_suspicious_sequence():
    now = correlation_service.datetime.now(correlation_service.UTC)
    sequence = correlation_service.detect_attack_sequence([
        {"ip": "10.0.0.50", "rule": "credential_stuffing", "timestamp": now - correlation_service.timedelta(minutes=1)},
        {"ip": "10.0.0.50", "rule": "anomaly_spike", "timestamp": now},
    ])

    assert sequence is not None
    assert sequence["ip"] == "10.0.0.50"
    assert sequence["sequence_type"] == "suspicious"
    assert sequence["attack_types"] == ["anomaly_spike", "credential_stuffing"]
    assert sequence["escalated"] is False


def test_risk_score_adds_sequence_bonus():
    alert = {
        "rule": "credential_stuffing",
        "ip": "10.0.0.66",
        "sequence": {"sequence_type": "coordinated"},
    }

    risk_alert = None
    for _ in range(2):
        risk_alert = scoring.update_score(alert)

    assert risk_alert is not None
    assert risk_alert["risk_score"] == 220
    assert risk_alert["risk_history"][-1]["score"] == 220


def test_risk_history_keeps_last_ten_scores():
    alert = {
        "rule": "streaming_fraud",
        "ip": "10.0.0.99",
    }

    for _ in range(12):
        scoring.update_score(alert)

    assert len(scoring.risk_history["10.0.0.99"]) == 10
    assert scoring.risk_history["10.0.0.99"][0]["score"] == 120
    assert scoring.risk_history["10.0.0.99"][-1]["score"] == 480


def test_disabling_rule_stops_alert_generation():
    update_detection_rule("credential_stuffing", {"enabled": False, "threshold": 10, "severity": "high", "time_window_seconds": 60})
    event = create_event("login_attempt", user_id="user-1", ip="10.0.0.5", device_id="device-1", status="failed")

    alert = None
    for _ in range(15):
        alert = credential_stuffing.check_credential_stuffing(event)

    assert alert is None
