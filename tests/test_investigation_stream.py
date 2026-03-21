from services.investigation_api import api as investigation_api


def test_build_stream_payload_exposes_dashboard_coordinates(monkeypatch):
    monkeypatch.setattr(
        investigation_api,
        "_get_alert_watchlist_metadata",
        lambda alert: {
            "watchlist_hit": False,
            "watchlist_hits_count": 0,
            "watchlist_matches": [],
        },
    )
    monkeypatch.setattr(
        investigation_api,
        "fetch_ip_geolocation",
        lambda ip: {
            "country": "Japan",
            "latitude": 35.6895,
            "longitude": 139.6917,
        },
    )
    monkeypatch.setattr(
        investigation_api,
        "get_geolocation_target",
        lambda: {
            "latitude": 51.5072,
            "longitude": -0.1276,
        },
    )

    payload = investigation_api.build_stream_payload(
        {
            "id": "alert-1",
            "ip": "1.2.3.4",
            "rule": "bruteforce",
            "severity": "high",
            "timestamp": "2026-03-15T18:00:00+00:00",
            "details": {
                "country": "JP",
                "risk_score": 85,
            },
        }
    )

    assert payload["source_ip"] == "1.2.3.4"
    assert payload["source_lat"] == 35.6895
    assert payload["source_lon"] == 139.6917
    assert payload["target_lat"] == 51.5072
    assert payload["target_lon"] == -0.1276
    assert payload["attack_type"] == "bruteforce"
    assert payload["country"] == "JP"
    assert payload["risk_score"] == 85
