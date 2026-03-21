import json

from services.geolocation_service import api as geolocation_api
from services.geolocation_service import service as geolocation_service
from shared import api_security


class DummyResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def setup_function():
    api_security._request_log.clear()
    geolocation_service._cache.clear()


def test_private_ip_is_not_mapped():
    result = geolocation_service.fetch_ip_geolocation("10.0.0.8")

    assert result["found"] is False
    assert result["reason"] == "private_ip"


def test_public_ip_lookup_normalizes_provider_payload(monkeypatch):
    monkeypatch.setattr(
        geolocation_service.urllib.request,
        "urlopen",
        lambda *args, **kwargs: DummyResponse(
            {
                "success": True,
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "city": "Mountain View",
                "latitude": 37.386,
                "longitude": -122.084
            }
        )
    )

    result = geolocation_service.fetch_ip_geolocation("8.8.8.8")

    assert result["found"] is True
    assert result["city"] == "Mountain View"
    assert result["country_code"] == "US"
    assert result["latitude"] == 37.386
    assert result["longitude"] == -122.084


def test_geolocation_lookup_requires_api_key(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    client = geolocation_api.app.test_client()

    response = client.post("/lookup", json={"ips": ["8.8.8.8"]})

    assert response.status_code == 401


def test_geolocation_lookup_returns_results(monkeypatch):
    monkeypatch.setenv("SECURITY_API_KEY", "secret-key")
    monkeypatch.setattr(
        geolocation_api,
        "batch_lookup",
        lambda ips: [{"ip": ips[0], "found": True, "latitude": 1.0, "longitude": 2.0}]
    )
    client = geolocation_api.app.test_client()

    response = client.post(
        "/lookup",
        headers={"X-API-Key": "secret-key"},
        json={"ips": ["8.8.8.8"]}
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "results": [{"ip": "8.8.8.8", "found": True, "latitude": 1.0, "longitude": 2.0}]
    }
