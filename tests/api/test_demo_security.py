from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel_ai.api.app import create_app


DEMO_SECRET = "test-only-secret-with-at-least-32-characters"


@pytest.fixture
def demo_client(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_PUBLIC_DEMO_MODE", "true")
    monkeypatch.setenv("SENTINEL_DEMO_API_SECRET", DEMO_SECRET)
    with TestClient(create_app(tmp_path / "demo.db", bootstrap_demo_data=False)) as client:
        yield client


def test_demo_mode_fails_closed_without_strong_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_PUBLIC_DEMO_MODE", "true")
    monkeypatch.setenv("SENTINEL_DEMO_API_SECRET", "too-short")
    with pytest.raises(RuntimeError, match="SENTINEL_DEMO_API_SECRET"):
        create_app(tmp_path / "demo.db", bootstrap_demo_data=False)


@pytest.mark.parametrize("authorization", [None, "Bearer incorrect-secret-with-at-least-32-characters"])
def test_demo_api_rejects_missing_or_invalid_credentials(demo_client, authorization):
    headers = {"authorization": authorization} if authorization else {}
    response = demo_client.get("/api/system/status", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "authorization" not in response.text.lower()
    assert DEMO_SECRET not in response.text


def test_demo_api_allows_authenticated_sensitive_read(demo_client):
    response = demo_client.get("/api/system/status", headers={"authorization": f"Bearer {DEMO_SECRET}"})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert DEMO_SECRET not in response.text


def test_every_api_route_rejects_anonymous_requests(demo_client):
    replacements = {
        "incident_id": "missing",
        "action_id": "missing",
        "proposal_id": "missing",
        "name": "missing",
        "employee_id": "missing",
        "event_id": "missing",
        "simulation_id": "missing",
        "alert_id": "missing",
        "entity_type": "user",
        "entity_id": "missing",
        "scenario_id": "missing",
        "user": "missing",
        "date": "2026-01-01",
        "run_id": "missing",
    }
    checked = 0
    for route in demo_client.app.routes:
        if not getattr(route, "path", "").startswith("/api/"):
            continue
        path = route.path
        for key, value in replacements.items():
            path = path.replace("{" + key + "}", value).replace("{" + key + ":path}", value)
        method = next(iter(set(route.methods or ()) - {"HEAD", "OPTIONS"}), "GET")
        response = demo_client.request(method, path)
        assert response.status_code == 401, f"{method} {route.path} was not protected"
        checked += 1
    assert checked >= 50


def test_demo_blocks_mutation_and_caller_claimed_privilege(demo_client):
    response = demo_client.post(
        "/api/shield/autonomous/proposals/attacker-selected/approval",
        headers={"authorization": f"Bearer {DEMO_SECRET}"},
        json={"actorId": "attacker", "role": "human_authorizer", "decision": "approve"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "public_demo_mutation_disabled"


def test_governance_route_still_requires_additional_token(demo_client):
    response = demo_client.post(
        "/api/shield/learning/policies/example/activate",
        headers={"authorization": f"Bearer {DEMO_SECRET}"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "model_governance_denied"


def test_openapi_schema_is_generated_and_contains_routes(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINEL_PUBLIC_DEMO_MODE", raising=False)
    monkeypatch.delenv("SENTINEL_DEMO_API_SECRET", raising=False)
    with TestClient(create_app(tmp_path / "local.db", bootstrap_demo_data=False)) as client:
        response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "/api/system/status" in response.json()["paths"]


def test_normal_local_mode_remains_unauthenticated(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINEL_PUBLIC_DEMO_MODE", raising=False)
    monkeypatch.delenv("SENTINEL_DEMO_API_SECRET", raising=False)
    with TestClient(create_app(tmp_path / "local.db", bootstrap_demo_data=False)) as client:
        response = client.get("/api/system/status")
    assert response.status_code == 200
