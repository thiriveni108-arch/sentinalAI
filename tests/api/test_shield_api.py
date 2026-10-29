import pytest
from fastapi.testclient import TestClient

from sentinel_ai.api.app import create_app


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "shield.db", bootstrap_demo_data=False)) as test_client:
        yield test_client


def test_shield_scenarios_and_flagship_plan(client):
    scenarios = client.get("/api/shield/scenarios")
    assert scenarios.status_code == 200
    assert len(scenarios.json()) == 3
    response = client.get("/api/shield/scenarios/multiple-routes")
    assert response.status_code == 200
    body = response.json()
    assert body["recommendation"]["feasible"] is True
    assert len(body["attackPaths"]) == 2
    assert body["counterfactuals"][0]["accepted"] is False
    assert body["quantum"]["quboAudit"]["energyMismatches"] == 0
    assert body["quantum"]["qaoaObjective"] == 3


def test_shield_unknown_scenario_is_404(client):
    assert client.get("/api/shield/scenarios/unknown").status_code == 404


def test_unified_session_lifecycle_is_versioned_authorized_and_auditable(client, tmp_path):
    created = client.post("/api/shield/sessions", json={"topology":"small-office"})
    assert created.status_code == 201
    initial = created.json(); incident = initial["incident_id"]
    assert initial["correlation_id"] and initial["available_actions"] == ["plan"]

    assert client.post(f"/api/shield/sessions/{incident}/plan", json={"version":99}).status_code == 409
    plan = client.post(f"/api/shield/sessions/{incident}/plan", json={"version":0})
    assert plan.status_code == 200 and plan.json()["plan"]["solver"] == "exact"

    submitted = client.post(f"/api/shield/sessions/{incident}/submit", json={"version":0}).json()
    duplicate = client.post(f"/api/shield/sessions/{incident}/submit", json={"version":submitted["version"]})
    assert duplicate.status_code == 200
    assert duplicate.json()["proposal"]["proposal_id"] == submitted["proposal"]["proposal_id"]

    denied = client.post(f"/api/shield/sessions/{incident}/approval", json={"version":submitted["version"],"identity":"client-admin","decision":"approve"})
    assert denied.status_code == 403
    identity = "simulated-analyst" if submitted["lifecycle_status"] == "PENDING_ANALYST" else "simulated-human"
    approved = client.post(f"/api/shield/sessions/{incident}/approval", json={"version":submitted["version"],"identity":identity,"decision":"approve"}).json()
    executed = client.post(f"/api/shield/sessions/{incident}/execute", json={"version":approved["version"]}).json()
    assert executed["experience_ingestion"]["attempted"] is True
    assert executed["experience_ingestion"]["created"] is True
    assert executed["timeline"][-1]["state"] in {"VERIFIED","RECOVERY_PENDING","ESCALATED"}

    if executed["lifecycle_status"] == "RECOVERY_PENDING":
        recovered = client.post(f"/api/shield/sessions/{incident}/recovery", json={"version":executed["version"],"identity":"simulated-analyst"})
        assert recovered.status_code == 200
        executed = recovered.json()
        assert executed["lifecycle_status"] in {"RECOVERED","ESCALATED"}
    experiences = client.get("/api/shield/learning/experiences").json()["items"]
    assert any(item["episode"]["incident_id"] == incident for item in experiences)

    with TestClient(create_app(tmp_path / "shield.db", bootstrap_demo_data=False)) as restarted:
        unavailable = restarted.get(f"/api/shield/sessions/{incident}")
        assert unavailable.status_code == 409
        assert unavailable.json()["error"]["code"] == "session_unavailable"
