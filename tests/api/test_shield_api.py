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
