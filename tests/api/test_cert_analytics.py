"""Read-only CERT dashboard analytics contracts."""

from __future__ import annotations

import importlib
import json

from fastapi.testclient import TestClient

from sentinel_ai.api import create_app
from sentinel_ai.cert import CertResearchService


def test_monthly_activity_returns_compact_provenance_carrying_aggregation(tmp_path, monkeypatch) -> None:
    service = CertResearchService(tmp_path)
    cache = tmp_path / "data" / "processed" / "cert_monthly_activity.json"
    cache.parent.mkdir(parents=True)
    points = [{"month": f"2010-{month:02d}", "login": month, "file": month * 2, "removableMedia": month * 3, "email": month * 4} for month in range(1, 13)]
    points += [{"month": f"2011-{month:02d}", "login": month, "file": month * 2, "removableMedia": month * 3, "email": month * 4} for month in range(1, 6)]
    cache.write_text(json.dumps({"dataset": "CERT Insider Threat r4.2", "unit": "raw telemetry events per calendar month", "reportingPeriod": {"start": "2010-01", "end": "2011-05", "months": 17}, "categories": [], "points": points, "totals": {"login": 81, "file": 162, "removableMedia": 243, "email": 324}, "provenance": {"aggregation": "test fixture"}}), encoding="utf-8")
    api_module = importlib.import_module("sentinel_ai.api.app")
    monkeypatch.setattr(api_module, "CertResearchService", lambda: service)
    with TestClient(create_app(tmp_path / "db.sqlite")) as client:
        response = client.get("/api/cert/analytics/monthly-activity")
    assert response.status_code == 200
    document = response.json()
    assert document["unit"] == "raw telemetry events per calendar month"
    assert document["reportingPeriod"] == {"start": "2010-01", "end": "2011-05", "months": 17}
    assert len(document["points"]) == 17
    assert set(document["points"][0]) == {"month", "login", "file", "removableMedia", "email"}
    assert document["provenance"]["available"] is True
    assert document["totals"] == {"login": 81, "file": 162, "removableMedia": 243, "email": 324}
