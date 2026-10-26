"""CERT user-day API contracts and safety boundaries."""

from __future__ import annotations

import pandas as pd
from fastapi.testclient import TestClient

from sentinel_ai.api import create_app
from sentinel_ai.cert.service import BEHAVIOURAL_SIGNALS, CertResearchService


def test_cert_status_identifies_primary_schema(tmp_path, monkeypatch) -> None:
    service = CertResearchService(tmp_path)
    service.data_dir.mkdir(parents=True)
    service.results_dir.mkdir(parents=True)
    (service.data_dir / "split_summary.json").write_text('{"overall":{"overall_positive_rate":0.0029}}')
    (service.results_dir / "metrics.json").write_text('{"metrics":{"qsvc":{"balanced_accuracy":0.93}}}')
    import importlib
    api_module = importlib.import_module("sentinel_ai.api.app")
    monkeypatch.setattr(api_module, "CertResearchService", lambda: service)
    with TestClient(create_app(tmp_path / "db.sqlite")) as client:
        body = client.get("/api/cert/status").json()
    assert body["primaryDataset"] == "CERT Insider Threat r4.2"
    assert body["entitySchema"] == "employee user-day"
    assert body["qsvcRole"] == "advisory"
    assert body["affectsProductionRisk"] is False


def test_cert_replay_does_not_invent_event_or_shield_context(tmp_path) -> None:
    service = CertResearchService(tmp_path)
    service.data_dir.mkdir(parents=True)
    row = {"user": "U1", "date": "2011-01-01", "label": 1, "scenario": 2}
    row.update({name: 1 for name in BEHAVIOURAL_SIGNALS})
    pd.DataFrame([row]).to_csv(service.data_dir / "test.csv", index=False)
    result = service.replay("U1")
    assert result["eventSequenceAvailable"] is False
    assert result["shieldHandoff"] is None
    assert result["simulatedContainment"] is False


def test_cert_identity_and_user_day_lists_are_paginated(tmp_path) -> None:
    service = CertResearchService(tmp_path)
    service.data_dir.mkdir(parents=True)
    rows = []
    for user, date, label in (("U1", "2011-01-01", 0), ("U1", "2011-01-02", 1), ("U2", "2011-01-01", 0)):
        row = {"user": user, "date": date, "label": label, "scenario": 2 if label else 0,
               "logon_count": 1, "logon_after_hours_count": label, "usb_connect_count": label,
               "file_copy_count": label, "email_sent_count": 2, "email_external_recipients": label}
        rows.append(row)
    pd.DataFrame(rows[:1]).to_csv(service.data_dir / "train.csv", index=False)
    pd.DataFrame(rows[1:2]).to_csv(service.data_dir / "validation.csv", index=False)
    pd.DataFrame(rows[2:]).to_csv(service.data_dir / "test.csv", index=False)
    users = service.list_users(page_size=1)
    days = service.list_user_days("U1")
    assert users["page"] == {"page": 1, "pageSize": 1, "total": 2, "totalPages": 2}
    assert days["page"]["total"] == 2
    assert days["source"] == "recorded CERT user-day aggregates"
