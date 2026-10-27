"""Connected CERT incident lifecycle using frozen artifacts and modeled SHIELD."""

from __future__ import annotations

import pandas as pd

from sentinel_ai.incidents import IncidentService


def test_controlled_cert_incidents_persist_and_remain_independent(tmp_path) -> None:
    service = IncidentService(tmp_path / "incidents.sqlite")
    frame = pd.read_csv(service.cert.data_dir / "test.csv")
    row = frame[frame["label"] == 0].iloc[0]
    first = service.create(str(row.user), str(row.date), "test")
    second = service.create(str(row.user), str(row.date), "test")

    assert first["incidentId"] != second["incidentId"]
    assert first["provenance"]["originalDatasetModified"] is False
    assert first["originalEvidence"]["file_copy_count"] == float(row.file_copy_count)
    assert first["injectedEvidence"]["file_copy_count"] == float(row.file_copy_count) + 40
    assert first["detection"]["injected"]["assessment"]["policy"] == "QSVC_LEAD"
    assert set(first["detection"]["injected"]["models"]) == {"qsvc", "vqc", "rbfSvm"}
    assert service.get(first["incidentId"])["incidentId"] == first["incidentId"]
    assert service.summary()["total"] == 2


def test_incident_shield_is_explicit_persisted_and_idempotent(tmp_path) -> None:
    service = IncidentService(tmp_path / "incidents.sqlite")
    row = pd.read_csv(service.cert.data_dir / "test.csv").query("label == 0").iloc[0]
    incident = service.create(str(row.user), str(row.date), "test")

    planned = service.plan_response(incident["incidentId"])
    repeated = service.plan_response(incident["incidentId"])
    result = planned["shield"]["result"]

    assert result["incidentId"] == incident["incidentId"]
    assert result["modeledContext"] is True
    assert result["scenario"]["riskScore"] is None
    assert result["solvers"]["exact"]["feasible"] is True
    assert result["solvers"]["exact"]["remaining_paths"] == ()
    assert result["quantum"]["executed"] is True
    assert repeated["updatedAt"] == planned["updatedAt"]
