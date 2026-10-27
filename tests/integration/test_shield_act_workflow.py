from __future__ import annotations

import pandas as pd

from sentinel_ai.incidents import IncidentService


def test_adaptive_response_persists_executes_idempotently_and_rolls_back(tmp_path) -> None:
    database = tmp_path / "incidents.sqlite"
    service = IncidentService(database)
    record = pd.read_csv(service.cert.data_dir / "test.csv").query("label == 0").iloc[0]
    incident = service.create(str(record.user), str(record.date), "test")

    planned = service.plan_adaptive_response(incident["incidentId"], "file-collection")
    act = planned["shieldAct"]
    assert act["status"] == "PLANNED"
    assert act["optimization"]["exact"]["feasible"] is True
    assert act["optimization"]["qaoa"]["solver"]
    action_id = act["recommendation"]["actionId"]
    assert action_id

    executed = service.execute_adaptive_action(incident["incidentId"], action_id)
    repeated = service.execute_adaptive_action(incident["incidentId"], action_id)
    assert repeated["shieldAct"]["state"] == executed["shieldAct"]["state"]
    assert action_id in IncidentService(database).get(incident["incidentId"])["shieldAct"]["state"]["appliedActions"]

    rolled_back = service.rollback_adaptive_action(incident["incidentId"], action_id)
    assert action_id not in rolled_back["shieldAct"]["state"]["appliedActions"]
    assert rolled_back["shieldAct"]["state"]["remainingPaths"]
