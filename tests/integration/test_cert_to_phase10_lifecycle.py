"""Real CERT injection through linked SHIELD, Phase 8 and Phase 10 memory."""
from __future__ import annotations

import pandas as pd

from sentinel_ai.incidents import IncidentService
from sentinel_ai.shield.autonomous_defense import DefenseCoordinator, DefenseStore
from sentinel_ai.shield.continuous_learning import ExperienceStore
from sentinel_ai.shield.unified_session import UnifiedSessionService


def test_cert_injection_reaches_governed_experience_without_losing_identity(tmp_path):
    incidents=IncidentService(tmp_path/"incidents.db")
    memory=ExperienceStore(tmp_path/"phase10.db")
    shield=UnifiedSessionService(DefenseCoordinator(DefenseStore(tmp_path/"phase8.db")),memory)
    row=pd.read_csv(incidents.cert.data_dir/"test.csv").query("label == 0").iloc[0]

    cert=incidents.create(str(row.user),str(row.date),"test")
    actual_outcome=cert["detection"]["outcome"]
    session=shield.create_linked(cert,"small-office",96001)
    incidents.attach_shield_session(cert["incidentId"],session)

    assert session["mode"]=="CERT_LINKED_INCIDENT"
    assert session["incident_id"]==cert["incidentId"]
    assert session["context"]["identity"]["identifier"]==cert["canonicalRecord"]["identity"]["sourceId"]
    assert session["context"]["detection_outcome"]==actual_outcome
    assert session["adapter"]["detectorOutcomePreserved"]==actual_outcome
    assert session["adapter"]["unknownFields"] and "hypothetical" in session["context"]["network_context"].lower()

    plan=shield.plan(cert["incidentId"],session["version"])
    session=shield.submit(cert["incidentId"],session["version"])
    proposal=session["proposal"]["proposal"]
    declared={n["identifier"] for n in session["topology_state"]["nodes"]}
    declared|={r.required_identity for r in shield.sessions[cert["incidentId"]].environment.topology.routes}
    assert set(proposal["targets"])<=declared
    assert not set(proposal["targets"])&{r.identifier for r in shield.sessions[cert["incidentId"]].environment.topology.routes}
    assert plan["plan"]["solver"]=="exact"

    if session["lifecycle_status"]=="PENDING_HUMAN":
        session=shield.approve(cert["incidentId"],"simulated-human","approve",session["version"])
    elif session["lifecycle_status"]=="PENDING_ANALYST":
        session=shield.approve(cert["incidentId"],"simulated-analyst","approve",session["version"])
    session=shield.execute(cert["incidentId"],session["version"])
    if session["lifecycle_status"]=="RECOVERY_PENDING":
        session=shield.recover(cert["incidentId"],"simulated-analyst",session["version"])
    incidents.sync_shield_lifecycle(cert["incidentId"],session)

    assert session["lifecycle_status"] in {"VERIFIED","RECOVERED","ESCALATED"}
    if session["proposal"]["feedback"]["verification"]=="not-contained":
        assert session["lifecycle_status"]=="ESCALATED"
    assert session["experience_ingestion"]["created"] is True
    stored=memory.history()
    assert stored and stored[-1]["episode"]["linkage"]["cert_incident_id"]==cert["incidentId"]
    linked=incidents.get(cert["incidentId"])["linkage"]
    assert linked["shieldSessionId"]==session["session_id"]
    assert linked["proposalIds"]==[session["proposal"]["proposal_id"]]
    assert linked["experienceFingerprint"]==session["experience_ingestion"]["fingerprint"]


def test_standalone_graph_exercise_never_claims_cert_identity(tmp_path):
    service=UnifiedSessionService(DefenseCoordinator(DefenseStore(tmp_path/"p8.db")),ExperienceStore(tmp_path/"p10.db"))
    session=service.create("credential-compromise","small-office",17)
    assert session["mode"]=="STANDALONE_GRAPH_EXERCISE"
    assert session["context"]["identity"]["established"] is False
    assert session["context"]["identity"]["identifier"] is None
