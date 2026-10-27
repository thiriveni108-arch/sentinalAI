"""Persistent vertical workflow for controlled CERT counterfactual exercises."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

import numpy as np
import pandas as pd

from sentinel_ai import config
from sentinel_ai.cert.service import BEHAVIOURAL_FEATURES, PCA_FEATURES, CertResearchService
from sentinel_ai.shield.models import Intervention, Scenario, ShieldEdge, ShieldNode
from sentinel_ai.shield.paths import enumerate_attack_paths
from sentinel_ai.shield.service import ShieldService


class IncidentService:
    SCENARIO = "suspicious-file-collection"

    def __init__(self, database_path: str | Path | None = None, cert: CertResearchService | None = None,
                 shield: ShieldService | None = None) -> None:
        self.path = Path(database_path or config.DEFAULT_DATABASE_PATH)
        self.cert = cert or CertResearchService()
        self.shield = shield or ShieldService()
        self._initialize()

    def _connection(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript("""
            CREATE TABLE IF NOT EXISTS cert_incident_runs (
                incident_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                detected INTEGER NOT NULL,
                user_id TEXT NOT NULL,
                record_date TEXT NOT NULL,
                split TEXT NOT NULL,
                scenario TEXT NOT NULL,
                document_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cert_incidents_created ON cert_incident_runs(created_at DESC);
            """)

    def create(self, user: str, date: str, split: str = "test", scenario: str = SCENARIO) -> dict[str, Any]:
        if scenario != self.SCENARIO:
            raise ValueError(f"Unsupported controlled CERT scenario: {scenario}")
        original = self.cert.record(user, date, split)
        injected, changes = self._inject(original)
        transformed = self.cert.transform_behavioural(injected)
        before = self.cert.assess_row(original)
        after = self.cert.assess_row(transformed)
        now = datetime.now(timezone.utc).isoformat()
        incident_id = f"INC-{uuid4().hex[:12].upper()}"
        identity = self.cert._identity(user)
        document = {
            "incidentId": incident_id, "createdAt": now, "updatedAt": now, "status": "DETECTION_COMPLETE",
            "sourceType": "controlled CERT counterfactual", "scenario": scenario,
            "scenarioLabel": "Suspicious File Collection / Potential Data Exfiltration",
            "canonicalRecord": {"user": user, "date": date, "split": split, "researchLabel": int(original["label"]),
                                "researchScenario": int(original["scenario"]), "identity": identity},
            "provenance": {"originalDatasetModified": False, "rawTelemetryReconstructed": False,
                           "simulationIntent": "Exercise supported file collection and removable-media indicators on a copied employee-day.",
                           "pcaTransformation": "Training-fitted StandardScaler then training-fitted four-component PCA."},
            "originalEvidence": self._features(original), "injectedEvidence": self._features(transformed),
            "featureChanges": changes,
            "baselineContext": {"original": self.cert.population_context(original, split),
                                "injected": self.cert.population_context(transformed, split),
                                "peerGroupAvailable": False,
                                "label": "Past-only personal and population comparison; not a verified peer group"},
            "detection": {"original": before, "injected": after,
                          "findingCreated": bool(after["assessment"]["prediction"]),
                          "outcome": "DETECTED" if after["assessment"]["prediction"] else "MISSED_BY_SELECTED_POLICY"},
            "shield": {"status": "NOT_RUN", "eligible": True,
                       "boundary": "Incident-associated hypothetical response graph; not discovered CERT access data."},
            "history": [
                {"at": now, "stage": "ATTACK", "detail": "Controlled feature injection applied to an in-memory copy."},
                {"at": now, "stage": "DETECT", "detail": f"Frozen models executed; outcome {after['assessment']['verdict']}."},
            ],
        }
        self._save(document)
        return document

    def plan_response(self, incident_id: str) -> dict[str, Any]:
        document = self.get(incident_id)
        if document["shield"]["status"] == "COMPLETE":
            return document
        scenario = self._shield_scenario(document)
        started = perf_counter()
        result = self.shield.analyze_scenario(scenario, include_quantum=True)
        result["incidentId"] = incident_id
        result["modeledContext"] = True
        result["scientificBoundary"] = "All asset, authorization, and attack-path relationships are explicit exercise assumptions, not CERT observations."
        now = datetime.now(timezone.utc).isoformat()
        document["shield"] = {"status": "COMPLETE", "eligible": True, "result": result,
                              "executionTimeMs": round((perf_counter() - started) * 1000, 2)}
        document["status"] = "RESPONSE_COMPLETE"; document["updatedAt"] = now
        document["history"].append({"at": now, "stage": "OPTIMIZE_RESPONSE",
                                    "detail": "Exact, greedy, and QAOA solvers executed on the incident-associated modeled graph."})
        self._save(document)
        return document

    def get(self, incident_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute("SELECT document_json FROM cert_incident_runs WHERE incident_id = ?", (incident_id,)).fetchone()
        if row is None: raise KeyError(incident_id)
        return json.loads(row["document_json"])

    def list(self, detected: bool | None = None, limit: int = 50) -> list[dict[str, Any]]:
        query = "SELECT document_json FROM cert_incident_runs"
        params: list[Any] = []
        if detected is not None:
            query += " WHERE detected = ?"; params.append(int(detected))
        query += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
        with self._connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [json.loads(row["document_json"]) for row in rows]

    def summary(self) -> dict[str, int]:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) total, SUM(detected) detected, SUM(CASE WHEN status='RESPONSE_COMPLETE' THEN 1 ELSE 0 END) planned FROM cert_incident_runs").fetchone()
        return {"total": int(row["total"] or 0), "detected": int(row["detected"] or 0), "responsePlanned": int(row["planned"] or 0)}

    def _save(self, document: dict[str, Any]) -> None:
        canonical = document["canonicalRecord"]
        with self._connection() as connection:
            connection.execute("""INSERT INTO cert_incident_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET updated_at=excluded.updated_at,status=excluded.status,
                detected=excluded.detected,document_json=excluded.document_json""",
                (document["incidentId"], document["createdAt"], document["updatedAt"], document["status"],
                 int(document["detection"]["findingCreated"]), canonical["user"], canonical["date"], canonical["split"],
                 document["scenario"], json.dumps(document, allow_nan=False)))

    @staticmethod
    def _features(row: pd.Series) -> dict[str, float]:
        return {name: float(row[name]) for name in (*BEHAVIOURAL_FEATURES, *PCA_FEATURES)}

    def _inject(self, original: pd.Series) -> tuple[pd.Series, list[dict[str, Any]]]:
        row = original.copy(deep=True)
        updates = {
            "usb_connect_count": float(row["usb_connect_count"]) + 1,
            "usb_after_hours_count": float(row["usb_after_hours_count"]) + 1,
            "usb_pc_count": max(1.0, float(row["usb_pc_count"])),
            "file_copy_count": float(row["file_copy_count"]) + 40,
            "file_after_hours_count": float(row["file_after_hours_count"]) + 40,
            "file_doc_count": float(row["file_doc_count"]) + 32,
            "file_other_count": float(row["file_other_count"]) + 8,
            "file_pc_count": max(1.0, float(row["file_pc_count"])),
        }
        changes = []
        for feature, after in updates.items():
            before = float(row[feature]); row[feature] = after
            changes.append({"feature": feature, "before": before, "after": after, "delta": after - before,
                            "provenance": "controlled counterfactual injection"})
        if not np.isclose(float(row["file_doc_count"] + row["file_other_count"] + row["file_exe_count"]), float(row["file_copy_count"])):
            raise ValueError("Injected file subtype counts do not equal file_copy_count")
        if row["file_after_hours_count"] > row["file_copy_count"]:
            raise ValueError("After-hours file activity cannot exceed total copied files")
        return row, changes

    def _shield_scenario(self, document: dict[str, Any]) -> Scenario:
        iid = document["incidentId"].lower(); identity = document["canonicalRecord"]["identity"]["displayLabel"]
        scenario = Scenario(
            f"incident-{iid}", "Incident-associated file collection response",
            f"Modeled exercise for {identity}; relationships below are hypothetical and scoped to this incident.",
            None, "Controlled potential data-exfiltration exercise", (f"session:{iid}",),
            (ShieldNode(f"session:{iid}", "session", f"Modeled session for {identity}"),
             ShieldNode(f"media:{iid}", "device", "Modeled removable media"),
             ShieldNode(f"repository:{iid}", "file", "Hypothetical sensitive repository", 4),
             ShieldNode(f"export:{iid}", "damaging_action", "Potential external transfer", 5)),
            (ShieldEdge(f"session:{iid}", f"media:{iid}", "USES_REMOVABLE_MEDIA", True, True, ("injected:usb_connect_count",)),
             ShieldEdge(f"session:{iid}", f"repository:{iid}", "CAN_ACCESS", True, False, ("assumption:exercise-access",)),
             ShieldEdge(f"repository:{iid}", f"export:{iid}", "CAN_EXPORT", True, False, ("injected:file_copy_count",))),
            (Intervention(f"disable-export-{iid}", "DISABLE_BULK_EXPORT", f"repository:{iid}", 1.5, (), explanation="Block new modeled exports while retaining ordinary access."),
             Intervention(f"restrict-repository-{iid}", "RESTRICT_RESOURCE", f"repository:{iid}", 3, (), explanation="Temporarily restrict the hypothetical repository."),
             Intervention(f"revoke-session-{iid}", "REVOKE_SESSION", f"session:{iid}", 4, (), explanation="Invalidate the modeled session."),
             Intervention(f"disable-account-{iid}", "DISABLE_ACCOUNT", f"user:{iid}", 10, (), implementation_impact="high", approval_required=True, explanation="Broad exercise containment.")),
            ("Injected removable-media indicator", "Injected after-hours file collection", "Hypothetical continuation to sensitive data transfer"),
        )
        paths = enumerate_attack_paths(scenario)
        path_ids = tuple(path.path_id for path in paths)
        actions = []
        for action in scenario.actions:
            if action.action_type in {"REVOKE_SESSION", "DISABLE_ACCOUNT"}: covered = path_ids
            else: covered = tuple(path.path_id for path in paths if action.target in path.nodes)
            actions.append(Intervention(**{**action.__dict__, "interrupts": covered}))
        return Scenario(**{**scenario.__dict__, "actions": tuple(actions)})
