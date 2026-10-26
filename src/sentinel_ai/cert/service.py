"""Read-only CERT r4.2 research workflow.

This module intentionally stays separate from the event-level production path.  A
CERT row is an employee/day aggregate and is never converted into an ActivityEvent.
"""

from __future__ import annotations

import json
import pickle
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from sentinel_ai import config
from .qsvc import make_state_circuit

PCA_FEATURES = ("pca_1", "pca_2", "pca_3", "pca_4")
IDENTITY = ("user", "date")
BEHAVIOURAL_SIGNALS = (
    "logon_after_hours_count", "usb_after_hours_count", "file_after_hours_count",
    "file_copy_count", "file_exe_count", "email_after_hours_count",
    "email_external_recipients", "email_total_attachments",
)


class CertResearchService:
    """Loads prepared data and a frozen benchmark model; it never fits at runtime."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or config.PROJECT_ROOT)
        self.data_dir = self.root / "data" / "processed" / "cert_r4_2"
        self.results_dir = self.root / "experiments" / "cert_qsvc" / "results"
        self.artifact_path = self.root / "artifacts" / "models" / "cert_r4_2_qsvc.pkl"

    def status(self) -> dict[str, Any]:
        summary = self._json(self.data_dir / "split_summary.json")
        metrics = self._json(self.results_dir / "metrics.json")
        model_ready = self.artifact_path.exists()
        return {
            "primaryDataset": "CERT Insider Threat r4.2",
            "entitySchema": "employee user-day",
            "featureSchema": list(PCA_FEATURES),
            "processedDataReady": all((self.data_dir / f"{name}.csv").exists() for name in ("train", "validation", "test")),
            "savedPreprocessingReady": (self.data_dir / "scaler_model.pkl").exists() and (self.data_dir / "pca_model.pkl").exists(),
            "qsvcArtifactReady": model_ready,
            "qsvcRole": "advisory",
            "affectsProductionRisk": False,
            "naturalPositiveRate": summary.get("overall", {}).get("overall_positive_rate"),
            "benchmark": metrics.get("metrics", {}).get("qsvc", {}),
            "runtimeBoundary": "CERT user-day inputs only; event-level SentinelAI quantum inputs are incompatible.",
            "legacyDemo": "Retained temporarily in SQLite and Attack Lab; it is not the primary research dataset.",
        }

    def investigate(self, user: str, date: str, split: str = "test") -> dict[str, Any]:
        row = self._find_row(user, date, split)
        prediction = self._predict(row)
        signals = [
            {"feature": name, "value": float(row[name]), "evidenceType": "recorded aggregate"}
            for name in BEHAVIOURAL_SIGNALS if float(row.get(name, 0)) > 0
        ]
        scenario = int(row["scenario"])
        return {
            "record": {"user": str(row["user"]), "date": str(row["date"]), "split": split,
                       "label": int(row["label"]), "scenario": scenario,
                       "features": {name: float(row[name]) for name in PCA_FEATURES}},
            "behaviouralEvidence": signals,
            "classicalEvidence": self._classical_evidence(row, prediction),
            "classification": prediction,
            "alert": {
                "raised": bool(prediction["prediction"]),
                "advisory": True,
                "title": "CERT user-day requires investigation" if prediction["prediction"] else "No QSVC alert",
                "groundTruthUsedForInference": False,
                "groundTruthVisibleForResearchEvaluation": True,
            },
            "threatContext": {
                "recorded": "Prepared CERT employee/day activity aggregates and research label.",
                "inferred": "QSVC class and local feature influence; no event order or access relationship is inferred.",
                "shieldEligible": False,
                "shieldHandoff": None,
                "reason": "The user-day schema contains no validated access-control or attack-graph relationships.",
            },
        }

    def replay(self, user: str, split: str = "test", malicious_only: bool = True, limit: int = 30) -> dict[str, Any]:
        frame = self._frame(split)
        rows = frame[frame["user"].astype(str) == user]
        if malicious_only:
            rows = rows[rows["label"] == 1]
        rows = rows.sort_values("date").head(limit)
        if rows.empty:
            raise KeyError(f"No matching CERT user-days for {user} in {split}")
        timeline = [{"date": str(row.date), "label": int(row.label), "scenario": int(row.scenario),
                     "recordedAggregates": {name: float(getattr(row, name)) for name in BEHAVIOURAL_SIGNALS}}
                    for row in rows.itertuples(index=False)]
        return {
            "user": user, "split": split, "replayType": "recorded user-day aggregate timeline",
            "timeline": timeline,
            "eventSequenceAvailable": False,
            "simulatedContainment": False,
            "shieldHandoff": None,
            "disclosure": "This is a chronological replay of prepared labelled user-days, not raw CERT events. Within-day event order and access relationships are unavailable, so Attack Lab sequence rules and SHIELD containment are not asserted.",
        }

    def _predict(self, row: pd.Series) -> dict[str, Any]:
        if not self.artifact_path.exists():
            raise FileNotFoundError("Frozen QSVC artifact is missing; run scripts/materialize_cert_qsvc.py once.")
        artifact = self._artifact(str(self.artifact_path))
        values = row.loc[list(PCA_FEATURES)].to_numpy(dtype=float).reshape(1, -1)
        scaled = artifact["input_scaler"].transform(values)
        state = self._state(scaled[0])
        kernel = np.abs(state.reshape(1, -1) @ artifact["train_states"].conj().T) ** 2
        score = float(artifact["model"].decision_function(kernel)[0])
        threshold = float(artifact["threshold"])
        baseline = np.zeros(4, dtype=float)
        influences = []
        for index, name in enumerate(PCA_FEATURES):
            perturbed = scaled[0].copy()
            perturbed[index] = baseline[index]
            pstate = self._state(perturbed)
            pkernel = np.abs(pstate.reshape(1, -1) @ artifact["train_states"].conj().T) ** 2
            pscore = float(artifact["model"].decision_function(pkernel)[0])
            influences.append({"feature": name, "value": float(values[0, index]), "scoreInfluence": score - pscore})
        influences.sort(key=lambda item: abs(item["scoreInfluence"]), reverse=True)
        return {"model": "PennyLane fidelity-kernel QSVC", "prediction": int(score >= threshold),
                "decisionScore": score, "decisionThreshold": threshold, "scoreIsProbability": False,
                "explanationMethod": "one-feature replacement in the benchmark-scaled PCA space",
                "featureInfluences": influences, "advisory": True,
                "validationCaveat": "Threshold was selected on an artificially balanced benchmark; natural-imbalance alert burden is not validated."}

    def _classical_evidence(self, row: pd.Series, prediction: dict[str, Any]) -> dict[str, Any]:
        artifact = self._artifact(str(self.artifact_path))
        values = row.loc[list(PCA_FEATURES)].to_numpy(dtype=float).reshape(1, -1)
        scaled = artifact["input_scaler"].transform(values)
        model = artifact.get("classical_model")
        comparison = None
        if model is not None:
            score = float(model.decision_function(scaled)[0])
            threshold = float(artifact["classical_threshold"])
            comparison = {"model": "RBF-SVM benchmark comparator", "prediction": int(score >= threshold),
                          "decisionScore": score, "decisionThreshold": threshold, "advisory": True}
        rules = []
        if float(row.get("file_copy_count", 0)) > 0:
            rules.append("REMOVABLE_MEDIA_FILE_ACTIVITY")
        if float(row.get("usb_connect_count", 0)) > 0:
            rules.append("REMOVABLE_MEDIA_CONNECTED")
        if sum(float(row.get(name, 0)) for name in ("logon_after_hours_count", "file_after_hours_count", "email_after_hours_count")) > 0:
            rules.append("AFTER_HOURS_ACTIVITY")
        if float(row.get("email_external_recipients", 0)) > 0:
            rules.append("EXTERNAL_EMAIL_ACTIVITY")
        return {"transparentUserDayRules": rules, "rbfSvm": comparison,
                "agreementWithQsvc": comparison is not None and comparison["prediction"] == prediction["prediction"],
                "note": "Legacy event Isolation Forest/rules are not applied because their schema is incompatible."}

    @staticmethod
    def _state(angles: np.ndarray) -> np.ndarray:
        # Same PennyLane feature map as the benchmark, evaluated by PennyLane.
        return np.asarray(make_state_circuit()(angles), dtype=complex)

    def _find_row(self, user: str, date: str, split: str) -> pd.Series:
        frame = self._frame(split)
        matches = frame[(frame["user"].astype(str) == user) & (frame["date"].astype(str) == date)]
        if len(matches) != 1:
            raise KeyError(f"CERT user-day not found: {user} {date} ({split})")
        return matches.iloc[0]

    @lru_cache(maxsize=3)
    def _frame(self, split: str) -> pd.DataFrame:
        names = {"train": "train.csv", "validation": "validation.csv", "test": "test.csv"}
        if split not in names:
            raise ValueError(f"Unsupported CERT split: {split}")
        return pd.read_csv(self.data_dir / names[split])

    @staticmethod
    @lru_cache(maxsize=1)
    def _artifact(path: str) -> dict[str, Any]:
        with Path(path).open("rb") as handle:
            return pickle.load(handle)

    @staticmethod
    def _json(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
