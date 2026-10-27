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
import pennylane as qml

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
        self.vqc_results_dir = self.root / "experiments" / "cert_vqc" / "results"
        self.vqc_artifact_path = self.vqc_results_dir / "best_vqc_checkpoint.npz"

    def status(self) -> dict[str, Any]:
        summary = self._json(self.data_dir / "split_summary.json")
        metrics = self._json(self.results_dir / "metrics.json")
        model_ready = self.artifact_path.exists()
        processed_ready = all((self.data_dir / f"{name}.csv").exists() for name in ("train", "validation", "test"))
        catalog = self._catalog() if processed_ready else pd.DataFrame(columns=["user", "date"])
        return {
            "primaryDataset": "CERT Insider Threat r4.2",
            "entitySchema": "employee user-day",
            "featureSchema": list(PCA_FEATURES),
            "processedDataReady": processed_ready,
            "savedPreprocessingReady": (self.data_dir / "scaler_model.pkl").exists() and (self.data_dir / "pca_model.pkl").exists(),
            "qsvcArtifactReady": model_ready,
            "vqcArtifactReady": self.vqc_artifact_path.exists(),
            "rbfSvmArtifactReady": model_ready and self._artifact(str(self.artifact_path)).get("classical_model") is not None,
            "assessmentPolicy": self._assessment_policy() if model_ready and self.vqc_artifact_path.exists() else None,
            "qsvcRole": "advisory",
            "affectsProductionRisk": False,
            "naturalPositiveRate": float(summary.get("overall", {}).get("overall_positive_rate", 0)) / 100.0,
            "availableEmployees": int(catalog["user"].nunique()) if processed_ready else 0,
            "processedUserDays": int(len(catalog)),
            "dateCoverage": {"start": str(catalog["date"].min()), "end": str(catalog["date"].max())} if processed_ready else {"start": "unavailable", "end": "unavailable"},
            "benchmark": metrics.get("metrics", {}).get("qsvc", {}),
            "runtimeBoundary": "CERT user-day inputs only; event-level SentinelAI quantum inputs are incompatible.",
            "legacyDemo": "Retained temporarily in SQLite and Attack Lab; it is not the primary research dataset.",
        }

    def investigate(self, user: str, date: str, split: str = "test") -> dict[str, Any]:
        row = self._find_row(user, date, split)
        prediction = self._predict(row)
        vqc = self._predict_vqc(row)
        classical = self._classical_evidence(row, prediction)
        policy = self._assessment_policy()
        verdict = self._apply_policy(policy["selectedPolicy"], prediction["prediction"], vqc["prediction"])
        agreement = prediction["prediction"] == vqc["prediction"]
        signals = [
            {"feature": name, "value": float(row[name]), "evidenceType": "recorded aggregate"}
            for name in BEHAVIOURAL_SIGNALS if float(row.get(name, 0)) > 0
        ]
        scenario = int(row["scenario"])
        return {
            "identity": self._identity(str(row["user"])),
            "record": {"user": str(row["user"]), "date": str(row["date"]), "split": split,
                       "label": int(row["label"]), "scenario": scenario,
                       "features": {name: float(row[name]) for name in PCA_FEATURES}},
            "behaviouralEvidence": signals,
            "classicalEvidence": classical,
            "classification": prediction,
            "models": {"qsvc": prediction, "vqc": vqc, "rbfSvm": classical["rbfSvm"]},
            "assessment": {
                "verdict": "REQUIRES_REVIEW" if verdict else "NO_ADVISORY_ALERT",
                "prediction": verdict, "policy": policy["selectedPolicy"],
                "reason": self._verdict_reason(policy["selectedPolicy"], prediction["prediction"], vqc["prediction"]),
                "quantumAgreement": agreement,
                "agreementLabel": "AGREE" if agreement else "DISAGREE",
                "limitations": "Independent uncalibrated model scores are not averaged. Agreement is not proof of correctness.",
            },
            "alert": {
                "raised": bool(verdict),
                "advisory": True,
                "title": "CERT user-day requires review" if verdict else "No advisory alert",
                "groundTruthUsedForInference": False,
                "groundTruthVisibleForResearchEvaluation": True,
            },
            "threatContext": {
                "recorded": "Prepared CERT employee/day activity aggregates and research label.",
                "inferred": "Frozen QSVC, VQC and RBF-SVM outputs; no event order or access relationship is inferred.",
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

    def list_users(self, q: str = "", page: int = 1, page_size: int = 50) -> dict[str, Any]:
        frame = self._catalog()
        grouped = frame.groupby("user", sort=True).agg(
            user_days=("date", "size"), first_date=("date", "min"), last_date=("date", "max"),
            labelled_malicious_days=("label", "sum"),
            login_after_hours=("logon_after_hours_count", "sum"), usb_connections=("usb_connect_count", "sum"),
            files_copied=("file_copy_count", "sum"), emails_sent=("email_sent_count", "sum"),
        ).reset_index()
        grouped["display_label"] = grouped["user"].astype(str).map(lambda value: self._identity(value)["displayLabel"])
        if q:
            grouped = grouped[grouped["user"].astype(str).str.contains(q, case=False, regex=False) |
                              grouped["display_label"].str.contains(q, case=False, regex=False)]
        total = len(grouped); start = (page - 1) * page_size
        items = [{"user": str(row.user), "identity": self._identity(str(row.user)), "userDays": int(row.user_days), "firstDate": str(row.first_date),
                  "lastDate": str(row.last_date), "labelledMaliciousDays": int(row.labelled_malicious_days),
                  "activityTotals": {"afterHoursLogons": int(row.login_after_hours), "usbConnections": int(row.usb_connections),
                                     "filesCopied": int(row.files_copied), "emailsSent": int(row.emails_sent)}}
                 for row in grouped.iloc[start:start + page_size].itertuples(index=False)]
        return {"items": items, "page": self._page(page, page_size, total),
                "source": "CERT r4.2 synthetic research dataset", "identityMetadataAvailable": False}

    def list_user_days(self, user: str, start_date: str | None = None, end_date: str | None = None,
                       page: int = 1, page_size: int = 50) -> dict[str, Any]:
        frame = self._catalog(); rows = frame[frame["user"].astype(str) == user]
        if start_date: rows = rows[rows["date"].astype(str) >= start_date]
        if end_date: rows = rows[rows["date"].astype(str) <= end_date]
        rows = rows.sort_values("date", ascending=False); total = len(rows); offset = (page - 1) * page_size
        items = []
        for row in rows.iloc[offset:offset + page_size].itertuples(index=False):
            items.append({"user": str(row.user), "identity": self._identity(str(row.user)), "date": str(row.date), "split": str(row.split),
                          "label": int(row.label), "scenario": int(row.scenario),
                          "activity": {"logons": int(row.logon_count), "afterHoursLogons": int(row.logon_after_hours_count),
                                       "usbConnections": int(row.usb_connect_count), "filesCopied": int(row.file_copy_count),
                                       "emailsSent": int(row.email_sent_count), "externalEmails": int(row.email_external_recipients)}})
        return {"items": items, "page": self._page(page, page_size, total), "source": "recorded CERT user-day aggregates"}

    def list_findings(self, q: str = "", prediction: int | None = 1, page: int = 1, page_size: int = 50) -> dict[str, Any]:
        cohort = pd.read_csv(self.data_dir / "quantum_benchmark" / "qsvc" / "test.csv")
        predictions = pd.read_csv(self.results_dir / "predictions.csv")
        vqc_predictions = pd.read_csv(self.vqc_results_dir / "predictions.csv")
        joined = pd.concat([cohort.reset_index(drop=True), predictions.reset_index(drop=True),
                            vqc_predictions[["vqc_score", "vqc_prediction"]].reset_index(drop=True)], axis=1)
        policy = self._assessment_policy()
        joined["assessment_prediction"] = [self._apply_policy(policy["selectedPolicy"], int(q), int(v))
                                             for q, v in zip(joined["qsvc_prediction"], joined["vqc_prediction"])]
        if q:
            joined = joined[joined["user"].astype(str).str.contains(q, case=False, regex=False) |
                            joined["date"].astype(str).str.contains(q, case=False, regex=False)]
        if prediction is not None: joined = joined[joined["assessment_prediction"] == prediction]
        total = len(joined); offset = (page - 1) * page_size; items = []
        for row in joined.iloc[offset:offset + page_size].itertuples(index=False):
            signals = [name for name in BEHAVIOURAL_SIGNALS if float(getattr(row, name)) > 0]
            items.append({"findingId": f"CERT-ASSESS-{row.user}-{row.date}", "user": str(row.user),
                          "identity": self._identity(str(row.user)), "date": str(row.date),
                          "source": "CERT r4.2 balanced benchmark", "model": "Quantum Threat Assessment",
                          "prediction": int(row.assessment_prediction), "decisionScore": float(row.qsvc_decision_score),
                          "decisionThreshold": -0.6163942499022663, "scoreIsProbability": False,
                          "qsvcPrediction": int(row.qsvc_prediction), "vqcPrediction": int(row.vqc_prediction),
                          "quantumAgreement": int(row.qsvc_prediction) == int(row.vqc_prediction),
                          "policy": policy["selectedPolicy"], "recordedLabel": int(row.label), "observedSignals": signals})
        return {"items": items, "page": self._page(page, page_size, total), "scoringCoverage": 100,
                "coverageBasis": "Persisted balanced test benchmark only; not all CERT user-days.", "advisory": True}

    def benchmark_results(self) -> dict[str, Any]:
        qsvc = self._json(self.results_dir / "metrics.json")
        vqc_dir = self.root / "experiments" / "cert_vqc" / "results"
        vqc = self._json(vqc_dir / "metrics.json")
        vqc_config = self._json(vqc_dir / "config.json")
        qsvc_config = self._json(self.results_dir / "config.json")
        return {"dataset": "CERT r4.2", "cohort": {"train": 250, "validation": 100, "test": 100,
                "balanced": True, "naturalPrevalenceValidated": False},
                "models": vqc.get("metrics", qsvc.get("metrics", {})),
                "fusionPolicy": self._assessment_policy(),
                "circuits": {"qsvc": qsvc_config.get("quantum", {}), "vqc": vqc_config.get("vqc", {})},
                "limitations": vqc.get("limitations", qsvc.get("limitations", [])),
                "claim": "No established quantum advantage; exact noiseless simulation only."}

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

    def _predict_vqc(self, row: pd.Series) -> dict[str, Any]:
        if not self.vqc_artifact_path.exists():
            return {"model": "PennyLane VQC", "available": False, "reason": "Saved checkpoint is missing"}
        artifact = self._vqc_artifact(str(self.vqc_artifact_path))
        values = row.loc[list(PCA_FEATURES)].to_numpy(dtype=float)
        span = np.where(artifact["scaler_max"] - artifact["scaler_min"] == 0, 1.0,
                        artifact["scaler_max"] - artifact["scaler_min"])
        scaled = np.clip((values - artifact["scaler_min"]) / span, 0.0, 1.0) * (2 * np.pi) - np.pi
        score = float(np.mean(self._vqc_circuit()(scaled, artifact["weights"])))
        threshold = float(artifact["threshold"])
        return {"model": "PennyLane VQC", "method": "Trainable quantum circuit", "available": True,
                "prediction": int(score >= threshold), "decisionScore": score,
                "decisionThreshold": threshold, "scoreIsProbability": False, "advisory": True,
                "circuit": {"qubits": 4, "layers": 2, "measurement": "mean Pauli-Z expectation"}}

    @lru_cache(maxsize=1)
    def _assessment_policy(self) -> dict[str, Any]:
        frame = pd.read_csv(self.data_dir / "quantum_benchmark" / "qsvc" / "val.csv")
        qsvc_artifact = self._artifact(str(self.artifact_path))
        values = frame.loc[:, list(PCA_FEATURES)].to_numpy(float)
        scaled = qsvc_artifact["input_scaler"].transform(values)
        states = np.asarray([self._state(row) for row in scaled])
        kernel = np.abs(states @ qsvc_artifact["train_states"].conj().T) ** 2
        qs = qsvc_artifact["model"].decision_function(kernel) >= float(qsvc_artifact["threshold"])
        vqc = np.asarray([self._predict_vqc(row)["prediction"] for _, row in frame.iterrows()], dtype=bool)
        labels = frame["label"].to_numpy(bool)
        candidates = {"QSVC_LEAD": qs, "VQC_ONLY": vqc, "AND_FUSION": qs & vqc, "OR_FUSION": qs | vqc}
        evidence = {}
        for name, values_ in candidates.items():
            fp = int(np.sum(values_ & ~labels)); fn = int(np.sum(~values_ & labels))
            evidence[name] = {"falsePositives": fp, "falseNegatives": fn, "securityCost": 5 * fn + fp}
        selected = min(candidates, key=lambda name: (evidence[name]["securityCost"], name != "QSVC_LEAD"))
        return {"selectedPolicy": selected, "objective": "Minimize 5 × missed threats + false alerts on validation only",
                "validationRows": len(frame), "evidence": evidence, "testLabelsUsedForSelection": False}

    @staticmethod
    def _apply_policy(policy: str, qsvc: int, vqc: int) -> int:
        return int({"QSVC_LEAD": bool(qsvc), "VQC_ONLY": bool(vqc), "AND_FUSION": bool(qsvc and vqc),
                    "OR_FUSION": bool(qsvc or vqc)}[policy])

    @staticmethod
    def _verdict_reason(policy: str, qsvc: int, vqc: int) -> str:
        if policy == "OR_FUSION": return "Review is advised when either independent quantum detector alerts."
        if policy == "AND_FUSION": return "Review is advised only when both independent quantum detectors alert."
        if policy == "VQC_ONLY": return "The validation-selected policy uses the VQC verdict; QSVC remains visible as independent evidence."
        return "QSVC is the validation-selected lead verdict; VQC remains visible as independent evidence."

    @lru_cache(maxsize=2048)
    def _identity(self, user: str) -> dict[str, str]:
        users = sorted(self._catalog()["user"].astype(str).unique())
        ordinal = users.index(user) + 1
        return {"displayLabel": f"Identity {ordinal:04d}", "sourceId": user,
                "monogram": f"I{ordinal:04d}", "source": "Deterministic UI label; not source-derived identity metadata"}

    @staticmethod
    @lru_cache(maxsize=1)
    def _vqc_artifact(path: str) -> dict[str, np.ndarray]:
        with np.load(path) as checkpoint:
            return {key: np.asarray(checkpoint[key]).copy() for key in checkpoint.files}

    @staticmethod
    @lru_cache(maxsize=1)
    def _vqc_circuit():
        device = qml.device("default.qubit", wires=4, shots=None)
        @qml.qnode(device, interface=None, diff_method=None)
        def circuit(features, weights):
            qml.AngleEmbedding(features, wires=range(4), rotation="Y")
            qml.StronglyEntanglingLayers(weights, wires=range(4), ranges=[1, 1])
            return tuple(qml.expval(qml.PauliZ(wire)) for wire in range(4))
        return circuit

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

    @lru_cache(maxsize=1)
    def _catalog(self) -> pd.DataFrame:
        columns = ["user", "date", "label", "scenario", "logon_count", "logon_after_hours_count",
                   "usb_connect_count", "file_copy_count", "email_sent_count", "email_external_recipients"]
        frames = []
        for split, name in (("train", "train.csv"), ("validation", "validation.csv"), ("test", "test.csv")):
            frame = pd.read_csv(self.data_dir / name, usecols=columns)
            frame["split"] = split; frames.append(frame)
        return pd.concat(frames, ignore_index=True)

    @staticmethod
    def _page(page: int, page_size: int, total: int) -> dict[str, int]:
        return {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)}

    @staticmethod
    @lru_cache(maxsize=1)
    def _artifact(path: str) -> dict[str, Any]:
        with Path(path).open("rb") as handle:
            return pickle.load(handle)

    @staticmethod
    def _json(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
