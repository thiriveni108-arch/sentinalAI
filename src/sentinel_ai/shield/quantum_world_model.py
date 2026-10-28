"""Four-qubit hybrid consequence model and read-only inference service.

The module deliberately has no execution path into SHIELD's response services.
"""

from __future__ import annotations

import json
import math
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np
import pandas as pd

from sentinel_ai import config
from .beliefs import BeliefState
from .dynamic_models import DefenderAction, DefenderObservation
from .world_dataset import build_features
from .world_model import WorldModelService


MODEL_VERSION = "shield-world-hybrid-q4-v1.0.0"
CLASS_TARGETS = ("target_contained", "target_route_switched", "target_next_malicious_observation")
REG_TARGETS = ("target_residual_exposure", "target_workflow_disruption")


def quantum_features(values: np.ndarray, weights: np.ndarray) -> np.ndarray:
    """Evaluate the reproducible four-qubit variational feature map."""
    import pennylane as qml

    values = np.asarray(values, dtype=float)
    device = qml.device("default.qubit", wires=4, shots=None)

    @qml.qnode(device, interface=None)
    def circuit(row, parameters):
        qml.AngleEmbedding(row, wires=range(4), rotation="Y")
        qml.StronglyEntanglingLayers(parameters, wires=range(4))
        return tuple(qml.expval(qml.PauliZ(wire)) for wire in range(4))

    return np.asarray([circuit(row, weights) for row in np.atleast_2d(values)], dtype=float)


def hybrid_matrix(raw: np.ndarray, scaler, reducer, weights: np.ndarray) -> np.ndarray:
    raw = np.asarray(raw, dtype=float)
    aligned = pd.DataFrame(raw, columns=scaler.feature_names_in_) if hasattr(scaler, "feature_names_in_") else raw
    reduced = reducer.transform(scaler.transform(aligned))
    angles = np.clip(reduced, -3.0, 3.0) * (np.pi / 3.0)
    return np.column_stack((reduced, quantum_features(angles, weights)))


@dataclass(frozen=True)
class QuantumWorldModelPrediction:
    available: bool
    applicable: bool
    model_version: str
    predictions: dict[str, object]
    uncertainty: dict[str, float]
    warnings: tuple[str, ...]
    reason: str | None = None


class QuantumWorldModelService:
    """Versioned advisory-only inference matching the Phase 4 input contract."""

    def __init__(self, root: Path | None = None) -> None:
        root = Path(root or config.PROJECT_ROOT)
        self.artifact_path = root / "artifacts/models/shield_quantum_world_model_q4_v1.pkl"
        self.metadata_path = root / "artifacts/reports/shield_quantum_world_model_q4_v1.json"
        self._artifact = None
        self._metadata = None

    def predict(self, observation: DefenderObservation, belief: BeliefState | Mapping[str, float],
                action: DefenderAction) -> QuantumWorldModelPrediction:
        if not self.artifact_path.exists() or not self.metadata_path.exists():
            return QuantumWorldModelPrediction(False, False, MODEL_VERSION, {}, {}, (), "quantum artifact unavailable")
        artifact, metadata = self._load()
        if metadata.get("model_version") != MODEL_VERSION or artifact.get("model_version") != MODEL_VERSION:
            return QuantumWorldModelPrediction(True, False, MODEL_VERSION, {}, {}, (), "quantum model version mismatch")
        try:
            belief_state = WorldModelService._validate_belief(observation, belief)
            feature_map = build_features(observation, belief_state, action)
            columns = metadata["feature_columns"]
            raw = np.asarray([[feature_map[column] for column in columns]], dtype=float)
        except (KeyError, TypeError, ValueError) as error:
            return QuantumWorldModelPrediction(True, False, MODEL_VERSION, {}, {}, (), f"invalid inference input: {error}")
        low, high = np.asarray(metadata["feature_min"]), np.asarray(metadata["feature_max"])
        invalid = [column for column, value, lo, hi in zip(columns, raw[0], low, high) if value < lo or value > hi]
        if invalid:
            return QuantumWorldModelPrediction(True, False, MODEL_VERSION, {}, {},
                                               ("outside frozen training feature ranges",),
                                               "out-of-distribution input: " + ", ".join(invalid))
        member_predictions: dict[str, list[float]] = {target: [] for target in (*CLASS_TARGETS, *REG_TARGETS)}
        for member in artifact["members"]:
            matrix = hybrid_matrix(raw, artifact["scaler"], artifact["reducer"], member["weights"])
            for target in CLASS_TARGETS:
                head = member["classifiers"][target]
                classes = list(head.classes_)
                probability = head.predict_proba(matrix)[0]
                member_predictions[target].append(float(probability[classes.index(1)]) if 1 in classes else 0.0)
            for target in REG_TARGETS:
                member_predictions[target].append(float(np.clip(member["regressors"][target].predict(matrix)[0], 0, 1)))
        predictions, uncertainty = {}, {}
        for target in CLASS_TARGETS:
            mean = float(np.mean(member_predictions[target]))
            predictions[target] = {"false": round(1 - mean, 12), "true": round(mean, 12)}
            uncertainty[target] = round(float(np.std(member_predictions[target])), 12)
        for target in REG_TARGETS:
            predictions[target] = round(float(np.mean(member_predictions[target])), 12)
            uncertainty[target] = round(float(np.std(member_predictions[target])), 12)
        return QuantumWorldModelPrediction(True, True, MODEL_VERSION, predictions, uncertainty, (
            "Synthetic simulator predictor; no operational validity or quantum advantage is claimed.",
            "Uncertainty is ensemble dispersion, not a confidence interval or simulator stochasticity.",
            "Bayesian belief uncertainty remains a separate model input.",
            "Read-only advisory prediction; no response action was executed.",
        ))

    def _load(self):
        if self._artifact is None:
            with self.artifact_path.open("rb") as handle:
                self._artifact = pickle.load(handle)
            self._metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        return self._artifact, self._metadata
