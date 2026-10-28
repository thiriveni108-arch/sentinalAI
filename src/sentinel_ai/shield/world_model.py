"""Versioned, read-only inference for the classical SHIELD world model."""

from __future__ import annotations

import json
import math
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np

from sentinel_ai import config
from .beliefs import MODES, AttackerMode, BeliefState, MODEL_VERSION as BELIEF_MODEL_VERSION
from .dynamic_models import DefenderAction, DefenderObservation
from .world_dataset import build_features, feature_columns


MODEL_VERSION = "shield-world-rf-v1.0.0"


@dataclass(frozen=True)
class WorldModelPrediction:
    available: bool
    applicable: bool
    model_version: str
    predictions: dict[str, object]
    uncertainty: dict[str, float]
    warnings: tuple[str, ...]
    reason: str | None = None


class WorldModelService:
    """Loads frozen local artifacts and performs prediction only."""

    def __init__(self, root: Path | None = None) -> None:
        root = Path(root or config.PROJECT_ROOT)
        self.artifact_path = root / "artifacts" / "models" / "shield_world_model_v1.pkl"
        self.metadata_path = root / "artifacts" / "reports" / "shield_world_model_v1.json"
        self._artifact = None
        self._metadata = None

    def predict(self, observation: DefenderObservation, belief: BeliefState | Mapping[str, float],
                action: DefenderAction) -> WorldModelPrediction:
        if not self.artifact_path.exists() or not self.metadata_path.exists():
            return WorldModelPrediction(False, False, MODEL_VERSION, {}, {}, (), "world-model artifact unavailable")
        artifact, metadata = self._load()
        if metadata.get("model_version") != MODEL_VERSION:
            return WorldModelPrediction(True, False, MODEL_VERSION, {}, {}, (), "world-model version mismatch")
        try:
            belief_state = self._validate_belief(observation, belief)
            values = build_features(observation, belief_state, action)
            columns = metadata["feature_columns"]
            vector = np.asarray([[values[item] for item in columns]], dtype=float)
        except (KeyError, TypeError, ValueError) as error:
            return WorldModelPrediction(True, False, MODEL_VERSION, {}, {}, (), f"invalid inference input: {error}")
        low, high = np.asarray(metadata["feature_min"]), np.asarray(metadata["feature_max"])
        violations = [columns[index] for index, value in enumerate(vector[0]) if value < low[index] or value > high[index]]
        if violations:
            return WorldModelPrediction(True, False, MODEL_VERSION, {}, {},
                                        ("outside frozen training feature ranges",),
                                        "out-of-distribution input: " + ", ".join(violations))
        predictions, uncertainty = {}, {}
        for target, model in artifact["classifiers"].items():
            probability = round(float(_positive_probability(model, vector)[0]), 12)
            predictions[target] = {"false": round(1.0 - probability, 12), "true": probability}
            uncertainty[target] = round(_classifier_tree_std(model, vector), 12)
        for target, model in artifact["regressors"].items():
            per_tree = np.asarray([tree.predict(vector)[0] for tree in model.estimators_], dtype=float)
            predictions[target] = round(float(np.clip(per_tree.mean(), 0.0, 1.0)), 12)
            uncertainty[target] = round(float(per_tree.std()), 12)
        warnings = (
            "Synthetic simulator model; predictions are not validated operational facts.",
            "Bayesian inputs are assumption-based and not empirically calibrated.",
            "Read-only advisory prediction; no response action was executed.",
        )
        return WorldModelPrediction(True, True, MODEL_VERSION, predictions, uncertainty, warnings)

    def _load(self):
        if self._artifact is None:
            with self.artifact_path.open("rb") as handle:
                self._artifact = pickle.load(handle)
            self._metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        return self._artifact, self._metadata

    @staticmethod
    def _validate_belief(observation: DefenderObservation,
                         belief: BeliefState | Mapping[str, float]) -> BeliefState:
        if isinstance(belief, BeliefState):
            if belief.episode_id != observation.episode_id or belief.time_step != observation.time_step:
                raise ValueError("belief and observation episode/time must match")
            return belief
        probabilities = {}
        for mode in MODES:
            key = mode.value
            probabilities[mode] = float(belief[key] if key in belief else belief[mode])
        if any(not math.isfinite(value) or value < 0 for value in probabilities.values()):
            raise ValueError("belief probabilities must be finite and non-negative")
        if not math.isclose(sum(probabilities.values()), 1.0, abs_tol=1e-8):
            raise ValueError("belief probabilities must sum to one")
        entropy = -sum(value * math.log(value) for value in probabilities.values() if value) / math.log(len(MODES))
        top = max(MODES, key=probabilities.get)
        return BeliefState(observation.episode_id, observation.time_step, probabilities, entropy, top,
                           BELIEF_MODEL_VERSION)


def _positive_probability(model, values: np.ndarray) -> np.ndarray:
    probabilities = model.predict_proba(values)
    classes = list(model.classes_)
    return probabilities[:, classes.index(1)] if 1 in classes else np.zeros(len(values))


def _classifier_tree_std(model, values: np.ndarray) -> float:
    probabilities = []
    for tree in model.estimators_:
        result = tree.predict_proba(values)[0]
        classes = list(tree.classes_)
        probabilities.append(result[classes.index(1)] if 1 in classes else 0.0)
    return float(np.std(probabilities))
