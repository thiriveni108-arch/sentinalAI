"""Read-only Phase 6 candidate-action consequence scoring."""

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
from .downstream import MODEL_VERSION
from .dynamic_models import DefenderAction, DefenderObservation
from .world_dataset import build_features
from .world_model import WorldModelService, _positive_probability


@dataclass(frozen=True)
class ConsequenceScore:
    available: bool
    applicable: bool
    model_version: str
    consequences: dict[str, object]
    uncertainty: dict[str, float | None]
    validation_status: dict[str, str]
    provenance: dict[str, str]
    warnings: tuple[str, ...]
    reason: str | None = None


class DownstreamConsequenceService:
    """Scores proposed actions without mutating a simulator or executing responses."""

    def __init__(self, root: Path | None = None) -> None:
        root = Path(root or config.PROJECT_ROOT)
        self.artifact_path = root / "artifacts/models/shield_downstream_consequence_v1.pkl"
        self.metadata_path = root / "artifacts/reports/shield_downstream_consequence_v1.json"
        self._artifact = None
        self._metadata = None

    def predict(self, observation: DefenderObservation, belief: BeliefState | Mapping[str, float],
                action: DefenderAction) -> ConsequenceScore:
        if not self.artifact_path.exists() or not self.metadata_path.exists():
            return ConsequenceScore(False, False, MODEL_VERSION, {}, {}, {}, {}, (), "downstream artifact unavailable")
        artifact, metadata = self._load()
        if artifact.get("model_version") != MODEL_VERSION or metadata.get("model_version") != MODEL_VERSION:
            return ConsequenceScore(True, False, MODEL_VERSION, {}, {}, {}, {}, (), "downstream model version mismatch")
        try:
            belief_state = WorldModelService._validate_belief(observation, belief)
            values = build_features(observation, belief_state, action)
            columns = artifact["feature_columns"]
            vector = np.asarray([[values[column] for column in columns]], dtype=float)
        except (KeyError, TypeError, ValueError) as error:
            return ConsequenceScore(True, False, MODEL_VERSION, {}, {}, {}, {}, (), f"invalid inference input: {error}")
        low, high = np.asarray(artifact["feature_min"]), np.asarray(artifact["feature_max"])
        invalid = [column for column, value, minimum, maximum in zip(columns, vector[0], low, high)
                   if value < minimum or value > maximum]
        if invalid:
            return ConsequenceScore(True, False, MODEL_VERSION, {}, {}, {}, {},
                                    ("outside frozen training feature ranges",),
                                    "out-of-distribution input: " + ", ".join(invalid))
        predictions, uncertainty = {}, {}
        model_input = pd.DataFrame(vector, columns=columns)
        for target, model in artifact["regressors"].items():
            per_tree = np.asarray([tree.predict(vector)[0] for tree in model.estimators_], dtype=float)
            minimum, maximum = artifact["target_bounds"][target]
            prediction = float(model.predict(model_input)[0])
            predictions[target] = float(np.clip(prediction, minimum, maximum))
            uncertainty[target] = float(per_tree.std())
        for target, model in artifact["classifiers"].items():
            probability = float(_positive_probability(model, model_input)[0])
            tree_probability = []
            for tree in model.estimators_:
                classes = list(tree.classes_); result = tree.predict_proba(vector)[0]
                tree_probability.append(float(result[classes.index(1)]) if 1 in classes else 0.0)
            predictions[target] = probability
            uncertainty[target] = float(np.std(tree_probability))
        unresolved = predictions["target_unresolved_at_horizon"]
        consequences = {
            "expected_cumulative_security_exposure": predictions["target_cumulative_exposure"],
            "expected_cumulative_operational_disruption": predictions["target_cumulative_disruption"],
            "attacker_adaptation_probability": predictions["target_attacker_adapted"],
            "unresolved_at_horizon_probability": unresolved,
            "expected_time_to_containment_censored": 1.0 + 4.0 * unresolved,
            "severe_outcome_risk": None,
            "expected_recovery_burden": None,
        }
        output_uncertainty = {
            "cumulative_security_exposure": uncertainty["target_cumulative_exposure"],
            "cumulative_operational_disruption": uncertainty["target_cumulative_disruption"],
            "attacker_adaptation": uncertainty["target_attacker_adapted"],
            "unresolved_at_horizon": uncertainty["target_unresolved_at_horizon"],
            "severe_outcome_risk": None, "recovery_burden": None,
        }
        return ConsequenceScore(True, True, MODEL_VERSION, consequences, output_uncertainty,
                                metadata["validation_status"],
                                {"dataset_version": artifact["dataset_version"],
                                 "dataset_sha256": artifact["dataset_sha256"],
                                 "model_family": "validation-selected classical tree ensembles",
                                 "vqc_status": "not trained: target-quality gate failed"},
                                ("Synthetic four-step NO_OP-continuation rollouts only.",
                                 "Severe risk and recovery burden are unavailable, not zero-risk estimates.",
                                 "Tree dispersion is heuristic uncertainty, not a confidence interval.",
                                 "Read-only advisory score; no response action was executed."))

    def _load(self):
        if self._artifact is None:
            with self.artifact_path.open("rb") as handle: self._artifact = pickle.load(handle)
            self._metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        return self._artifact, self._metadata
