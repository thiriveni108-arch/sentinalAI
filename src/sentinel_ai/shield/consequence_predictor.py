"""Validated, defender-observable consequence models for SHIELD Phase 7.

The model deliberately excludes every ``*_audit`` column, identifiers, topology
labels, simulator state, and future transition fields.  It is a research model
trained only from the frozen Phase 6.5 split contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (brier_score_loss, mean_absolute_error,
                             mean_squared_error, roc_auc_score)
from scipy.stats import spearmanr

from .topology import TopologyScenario


CONTINUOUS_TARGETS = ("target_cumulative_exposure", "target_cumulative_disruption",
                      "target_recovery_burden", "target_time_to_containment")
BINARY_TARGETS = ("target_severe_outcome", "target_delayed_adaptation", "target_unresolved")
VISIBLE_STATE = ("state_tick", "service_health", "observed_compromise",
                 "observed_malicious_activity", "evidence_count")


def feature_columns(frame: pd.DataFrame) -> tuple[str, ...]:
    encoded = [c for c in frame if c.startswith("candidate__") or c.startswith("policy__")]
    return tuple(c for c in VISIBLE_STATE if c in frame) + tuple(sorted(encoded))


def expected_calibration_error(y: np.ndarray, probability: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    result = 0.0
    for low, high in zip(edges[:-1], edges[1:]):
        mask = (probability >= low) & (probability < high if high < 1 else probability <= high)
        if mask.any():
            result += mask.mean() * abs(float(y[mask].mean()) - float(probability[mask].mean()))
    return float(result)


@dataclass
class ConsequencePrediction:
    means: dict[str, float]
    uncertainty: dict[str, float]


class ConsequencePredictor:
    """Random-forest outcomes with validation-only Platt calibration."""

    def __init__(self, seed: int = 7301, trees: int = 160) -> None:
        self.seed, self.trees = seed, trees
        self.features: tuple[str, ...] = ()
        self.regressors: dict[str, RandomForestRegressor] = {}
        self.classifiers: dict[str, RandomForestClassifier] = {}
        self.calibrators: dict[str, LogisticRegression | None] = {}

    def fit(self, frame: pd.DataFrame) -> "ConsequencePredictor":
        self.features = feature_columns(frame)
        train, validation = frame[frame.split == "train"], frame[frame.split == "validation"]
        if train.empty or validation.empty:
            raise ValueError("Frozen train and validation partitions are required")
        x_train, x_validation = train.loc[:, self.features], validation.loc[:, self.features]
        for target in CONTINUOUS_TARGETS:
            model = RandomForestRegressor(n_estimators=self.trees, min_samples_leaf=4,
                                          random_state=self.seed, n_jobs=1)
            model.fit(x_train, train[target]); self.regressors[target] = model
        for target in BINARY_TARGETS:
            model = RandomForestClassifier(n_estimators=self.trees, min_samples_leaf=4,
                                           random_state=self.seed, n_jobs=1)
            model.fit(x_train, train[target]); self.classifiers[target] = model
            raw = model.predict_proba(x_validation)[:, 1]
            if validation[target].nunique() == 2:
                calibrator = LogisticRegression(random_state=self.seed)
                calibrator.fit(raw.reshape(-1, 1), validation[target])
                self.calibrators[target] = calibrator
            else:
                self.calibrators[target] = None
        return self

    def _probability(self, target: str, x: pd.DataFrame) -> np.ndarray:
        raw = self.classifiers[target].predict_proba(x)[:, 1]
        calibration = self.calibrators[target]
        return raw if calibration is None else calibration.predict_proba(raw.reshape(-1, 1))[:, 1]

    def predict_frame(self, frame: pd.DataFrame) -> dict[str, np.ndarray]:
        x = frame.reindex(columns=self.features, fill_value=0)
        result = {target: model.predict(x) for target, model in self.regressors.items()}
        result.update({target: self._probability(target, x) for target in BINARY_TARGETS})
        return result

    def predict(self, visible: Mapping[str, float], candidate: str,
                policy: str) -> ConsequencePrediction:
        row = {name: float(visible.get(name, 0.0)) for name in self.features}
        row[f"candidate__{candidate}"] = 1.0; row[f"policy__{policy}"] = 1.0
        x = pd.DataFrame([row]).reindex(columns=self.features, fill_value=0)
        means, uncertainty = {}, {}
        raw_x = x.to_numpy(dtype=np.float32)
        for target, model in self.regressors.items():
            values = np.array([tree.predict(raw_x, check_input=False)[0] for tree in model.estimators_])
            means[target], uncertainty[target] = float(values.mean()), float(values.std())
        for target in BINARY_TARGETS:
            probability = float(self._probability(target, x)[0])
            means[target] = probability
            uncertainty[target] = float(np.sqrt(probability * (1.0 - probability)))
        return ConsequencePrediction(means, uncertainty)

    def evaluate(self, frame: pd.DataFrame) -> dict:
        report: dict[str, object] = {"features": list(self.features), "splits": {}}
        for split in ("validation", "test"):
            part = frame[frame.split == split]; predicted = self.predict_frame(part)
            metrics: dict[str, dict] = {}
            for target in CONTINUOUS_TARGETS:
                y, p = part[target].to_numpy(), predicted[target]
                metrics[target] = {"mae": float(mean_absolute_error(y, p)),
                                   "rmse": float(mean_squared_error(y, p) ** .5)}
                metrics[target]["ranking_spearman"] = float(spearmanr(y, p).statistic)
            for target in BINARY_TARGETS:
                y, p = part[target].to_numpy(), predicted[target]
                metrics[target] = {"brier": float(brier_score_loss(y, p)),
                                   "ece": expected_calibration_error(y, p),
                                   "auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None}
            report["splits"][split] = metrics
            per_action = {}
            for action, indices in part.groupby("candidate_action").groups.items():
                positions = part.index.get_indexer(indices)
                per_action[action] = {
                    **{target: {"mae": float(mean_absolute_error(part.loc[indices, target], predicted[target][positions]))}
                       for target in CONTINUOUS_TARGETS},
                    **{target: {"brier": float(brier_score_loss(part.loc[indices, target], predicted[target][positions]))}
                       for target in BINARY_TARGETS},
                }
            report["splits"][split]["per_action"] = per_action
        severe = report["splits"]["test"]["target_severe_outcome"]
        report["severe_probability_synthetic_calibration_gate_passed"] = bool(severe["ece"] <= .10 and severe["brier"] <= .20)
        report["severe_probability_operationally_suitable"] = False
        report["operational_rejection_reason"] = "Synthetic, structurally homogeneous initial conditions provide no empirical operational calibration."
        report["calibration_rule"] = "test ECE <= 0.10 and Brier <= 0.20; test is evaluation-only"
        return report


class GraphAwareConsequencePredictor:
    """Explicit structural adjustment around a frozen Phase 7 predictor.

    The base Phase 7 model was not trained on graph scenarios.  This wrapper
    makes known topology effects visible to the existing planner without
    pretending they are empirically calibrated predictions.  Its output must
    therefore remain diagnostic-only until a graph-grouped data set retrains
    and validates the learned predictor.
    """
    diagnostic_only = True

    def __init__(self, base: ConsequencePredictor, topology: TopologyScenario) -> None:
        self.base, self.topology = base, topology
        self.features = base.features

    def predict(self, visible: Mapping[str, float], candidate: str,
                policy: str) -> ConsequencePrediction:
        raw = self.base.predict(visible, candidate, policy)
        coverage, workflow_loss = self.topology.action_consequence_context(candidate)
        means, uncertainty = dict(raw.means), dict(raw.uncertainty)
        # Coverage reduces only structurally addressed routes; it is not an
        # assertion that the hidden attacker currently uses those routes.
        means["target_cumulative_exposure"] *= 1.0 - .35 * coverage
        means["target_unresolved"] *= 1.0 - .25 * coverage
        means["target_severe_outcome"] *= 1.0 - .15 * coverage
        means["target_cumulative_disruption"] += 2.0 * workflow_loss
        means["target_recovery_burden"] += .5 * workflow_loss
        for key in uncertainty:
            uncertainty[key] = min(1.0, uncertainty[key] + .15)
        return ConsequencePrediction(means, uncertainty)


def load_phase65(path: str | Path = "data/processed/shield_multistep_v2/model_table.parquet") -> pd.DataFrame:
    return pd.read_parquet(path)
