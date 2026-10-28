"""Train and evaluate classical probabilistic SHIELD world-model heads."""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.dummy import DummyClassifier, DummyRegressor
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.metrics import (brier_score_loss, f1_score, mean_absolute_error, mean_squared_error,
                             precision_score, r2_score, recall_score, roc_auc_score)
from sklearn.tree import DecisionTreeClassifier, DecisionTreeRegressor

from sentinel_ai.shield.world_dataset import TARGET_COLUMNS, feature_columns, sha256
from sentinel_ai.shield.world_model import MODEL_VERSION, _positive_probability


SEED = 42073
CLASS_TARGETS = ["target_contained", "target_route_switched", "target_next_malicious_observation"]
REG_TARGETS = ["target_residual_exposure", "target_workflow_disruption"]


def ece(y: np.ndarray, probability: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for index in range(bins):
        mask = (probability >= edges[index]) & (probability < edges[index + 1] if index < bins - 1 else probability <= 1)
        if mask.any():
            total += mask.mean() * abs(float(y[mask].mean()) - float(probability[mask].mean()))
    return float(total)


def classification_metrics(y, probability) -> dict[str, float | None]:
    predicted = probability >= 0.5
    return {
        "precision": precision_score(y, predicted, zero_division=0),
        "recall": recall_score(y, predicted, zero_division=0),
        "f1": f1_score(y, predicted, zero_division=0),
        "brier": brier_score_loss(y, probability),
        "ece_10_bin": ece(np.asarray(y), probability),
        "roc_auc": roc_auc_score(y, probability) if len(np.unique(y)) > 1 else None,
    }


def regression_metrics(y, prediction) -> dict[str, float]:
    return {"mae": mean_absolute_error(y, prediction),
            "rmse": mean_squared_error(y, prediction) ** .5,
            "r2": r2_score(y, prediction)}


def fit_variant(train: pd.DataFrame, columns: list[str]):
    x = train[columns].to_numpy(float)
    classifiers, regressors = {}, {}
    for target in CLASS_TARGETS:
        classifiers[target] = RandomForestClassifier(
            n_estimators=160, min_samples_leaf=3, class_weight="balanced", n_jobs=-1, random_state=SEED
        ).fit(x, train[target].to_numpy(int))
    for target in REG_TARGETS:
        regressors[target] = RandomForestRegressor(
            n_estimators=160, min_samples_leaf=3, n_jobs=-1, random_state=SEED
        ).fit(x, train[target].to_numpy(float))
    return {"classifiers": classifiers, "regressors": regressors}


def evaluate(models, frame: pd.DataFrame, columns: list[str]) -> dict[str, object]:
    x = frame[columns].to_numpy(float)
    result = {"rows": len(frame), "classification": {}, "regression": {}, "uncertainty": {}}
    for target, model in models["classifiers"].items():
        probability = _positive_probability(model, x)
        result["classification"][target] = classification_metrics(frame[target].to_numpy(int), probability)
        entropy = -(probability * np.log(np.clip(probability, 1e-12, 1)) +
                    (1-probability) * np.log(np.clip(1-probability, 1e-12, 1)))
        errors = ((probability >= .5) != frame[target].to_numpy(int)).astype(float)
        result["uncertainty"][target] = {"error_entropy_spearman": float(spearmanr(errors, entropy).statistic or 0.0)}
    for target, model in models["regressors"].items():
        per_tree = np.asarray([tree.predict(x) for tree in model.estimators_])
        prediction, std = per_tree.mean(axis=0), per_tree.std(axis=0)
        result["regression"][target] = regression_metrics(frame[target].to_numpy(float), prediction)
        absolute_error = np.abs(frame[target].to_numpy(float) - prediction)
        coefficient = spearmanr(absolute_error, std).statistic
        result["uncertainty"][target] = {"error_std_spearman": float(0.0 if np.isnan(coefficient) else coefficient),
                                          "mean_tree_std": float(std.mean())}
    return result


def baselines(train: pd.DataFrame, test: pd.DataFrame, columns: list[str]) -> dict[str, object]:
    x_train, x_test = train[columns].to_numpy(float), test[columns].to_numpy(float)
    output = {"classification": {}, "regression": {}}
    for target in CLASS_TARGETS:
        model = DummyClassifier(strategy="prior").fit(x_train, train[target])
        output["classification"][target] = classification_metrics(test[target].to_numpy(int), _positive_probability(model, x_test))
    for target in REG_TARGETS:
        model = DummyRegressor(strategy="mean").fit(x_train, train[target])
        output["regression"][target] = regression_metrics(test[target], model.predict(x_test))
    return output


def simple_baselines(train: pd.DataFrame, test: pd.DataFrame, columns: list[str]) -> dict[str, object]:
    x_train, x_test = train[columns].to_numpy(float), test[columns].to_numpy(float)
    output = {"logistic_ridge": {"classification": {}, "regression": {}},
              "shallow_deterministic_tree": {"classification": {}, "regression": {}}}
    for target in CLASS_TARGETS:
        logistic = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED).fit(x_train, train[target])
        output["logistic_ridge"]["classification"][target] = classification_metrics(
            test[target].to_numpy(int), logistic.predict_proba(x_test)[:, list(logistic.classes_).index(1)])
        tree = DecisionTreeClassifier(max_depth=4, min_samples_leaf=10, class_weight="balanced", random_state=SEED).fit(x_train, train[target])
        output["shallow_deterministic_tree"]["classification"][target] = classification_metrics(
            test[target].to_numpy(int), _positive_probability(tree, x_test))
    for target in REG_TARGETS:
        ridge = Ridge(alpha=1.0).fit(x_train, train[target])
        output["logistic_ridge"]["regression"][target] = regression_metrics(test[target], ridge.predict(x_test))
        tree = DecisionTreeRegressor(max_depth=4, min_samples_leaf=10, random_state=SEED).fit(x_train, train[target])
        output["shallow_deterministic_tree"]["regression"][target] = regression_metrics(test[target], tree.predict(x_test))
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("data/processed/shield_world_v2/model_table.parquet"))
    parser.add_argument("--artifact", type=Path, default=Path("artifacts/models/shield_world_model_v1.pkl"))
    parser.add_argument("--report", type=Path, default=Path("artifacts/reports/shield_world_model_v1.json"))
    args = parser.parse_args()
    frame = pd.read_parquet(args.data)
    train, validation, test = (frame[frame.split == item].copy() for item in ("train", "validation", "test"))
    columns, no_belief = feature_columns(True), feature_columns(False)
    started = time.perf_counter(); models = fit_variant(train, columns); training_seconds = time.perf_counter() - started
    no_belief_models = fit_variant(train, no_belief)
    inference_started = time.perf_counter(); test_metrics = evaluate(models, test, columns); inference_seconds = time.perf_counter() - inference_started
    no_belief_metrics = evaluate(no_belief_models, test, no_belief)
    validation_metrics = evaluate(models, validation, columns)
    baseline_metrics = baselines(train, test, columns)
    simple_baseline_metrics = simple_baselines(train, test, columns)
    family_metrics = {family: evaluate(models, group, columns) for family, group in test.groupby("scenario_family_audit")}
    # Explicit unseen-strategy experiment: sensitive exfiltration is absent from this auxiliary fit.
    ood_train = frame[(frame.split == "train") & (frame.scenario_family_audit != "sensitive-data-exfiltration")]
    ood_test = test[test.scenario_family_audit == "sensitive-data-exfiltration"]
    ood_models = fit_variant(ood_train, columns)
    ood_metrics = evaluate(ood_models, ood_test, columns)
    low, high = train[columns].min().to_numpy(float), train[columns].max().to_numpy(float)
    artifact = {**models, "model_version": MODEL_VERSION, "feature_columns": columns}
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    with args.artifact.open("wb") as handle: pickle.dump(artifact, handle)
    report = {
        "model_version": MODEL_VERSION, "model_family": "RandomForest probabilistic multi-head ensemble",
        "catboost_not_used": "CatBoost was not installed; RandomForest avoids a new dependency and exposes per-tree uncertainty.",
        "dataset_sha256": sha256(args.data), "feature_columns": columns, "feature_min": low.tolist(), "feature_max": high.tolist(),
        "targets": TARGET_COLUMNS, "splits": {item: int((frame.split == item).sum()) for item in ("train", "validation", "test")},
        "with_beliefs": {"validation": validation_metrics, "test": test_metrics},
        "without_beliefs_test": no_belief_metrics, "dummy_baselines_test": baseline_metrics,
        "simple_baselines_test": simple_baseline_metrics,
        "unseen_strategy": {"held_out_strategy": "sensitive-data-exfiltration", "metrics": ood_metrics},
        "test_by_strategy": family_metrics,
        "latency": {"training_seconds_primary": training_seconds, "test_inference_seconds": inference_seconds,
                    "test_rows_per_second": len(test) / inference_seconds},
        "limitations": ["Synthetic simulator behavior only; no real-world generalization or calibration is claimed.",
                        "Independent heads may retain residual cross-target inconsistency; service returns probabilities and bounded continuous predictions.",
                        "Tree dispersion is an epistemic heuristic, not a calibrated prediction interval."],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
