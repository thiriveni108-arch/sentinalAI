"""Validate Phase 6 targets and train classical downstream consequence heads."""

from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.ensemble import ExtraTreesClassifier, ExtraTreesRegressor, RandomForestClassifier, RandomForestRegressor
from sklearn.metrics import (balanced_accuracy_score, brier_score_loss, f1_score, mean_absolute_error,
                             mean_squared_error, precision_score, recall_score, roc_auc_score)

from scripts.train_shield_world_model import ece
from sentinel_ai.shield.downstream import (CLASS_TARGETS, DATASET_VERSION, MODEL_VERSION,
                                           REG_TARGETS, TARGET_COLUMNS)
from sentinel_ai.shield.world_dataset import feature_columns, sha256
from sentinel_ai.shield.world_model import _positive_probability


VALID_CLASS_TARGETS = ("target_attacker_adapted", "target_unresolved_at_horizon")
VALID_REG_TARGETS = ("target_cumulative_exposure", "target_cumulative_disruption")
SEED = 63001


def classification_metrics(y, probability):
    predicted = np.asarray(probability) >= .5
    return {"precision": float(precision_score(y, predicted, zero_division=0)),
            "recall": float(recall_score(y, predicted, zero_division=0)),
            "f1": float(f1_score(y, predicted, zero_division=0)),
            "balanced_accuracy": float(balanced_accuracy_score(y, predicted)),
            "roc_auc": float(roc_auc_score(y, probability)) if len(np.unique(y)) > 1 else None,
            "brier": float(brier_score_loss(y, probability)), "ece_10_bin": ece(np.asarray(y), np.asarray(probability))}


def regression_metrics(y, prediction):
    coefficient = spearmanr(y, prediction).statistic
    return {"mae": float(mean_absolute_error(y, prediction)), "rmse": float(mean_squared_error(y, prediction) ** .5),
            "spearman": None if np.isnan(coefficient) else float(coefficient)}


def fit(family, train, columns):
    classifiers, regressors = {}, {}
    for target in VALID_CLASS_TARGETS:
        cls = (RandomForestClassifier(n_estimators=240, min_samples_leaf=3, class_weight="balanced", n_jobs=-1, random_state=SEED)
               if family == "random_forest" else
               ExtraTreesClassifier(n_estimators=240, min_samples_leaf=3, class_weight="balanced", n_jobs=-1, random_state=SEED))
        classifiers[target] = cls.fit(train[columns], train[target])
    for target in VALID_REG_TARGETS:
        reg = (RandomForestRegressor(n_estimators=240, min_samples_leaf=3, n_jobs=-1, random_state=SEED)
               if family == "random_forest" else
               ExtraTreesRegressor(n_estimators=240, min_samples_leaf=3, n_jobs=-1, random_state=SEED))
        regressors[target] = reg.fit(train[columns], train[target])
    return {"classifiers": classifiers, "regressors": regressors}


def evaluate(models, frame, columns):
    output = {"rows": len(frame), "classification": {}, "regression": {}}
    for target, model in models["classifiers"].items():
        output["classification"][target] = classification_metrics(frame[target], _positive_probability(model, frame[columns]))
    for target, model in models["regressors"].items():
        output["regression"][target] = regression_metrics(frame[target], model.predict(frame[columns]))
    return output


def target_quality(frame):
    target = {}
    for column in TARGET_COLUMNS:
        values = frame[column]
        target[column] = {"unique": int(values.nunique()), "mean": float(values.mean()), "std": float(values.std()),
                          "min": float(values.min()), "max": float(values.max())}
        if set(values.unique()).issubset({0, 1}):
            target[column]["positive"] = int(values.sum())
            target[column]["positive_fraction"] = float(values.mean())
    action_means = frame.groupby("action_type_audit")[list(TARGET_COLUMNS)].mean().to_dict(orient="index")
    action_support = {action: {"rows": int(len(group)),
                              "adapted_positive": int(group.target_attacker_adapted.sum()),
                              "unresolved_positive": int(group.target_unresolved_at_horizon.sum())}
                      for action, group in frame.groupby("action_type_audit")}
    within_condition = frame.groupby("initial_condition_id")[list(TARGET_COLUMNS)].nunique()
    variation = {column: float((within_condition[column] > 1).mean()) for column in TARGET_COLUMNS}
    downstream_one_step = {
        "cumulative_exposure_vs_one_step_exposure_spearman": float(spearmanr(
            frame.target_cumulative_exposure, frame.one_step_exposure_audit).statistic),
        "cumulative_disruption_vs_one_step_disruption_spearman": float(spearmanr(
            frame.target_cumulative_disruption, frame.one_step_disruption_audit).statistic),
        "unresolved_vs_one_step_containment_spearman": float(spearmanr(
            frame.target_unresolved_at_horizon, frame.one_step_contained_audit).statistic),
        "adaptation_beyond_first_step_rows": int(((frame.target_attacker_adapted == 1) &
                                                    (frame.one_step_route_switched_audit == 0)).sum()),
    }
    return {"targets": target, "per_action_support": action_support, "per_action_means": action_means,
            "initial_conditions_with_action_dependent_variation_fraction": variation,
            "relationship_to_phase4_one_step_targets": downstream_one_step,
            "correlations": frame[list(TARGET_COLUMNS)].corr().fillna(0).to_dict(),
            "invalid_targets": {"target_recovery_burden": "constant zero: simulator actions emit no recovery cost",
                                "target_severe_residual_damage": "constant zero: no ATTACK_SUCCESS within four-step horizon",
                                "target_time_to_containment": "exactly 1 when resolved and horizon+1 otherwise; redundant with unresolved"},
            "vqc_gate": "fail"}


def planning_value(models, test, columns):
    rows = test.copy()
    rows["predicted_exposure"] = models["regressors"]["target_cumulative_exposure"].predict(rows[columns])
    rows["predicted_disruption"] = models["regressors"]["target_cumulative_disruption"].predict(rows[columns])
    results = {}
    for target, prediction in (("target_cumulative_exposure", "predicted_exposure"),
                               ("target_cumulative_disruption", "predicted_disruption")):
        correlations, correct, total = [], 0, 0
        for _, group in rows.groupby("initial_condition_id"):
            coefficient = spearmanr(group[target], group[prediction]).statistic
            if not np.isnan(coefficient): correlations.append(coefficient)
            actual = group[target].to_numpy(); predicted = group[prediction].to_numpy()
            for left in range(len(group)):
                for right in range(left + 1, len(group)):
                    if actual[left] != actual[right]:
                        correct += int(np.sign(actual[left] - actual[right]) == np.sign(predicted[left] - predicted[right]))
                        total += 1
        results[target] = {"mean_within_condition_spearman": float(np.mean(correlations)),
                           "pairwise_action_order_accuracy": correct / total if total else None,
                           "comparable_pairs": total}
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("data/processed/shield_downstream_v1/model_table.parquet"))
    parser.add_argument("--artifact", type=Path, default=Path("artifacts/models/shield_downstream_consequence_v1.pkl"))
    parser.add_argument("--report", type=Path, default=Path("artifacts/reports/shield_downstream_consequence_v1.json"))
    args = parser.parse_args()
    frame = pd.read_parquet(args.data); columns = feature_columns(True)
    train, validation, test = (frame[frame.split == split].copy() for split in ("train", "validation", "test"))
    quality = target_quality(frame)
    candidates, timings = {}, {}
    for family in ("random_forest", "extra_trees"):
        clock = time.perf_counter(); candidates[family] = fit(family, train, columns); timings[family] = time.perf_counter() - clock
    validation_metrics = {family: evaluate(models, validation, columns) for family, models in candidates.items()}
    selected = {"classifiers": {}, "regressors": {}, "families": {}}
    for target in VALID_CLASS_TARGETS:
        family = min(candidates, key=lambda name: validation_metrics[name]["classification"][target]["brier"])
        selected["classifiers"][target] = candidates[family]["classifiers"][target]; selected["families"][target] = family
    for target in VALID_REG_TARGETS:
        family = min(candidates, key=lambda name: validation_metrics[name]["regression"][target]["rmse"])
        selected["regressors"][target] = candidates[family]["regressors"][target]; selected["families"][target] = family
    test_metrics = evaluate(selected, test, columns)
    per_action = {action: evaluate(selected, group, columns) for action, group in test.groupby("action_type_audit")}
    artifact = {"model_version": MODEL_VERSION, "dataset_version": DATASET_VERSION, "dataset_sha256": sha256(args.data),
                "feature_columns": columns, "feature_min": train[columns].min().to_numpy(float),
                "feature_max": train[columns].max().to_numpy(float), **selected,
                "target_bounds": {target: (float(frame[target].min()), float(frame[target].max()))
                                  for target in (*VALID_CLASS_TARGETS, *VALID_REG_TARGETS)},
                "unsupported_targets": {"target_recovery_burden", "target_severe_residual_damage"}}
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    with args.artifact.open("wb") as handle: pickle.dump(artifact, handle)
    report = {"model_version": MODEL_VERSION, "dataset_version": DATASET_VERSION, "dataset_sha256": sha256(args.data),
              "vqc_trained": False, "vqc_gate": quality["vqc_gate"], "vqc_reason": quality["invalid_targets"],
              "feature_columns": columns, "target_quality": quality,
              "split_rows": frame.split.value_counts().to_dict(), "training_seconds": timings,
              "candidate_validation": validation_metrics, "selected_families": selected["families"],
              "selected_test": test_metrics, "test_by_action": per_action,
              "planning_value": planning_value(selected, test, columns),
              "validation_status": {"target_cumulative_exposure": "validated_synthetic",
                  "target_cumulative_disruption": "validated_synthetic", "target_attacker_adapted": "validated_synthetic",
                  "target_unresolved_at_horizon": "validated_synthetic", "target_time_to_containment": "redundant_derived",
                  "target_recovery_burden": "unsupported_constant", "target_severe_residual_damage": "unsupported_constant"},
              "limitations": ["Synthetic four-step rollouts only.", "Continuation policy is NO_OP after the candidate intervention.",
                  "Recovery burden and severe damage are absent under current simulator/horizon semantics.",
                  "Time-to-containment is censored and redundant with unresolved-at-horizon.",
                  "Tree dispersion is heuristic model uncertainty, not a confidence interval.",
                  "No VQC or quantum advantage claim is scientifically justified."]}
    args.report.parent.mkdir(parents=True, exist_ok=True); args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"artifact": str(args.artifact), "report": str(args.report), "vqc_gate": quality["vqc_gate"],
                      "selected_test": test_metrics, "planning_value": report["planning_value"]}, indent=2))


if __name__ == "__main__": main()
