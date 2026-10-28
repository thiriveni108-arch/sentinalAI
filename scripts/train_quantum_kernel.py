"""Phase 5B trainable projected-quantum-kernel experiment."""

from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, balanced_accuracy_score, brier_score_loss,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from scripts.train_shield_world_model import ece
from sentinel_ai.shield.quantum_kernel import (MODEL_VERSION, centered_kernel_alignment,
                                               fidelity_kernel, projected_kernel,
                                               projected_observables, quantum_states)
from sentinel_ai.shield.quantum_world_model import hybrid_matrix
from sentinel_ai.shield.world_dataset import ACTION_TYPES, feature_columns, sha256
from sentinel_ai.shield.world_model import _positive_probability


TARGET = "target_contained"
SEEDS = (42073, 42089, 42101)


def metrics(y, probability, threshold=.5):
    probability = np.asarray(probability, dtype=float)
    predicted = probability >= threshold
    return {"precision": float(precision_score(y, predicted, zero_division=0)),
            "recall": float(recall_score(y, predicted, zero_division=0)),
            "f1": float(f1_score(y, predicted, zero_division=0)),
            "balanced_accuracy": float(balanced_accuracy_score(y, predicted)),
            "roc_auc": float(roc_auc_score(y, probability)),
            "pr_auc": float(average_precision_score(y, probability)),
            "brier": float(brier_score_loss(y, probability)),
            "ece_10_bin": ece(np.asarray(y), probability), "decision_threshold": float(threshold)}


def validation_threshold(y, probability):
    candidates = np.unique(np.r_[np.linspace(.01, .5, 100), probability])
    scored = [(f1_score(y, np.asarray(probability) >= value, zero_division=0),
               balanced_accuracy_score(y, np.asarray(probability) >= value), float(value))
              for value in candidates]
    return max(scored)[2]


def deterministic_subset(train: pd.DataFrame, size: int, seed: int) -> np.ndarray:
    """Stratified training-only selection; test labels are never inspected."""
    rng = np.random.default_rng(seed)
    selected = []
    for label in (0, 1):
        candidates = np.flatnonzero(train[TARGET].to_numpy(int) == label)
        allocation = round(size * len(candidates) / len(train))
        allocation = max(2, min(allocation, len(candidates)))
        selected.extend(rng.choice(candidates, allocation, replace=False).tolist())
    if len(selected) < size:
        remaining = np.setdiff1d(np.arange(len(train)), np.asarray(selected))
        selected.extend(rng.choice(remaining, size - len(selected), replace=False).tolist())
    return np.asarray(sorted(selected[:size]), dtype=int)


def support(frame: pd.DataFrame):
    return {"rows": int(len(frame)), "negative": int((frame[TARGET] == 0).sum()),
            "positive": int(frame[TARGET].sum()), "positive_fraction": float(frame[TARGET].mean()),
            "per_action": {action: {"rows": int(frame[f"action__{action}"].sum()),
                "positive": int(frame.loc[frame[f"action__{action}"] == 1, TARGET].sum())}
                for action in ACTION_TYPES}}


def fit_precomputed(train_kernel, y, c, seed):
    base = SVC(kernel="precomputed", C=c, class_weight="balanced", probability=True,
               random_state=seed)
    return base.fit(train_kernel, y)


def tune_kernel(train_kernel, val_kernel, y_train, y_val, seed):
    best = None
    for c in (.1, 1.0, 10.0):
        model = fit_precomputed(train_kernel, y_train, c, seed)
        probability = model.predict_proba(val_kernel)[:, list(model.classes_).index(1)]
        candidate = (metrics(y_val, probability)["pr_auc"], c, model)
        if best is None or candidate[0] > best[0]:
            best = candidate
    return best[2], {"C": best[1], "validation_pr_auc": best[0]}


def optimize_weights(angles, labels, seed, depth=2, steps=6):
    rng = np.random.default_rng(seed)
    weights = rng.normal(0, .15, size=(depth, 4, 2))
    best_weights, best_alignment = weights.copy(), -1.0
    history = []
    for step in range(steps):
        delta = rng.choice((-1.0, 1.0), size=weights.shape)
        radius = .15 / ((step + 1) ** .101)
        learning_rate = .1 / ((step + 1) ** .602)
        scores = []
        for sign in (1, -1):
            candidate = weights + sign * radius * delta
            features = projected_observables(quantum_states(angles, candidate, depth))
            score = centered_kernel_alignment(projected_kernel(features, gamma=1.0), labels)
            scores.append(score)
            if score > best_alignment:
                best_alignment, best_weights = score, candidate.copy()
        weights += learning_rate * (scores[0] - scores[1]) / (2 * radius) * delta
        history.append(max(scores))
    return best_weights, best_alignment, history


def evaluate_by_action(frame, probabilities, threshold=.5):
    result = {}
    for action in ACTION_TYPES:
        mask = frame[f"action__{action}"].to_numpy(bool)
        if mask.sum() and len(np.unique(frame.loc[mask, TARGET])) == 2:
            result[action] = metrics(frame.loc[mask, TARGET], np.asarray(probabilities)[mask], threshold)
        else:
            result[action] = {"rows": int(mask.sum()), "note": "both classes required for complete metrics"}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("data/processed/shield_world_v2/model_table.parquet"))
    parser.add_argument("--subset-size", type=int, default=320)
    parser.add_argument("--alignment-size", type=int, default=160)
    parser.add_argument("--report", type=Path, default=Path("artifacts/reports/shield_quantum_kernel_q4_v1.json"))
    parser.add_argument("--artifact", type=Path, default=Path("artifacts/models/shield_quantum_kernel_q4_v1.pkl"))
    args = parser.parse_args()
    frame = pd.read_parquet(args.data)
    columns = feature_columns(True)
    train, validation, test = (frame[frame.split == split].copy() for split in ("train", "validation", "test"))
    subset_index = deterministic_subset(train, args.subset_size, SEEDS[0])
    subset = train.iloc[subset_index].copy()
    scaler = StandardScaler().fit(subset[columns])
    reducer = PCA(n_components=4, random_state=SEEDS[0]).fit(scaler.transform(subset[columns]))
    reduced = {name: reducer.transform(scaler.transform(part[columns])) for name, part in
               (("train", subset), ("validation", validation), ("test", test))}
    angles = {name: np.clip(value, -3, 3) * np.pi / 3 for name, value in reduced.items()}
    y_train, y_val, y_test = (part[TARGET].to_numpy(int) for part in (subset, validation, test))

    fixed_states, fixed_state_seconds = {}, {}
    for name, value in angles.items():
        started = time.perf_counter(); fixed_states[name] = quantum_states(value)
        fixed_state_seconds[name] = time.perf_counter() - started
    fidelity = {"train": fidelity_kernel(fixed_states["train"]),
                "validation": fidelity_kernel(fixed_states["validation"], fixed_states["train"]),
                "test": fidelity_kernel(fixed_states["test"], fixed_states["train"])}
    fidelity_model, fidelity_tuning = tune_kernel(fidelity["train"], fidelity["validation"], y_train, y_val, SEEDS[0])
    clock = time.perf_counter(); fidelity_probability = _positive_probability(fidelity_model, fidelity["test"])
    fidelity_predict_seconds = time.perf_counter() - clock
    fidelity_threshold = validation_threshold(y_val, _positive_probability(fidelity_model, fidelity["validation"]))

    fixed_projected = {name: projected_observables(state) for name, state in fixed_states.items()}
    best_projected = None
    for gamma in (.25, 1.0, 4.0):
        kernels = {"train": projected_kernel(fixed_projected["train"], gamma=gamma),
                   "validation": projected_kernel(fixed_projected["validation"], fixed_projected["train"], gamma)}
        model, tuning = tune_kernel(kernels["train"], kernels["validation"], y_train, y_val, SEEDS[0])
        candidate = (tuning["validation_pr_auc"], gamma, model)
        if best_projected is None or candidate[0] > best_projected[0]: best_projected = candidate
    clock = time.perf_counter(); projected_probability = _positive_probability(best_projected[2], projected_kernel(
        fixed_projected["test"], fixed_projected["train"], best_projected[1]))
    projected_predict_seconds = time.perf_counter() - clock
    projected_val_probability = _positive_probability(best_projected[2], projected_kernel(
        fixed_projected["validation"], fixed_projected["train"], best_projected[1]))
    projected_threshold = validation_threshold(y_val, projected_val_probability)

    alignment_index = deterministic_subset(subset, min(args.alignment_size, len(subset)), SEEDS[0])
    trainable_members, trainable_probabilities, trainable_val_probabilities, optimization = [], [], [], []
    trainable_test_inference_seconds = []
    trainable_started = time.perf_counter()
    for seed in SEEDS:
        weights, alignment, history = optimize_weights(angles["train"][alignment_index], y_train[alignment_index], seed)
        features = {}
        for name, value in angles.items():
            feature_clock = time.perf_counter(); features[name] = projected_observables(quantum_states(value, weights))
            if name == "test": test_feature_seconds = time.perf_counter() - feature_clock
        best = None
        for gamma in (.25, 1.0, 4.0):
            train_kernel = projected_kernel(features["train"], gamma=gamma)
            val_kernel = projected_kernel(features["validation"], features["train"], gamma)
            model, tuning = tune_kernel(train_kernel, val_kernel, y_train, y_val, seed)
            candidate = (tuning["validation_pr_auc"], gamma, model)
            if best is None or candidate[0] > best[0]: best = candidate
        predict_clock = time.perf_counter()
        probability = _positive_probability(best[2], projected_kernel(features["test"], features["train"], best[1]))
        trainable_test_inference_seconds.append(test_feature_seconds + time.perf_counter() - predict_clock)
        val_probability = _positive_probability(best[2], projected_kernel(features["validation"], features["train"], best[1]))
        trainable_probabilities.append(probability)
        trainable_val_probabilities.append(val_probability)
        trainable_members.append({"seed": seed, "weights": weights, "gamma": best[1], "model": best[2]})
        optimization.append({"seed": seed, "alignment": alignment, "history": history,
                             "validation_pr_auc": best[0], "gamma": best[1]})
    trainable_seconds = time.perf_counter() - trainable_started
    trainable_probability = np.mean(trainable_probabilities, axis=0)
    quantum_val_probability = np.mean(trainable_val_probabilities, axis=0)
    trainable_threshold = validation_threshold(y_val, quantum_val_probability)

    x_train, x_val, x_test = (scaler.transform(part[columns]) for part in (subset, validation, test))
    classical = {}
    classical_probabilities = {}
    for name, builder in {
        "matched_random_forest": lambda: RandomForestClassifier(n_estimators=160, min_samples_leaf=3, class_weight="balanced", random_state=SEEDS[0], n_jobs=-1),
        "matched_rbf_svm": lambda: SVC(kernel="rbf", C=1, gamma="scale", class_weight="balanced", probability=True, random_state=SEEDS[0]),
        "matched_neural_network": lambda: MLPClassifier(hidden_layer_sizes=(16, 8), alpha=.01, max_iter=500, early_stopping=True, random_state=SEEDS[0]),
    }.items():
        clock = time.perf_counter(); model = builder().fit(x_train, y_train); train_time = time.perf_counter() - clock
        clock = time.perf_counter(); probability = _positive_probability(model, x_test); inference = time.perf_counter() - clock
        threshold = validation_threshold(y_val, _positive_probability(model, x_val))
        classical[name] = {"metrics": metrics(y_test, probability, threshold), "training_seconds": train_time,
                           "test_inference_seconds": inference}
        classical_probabilities[name] = probability

    with Path("artifacts/models/shield_world_model_v1.pkl").open("rb") as handle: full_rf = pickle.load(handle)
    full_rf_probability = _positive_probability(full_rf["classifiers"][TARGET], test[columns].to_numpy(float))
    with Path("artifacts/models/shield_quantum_world_model_q4_v1.pkl").open("rb") as handle: hybrid = pickle.load(handle)
    hybrid_probability = np.mean([_positive_probability(member["classifiers"][TARGET], hybrid_matrix(
        test[columns].to_numpy(float), hybrid["scaler"], hybrid["reducer"], member["weights"])) for member in hybrid["members"]], axis=0)

    # Validation-only ensemble-weight selection, then one untouched test evaluation.
    rf_val_probability = _positive_probability(full_rf["classifiers"][TARGET], validation[columns].to_numpy(float))
    ensemble_candidates = []
    for weight in np.linspace(0, 1, 11):
        probability = weight * rf_val_probability + (1 - weight) * quantum_val_probability
        ensemble_candidates.append((metrics(y_val, probability)["pr_auc"], float(weight)))
    _, rf_weight = max(ensemble_candidates)
    ensemble_probability = rf_weight * full_rf_probability + (1 - rf_weight) * trainable_probability
    ensemble_val_probability = rf_weight * rf_val_probability + (1 - rf_weight) * quantum_val_probability
    ensemble_threshold = validation_threshold(y_val, ensemble_val_probability)
    rf_error = (full_rf_probability >= .5) != y_test
    quantum_error = (trainable_probability >= .5) != y_test

    artifact = {"model_version": MODEL_VERSION, "dataset_sha256": sha256(args.data), "target": TARGET,
                "feature_columns": columns, "subset_transition_ids": subset.transition_id.tolist(),
                "scaler": scaler, "reducer": reducer, "fidelity_model": fidelity_model,
                "projected_model": best_projected[2], "projected_gamma": best_projected[1],
                "trainable_members": trainable_members}
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    with args.artifact.open("wb") as handle: pickle.dump(artifact, handle)
    report = {"model_version": MODEL_VERSION, "task": TARGET, "dataset_sha256": sha256(args.data),
              "configuration": {"qubits": 4, "depth": 2, "subset_size": len(subset),
                  "alignment_size": len(alignment_index), "seeds": list(SEEDS), "alignment_steps": 6,
                  "selection": "deterministic target-stratified sampling from training only; no validation/test outcomes used"},
              "support": {"full_train": support(train), "selected_train": support(subset),
                          "validation": support(validation), "test": support(test)},
              "pca_explained_variance_ratio": reducer.explained_variance_ratio_.tolist(),
              "matched_subset_results": {**classical,
                  "standard_fidelity_kernel": {"metrics": metrics(y_test, fidelity_probability, fidelity_threshold), "tuning": fidelity_tuning},
                  "projected_quantum_kernel": {"metrics": metrics(y_test, projected_probability, projected_threshold),
                      "tuning": {"gamma": best_projected[1], "validation_pr_auc": best_projected[0]}},
                  "trainable_projected_kernel": {"metrics": metrics(y_test, trainable_probability, trainable_threshold),
                      "seed_metric_std": {key: float(np.std([metrics(y_test, p, validation_threshold(y_val, vp))[key]
                                                              for p, vp in zip(trainable_probabilities, trainable_val_probabilities)]))
                                          for key in ("f1", "roc_auc", "pr_auc", "brier")},
                      "optimization": optimization}},
              "full_data_context_not_matched": {"frozen_random_forest": metrics(y_test, full_rf_probability),
                                                "phase5_hybrid_vqc": metrics(y_test, hybrid_probability)},
              "complementarity": {"rf_error_count": int(rf_error.sum()), "quantum_error_count": int(quantum_error.sum()),
                  "both_wrong": int((rf_error & quantum_error).sum()), "rf_only_wrong": int((rf_error & ~quantum_error).sum()),
                  "quantum_only_wrong": int((~rf_error & quantum_error).sum()), "both_correct": int((~rf_error & ~quantum_error).sum()),
                  "validation_selected_rf_weight": rf_weight, "ensemble_test": metrics(y_test, ensemble_probability, ensemble_threshold),
                  "integration_promoted": False},
              "trainable_test_by_action": evaluate_by_action(test, trainable_probability, trainable_threshold),
              "cost": {"fixed_state_construction_seconds_by_split": fixed_state_seconds,
                       "standard_fidelity_test_inference_seconds": fixed_state_seconds["test"] + fidelity_predict_seconds,
                       "projected_test_inference_seconds": fixed_state_seconds["test"] + projected_predict_seconds,
                       "trainable_test_inference_seconds_by_seed": trainable_test_inference_seconds,
                       "trainable_optimization_and_fit_seconds": trainable_seconds,
                       "fidelity_train_kernel_shape": list(fidelity["train"].shape),
                       "trainable_parameters_per_seed": 16},
              "limitations": ["Synthetic simulator data only.", "The quantum models use a bounded subset and are compared fairly to subset-matched classical models.",
                  "Positive containment support is small, especially within rare actions.", "SVC probabilities are not guaranteed operationally calibrated.",
                  "Three seeds and a small alignment search provide limited uncertainty evidence.", "No quantum advantage or integration promotion is claimed."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"artifact": str(args.artifact), "report": str(args.report),
                      "trainable": report["matched_subset_results"]["trainable_projected_kernel"]["metrics"],
                      "ensemble": report["complementarity"]["ensemble_test"]}, indent=2))


if __name__ == "__main__": main()
