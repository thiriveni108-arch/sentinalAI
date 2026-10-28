"""Reproducible Phase 5 hybrid benchmark and artifact builder."""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.metrics import (brier_score_loss, f1_score, mean_absolute_error, mean_squared_error,
                             precision_score, recall_score)
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.preprocessing import StandardScaler

from sentinel_ai.shield.quantum_world_model import (CLASS_TARGETS, MODEL_VERSION, REG_TARGETS,
                                                     hybrid_matrix, quantum_features)
from sentinel_ai.shield.world_dataset import TARGET_COLUMNS, feature_columns, sha256
from sentinel_ai.shield.world_model import _positive_probability
from scripts.train_shield_world_model import ece


DEFAULT_SEEDS = (42073, 42089, 42101)


def classification_metrics(y, p):
    pred = np.asarray(p) >= .5
    return {"precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "brier": float(brier_score_loss(y, p)), "ece_10_bin": ece(np.asarray(y), np.asarray(p))}


def regression_metrics(y, p):
    return {"mae": float(mean_absolute_error(y, p)),
            "rmse": float(mean_squared_error(y, p) ** .5)}


def fit_heads(matrix, frame, seed, neural=False):
    classifiers, regressors = {}, {}
    for target in CLASS_TARGETS:
        if neural:
            model = MLPClassifier(hidden_layer_sizes=(16, 8), alpha=.01, max_iter=500, early_stopping=True,
                                  random_state=seed)
        else:
            model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed)
        classifiers[target] = model.fit(matrix, frame[target].to_numpy(int))
    for target in REG_TARGETS:
        if neural:
            model = MLPRegressor(hidden_layer_sizes=(16, 8), alpha=.01, max_iter=500, early_stopping=True,
                                 random_state=seed)
        else:
            model = Ridge(alpha=1.0)
        regressors[target] = model.fit(matrix, frame[target].to_numpy(float))
    return classifiers, regressors


def evaluate_heads(classifiers, regressors, matrix, frame):
    output = {"rows": int(len(frame)), "classification": {}, "regression": {}}
    for target, model in classifiers.items():
        output["classification"][target] = classification_metrics(frame[target], _positive_probability(model, matrix))
    for target, model in regressors.items():
        output["regression"][target] = regression_metrics(frame[target], np.clip(model.predict(matrix), 0, 1))
    return output


def member_predictions(member, matrix):
    values = {}
    for target, model in member["classifiers"].items():
        values[target] = _positive_probability(model, matrix)
    for target, model in member["regressors"].items():
        values[target] = np.clip(model.predict(matrix), 0, 1)
    return values


def evaluate_ensemble(members, matrices, frame):
    predictions = {target: np.mean([member_predictions(member, matrix)[target]
                                    for member, matrix in zip(members, matrices)], axis=0)
                   for target in (*CLASS_TARGETS, *REG_TARGETS)}
    output = {"rows": int(len(frame)), "classification": {}, "regression": {}, "uncertainty": {}}
    for target in CLASS_TARGETS:
        output["classification"][target] = classification_metrics(frame[target], predictions[target])
        spread = np.std([member_predictions(m, x)[target] for m, x in zip(members, matrices)], axis=0)
        output["uncertainty"][target] = {"mean_ensemble_std": float(np.mean(spread))}
    for target in REG_TARGETS:
        output["regression"][target] = regression_metrics(frame[target], predictions[target])
        spread = np.std([member_predictions(m, x)[target] for m, x in zip(members, matrices)], axis=0)
        output["uncertainty"][target] = {"mean_ensemble_std": float(np.mean(spread))}
    return output


def score_candidate(train_frame, fit_matrix, check_matrix, fit_index, check_index, seed):
    fit = train_frame.iloc[fit_index]
    check = train_frame.iloc[check_index]
    classifiers, regressors = fit_heads(fit_matrix, fit, seed)
    score = 0.0
    for target, model in classifiers.items():
        score += brier_score_loss(check[target], _positive_probability(model, check_matrix))
    for target, model in regressors.items():
        score += mean_squared_error(check[target], np.clip(model.predict(check_matrix), 0, 1))
    return score / 5.0


def train_quantum_member(train, reduced, seed, layers=2, steps=8, sample_size=384):
    """Supervised SPSA-style optimization of variational circuit parameters."""
    rng = np.random.default_rng(seed)
    weights = rng.normal(0, .15, size=(layers, 4, 3))
    chosen = rng.choice(len(train), size=min(sample_size, len(train)), replace=False)
    cut = max(32, int(len(chosen) * .75))
    fit_index, check_index = chosen[:cut], chosen[cut:]
    angles = np.clip(reduced, -3, 3) * np.pi / 3
    best_weights, best_loss = weights.copy(), float("inf")
    for step in range(steps):
        delta = rng.choice((-1.0, 1.0), size=weights.shape)
        radius = .12 / ((step + 1) ** .101)
        learning_rate = .08 / ((step + 1) ** .602)
        losses = []
        for sign in (1, -1):
            candidate = weights + sign * radius * delta
            qfit = quantum_features(angles[fit_index], candidate)
            qcheck = quantum_features(angles[check_index], candidate)
            losses.append(score_candidate(train, np.column_stack((reduced[fit_index], qfit)),
                                          np.column_stack((reduced[check_index], qcheck)),
                                          fit_index, check_index, seed))
            if losses[-1] < best_loss:
                best_loss, best_weights = losses[-1], candidate.copy()
        gradient = (losses[0] - losses[1]) / (2 * radius) * delta
        weights -= learning_rate * gradient
    return best_weights, best_loss


def audit(frame, manifest, data_path):
    columns = feature_columns(True)
    forbidden = [c for c in columns if c.startswith(("target_", "next_")) or "_gt" in c or
                 any(token in c for token in ("outcome", "topology", "scenario_family", "forced_effectiveness"))]
    episodes = frame.groupby("episode_id").split.nunique()
    topologies = frame.groupby("topology_id").split.nunique()
    action_counts = {c.removeprefix("action__"): int(frame[c].sum()) for c in columns if c.startswith("action__")}
    return {"dataset_present": data_path.exists(), "dataset_sha256": sha256(data_path),
            "manifest_hash_matches": sha256(data_path) == manifest["files"]["model_table.parquet"],
            "phase4_artifact_present": Path("artifacts/models/shield_world_model_v1.pkl").exists(),
            "phase4_report_present": Path("artifacts/reports/shield_world_model_v1.json").exists(),
            "episode_overlap_count": int((episodes > 1).sum()),
            "topology_overlap_count": int((topologies > 1).sum()), "forbidden_features": forbidden,
            "features_exactly_match_manifest": columns == manifest["feature_columns"],
            "targets_exactly_match_manifest": TARGET_COLUMNS == manifest["target_columns"],
            "action_counts": action_counts, "no_op_fraction": action_counts["NO_OP"] / len(frame),
            "hidden_action_effectiveness": "forced_effectiveness is sampled by the simulator but excluded from features",
            "status": "pass" if not forbidden and not (episodes > 1).any() and not (topologies > 1).any() else "fail"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("data/processed/shield_world_v2/model_table.parquet"))
    parser.add_argument("--artifact", type=Path, default=Path("artifacts/models/shield_quantum_world_model_q4_v1.pkl"))
    parser.add_argument("--report", type=Path, default=Path("artifacts/reports/shield_quantum_world_model_q4_v1.json"))
    parser.add_argument("--seeds", default=",".join(map(str, DEFAULT_SEEDS)))
    parser.add_argument("--steps", type=int, default=4)
    args = parser.parse_args()
    seeds = tuple(int(x) for x in args.seeds.split(","))
    frame = pd.read_parquet(args.data)
    manifest = json.loads((args.data.parent / "manifest.json").read_text(encoding="utf-8"))
    foundation_audit = audit(frame, manifest, args.data)
    if foundation_audit["status"] != "pass" or not foundation_audit["manifest_hash_matches"]:
        raise RuntimeError(f"Phase 4 foundation audit failed: {foundation_audit}")
    columns = feature_columns(True)
    train, validation, test = (frame[frame.split == split].copy() for split in ("train", "validation", "test"))
    scaler = StandardScaler().fit(train[columns])
    reducer = PCA(n_components=4, random_state=seeds[0]).fit(scaler.transform(train[columns]))
    reduced = {name: reducer.transform(scaler.transform(part[columns]))
               for name, part in (("train", train), ("validation", validation), ("test", test))}

    started = time.perf_counter()
    members, train_losses = [], []
    for seed in seeds:
        weights, loss = train_quantum_member(train, reduced["train"], seed, steps=args.steps)
        matrix = np.column_stack((reduced["train"], quantum_features(np.clip(reduced["train"], -3, 3) * np.pi / 3, weights)))
        classifiers, regressors = fit_heads(matrix, train, seed)
        members.append({"seed": seed, "weights": weights, "classifiers": classifiers, "regressors": regressors})
        train_losses.append(loss)
    quantum_training_seconds = time.perf_counter() - started

    quantum_inference_started = time.perf_counter()
    quantum_matrices = {}
    for name in ("validation", "test"):
        quantum_matrices[name] = [np.column_stack((reduced[name], quantum_features(
            np.clip(reduced[name], -3, 3) * np.pi / 3, member["weights"]))) for member in members]
    validation_metrics = evaluate_ensemble(members, quantum_matrices["validation"], validation)
    test_metrics = evaluate_ensemble(members, quantum_matrices["test"], test)
    quantum_validation_test_seconds = time.perf_counter() - quantum_inference_started
    service_started = time.perf_counter()
    _ = [hybrid_matrix(test[columns].iloc[:1].to_numpy(float), scaler, reducer, member["weights"])
         for member in members]
    hybrid_single_row_seconds = time.perf_counter() - service_started

    nn_started = time.perf_counter()
    nn_classifiers, nn_regressors = fit_heads(scaler.transform(train[columns]), train, seeds[0], neural=True)
    nn_training_seconds = time.perf_counter() - nn_started
    nn_test_matrix = scaler.transform(test[columns])
    nn_inference_started = time.perf_counter()
    nn_metrics = evaluate_heads(nn_classifiers, nn_regressors, nn_test_matrix, test)
    nn_inference_seconds = time.perf_counter() - nn_inference_started

    with Path("artifacts/models/shield_world_model_v1.pkl").open("rb") as handle:
        rf = pickle.load(handle)
    rf_started = time.perf_counter()
    rf_metrics = evaluate_heads(rf["classifiers"], rf["regressors"], test[columns].to_numpy(float), test)
    rf_inference_seconds = time.perf_counter() - rf_started

    by_action, by_scenario = {}, {}
    for action_column in (c for c in columns if c.startswith("action__")):
        mask = test[action_column] == 1
        if mask.any():
            indices = np.flatnonzero(mask.to_numpy())
            by_action[action_column.removeprefix("action__")] = evaluate_ensemble(
                members, [matrix[indices] for matrix in quantum_matrices["test"]], test.iloc[indices])
    for scenario, group in test.groupby("scenario_family_audit"):
        indices = test.index.get_indexer(group.index)
        by_scenario[scenario] = evaluate_ensemble(members, [matrix[indices] for matrix in quantum_matrices["test"]], group)

    artifact = {"model_version": MODEL_VERSION, "dataset_sha256": sha256(args.data), "feature_columns": columns,
                "scaler": scaler, "reducer": reducer, "members": members}
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    with args.artifact.open("wb") as handle:
        pickle.dump(artifact, handle)
    phase4_report = json.loads(Path("artifacts/reports/shield_world_model_v1.json").read_text(encoding="utf-8"))
    report = {"model_version": MODEL_VERSION, "architecture": "StandardScaler -> train-fitted PCA(4) -> 4-qubit, 2-layer variational circuit -> classical heads",
              "foundation_audit": foundation_audit, "dataset_sha256": sha256(args.data), "feature_columns": columns,
              "feature_min": train[columns].min().tolist(), "feature_max": train[columns].max().tolist(),
              "targets": TARGET_COLUMNS, "split_rows": {s: int((frame.split == s).sum()) for s in ("train", "validation", "test")},
              "pca_explained_variance_ratio": reducer.explained_variance_ratio_.tolist(), "seeds": list(seeds),
              "variational_training_objective": "mean of 3 Brier and 2 MSE losses on an inner training-only holdout",
              "variational_inner_losses": train_losses, "hybrid": {"validation": validation_metrics, "test": test_metrics,
              "test_by_action": by_action, "test_by_attacker_scenario": by_scenario},
              "random_forest_test": rf_metrics, "classical_neural_network_test": nn_metrics,
              "held_out_topologies": sorted(test.topology_id.unique().tolist()),
              "timing_seconds": {"hybrid_training": quantum_training_seconds,
                                 "hybrid_validation_and_test_inference": quantum_validation_test_seconds,
                                 "hybrid_single_row_service_inference": hybrid_single_row_seconds,
                                 "nn_training": nn_training_seconds, "nn_test_inference": nn_inference_seconds,
                                 "rf_training_phase4": phase4_report["latency"]["training_seconds_primary"],
                                 "rf_test_inference": rf_inference_seconds},
              "complexity": {"qubits": 4, "circuit_layers": 2, "variational_parameters_per_member": 24,
                             "ensemble_members": len(members), "hybrid_head_input_dimensions": 8,
                             "rf_estimators_per_head": 160},
              "uncertainty_semantics": {"predicted_probability": "mean classification-head probability",
                  "model_uncertainty": "standard deviation across independently seeded hybrid members",
                  "bayesian_belief_uncertainty": "belief probabilities and entropy supplied as observable features",
                  "simulator_stochasticity": "aleatoric data-generation variation; not isolated by this model"},
              "limitations": ["Synthetic simulator data only; no operational generalization is established.",
                 "Ensemble dispersion is heuristic epistemic uncertainty, not a validated confidence interval.",
                 "NO_OP dominates the release, so rare-action metrics have high variance.",
                 "Five consequence heads do not generate a complete next state and cannot support imagined RL rollouts.",
                 "No quantum advantage is claimed; compare the measured metrics and computational cost."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"artifact": str(args.artifact), "report": str(args.report), "timing": report["timing_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
