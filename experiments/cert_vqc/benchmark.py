"""Bounded PennyLane VQC and MLP benchmark against immutable QSVC results."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pennylane as qml
from pennylane import numpy as pnp
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MinMaxScaler

SEED = 42
FEATURES = ["pca_1", "pca_2", "pca_3", "pca_4"]
N_QUBITS = 4
N_LAYERS = 2
LEARNING_RATE = 0.03
MAX_EPOCHS = 30
BATCH_SIZE = 25
PATIENCE = 6
MIN_DELTA = 1e-4


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_label(frames: dict[str, pd.DataFrame]) -> str:
    excluded = set(FEATURES) | {"is_weekend"}
    candidates = []
    for column in frames["train"].columns:
        if column in excluded:
            continue
        values = set(pd.concat([frame[column] for frame in frames.values()]).dropna().unique())
        if values == {0, 1}:
            candidates.append(column)
    if len(candidates) != 1:
        raise ValueError(f"Expected one binary target, found {candidates}")
    return candidates[0]


def load_and_verify(data_dir: Path, qsvc_data_dir: Path):
    frames = {split: pd.read_csv(data_dir / f"{split}.csv") for split in ("train", "val", "test")}
    expected = {"train": 250, "val": 100, "test": 100}
    if {key: len(value) for key, value in frames.items()} != expected:
        raise ValueError("Unexpected VQC cohort sizes")
    label = discover_label(frames)
    identity_columns = ["user", "date", label, *FEATURES]
    cohort_checks = {}
    for split, frame in frames.items():
        qsvc_frame = pd.read_csv(qsvc_data_dir / f"{split}.csv")
        identical = frame[identity_columns].equals(qsvc_frame[identity_columns])
        cohort_checks[split] = {"rows": len(frame), "identical_to_qsvc": identical}
        if not identical:
            raise ValueError(f"{split} VQC cohort differs from QSVC cohort")
    x = {split: frame[FEATURES].to_numpy(float) for split, frame in frames.items()}
    y = {split: frame[label].to_numpy(int) for split, frame in frames.items()}
    if not all(np.isfinite(value).all() for value in x.values()):
        raise ValueError("Non-finite PCA input")
    return x, y, label, cohort_checks


def make_vqc():
    device = qml.device("default.qubit", wires=N_QUBITS, shots=None)

    @qml.qnode(device, interface="autograd", diff_method="backprop")
    def circuit(features, weights):
        qml.AngleEmbedding(features, wires=range(N_QUBITS), rotation="Y")
        qml.StronglyEntanglingLayers(weights, wires=range(N_QUBITS), ranges=[1, 1])
        return tuple(qml.expval(qml.PauliZ(wire)) for wire in range(N_QUBITS))

    return circuit


def predict_vqc(circuit, weights, x: np.ndarray):
    # Mean Pauli-Z expectation is a continuous, uncalibrated classification score.
    # PennyLane parameter broadcasting evaluates the entire input batch in one
    # QNode call; each returned expectation has shape (batch,).
    expectations = pnp.stack(circuit(x, weights))
    return pnp.mean(expectations, axis=0)


def mse_loss(circuit, weights, x, targets):
    scores = predict_vqc(circuit, weights, x)
    signed_targets = 2.0 * targets - 1.0
    return pnp.mean((scores - signed_targets) ** 2)


def threshold_for_validation(y: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    unique = np.unique(scores)
    candidates = np.r_[unique[0] - 1e-12, (unique[:-1] + unique[1:]) / 2, unique[-1] + 1e-12]
    ranked = [(balanced_accuracy_score(y, scores >= threshold), -abs(float(threshold)), -float(threshold), float(threshold)) for threshold in candidates]
    best = max(ranked)
    return best[3], float(best[0])


def selection_key(y, scores, threshold):
    predictions = (scores >= threshold).astype(int)
    return (
        balanced_accuracy_score(y, predictions),
        f1_score(y, predictions, zero_division=0),
        average_precision_score(y, scores),
    )


def train_vqc(circuit, x_train, y_train, x_val, y_val):
    rng = np.random.default_rng(SEED)
    initial = pnp.array(rng.normal(0.0, 0.1, size=(N_LAYERS, N_QUBITS, 3)), requires_grad=True)
    weights = initial.copy()
    optimizer = qml.AdamOptimizer(stepsize=LEARNING_RATE)
    best_weights = weights.copy()
    best_val_loss = float("inf")
    history = []
    stale_epochs = 0
    started = time.perf_counter()
    for epoch in range(1, MAX_EPOCHS + 1):
        order = rng.permutation(len(x_train))
        batch_losses = []
        for start in range(0, len(order), BATCH_SIZE):
            indices = order[start : start + BATCH_SIZE]
            weights, loss_value = optimizer.step_and_cost(
                lambda current: mse_loss(circuit, current, x_train[indices], y_train[indices]),
                weights,
            )
            batch_losses.append(float(loss_value))
        train_loss = float(mse_loss(circuit, weights, x_train, y_train))
        val_scores = np.asarray(predict_vqc(circuit, weights, x_val), dtype=float)
        val_loss = float(np.mean((val_scores - (2.0 * y_val - 1.0)) ** 2))
        threshold, val_balanced_accuracy = threshold_for_validation(y_val, val_scores)
        history.append({"epoch": epoch, "minibatch_loss_mean": float(np.mean(batch_losses)), "train_loss": train_loss, "validation_loss": val_loss, "validation_balanced_accuracy": val_balanced_accuracy, "validation_threshold": threshold})
        if val_loss < best_val_loss - MIN_DELTA:
            best_val_loss = val_loss
            best_weights = weights.copy()
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= PATIENCE:
                break
    runtime = time.perf_counter() - started
    update_norm = float(np.linalg.norm(np.asarray(best_weights) - np.asarray(initial)))
    if not np.isfinite(best_weights).all() or update_norm <= 1e-8:
        raise ValueError("VQC parameters did not update to finite values")
    validation_scores = np.asarray(predict_vqc(circuit, best_weights, x_val), dtype=float)
    threshold, _ = threshold_for_validation(y_val, validation_scores)
    return best_weights, threshold, history, runtime, update_norm, best_val_loss


def train_mlp(x_train, y_train, x_val, y_val):
    candidates = []
    for hidden in ((8,), (8, 4)):
        model = MLPClassifier(hidden_layer_sizes=hidden, activation="tanh", solver="adam", alpha=1e-3, batch_size=25, learning_rate_init=0.01, max_iter=300, early_stopping=True, validation_fraction=0.2, n_iter_no_change=15, random_state=SEED)
        started = time.perf_counter()
        model.fit(x_train, y_train)
        runtime = time.perf_counter() - started
        scores = model.predict_proba(x_val)[:, 1]
        threshold, _ = threshold_for_validation(y_val, scores)
        candidates.append((selection_key(y_val, scores, threshold), tuple(-v for v in hidden), model, threshold, runtime, hidden))
    chosen = max(candidates, key=lambda item: (item[0], item[1]))
    return chosen[2], chosen[3], chosen[4], chosen[5], chosen[0]


def evaluate(y, scores, threshold, training_seconds, inference_seconds):
    if not np.isfinite(scores).all():
        raise ValueError("Non-finite prediction scores")
    prediction = (scores >= threshold).astype(int)
    cm = confusion_matrix(y, prediction, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "confusion_matrix": cm.tolist(),
        "precision": float(precision_score(y, prediction, zero_division=0)),
        "recall": float(recall_score(y, prediction, zero_division=0)),
        "f1": float(f1_score(y, prediction, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y, prediction)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "average_precision_pr_auc": float(average_precision_score(y, scores)),
        "false_positive_rate": float(fp / (fp + tn)),
        "training_seconds": training_seconds,
        "inference_seconds": inference_seconds,
        "decision_threshold": float(threshold),
        "note": "Continuous scores are used for ranking metrics and are not calibrated probabilities.",
    }, prediction


def save_confusion(cm, title, path):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(4, 4))
    image = ax.imshow(cm, cmap="Blues")
    for row in range(2):
        for column in range(2):
            ax.text(column, row, str(cm[row][column]), ha="center", va="center")
    ax.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["benign", "malicious"], yticklabels=["benign", "malicious"], xlabel="Predicted", ylabel="Actual", title=title)
    fig.colorbar(image, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("data/processed/cert_r4_2/quantum_benchmark/vqc"))
    parser.add_argument("--output-dir", type=Path, default=Path("experiments/cert_vqc/results"))
    args = parser.parse_args()
    np.random.seed(SEED)
    root = project_root()
    data_dir = args.data_dir if args.data_dir.is_absolute() else root / args.data_dir
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    qsvc_dir = root / "experiments/cert_qsvc/results"
    qsvc_data_dir = root / "data/processed/cert_r4_2/quantum_benchmark/qsvc"
    immutable_paths = [root / "experiments/cert_qsvc/benchmark.py", qsvc_dir / "metrics.json", qsvc_dir / "config.json", qsvc_dir / "predictions.csv"]
    hashes_before = {str(path.relative_to(root)).replace("\\", "/"): sha256(path) for path in immutable_paths}
    existing_metrics = json.loads((qsvc_dir / "metrics.json").read_text(encoding="utf-8"))
    existing_config = json.loads((qsvc_dir / "config.json").read_text(encoding="utf-8"))
    existing_predictions = pd.read_csv(qsvc_dir / "predictions.csv")

    x_raw, y, label, cohort_checks = load_and_verify(data_dir, qsvc_data_dir)
    scaler = MinMaxScaler(feature_range=(-np.pi, np.pi), clip=True).fit(x_raw["train"])
    if not (np.allclose(scaler.data_min_, existing_config["input_transform"]["data_min"]) and np.allclose(scaler.data_max_, existing_config["input_transform"]["data_max"])):
        raise ValueError("VQC training scaler differs from saved QSVC scaler")
    x = {split: scaler.transform(values) for split, values in x_raw.items()}
    circuit = make_vqc()
    weights, vqc_threshold, history, vqc_training_seconds, update_norm, best_val_loss = train_vqc(circuit, x["train"], y["train"], x["val"], y["val"])
    # Architecture, checkpoint, and threshold are now fixed; only now score test.
    started = time.perf_counter()
    vqc_scores = np.asarray(predict_vqc(circuit, weights, x["test"]), dtype=float)
    vqc_inference_seconds = time.perf_counter() - started
    vqc_metrics, vqc_prediction = evaluate(y["test"], vqc_scores, vqc_threshold, vqc_training_seconds, vqc_inference_seconds)

    mlp, mlp_threshold, mlp_training_seconds, hidden, mlp_val_key = train_mlp(x["train"], y["train"], x["val"], y["val"])
    started = time.perf_counter()
    mlp_scores = mlp.predict_proba(x["test"])[:, 1]
    mlp_inference_seconds = time.perf_counter() - started
    mlp_metrics, mlp_prediction = evaluate(y["test"], mlp_scores, mlp_threshold, mlp_training_seconds, mlp_inference_seconds)

    # Expand templates to device-level operations for meaningful gate/depth data.
    specs = qml.specs(circuit, level="device")(x["train"][0], weights)
    resources = specs["resources"]
    hashes_after = {key: sha256(root / key) for key in hashes_before}
    if hashes_before != hashes_after:
        raise RuntimeError("Existing QSVC artifacts changed")
    if not np.array_equal(existing_predictions["actual_label"].to_numpy(), y["test"]):
        raise ValueError("Existing predictions use a different test-label order")

    np.savez(output_dir / "best_vqc_checkpoint.npz", weights=np.asarray(weights), threshold=vqc_threshold, scaler_min=scaler.data_min_, scaler_max=scaler.data_max_)
    pd.DataFrame(history).to_csv(output_dir / "training_history.csv", index=False)
    predictions = existing_predictions.copy()
    predictions["vqc_score"] = vqc_scores
    predictions["vqc_prediction"] = vqc_prediction
    predictions["mlp_score"] = mlp_scores
    predictions["mlp_prediction"] = mlp_prediction
    predictions.to_csv(output_dir / "predictions.csv", index=False)

    all_metrics = {
        "qsvc": existing_metrics["metrics"]["qsvc"],
        "vqc": vqc_metrics,
        "rbf_svm": existing_metrics["metrics"]["rbf_svm"],
        "mlp": mlp_metrics,
    }
    result = {
        "experiment": "CERT r4.2 PennyLane VQC comparison",
        "metrics": all_metrics,
        "cohort_verification": cohort_checks,
        "parameter_update_norm": update_norm,
        "loss_and_predictions_finite": bool(np.isfinite(pd.DataFrame(history).select_dtypes(include=[np.number])).all().all() and np.isfinite(vqc_scores).all() and np.isfinite(mlp_scores).all()),
        "existing_qsvc_sha256_unchanged": hashes_after,
        "limitations": existing_metrics["limitations"],
    }
    config = {
        "seed": SEED,
        "label_column_discovered": label,
        "features": FEATURES,
        "partitions": {split: len(values) for split, values in y.items()},
        "preprocessing": {"type": "MinMaxScaler", "range": [-float(np.pi), float(np.pi)], "clip": True, "fit_partition": "train only", "identical_to_qsvc": True, "data_min": scaler.data_min_.tolist(), "data_max": scaler.data_max_.tolist()},
        "threshold_policy": existing_config["threshold_policy"],
        "vqc": {
            "backend": "PennyLane default.qubit exact statevector (shots=None)",
            "qubits": N_QUBITS,
            "architecture": "RY AngleEmbedding; 2 StronglyEntanglingLayers, each with one Rot per qubit and ring CNOTs; mean of four Pauli-Z expectations",
            "depth": int(resources.depth),
            "gate_count": int(resources.num_gates),
            "gate_types": dict(resources.gate_types),
            "trainable_parameters": int(np.asarray(weights).size),
            "loss": "mean squared error against labels mapped to {-1,+1}",
            "optimizer": "PennyLane AdamOptimizer",
            "learning_rate": LEARNING_RATE,
            "batch_size": BATCH_SIZE,
            "maximum_epochs": MAX_EPOCHS,
            "epochs_completed": len(history),
            "early_stopping": {"monitor": "validation_loss", "patience": PATIENCE, "minimum_delta": MIN_DELTA, "best_validation_loss": best_val_loss},
            "decision_threshold": vqc_threshold,
            "parameter_update_norm": update_norm,
        },
        "mlp": {"selected_hidden_layers": list(hidden), "activation": "tanh", "alpha": 1e-3, "learning_rate": 0.01, "validation_selection_candidates": [[8], [8, 4]], "selected_validation_balanced_accuracy": mlp_val_key[0], "selected_validation_f1": mlp_val_key[1], "selected_validation_average_precision": mlp_val_key[2], "decision_threshold": mlp_threshold},
    }
    (output_dir / "metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (output_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    comparison_rows = []
    for model, values in all_metrics.items():
        comparison_rows.append({"model": model, **{key: values[key] for key in ("precision", "recall", "f1", "balanced_accuracy", "roc_auc", "average_precision_pr_auc", "false_positive_rate", "training_seconds", "inference_seconds")}})
    pd.DataFrame(comparison_rows).to_csv(output_dir / "comparison.csv", index=False)
    save_confusion(vqc_metrics["confusion_matrix"], "PennyLane VQC", output_dir / "confusion_matrix_vqc.png")
    save_confusion(mlp_metrics["confusion_matrix"], "Classical MLP", output_dir / "confusion_matrix_mlp.png")
    report = f"""# Four-model comparison

All models use the identical chronological 250/100/100 cohorts. QSVC and
RBF-SVM values and predictions are copied unchanged from `cert_qsvc/results`.

| Model | Precision | Recall | F1 | Balanced accuracy | ROC-AUC | Average precision | Train s | Infer s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
""" + "\n".join(
        f"| {row['model']} | {row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} | {row['balanced_accuracy']:.3f} | {row['roc_auc']:.3f} | {row['average_precision_pr_auc']:.3f} | {row['training_seconds']:.3f} | {row['inference_seconds']:.3f} |"
        for row in comparison_rows
    ) + """

Model comparisons should consider thresholded and ranking metrics together;
no winner is declared from accuracy or F1 alone. The balanced 100-row test set
cannot estimate natural-prevalence alert burden or demonstrate quantum
advantage. Temporal partitions may also contain recurring identities.
"""
    (output_dir / "comparison.md").write_text(report, encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
