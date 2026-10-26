"""Reproducible PennyLane fidelity-kernel benchmark for CERT r4.2.

Only the existing chronological qsvc/{train,val,test}.csv partitions are read.
The quantum kernel is exact statevector simulation: each transformed row is
encoded once, cached, and pairwise kernels are squared statevector overlaps.
"""

from __future__ import annotations

import argparse
import json
import platform
import time
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pennylane as qml
import sklearn
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import SVC

SEED = 42
FEATURES = ["pca_1", "pca_2", "pca_3", "pca_4"]
N_QUBITS = 4


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def discover_label(frames: dict[str, pd.DataFrame]) -> str:
    """Identify, rather than assume, the sole binary non-feature target column."""
    excluded = set(FEATURES) | {"is_weekend"}
    candidates = []
    for column in frames["train"].columns:
        if column in excluded:
            continue
        values = set(pd.concat([f[column] for f in frames.values()]).dropna().unique())
        if values == {0, 1}:
            candidates.append(column)
    if len(candidates) != 1:
        raise ValueError(f"Expected one binary target candidate, found {candidates}")
    return candidates[0]


def load_data(data_dir: Path) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray], str]:
    frames = {name: pd.read_csv(data_dir / f"{name}.csv") for name in ("train", "val", "test")}
    expected = {"train": 250, "val": 100, "test": 100}
    if {k: len(v) for k, v in frames.items()} != expected:
        raise ValueError(f"Unexpected cohort sizes: { {k: len(v) for k, v in frames.items()} }")
    label = discover_label(frames)
    xs = {k: v.loc[:, FEATURES].to_numpy(dtype=float) for k, v in frames.items()}
    ys = {k: v[label].to_numpy(dtype=int) for k, v in frames.items()}
    for name in frames:
        if not np.isfinite(xs[name]).all() or set(np.unique(ys[name])) != {0, 1}:
            raise ValueError(f"Invalid features or labels in {name}")
    return xs, ys, label


def make_state_circuit():
    dev = qml.device("default.qubit", wires=N_QUBITS, shots=None)

    @qml.qnode(dev, interface=None, diff_method=None)
    def circuit(angles: np.ndarray):
        # Two data-dependent layers separated by ring entanglement. The second
        # layer prevents the entanglers from being a feature-independent suffix
        # that cancels from every fidelity overlap.
        for wire in range(N_QUBITS):
            qml.Hadamard(wires=wire)
            qml.RY(angles[wire], wires=wire)
            qml.RZ(0.5 * angles[wire], wires=wire)
        for wire in range(N_QUBITS):
            qml.CZ(wires=[wire, (wire + 1) % N_QUBITS])
        for wire in range(N_QUBITS):
            interaction = angles[wire] * angles[(wire + 1) % N_QUBITS] / np.pi
            qml.RY(interaction, wires=wire)
        return qml.state()

    return circuit


def states(circuit, x: np.ndarray) -> np.ndarray:
    return np.asarray([circuit(row) for row in x], dtype=complex)


def fidelity_kernel(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    return np.abs(left @ right.conj().T) ** 2


def validate_train_kernel(kernel: np.ndarray, tolerance: float = 1e-9) -> dict[str, Any]:
    symmetry_error = float(np.max(np.abs(kernel - kernel.T)))
    diagonal_error = float(np.max(np.abs(np.diag(kernel) - 1.0)))
    eigenvalues = np.linalg.eigvalsh((kernel + kernel.T) / 2)
    result = {
        "shape": list(kernel.shape),
        "finite": bool(np.isfinite(kernel).all()),
        "max_symmetry_error": symmetry_error,
        "max_diagonal_error": diagonal_error,
        "minimum_eigenvalue": float(eigenvalues.min()),
        "psd_tolerance": tolerance,
        "psd_within_tolerance": bool(eigenvalues.min() >= -tolerance),
    }
    if not (result["finite"] and symmetry_error <= tolerance and diagonal_error <= tolerance and result["psd_within_tolerance"]):
        raise ValueError(f"Quantum kernel validation failed: {result}")
    return result


def threshold_for_validation(y: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    """Maximize validation balanced accuracy; ties prefer closest to SVM zero."""
    unique = np.unique(scores)
    candidates = np.r_[unique[0] - 1e-12, (unique[:-1] + unique[1:]) / 2, unique[-1] + 1e-12]
    ranked = [(balanced_accuracy_score(y, scores >= t), -abs(float(t)), -float(t), float(t)) for t in candidates]
    best = max(ranked)
    return best[3], float(best[0])


def selection_key(y: np.ndarray, scores: np.ndarray, threshold: float) -> tuple[float, float, float]:
    pred = (scores >= threshold).astype(int)
    return (
        balanced_accuracy_score(y, pred),
        f1_score(y, pred, zero_division=0),
        average_precision_score(y, scores),
    )


def tune_precomputed(k_train: np.ndarray, y_train: np.ndarray, k_val: np.ndarray, y_val: np.ndarray):
    records = []
    for c in (0.1, 1.0, 10.0):
        model = SVC(C=c, kernel="precomputed")
        model.fit(k_train, y_train)
        scores = model.decision_function(k_val)
        threshold, _ = threshold_for_validation(y_val, scores)
        key = selection_key(y_val, scores, threshold)
        records.append((key, -c, model, threshold, {"C": c, "validation_balanced_accuracy": key[0], "validation_f1": key[1], "validation_average_precision": key[2], "threshold": threshold}))
    return max(records, key=lambda row: (row[0], row[1]))[2:]


def tune_rbf(x_train: np.ndarray, y_train: np.ndarray, x_val: np.ndarray, y_val: np.ndarray):
    records = []
    for c in (0.1, 1.0, 10.0):
        for gamma in ("scale", 0.1, 1.0):
            model = SVC(C=c, gamma=gamma, kernel="rbf")
            model.fit(x_train, y_train)
            scores = model.decision_function(x_val)
            threshold, _ = threshold_for_validation(y_val, scores)
            key = selection_key(y_val, scores, threshold)
            gamma_rank = {"scale": 0, 0.1: -1, 1.0: -2}[gamma]
            records.append((key, -c, gamma_rank, model, threshold, {"C": c, "gamma": gamma, "validation_balanced_accuracy": key[0], "validation_f1": key[1], "validation_average_precision": key[2], "threshold": threshold}))
    return max(records, key=lambda row: (row[0], row[1], row[2]))[3:]


def metrics(y: np.ndarray, scores: np.ndarray, threshold: float, training_seconds: float, inference_seconds: float, support_vectors: int) -> tuple[dict[str, Any], np.ndarray]:
    pred = (scores >= threshold).astype(int)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "confusion_matrix": cm.tolist(),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "average_precision_pr_auc": float(average_precision_score(y, scores)),
        "false_positive_rate": float(fp / (fp + tn)),
        "training_seconds": training_seconds,
        "inference_seconds": inference_seconds,
        "number_support_vectors": support_vectors,
        "decision_threshold": threshold,
        "note": "Ranking metrics use uncalibrated decision_function scores.",
    }, pred


def save_confusion_matrix(cm: list[list[int]], title: str, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(4, 4))
    image = ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i][j]), ha="center", va="center")
    ax.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["benign", "malicious"], yticklabels=["benign", "malicious"], xlabel="Predicted", ylabel="Actual", title=title)
    fig.colorbar(image, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("data/processed/cert_r4_2/quantum_benchmark/qsvc"))
    parser.add_argument("--output-dir", type=Path, default=Path("experiments/cert_qsvc/results"))
    args = parser.parse_args()
    np.random.seed(SEED)
    root = project_root()
    data_dir = args.data_dir if args.data_dir.is_absolute() else root / args.data_dir
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    xs, ys, label = load_data(data_dir)

    scaler = MinMaxScaler(feature_range=(-np.pi, np.pi), clip=True).fit(xs["train"])
    xq = {name: scaler.transform(value) for name, value in xs.items()}
    circuit = make_state_circuit()
    state_seconds = {}
    state_cache = {}
    for name in ("train", "val", "test"):
        started = time.perf_counter()
        state_cache[name] = states(circuit, xq[name])
        state_seconds[name] = time.perf_counter() - started
    started = time.perf_counter()
    k_train = fidelity_kernel(state_cache["train"], state_cache["train"])
    train_kernel_seconds = time.perf_counter() - started
    started = time.perf_counter()
    k_val = fidelity_kernel(state_cache["val"], state_cache["train"])
    validation_kernel_seconds = time.perf_counter() - started
    kernel_validation = validate_train_kernel(k_train)
    if k_val.shape != (100, 250):
        raise ValueError(f"Invalid validation kernel shape {k_val.shape}")

    tune_started = time.perf_counter()
    q_model, q_threshold, q_selection = tune_precomputed(k_train, ys["train"], k_val, ys["val"])
    q_tuning_seconds = time.perf_counter() - tune_started
    q_final = SVC(C=q_selection["C"], kernel="precomputed")
    fit_started = time.perf_counter()
    q_final.fit(k_train, ys["train"])
    q_fit_seconds = time.perf_counter() - fit_started
    infer_started = time.perf_counter()
    k_test = fidelity_kernel(state_cache["test"], state_cache["train"])
    if k_test.shape != (100, 250):
        raise ValueError(f"Invalid test kernel shape {k_test.shape}")
    q_scores = q_final.decision_function(k_test)
    q_infer_seconds = state_seconds["test"] + (time.perf_counter() - infer_started)
    q_training_seconds = state_seconds["train"] + train_kernel_seconds + q_fit_seconds
    q_metrics, q_pred = metrics(ys["test"], q_scores, q_threshold, q_training_seconds, q_infer_seconds, int(q_final.n_support_.sum()))

    classical_scaler = MinMaxScaler(feature_range=(-np.pi, np.pi), clip=True).fit(xs["train"])
    xc = {name: classical_scaler.transform(value) for name, value in xs.items()}
    c_tune_started = time.perf_counter()
    c_model, c_threshold, c_selection = tune_rbf(xc["train"], ys["train"], xc["val"], ys["val"])
    c_tuning_seconds = time.perf_counter() - c_tune_started
    c_final = SVC(C=c_selection["C"], gamma=c_selection["gamma"], kernel="rbf")
    c_fit_started = time.perf_counter()
    c_final.fit(xc["train"], ys["train"])
    c_fit_seconds = time.perf_counter() - c_fit_started
    c_infer_started = time.perf_counter()
    c_scores = c_final.decision_function(xc["test"])
    c_infer_seconds = time.perf_counter() - c_infer_started
    c_metrics, c_pred = metrics(ys["test"], c_scores, c_threshold, c_fit_seconds, c_infer_seconds, int(c_final.n_support_.sum()))

    specs = qml.specs(circuit)(xq["train"][0])
    resources = specs["resources"]
    config = {
        "seed": SEED,
        "data_directory": str(args.data_dir).replace("\\", "/"),
        "partitions": {name: int(len(ys[name])) for name in ys},
        "label_column_discovered": label,
        "features": FEATURES,
        "input_transform": {"type": "MinMaxScaler", "range": [-float(np.pi), float(np.pi)], "clip": True, "fit_partition": "train only", "data_min": scaler.data_min_.tolist(), "data_max": scaler.data_max_.tolist()},
        "threshold_policy": "Per model/config, maximize validation balanced accuracy; ties prefer threshold nearest zero, then lower threshold. Test labels never used.",
        "quantum": {
            "backend": "PennyLane default.qubit exact statevector (shots=None)",
            "qubits": N_QUBITS,
            "feature_map": "Per qubit H-RY(x_i)-RZ(x_i/2), ring CZ(i,i+1), then RY(x_i*x_(i+1)/pi)",
            "depth": int(resources.depth),
            "gate_count": int(resources.num_gates),
            "gate_types": dict(resources.gate_types),
            "kernel": "|<psi(x)|psi(y)>|^2 from cached statevectors",
            "selected": q_selection,
        },
        "classical": {"input": "same four training-scaled PCA features and cohorts", "selected": c_selection},
        "search": {"qsvc_C": [0.1, 1.0, 10.0], "rbf_C": [0.1, 1.0, 10.0], "rbf_gamma": ["scale", 0.1, 1.0], "selection_partition": "validation only"},
    }
    runtime = {
        "quantum_statevector_seconds": state_seconds,
        "quantum_train_kernel_seconds": train_kernel_seconds,
        "quantum_validation_kernel_seconds": validation_kernel_seconds,
        "quantum_svc_fit_seconds": q_fit_seconds,
        "quantum_tuning_seconds": q_tuning_seconds,
        "classical_tuning_seconds": c_tuning_seconds,
        "kernel_matrix_cost": {"train_overlaps": 250 * 250, "validation_overlaps": 100 * 250, "test_overlaps": 100 * 250, "state_dimension": 2**N_QUBITS},
    }
    output = {
        "experiment": "CERT r4.2 balanced PennyLane QSVC benchmark",
        "metrics": {"qsvc": q_metrics, "rbf_svm": c_metrics},
        "kernel_validation": kernel_validation,
        "runtime_details": runtime,
        "environment": {"python": platform.python_version(), "pennylane": qml.__version__, "numpy": np.__version__, "pandas": pd.__version__, "scikit_learn": sklearn.__version__},
        "limitations": [
            "The shared benchmark is artificially balanced; it cannot estimate deployment precision or false-alert burden at CERT's approximately 0.29% natural malicious prevalence.",
            "Chronological partitions may contain recurring employee identities, creating identity-related dependence across cohorts.",
            "A 100-row balanced test set is small and cannot establish quantum advantage.",
            "This is noiseless exact statevector simulation, not quantum hardware execution.",
        ],
    }
    (output_dir / "metrics.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    (output_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    pd.DataFrame({"row_index": np.arange(len(ys["test"])), "actual_label": ys["test"], "qsvc_decision_score": q_scores, "qsvc_prediction": q_pred, "rbf_svm_decision_score": c_scores, "rbf_svm_prediction": c_pred}).to_csv(output_dir / "predictions.csv", index=False)
    save_confusion_matrix(q_metrics["confusion_matrix"], "PennyLane QSVC", output_dir / "confusion_matrix_qsvc.png")
    save_confusion_matrix(c_metrics["confusion_matrix"], "Classical RBF-SVM", output_dir / "confusion_matrix_rbf_svm.png")
    results_readme = f"""# Benchmark results

The exact PennyLane statevector QSVC ran successfully. On the fixed balanced
100-row test partition it produced balanced accuracy {q_metrics['balanced_accuracy']:.3f},
F1 {q_metrics['f1']:.3f}, ROC-AUC {q_metrics['roc_auc']:.3f}, and average precision
{q_metrics['average_precision_pr_auc']:.3f}. The classical RBF-SVM produced balanced
accuracy {c_metrics['balanced_accuracy']:.3f}, F1 {c_metrics['f1']:.3f}, ROC-AUC
{c_metrics['roc_auc']:.3f}, and average precision {c_metrics['average_precision_pr_auc']:.3f}.

QSVC used {N_QUBITS} qubits, circuit depth {resources.depth}, and {resources.num_gates} gates.
The 250x250 training kernel was finite and symmetric, had maximum diagonal error
{kernel_validation['max_diagonal_error']:.3e}, and minimum eigenvalue
{kernel_validation['minimum_eigenvalue']:.3e}. See `metrics.json` and `config.json`
for full timings, selections, and limitations. These small balanced-sample results
do not demonstrate quantum advantage or realistic deployment alert burden.
"""
    (output_dir / "README.md").write_text(results_readme, encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
