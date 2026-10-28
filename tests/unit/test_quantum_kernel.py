from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from scripts.train_quantum_kernel import deterministic_subset
from sentinel_ai.shield.quantum_kernel import (MODEL_VERSION, centered_kernel_alignment,
                                               fidelity_kernel, projected_kernel,
                                               projected_observables, quantum_states)
from sentinel_ai.shield.world_dataset import feature_columns


def test_quantum_kernel_is_reproducible_symmetric_and_bounded() -> None:
    angles = np.random.default_rng(7).normal(size=(5, 4))
    first = quantum_states(angles)
    second = quantum_states(angles)
    kernel = fidelity_kernel(first)
    assert np.allclose(first, second)
    assert np.allclose(kernel, kernel.T)
    assert np.allclose(np.diag(kernel), 1.0)
    assert np.all((kernel >= 0) & (kernel <= 1 + 1e-12))


def test_projected_kernel_and_alignment_are_finite() -> None:
    angles = np.random.default_rng(8).normal(size=(6, 4))
    projected = projected_observables(quantum_states(angles))
    kernel = projected_kernel(projected, gamma=.25)
    alignment = centered_kernel_alignment(kernel, np.asarray([0, 1, 0, 1, 0, 1]))
    assert projected.shape == (6, 8)
    assert np.allclose(kernel, kernel.T)
    assert np.isfinite(alignment) and -1 <= alignment <= 1


def test_subset_selection_is_training_only_deterministic_and_label_stratified() -> None:
    frame = pd.DataFrame({"target_contained": [0] * 90 + [1] * 10,
                          "split": ["train"] * 100})
    first = deterministic_subset(frame, 40, 42073)
    second = deterministic_subset(frame, 40, 42073)
    assert np.array_equal(first, second)
    assert len(first) == 40
    assert frame.iloc[first].target_contained.sum() == 4


def test_frozen_kernel_artifact_and_report_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    with (root / "artifacts/models/shield_quantum_kernel_q4_v1.pkl").open("rb") as handle:
        artifact = pickle.load(handle)
    report = json.loads((root / "artifacts/reports/shield_quantum_kernel_q4_v1.json").read_text(encoding="utf-8"))
    assert artifact["model_version"] == report["model_version"] == MODEL_VERSION
    assert artifact["feature_columns"] == feature_columns(True)
    assert len(artifact["subset_transition_ids"]) == 320
    assert report["configuration"]["qubits"] == 4
    assert report["complementarity"]["integration_promoted"] is False

