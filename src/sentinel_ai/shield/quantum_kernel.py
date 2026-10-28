"""Bounded four-qubit feature maps for Phase 5B kernel research."""

from __future__ import annotations

import numpy as np


MODEL_VERSION = "shield-containment-qkernel-q4-v1.0.0"


def quantum_states(angles: np.ndarray, weights: np.ndarray | None = None,
                   depth: int = 2) -> np.ndarray:
    """Return deterministic statevectors for a four-qubit re-uploading map."""
    import pennylane as qml

    device = qml.device("default.qubit", wires=4, shots=None)

    @qml.qnode(device, interface=None)
    def circuit(row, parameters):
        for layer in range(depth):
            qml.AngleEmbedding(row, wires=range(4), rotation="Y")
            if parameters is not None:
                for wire in range(4):
                    qml.RY(parameters[layer, wire, 0], wires=wire)
                    qml.RZ(parameters[layer, wire, 1], wires=wire)
            for wire in range(4):
                qml.CNOT(wires=(wire, (wire + 1) % 4))
        return qml.state()

    return np.asarray([circuit(row, weights) for row in np.atleast_2d(angles)], dtype=complex)


def fidelity_kernel(left_states: np.ndarray, right_states: np.ndarray | None = None) -> np.ndarray:
    right_states = left_states if right_states is None else right_states
    return np.abs(np.asarray(left_states) @ np.asarray(right_states).conj().T) ** 2


def projected_observables(states: np.ndarray) -> np.ndarray:
    """Measure four local Z and four ring-neighbour ZZ expectations."""
    probabilities = np.abs(np.asarray(states)) ** 2
    basis = np.arange(16, dtype=int)
    z = np.asarray([[1.0 if ((index >> (3 - wire)) & 1) == 0 else -1.0
                     for index in basis] for wire in range(4)])
    local = probabilities @ z.T
    pair = probabilities @ np.asarray([z[wire] * z[(wire + 1) % 4] for wire in range(4)]).T
    return np.column_stack((local, pair))


def projected_kernel(left: np.ndarray, right: np.ndarray | None = None,
                     gamma: float = 1.0) -> np.ndarray:
    right = left if right is None else right
    distances = np.sum(left * left, axis=1)[:, None] + np.sum(right * right, axis=1)[None, :] - 2 * left @ right.T
    return np.exp(-gamma * np.maximum(distances, 0.0))


def centered_kernel_alignment(kernel: np.ndarray, labels: np.ndarray) -> float:
    labels = 2 * np.asarray(labels, dtype=float) - 1
    target = np.outer(labels, labels)
    count = len(labels)
    center = np.eye(count) - np.ones((count, count)) / count
    centered_kernel = center @ kernel @ center
    centered_target = center @ target @ center
    denominator = np.linalg.norm(centered_kernel) * np.linalg.norm(centered_target)
    return float(np.sum(centered_kernel * centered_target) / denominator) if denominator else 0.0

