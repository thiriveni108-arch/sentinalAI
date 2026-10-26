"""Shared PennyLane feature map used by benchmark-compatible inference."""

from __future__ import annotations

import numpy as np
import pennylane as qml

N_QUBITS = 4


def make_state_circuit():
    dev = qml.device("default.qubit", wires=N_QUBITS, shots=None)

    @qml.qnode(dev, interface=None, diff_method=None)
    def circuit(angles: np.ndarray):
        for wire in range(N_QUBITS):
            qml.Hadamard(wires=wire)
            qml.RY(angles[wire], wires=wire)
            qml.RZ(0.5 * angles[wire], wires=wire)
        for wire in range(N_QUBITS):
            qml.CZ(wires=[wire, (wire + 1) % N_QUBITS])
        for wire in range(N_QUBITS):
            qml.RY(angles[wire] * angles[(wire + 1) % N_QUBITS] / np.pi, wires=wire)
        return qml.state()

    return circuit


def states(circuit, values: np.ndarray) -> np.ndarray:
    return np.asarray([circuit(row) for row in values], dtype=complex)


def fidelity_kernel(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    return np.abs(left @ right.conj().T) ** 2
