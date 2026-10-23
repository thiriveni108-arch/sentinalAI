"""Reusable four-qubit feature encoding and advisory event analysis.

Nothing in this module participates in SentinelAI's production risk, alert,
MITRE, graph, or response paths.  Scores are experimental simulator outputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import version
from math import pi
from time import perf_counter
from typing import Any, Mapping, Sequence

import numpy as np
from scipy.optimize import minimize

from sentinel_ai import config
from sentinel_ai.domain import FeatureVector


FEATURE_QUBIT_MAPPING = (
    ("loginTimeDeviation", "Login-time deviation", 0, "login_hour_deviation", "clamp(hours / 12, 0, 1)"),
    ("failedLoginBehaviour", "Failed-login behaviour", 1, "failed_login_count", "clamp(count / 10, 0, 1)"),
    ("downloadVolumeAnomaly", "Download-volume anomaly", 2, "download_count_deviation + download_size_deviation", "clamp(max(positive deviations) / 5, 0, 1)"),
    ("deviceLocationAnomaly", "Device/location anomaly", 3, "unknown_device + location_anomaly", "mean(binary device, binary location)"),
)

FEATURE_KEYS = tuple(item[0] for item in FEATURE_QUBIT_MAPPING)
BACKEND = "Qiskit circuit + local exact statevector simulator (noiseless)"


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def extract_quantum_features(features: FeatureVector) -> dict[str, float]:
    """Extract four meaningful behavioral signals from the production vector."""

    return {
        "loginTimeDeviation": float(features.login_hour_deviation),
        "failedLoginBehaviour": float(features.failed_login_count),
        "downloadVolumeAnomaly": max(0.0, float(features.download_count_deviation), float(features.download_size_deviation)),
        "deviceLocationAnomaly": (float(features.unknown_device) + float(features.location_anomaly)) / 2.0,
    }


def normalize_quantum_features(values: Mapping[str, float]) -> dict[str, float]:
    """Normalize raw signals to [0, 1] before converting them to angles."""

    return {
        "loginTimeDeviation": _clamp(values["loginTimeDeviation"] / 12.0),
        "failedLoginBehaviour": _clamp(values["failedLoginBehaviour"] / 10.0),
        "downloadVolumeAnomaly": _clamp(values["downloadVolumeAnomaly"] / 5.0),
        "deviceLocationAnomaly": _clamp(values["deviceLocationAnomaly"]),
    }


def normalized_vector(values: Mapping[str, float]) -> np.ndarray:
    return np.asarray([float(values[key]) for key in FEATURE_KEYS], dtype=float)


def build_quantum_circuit(values: Mapping[str, float]):
    """Create the shared four-qubit RY/RZ encoder with ring entanglement."""

    from qiskit import QuantumCircuit

    circuit = QuantumCircuit(4, name="SentinelAIEncoder")
    for qubit, key in enumerate(FEATURE_KEYS):
        angle = pi * _clamp(values[key])
        circuit.ry(angle, qubit)
        circuit.rz(angle / 2.0, qubit)
    circuit.barrier()
    for control, target in ((0, 1), (1, 2), (2, 3), (3, 0)):
        circuit.cx(control, target)
    return circuit


def _statevector(values: Mapping[str, float], weights: Sequence[float] | None = None):
    """Execute the Qiskit-compatible four-qubit gate sequence exactly.

    The small NumPy executor keeps API requests deterministic and thread-safe;
    ``build_quantum_circuit`` remains the authoritative Qiskit construction.
    """

    state = np.zeros(16, dtype=complex)
    state[0] = 1.0

    def single(gate: np.ndarray, qubit: int) -> None:
        step = 1 << qubit
        for start in range(0, 16, step * 2):
            for offset in range(step):
                zero = start + offset
                one = zero + step
                left, right = state[zero], state[one]
                state[zero] = gate[0, 0] * left + gate[0, 1] * right
                state[one] = gate[1, 0] * left + gate[1, 1] * right

    def ry(angle: float, qubit: int) -> None:
        cosine, sine = np.cos(angle / 2.0), np.sin(angle / 2.0)
        single(np.asarray(((cosine, -sine), (sine, cosine)), dtype=complex), qubit)

    def rz(angle: float, qubit: int) -> None:
        single(np.diag((np.exp(-0.5j * angle), np.exp(0.5j * angle))), qubit)

    def cx(control: int, target: int) -> None:
        original = state.copy()
        for basis in range(16):
            destination = basis ^ (1 << target) if basis & (1 << control) else basis
            state[destination] = original[basis]

    for qubit, key in enumerate(FEATURE_KEYS):
        angle = pi * _clamp(values[key])
        ry(angle, qubit)
        rz(angle / 2.0, qubit)
    for control, target in ((0, 1), (1, 2), (2, 3), (3, 0)):
        cx(control, target)
    if weights is not None:
        if len(weights) != 8:
            raise ValueError("The VQC ansatz requires exactly eight parameters")
        for qubit in range(4):
            ry(float(weights[qubit]), qubit)
        for control, target in ((0, 1), (1, 2), (2, 3)):
            cx(control, target)
        for qubit in range(4):
            ry(float(weights[qubit + 4]), qubit)
    return state


def quantum_kernel_similarity(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    """Return the fidelity kernel |<phi(x)|phi(y)>|^2 in [0, 1]."""

    # Fidelity is exactly reflexive. Avoid exposing harmless statevector
    # round-off (for example 0.9999999999999998) as a mathematical violation.
    if left == right:
        return 1.0
    left_state = _statevector(left)
    right_state = _statevector(right)
    return float(np.clip(abs(np.vdot(left_state, right_state)) ** 2, 0.0, 1.0))


def _vqc_probability(values: Mapping[str, float], weights: Sequence[float]) -> float:
    state = _statevector(values, weights)
    probability = float(sum(abs(amplitude) ** 2 for basis, amplitude in enumerate(state) if basis & 1))
    return float(np.clip(probability, 1e-6, 1.0 - 1e-6))


def _representative_training_set() -> tuple[tuple[np.ndarray, int], ...]:
    normal = (
        (0.02, 0.00, 0.02, 0.00), (0.08, 0.10, 0.04, 0.00),
        (0.16, 0.00, 0.10, 0.25), (0.04, 0.20, 0.16, 0.00),
        (0.20, 0.10, 0.08, 0.25), (0.10, 0.00, 0.22, 0.00),
    )
    suspicious = (
        (0.78, 0.80, 0.08, 0.75), (0.15, 0.20, 0.95, 0.50),
        (0.45, 0.90, 0.35, 1.00), (0.80, 0.40, 0.80, 0.75),
        (0.30, 0.70, 0.90, 0.50), (0.95, 1.00, 0.15, 1.00),
    )
    return tuple((np.asarray(row), 0) for row in normal) + tuple((np.asarray(row), 1) for row in suspicious)


@dataclass(frozen=True)
class VqcModel:
    weights: tuple[float, ...]
    iterations: int
    objective: float


@lru_cache(maxsize=1)
def trained_vqc() -> VqcModel:
    """Train once per process on a deterministic, documented representative set."""

    training = _representative_training_set()

    def objective(weights: np.ndarray) -> float:
        losses = []
        for row, label in training:
            values = dict(zip(FEATURE_KEYS, row, strict=True))
            probability = _vqc_probability(values, weights)
            losses.append(-(label * np.log(probability) + (1 - label) * np.log(1 - probability)))
        return float(np.mean(losses) + 0.001 * np.mean(np.square(weights)))

    initial = np.random.default_rng(config.RANDOM_SEED).uniform(-0.25, 0.25, size=8)
    result = minimize(objective, initial, method="COBYLA", options={"maxiter": 60, "rhobeg": 0.35, "catol": 1e-5})
    return VqcModel(tuple(float(item) for item in result.x), int(getattr(result, "nfev", 0)), float(result.fun))


def run_vqc(values: Mapping[str, float]) -> dict[str, Any]:
    started = perf_counter()
    model = trained_vqc()
    score = _vqc_probability(values, model.weights)
    return {
        "prediction": "SUSPICIOUS" if score >= 0.5 else "NORMAL",
        "modelScore": round(score, 6),
        "scoreMeaning": "Variational circuit output for the SUSPICIOUS class; it is not a calibrated confidence.",
        "modelType": "VQC",
        "qubits": 4,
        "ansatz": "Two RY parameter layers (8 trainable angles) with linear CX entanglement",
        "trainingRows": len(_representative_training_set()),
        "optimizer": "COBYLA (60 maximum evaluations, deterministic initialization)",
        "executionBackend": BACKEND,
        "executionTimeMs": round((perf_counter() - started) * 1000.0, 3),
        "experimental": True,
        "affectsProductionRisk": False,
    }


THREAT_PROFILES: dict[str, dict[str, float]] = {
    "Normal Behaviour": dict(zip(FEATURE_KEYS, (0.05, 0.05, 0.05, 0.00), strict=True)),
    "Credential Compromise": dict(zip(FEATURE_KEYS, (0.80, 0.90, 0.10, 1.00), strict=True)),
    "Suspicious Data Collection": dict(zip(FEATURE_KEYS, (0.15, 0.15, 0.95, 0.50), strict=True)),
    "Account Manipulation": dict(zip(FEATURE_KEYS, (0.35, 0.70, 0.30, 0.75), strict=True)),
}


class QuantumAnalyzer:
    """Compose circuit, fidelity-kernel, VQC, and comparison API documents."""

    @staticmethod
    def status() -> dict[str, Any]:
        return {
            "status": "ready",
            "backend": BACKEND,
            "simulation": True,
            "realQuantumHardware": False,
            "qubits": 4,
            "quantumKernelStatus": "ready",
            "vqcStatus": "ready",
            "affectsProductionRisk": False,
            "versions": {"qiskit": version("qiskit"), "qiskitAer": version("qiskit-aer"), "qiskitMachineLearning": version("qiskit-machine-learning")},
        }

    @staticmethod
    def models() -> dict[str, Any]:
        return {
            "items": [
                {"name": "Quantum Fidelity Kernel", "modelType": "Fidelity kernel", "qubits": 4, "status": "ready", "experimental": True, "affectsProductionRisk": False},
                {"name": "Variational Quantum Classifier", "modelType": "VQC", "qubits": 4, "status": "ready", "experimental": True, "affectsProductionRisk": False},
            ],
            "disclosure": "Experimental quantum analysis. Quantum outputs do not modify SentinelAI's production risk score. No quantum advantage is claimed.",
        }

    @staticmethod
    def circuit(event_id: str, employee: str, raw: Mapping[str, float], normalized: Mapping[str, float]) -> dict[str, Any]:
        rotations = [
            {"feature": key, "qubit": index, "ryRadians": round(pi * normalized[key], 6), "rzRadians": round(pi * normalized[key] / 2.0, 6)}
            for index, key in enumerate(FEATURE_KEYS)
        ]
        return {
            "eventId": event_id,
            "employee": employee,
            "originalFeatureValues": {key: round(float(raw[key]), 6) for key in FEATURE_KEYS},
            "normalizedFeatureValues": {key: round(float(normalized[key]), 6) for key in FEATURE_KEYS},
            "featureQubitMapping": [
                {"feature": key, "label": label, "qubit": qubit, "sourceFeature": source, "normalization": normalization}
                for key, label, qubit, source, normalization in FEATURE_QUBIT_MAPPING
            ],
            "qubits": 4,
            "rotationParameters": rotations,
            "gateSequence": ["RY(q0..q3)", "RZ(q0..q3)", "CX(0→1)", "CX(1→2)", "CX(2→3)", "CX(3→0)"],
            "entanglementStructure": "Four-qubit CX ring: 0→1→2→3→0",
            "circuitDiagram": "\n".join((
                f"q[0] ─ RY({pi * normalized['loginTimeDeviation']:.3f}) ─ RZ({pi * normalized['loginTimeDeviation'] / 2:.3f}) ──■──────────────X─",
                f"q[1] ─ RY({pi * normalized['failedLoginBehaviour']:.3f}) ─ RZ({pi * normalized['failedLoginBehaviour'] / 2:.3f}) ──X──■───────────│─",
                f"q[2] ─ RY({pi * normalized['downloadVolumeAnomaly']:.3f}) ─ RZ({pi * normalized['downloadVolumeAnomaly'] / 2:.3f}) ─────X──■────────│─",
                f"q[3] ─ RY({pi * normalized['deviceLocationAnomaly']:.3f}) ─ RZ({pi * normalized['deviceLocationAnomaly'] / 2:.3f}) ────────X──────■─",
                "                                      CX ring: q0 → q1 → q2 → q3 → q0",
            )),
            "backend": BACKEND,
            "simulation": True,
            "affectsProductionRisk": False,
        }

    @staticmethod
    def kernel(normalized: Mapping[str, float], normal_rows: Sequence[Mapping[str, float]]) -> dict[str, Any]:
        started = perf_counter()
        baseline = {key: float(np.mean([row[key] for row in normal_rows])) if normal_rows else 0.0 for key in FEATURE_KEYS}
        similarity = quantum_kernel_similarity(normalized, baseline)
        anomaly = 1.0 - similarity
        if anomaly >= 0.75:
            interpretation = "Behaviour differs significantly from the normal baseline."
        elif anomaly >= 0.40:
            interpretation = "Behaviour shows a moderate difference from the normal baseline."
        else:
            interpretation = "Behaviour is quantum-kernel-similar to the normal baseline."
        return {
            "similarityToNormalBaseline": round(similarity, 6),
            "anomalyScore": round(anomaly, 6),
            "scoreMeaning": "Fidelity similarity is |<φ(event)|φ(normal baseline)>|²; anomaly is 1 − similarity. Neither is a probability of attack.",
            "interpretation": interpretation,
            "normalBaselineRows": len(normal_rows),
            "normalBaselineVector": {key: round(value, 6) for key, value in baseline.items()},
            "featureDimensions": 4,
            "executionBackend": BACKEND,
            "executionTimeMs": round((perf_counter() - started) * 1000.0, 3),
            "experimental": True,
            "affectsProductionRisk": False,
        }

    @staticmethod
    def similarity(normalized: Mapping[str, float]) -> dict[str, Any]:
        started = perf_counter()
        items = [
            {"profile": name, "similarity": round(quantum_kernel_similarity(normalized, profile), 6), "referenceVector": profile}
            for name, profile in THREAT_PROFILES.items()
        ]
        items.sort(key=lambda item: item["similarity"], reverse=True)
        return {
            "items": items,
            "scoreMeaning": "Each value is a fidelity-kernel similarity to a representative encoded profile, not a class probability.",
            "executionBackend": BACKEND,
            "executionTimeMs": round((perf_counter() - started) * 1000.0, 3),
            "experimental": True,
            "affectsProductionRisk": False,
        }
