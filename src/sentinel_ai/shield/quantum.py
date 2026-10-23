from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from time import perf_counter

from .models import AttackPath, Intervention, Plan
from .optimizer import audit_qubo, build_qubo, evaluate, qubo_value, solve_exact


@dataclass(frozen=True)
class QaoaConfig:
    depth: int = 1
    shots: int = 512
    seed: int = 41
    optimizer: str = "COBYLA"
    maxiter: int = 45
    initialization: str = "fixed"


def _ising(qubo: dict[tuple[int, int], float], n: int):
    """Map upper-triangular E(x), x=(1-Z)/2, to h_i Z_i + J_ij Z_iZ_j."""
    linear = [0.0] * n
    coupling: dict[tuple[int, int], float] = {}
    constant = 0.0
    for (i, j), coefficient in qubo.items():
        if i == j:
            constant += coefficient / 2
            linear[i] -= coefficient / 2
        else:
            constant += coefficient / 4
            linear[i] -= coefficient / 4
            linear[j] -= coefficient / 4
            coupling[i, j] = coupling.get((i, j), 0.0) + coefficient / 4
    return linear, coupling, constant


def run_qaoa_once(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...],
                  config: QaoaConfig = QaoaConfig()) -> tuple[Plan | None, dict]:
    """Optimize exactly evaluated QAOA expectation, then sample and validate candidates."""
    import numpy as np
    from qiskit import QuantumCircuit
    from qiskit.quantum_info import Statevector
    from qiskit_aer import AerSimulator
    from scipy.optimize import minimize

    started = perf_counter()
    qubo, penalty = build_qubo(paths, actions)
    n = 1 + max(max(pair) for pair in qubo)
    linear, coupling, ising_constant = _ising(qubo, n)
    energies = np.array([qubo_value(tuple((basis >> i) & 1 for i in range(n)), qubo)
                         for basis in range(2 ** n)], dtype=float)

    def circuit(parameters, measure: bool = False):
        qc = QuantumCircuit(n, n if measure else 0)
        qc.h(range(n))
        for layer in range(config.depth):
            beta, gamma = parameters[layer], parameters[config.depth + layer]
            for i, value in enumerate(linear):
                qc.rz(2 * gamma * value, i)
            for (i, j), value in coupling.items():
                qc.rzz(2 * gamma * value, i, j)
            for i in range(n):
                qc.rx(2 * beta, i)
        if measure:
            qc.measure(range(n), range(n))
        return qc

    def objective(parameters):
        probabilities = np.abs(Statevector.from_instruction(circuit(parameters)).data) ** 2
        return float(probabilities @ energies)

    rng = np.random.default_rng(config.seed)
    if config.initialization == "fixed":
        initial = np.concatenate((np.full(config.depth, 0.35), np.full(config.depth, 0.7)))
    elif config.initialization == "ramp":
        initial = np.concatenate((np.linspace(0.2, 0.55, config.depth), np.linspace(0.35, 0.9, config.depth)))
    else:
        initial = np.concatenate((rng.uniform(0.05, 0.75, config.depth), rng.uniform(0.1, 1.2, config.depth)))
    method_options = {"maxiter": config.maxiter}
    optimized = minimize(objective, initial, method=config.optimizer, options=method_options)
    final = circuit(optimized.x, measure=True)
    counts = AerSimulator(seed_simulator=config.seed).run(
        final, shots=config.shots, seed_simulator=config.seed
    ).result().get_counts()

    candidates = []
    for displayed_bits, count in counts.items():
        bits = tuple(int(bit) for bit in reversed(displayed_bits.replace(" ", "")))
        selected = {actions[i].action_id for i, bit in enumerate(bits[:len(actions)]) if bit}
        checked = evaluate(selected, paths, actions)
        if checked.feasible:
            candidates.append((checked.objective, -count, displayed_bits, checked))
    # The prior implementation chose the most frequent feasible sample. For an
    # optimizer, the defensible candidate is the lowest objective feasible sample.
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    candidate = candidates[0][3] if candidates else None
    measured = candidates[0][2] if candidates else None
    most_frequent = max(counts, key=counts.get)
    feasible_shots = sum(-item[1] for item in candidates)
    return candidate, {
        "seed": config.seed, "optimizer": config.optimizer, "initialization": config.initialization,
        "shots": config.shots, "qaoaDepth": config.depth, "qubitCount": n,
        "circuitDepth": final.depth(), "optimizedExpectation": round(float(optimized.fun), 6),
        "optimizerSuccess": bool(optimized.success), "measuredBitstring": measured,
        "mostFrequentBitstring": most_frequent, "bestFeasibleObjective": candidate.objective if candidate else None,
        "feasibleShotRate": round(feasible_shots / config.shots, 6), "penalty": penalty,
        "isingConstant": round(ising_constant, 6),
        "executionTimeMs": round((perf_counter() - started) * 1000, 2),
    }


def run_qaoa_experiment(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...]) -> dict:
    """Small reproducible matrix spanning depth, optimizer, shots, seed and initialization."""
    exact = solve_exact(paths, actions)
    configs = [
        QaoaConfig(1, 512, 41, "COBYLA", 45, "fixed"),
        QaoaConfig(1, 512, 43, "COBYLA", 45, "random"),
        QaoaConfig(1, 1024, 47, "POWELL", 45, "random"),
        QaoaConfig(2, 512, 41, "COBYLA", 60, "ramp"),
        QaoaConfig(2, 512, 43, "COBYLA", 60, "random"),
        QaoaConfig(2, 1024, 47, "POWELL", 60, "random"),
    ]
    trials = []
    for config in configs:
        candidate, metadata = run_qaoa_once(paths, actions, config)
        objective = candidate.objective if candidate else None
        gap = objective - exact.objective if objective is not None else None
        metadata.update({
            "feasible": candidate is not None,
            "selectedActions": list(candidate.selected) if candidate else [],
            "absoluteOptimalityGap": gap,
            "relativeOptimalityGap": None if gap is None or exact.objective == 0 else round(gap / exact.objective, 6),
            "approximationRatio": None if objective is None or exact.objective == 0 else round(objective / exact.objective, 6),
        })
        trials.append(metadata)
    feasible = [trial for trial in trials if trial["feasible"]]
    best = min(feasible, key=lambda trial: (trial["bestFeasibleObjective"], trial["executionTimeMs"])) if feasible else None
    objectives = [float(trial["bestFeasibleObjective"]) for trial in feasible]
    return {
        "trialCount": len(trials), "feasibilityRate": round(len(feasible) / len(trials), 6),
        "bestFeasible": best, "medianFeasibleObjective": median(objectives) if objectives else None,
        "medianApproximationRatio": median(objective / exact.objective for objective in objectives) if objectives and exact.objective else None,
        "medianRuntimeMs": median(float(trial["executionTimeMs"]) for trial in trials),
        "classicalOptimum": exact.objective, "trials": trials,
    }


def run_qaoa(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...], shots: int = 512) -> tuple[Plan, dict]:
    """Single bounded QAOA run; exact remains the safe fallback and authority."""
    started = perf_counter()
    exact = solve_exact(paths, actions)
    try:
        candidate, metadata = run_qaoa_once(paths, actions, QaoaConfig(shots=shots))
        fallback = candidate is None
        plan = exact if fallback else Plan(**{**candidate.__dict__, "solver": "qaoa-validated"})
        gap = None if candidate is None else candidate.objective - exact.objective
        metadata.update({"executed": True, "backend": "AerSimulator", "feasible": candidate is not None,
                         "fallbackUsed": fallback, "classicalOptimum": exact.objective,
                         "qaoaObjective": candidate.objective if candidate else None,
                         "optimalityGap": gap,
                         "relativeOptimalityGap": None if gap is None or exact.objective == 0 else round(gap / exact.objective, 6),
                         "approximationRatio": None if candidate is None or exact.objective == 0 else round(candidate.objective / exact.objective, 6),
                         "quboAudit": audit_qubo(paths, actions),
                         "disclosure": "Quantum candidates are classically validated; the exact plan remains authoritative. No quantum advantage is claimed."})
        return plan, metadata
    except Exception as exc:
        return exact, {"executed": False, "backend": "unavailable", "fallbackUsed": True,
                       "feasible": exact.feasible, "classicalOptimum": exact.objective,
                       "qaoaObjective": None, "optimalityGap": None,
                       "executionTimeMs": round((perf_counter() - started) * 1000, 2),
                       "error": f"{type(exc).__name__}: {exc}",
                       "disclosure": "QAOA was unavailable or invalid; the validated exact solution is returned."}
