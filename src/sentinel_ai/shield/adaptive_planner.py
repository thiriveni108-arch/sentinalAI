"""Consequence-aware classical and QAOA planning (research/advisory only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from time import perf_counter
from typing import Mapping

from .consequence_predictor import ConsequencePrediction, ConsequencePredictor


TIERS = {"automatic": 0, "semi-automatic": 1, "human-approval": 2}


@dataclass(frozen=True)
class ActionSpec:
    name: str
    cost: float
    disruption_budget: float = 1.0
    reversible: bool = True
    tier: str = "automatic"
    prerequisites: tuple[str, ...] = ()
    incompatible_with: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlanningWeights:
    security_damage: float = .20
    exposure: float = .20
    disruption: float = .15
    recovery: float = .10
    severe_tail: float = .20
    action_cost: float = .08
    irreversibility: float = .04
    uncertainty: float = .03

    def __post_init__(self) -> None:
        if abs(sum(self.__dict__.values()) - 1.0) > 1e-9 or min(self.__dict__.values()) < 0:
            raise ValueError("Objective weights must be non-negative and sum to one")


@dataclass(frozen=True)
class PlanningProblem:
    actions: tuple[ActionSpec, ...]
    policies: tuple[str, ...]
    predictions: Mapping[tuple[str, str], ConsequencePrediction]
    allowed_tier: str = "automatic"
    approvals: frozenset[str] = frozenset()
    completed_controls: frozenset[str] = frozenset()
    disruption_limit: float = 1.0
    weights: PlanningWeights = field(default_factory=PlanningWeights)
    belief_entropy: float = 0.0


@dataclass(frozen=True)
class AdaptivePlan:
    action: str
    policy: str
    objective: float
    feasible: bool
    solver: str
    components: Mapping[str, float]
    reason: str = ""


NORMALIZERS = {"target_cumulative_exposure": 5.0, "target_cumulative_disruption": 5.0,
               "target_recovery_burden": 1.0, "target_delayed_adaptation": 1.0,
               "target_severe_outcome": 1.0, "target_unresolved": 1.0}


def _feasible(action: ActionSpec, problem: PlanningProblem) -> tuple[bool, str]:
    if TIERS[action.tier] > TIERS[problem.allowed_tier]: return False, "execution tier withheld"
    if action.tier == "human-approval" and action.name not in problem.approvals: return False, "approval missing"
    if not set(action.prerequisites).issubset(problem.completed_controls): return False, "prerequisite incomplete"
    if set(action.incompatible_with) & problem.completed_controls: return False, "incompatible control present"
    if action.disruption_budget > problem.disruption_limit: return False, "disruption constraint"
    return True, ""


def score(problem: PlanningProblem, action: ActionSpec, policy: str) -> AdaptivePlan:
    valid, reason = _feasible(action, problem)
    prediction = problem.predictions[(action.name, policy)]; y = prediction.means; w = problem.weights
    components = {
        "security_damage": y["target_unresolved"],
        "exposure": y["target_cumulative_exposure"] / NORMALIZERS["target_cumulative_exposure"],
        "disruption": y["target_cumulative_disruption"] / NORMALIZERS["target_cumulative_disruption"],
        "recovery": y["target_recovery_burden"], "severe_tail": y["target_severe_outcome"],
        "action_cost": action.cost, "irreversibility": 0.0 if action.reversible else 1.0,
        "uncertainty": min(1.0, prediction.uncertainty["target_severe_outcome"] + .5 * problem.belief_entropy),
    }
    value = sum(getattr(w, key) * value for key, value in components.items())
    return AdaptivePlan(action.name, policy, float(value), valid, "evaluation", components, reason)


def solve_exact(problem: PlanningProblem) -> AdaptivePlan:
    candidates = [score(problem, action, policy) for action, policy in product(problem.actions, problem.policies)]
    feasible = [item for item in candidates if item.feasible]
    if not feasible: return AdaptivePlan("", "", float("inf"), False, "exact", {}, "no feasible plan")
    best = min(feasible, key=lambda item: (item.objective, item.action, item.policy))
    return AdaptivePlan(**{**best.__dict__, "solver": "exact"})


def solve_greedy(problem: PlanningProblem) -> AdaptivePlan:
    # Scalable separable search: best policy for each action, then best action.
    candidates = []
    for action in problem.actions:
        choices = [score(problem, action, policy) for policy in problem.policies]
        choices = [choice for choice in choices if choice.feasible]
        if choices: candidates.append(min(choices, key=lambda x: x.objective))
    if not candidates: return AdaptivePlan("", "", float("inf"), False, "greedy", {}, "no feasible plan")
    best = min(candidates, key=lambda x: (x.objective, x.action, x.policy))
    return AdaptivePlan(**{**best.__dict__, "solver": "greedy"})


def build_qubo(problem: PlanningProblem, penalty: float | None = None):
    """One-hot action and continuation-policy variables with pairwise outcome costs."""
    na, npolicy = len(problem.actions), len(problem.policies)
    p = penalty or 2.0
    q: dict[tuple[int, int], float] = {}
    # P(sum(x)-1)^2 for both one-hot groups, constants omitted.
    for group in (range(na), range(na, na + npolicy)):
        group = list(group)
        for i in group: q[i, i] = q.get((i, i), 0.0) - p
        for pos, i in enumerate(group):
            for j in group[pos + 1:]: q[i, j] = q.get((i, j), 0.0) + 2 * p
    for i, action in enumerate(problem.actions):
        valid, _ = _feasible(action, problem)
        if not valid: q[i, i] = q.get((i, i), 0.0) + p
        for j, policy in enumerate(problem.policies):
            q[i, na + j] = q.get((i, na + j), 0.0) + score(problem, action, policy).objective
    return q, p


def qubo_value(bits: tuple[int, ...], q: Mapping[tuple[int, int], float]) -> float:
    return sum(value * bits[i] * bits[j] for (i, j), value in q.items())


def audit_qubo(problem: PlanningProblem) -> dict:
    q, penalty = build_qubo(problem); n = len(problem.actions) + len(problem.policies)
    maximum_error = 0.0; feasible_assignments = 0
    for bits in product((0, 1), repeat=n):
        action_count, policy_count = sum(bits[:len(problem.actions)]), sum(bits[len(problem.actions):])
        residual = penalty * ((action_count - 1) ** 2 + (policy_count - 1) ** 2)
        semantic = residual
        for i, action in enumerate(problem.actions):
            if bits[i] and not _feasible(action, problem)[0]: semantic += penalty
            for j, policy in enumerate(problem.policies):
                semantic += bits[i] * bits[len(problem.actions)+j] * score(problem, action, policy).objective
        # QUBO omits the two equality constants.
        maximum_error = max(maximum_error, abs((qubo_value(bits, q) + 2 * penalty) - semantic))
        feasible_assignments += int(action_count == policy_count == 1)
    return {"assignments": 2 ** n, "one_hot_assignments": feasible_assignments,
            "maximum_encoding_error": maximum_error, "verified": maximum_error < 1e-9}


def run_qaoa(problem: PlanningProblem, depth: int = 1, shots: int = 512, seed: int = 7301):
    """Bounded QAOA; sampled candidates are always independently hard-validated."""
    import numpy as np
    from qiskit import QuantumCircuit
    from qiskit.quantum_info import Statevector
    from qiskit_aer import AerSimulator
    from scipy.optimize import minimize
    started = perf_counter(); q, penalty = build_qubo(problem)
    n = len(problem.actions) + len(problem.policies)
    energies = np.array([qubo_value(tuple((basis >> i) & 1 for i in range(n)), q) for basis in range(2**n)])
    def circuit(params, measure=False):
        qc = QuantumCircuit(n, n if measure else 0); qc.h(range(n))
        for layer in range(depth):
            gamma, beta = params[layer], params[depth + layer]
            for (i, j), value in q.items():
                if i == j: qc.rz(-gamma * value, i)
                else: qc.rzz(gamma * value / 2, i, j); qc.rz(-gamma * value / 2, i); qc.rz(-gamma * value / 2, j)
            qc.rx(2 * beta, range(n))
        if measure: qc.measure(range(n), range(n))
        return qc
    def objective(params):
        probabilities = np.abs(Statevector.from_instruction(circuit(params)).data) ** 2
        return float(probabilities @ energies)
    result = minimize(objective, np.array([.7] * depth + [.35] * depth), method="COBYLA", options={"maxiter": 60})
    measured = circuit(result.x, True)
    counts = AerSimulator(seed_simulator=seed).run(measured, shots=shots).result().get_counts()
    candidates = []
    for displayed, count in counts.items():
        bits = tuple(int(bit) for bit in reversed(displayed.replace(" ", "")))
        ai = [i for i, bit in enumerate(bits[:len(problem.actions)]) if bit]
        pi = [i for i, bit in enumerate(bits[len(problem.actions):]) if bit]
        if len(ai) == len(pi) == 1:
            candidate = score(problem, problem.actions[ai[0]], problem.policies[pi[0]])
            if candidate.feasible: candidates.append((candidate.objective, -count, candidate))
    exact = solve_exact(problem)
    chosen = min(candidates, default=(0, 0, exact), key=lambda x: (x[0], x[1]))[2]
    return AdaptivePlan(**{**chosen.__dict__, "solver": "qaoa-validated"}), {
        "qubits": n, "circuit_depth": measured.depth(), "shots": shots, "qaoa_depth": depth,
        "runtime_ms": (perf_counter()-started)*1000, "feasible": bool(candidates),
        "fallback_used": not bool(candidates), "exact_objective": exact.objective,
        "optimality_gap": chosen.objective-exact.objective, "qubo_audit": audit_qubo(problem),
        "disclosure": "QAOA optimizes supplied predictions; it does not learn attacker behavior or establish quantum advantage."}


def make_problem(predictor: ConsequencePredictor, visible: Mapping[str, float],
                 actions: tuple[ActionSpec, ...], policies: tuple[str, ...], **kwargs) -> PlanningProblem:
    predictions = {(action.name, policy): predictor.predict(visible, action.name, policy)
                   for action, policy in product(actions, policies)}
    return PlanningProblem(actions, policies, predictions, **kwargs)
