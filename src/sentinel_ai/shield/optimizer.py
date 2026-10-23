from __future__ import annotations

from itertools import combinations, product
from math import ceil, log2
from time import perf_counter

from .models import AttackPath, Intervention, Plan


def _valid(selected: set[str], actions: dict[str, Intervention]) -> bool:
    for action_id in selected:
        action = actions[action_id]
        if not set(action.prerequisites).issubset(selected):
            return False
        if set(action.incompatible_with).intersection(selected):
            return False
    return True


def evaluate(selected: set[str], paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...]) -> Plan:
    by_id = {action.action_id: action for action in actions}
    covered = {pid for aid in selected for pid in by_id[aid].interrupts}
    required = {path.path_id for path in paths if path.criticality >= 3}
    remaining = required - covered
    valid = _valid(selected, by_id)
    cost = sum(by_id[item].cost for item in selected)
    return Plan(tuple(sorted(selected)), valid and not remaining, cost, cost,
                tuple(sorted(required & covered)), tuple(sorted(remaining)), "evaluation",
                "All enumerated critical paths are interrupted." if valid and not remaining else "One or more constraints or paths remain unsatisfied.")


def solve_exact(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...]) -> Plan:
    best: Plan | None = None
    ids = [item.action_id for item in actions]
    for count in range(len(ids) + 1):
        for subset in combinations(ids, count):
            candidate = evaluate(set(subset), paths, actions)
            if candidate.feasible and (best is None or (candidate.objective, candidate.selected) < (best.objective, best.selected)):
                best = candidate
    if best is None:
        return Plan((), False, float("inf"), float("inf"), (), tuple(path.path_id for path in paths), "exact", "No feasible intervention combination exists.")
    return Plan(**{**best.__dict__, "solver": "exact"})


def solve_greedy(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...]) -> Plan:
    required = {path.path_id for path in paths if path.criticality >= 3}
    selected: set[str] = set()
    while required:
        choices = []
        for action in actions:
            if action.action_id in selected:
                continue
            gain = len(required.intersection(action.interrupts))
            if gain:
                choices.append((action.cost / gain, action.action_id, action))
        if not choices:
            break
        action = min(choices)[2]
        selected.add(action.action_id)
        selected.update(action.prerequisites)
        required.difference_update(action.interrupts)
    result = evaluate(selected, paths, actions)
    return Plan(**{**result.__dict__, "solver": "greedy"})


def build_qubo(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...], penalty: float | None = None):
    """Upper-triangular QUBO using binary slack for sum(cover) - 1 - slack = 0."""
    n = len(actions)
    index = {action.action_id: i for i, action in enumerate(actions)}
    q: dict[tuple[int, int], float] = {(i, i): action.cost for i, action in enumerate(actions)}
    p = (sum(action.cost for action in actions) + 1.0) if penalty is None else penalty
    if p <= sum(action.cost for action in actions):
        raise ValueError("QUBO penalty must exceed the sum of all non-negative action costs.")
    next_variable = n
    for path in paths:
        covering = [index[a.action_id] for a in actions if path.path_id in a.interrupts]
        if not covering:
            raise ValueError(f"Critical path {path.path_id} has no covering action.")
        terms = [(i, 1.0) for i in covering]
        slack_bits = ceil(log2(len(covering))) if len(covering) > 1 else 0
        for bit in range(slack_bits):
            terms.append((next_variable, -(2.0 ** bit)))
            next_variable += 1
        # P(-1 + sum a_i z_i)^2; z_i^2=z_i.
        for i, coefficient in terms:
            q[i, i] = q.get((i, i), 0.0) + p * (coefficient * coefficient - 2 * coefficient)
        for left in range(len(terms)):
            for right in range(left + 1, len(terms)):
                i, ai = terms[left]
                j, aj = terms[right]
                key = tuple(sorted((i, j)))
                q[key] = q.get(key, 0.0) + 2 * p * ai * aj
    # prerequisite x_i <= x_j: P*x_i*(1-x_j)
    for action in actions:
        i = index[action.action_id]
        for required in action.prerequisites:
            j = index[required]
            q[i, i] = q.get((i, i), 0.0) + p
            key = tuple(sorted((i, j)))
            q[key] = q.get(key, 0.0) - p
        # incompatible pair: P*x_i*x_j (add once)
        for other in action.incompatible_with:
            j = index[other]
            if i < j:
                q[i, j] = q.get((i, j), 0.0) + p
    return q, p


def qubo_value(bits: tuple[int, ...], qubo: dict[tuple[int, int], float]) -> float:
    return sum(value * bits[i] * bits[j] for (i, j), value in qubo.items())


def reference_qubo_value(bits: tuple[int, ...], paths: tuple[AttackPath, ...],
                         actions: tuple[Intervention, ...], penalty: float) -> tuple[float, float, bool]:
    """Independent semantic objective, returned with the QUBO's omitted constant removed."""
    selected = bits[:len(actions)]
    cost = sum(action.cost * selected[i] for i, action in enumerate(actions))
    cursor = len(actions)
    residual = 0.0
    for path in paths:
        covering = [i for i, action in enumerate(actions) if path.path_id in action.interrupts]
        slack_bits = ceil(log2(len(covering))) if len(covering) > 1 else 0
        slack = sum((2 ** bit) * bits[cursor + bit] for bit in range(slack_bits))
        cursor += slack_bits
        residual += (sum(selected[i] for i in covering) - 1 - slack) ** 2
    by_id = {action.action_id: i for i, action in enumerate(actions)}
    for i, action in enumerate(actions):
        for required in action.prerequisites:
            residual += selected[i] * (1 - selected[by_id[required]])
        for other in action.incompatible_with:
            j = by_id[other]
            if i < j:
                residual += selected[i] * selected[j]
    omitted_constant = penalty * len(paths)
    return cost + penalty * residual - omitted_constant, residual, residual == 0


def audit_qubo(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...]) -> dict[str, object]:
    """Compare compiled and independent energies for every small-instance bitstring."""
    qubo, penalty = build_qubo(paths, actions)
    variable_count = 1 + max(max(pair) for pair in qubo)
    feasible = violating = mismatches = 0
    maximum_error = 0.0
    for bits in product((0, 1), repeat=variable_count):
        compiled = qubo_value(bits, qubo)
        reference, _, satisfies_penalties = reference_qubo_value(bits, paths, actions, penalty)
        error = abs(compiled - reference)
        maximum_error = max(maximum_error, error)
        mismatches += int(error > 1e-9)
        feasible += int(satisfies_penalties)
        violating += int(not satisfies_penalties)
    return {"variableCount": variable_count, "bitstringsChecked": 2 ** variable_count,
            "penalty": penalty, "feasibleEncodings": feasible, "penaltyViolatingEncodings": violating,
            "energyMismatches": mismatches, "maximumEnergyError": maximum_error,
            "upperTriangularConvention": True, "constantOffset": -penalty * len(paths)}


def solve_qubo_exhaustive(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...]) -> Plan:
    qubo, _ = build_qubo(paths, actions)
    variable_count = 1 + max(max(pair) for pair in qubo)
    ranked = sorted(product((0, 1), repeat=variable_count), key=lambda bits: (qubo_value(bits, qubo), bits))
    for bits in ranked:  # explicit feasibility validation is mandatory
        selected = {actions[i].action_id for i, bit in enumerate(bits) if bit}
        result = evaluate(selected, paths, actions)
        if result.feasible:
            return Plan(**{**result.__dict__, "solver": "qubo-validated"})
    return solve_exact(paths, actions)
