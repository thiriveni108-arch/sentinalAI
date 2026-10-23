from dataclasses import replace
from itertools import product

from sentinel_ai.shield.models import Scenario, ShieldEdge, ShieldNode
from sentinel_ai.shield.optimizer import audit_qubo, build_qubo, evaluate, qubo_value, reference_qubo_value, solve_exact
from sentinel_ai.shield.paths import enumerate_attack_paths
from sentinel_ai.shield.scenarios import scenarios
from sentinel_ai.shield.service import ShieldService


def test_multiple_routes_require_complete_plan():
    scenario = scenarios()["multiple-routes"]
    paths = enumerate_attack_paths(scenario)
    assert len(paths) == 2
    cheap = evaluate({"disable-finance-export"}, paths, scenario.actions)
    assert not cheap.feasible
    plan = solve_exact(paths, scenario.actions)
    assert plan.feasible
    assert plan.selected == ("disable-finance-export", "remove-ops-role")
    assert plan.objective == 3
    chosen = [action for action in scenario.actions if action.action_id in plan.selected]
    assert {path.path_id for action in chosen for path in paths if path.path_id in action.interrupts} == {path.path_id for path in paths}
    assert all(action.assumptions for action in chosen)


def test_path_enumeration_respects_direction_semantics_and_cycles():
    scenario = scenarios()["credential-compromise"]
    extra = (
        ShieldEdge("privilege:analyst", "session:suspicious", "CAN_ACCESS", True, False),
        ShieldEdge("database:customer", "session:suspicious", "VISUAL_ASSOCIATION", True, False),
    )
    paths = enumerate_attack_paths(replace(scenario, edges=scenario.edges + extra), max_depth=5)
    assert len(paths) == 1
    assert paths[0].nodes[-1] == "database:customer"


def test_qubo_global_minima_decode_to_exact_feasible_cost():
    scenario = scenarios()["multiple-routes"]
    paths = enumerate_attack_paths(scenario)
    qubo, _ = build_qubo(paths, scenario.actions)
    count = 1 + max(max(pair) for pair in qubo)
    values = [(qubo_value(bits, qubo), bits) for bits in product((0, 1), repeat=count)]
    minimum = min(value for value, _ in values)
    decoded = []
    for value, bits in values:
        if value == minimum:
            decoded.append(evaluate({a.action_id for i, a in enumerate(scenario.actions) if bits[i]}, paths, scenario.actions))
    assert all(item.feasible for item in decoded)
    assert all(item.objective == solve_exact(paths, scenario.actions).objective for item in decoded)


def test_every_qubo_energy_matches_independent_semantic_reference():
    for scenario in scenarios().values():
        paths = enumerate_attack_paths(scenario)
        qubo, penalty = build_qubo(paths, scenario.actions)
        count = 1 + max(max(pair) for pair in qubo)
        saw_feasible = saw_violation = False
        for bits in product((0, 1), repeat=count):
            expected, residual, penalty_satisfied = reference_qubo_value(bits, paths, scenario.actions, penalty)
            assert abs(qubo_value(bits, qubo) - expected) < 1e-9
            saw_feasible |= penalty_satisfied
            saw_violation |= residual > 0
        assert saw_feasible and saw_violation
        audit = audit_qubo(paths, scenario.actions)
        assert audit["energyMismatches"] == 0
        assert audit["bitstringsChecked"] == 2 ** count


def test_counterfactuals_are_isolated_and_deterministic():
    service = ShieldService()
    first = service.analyze("multiple-routes", include_quantum=False)
    second = service.analyze("multiple-routes", include_quantum=False)
    assert first["recommendation"] == second["recommendation"]
    assert first["counterfactuals"][0]["remainingPaths"] == second["counterfactuals"][0]["remainingPaths"]
    assert first["counterfactuals"][0]["feasible"] is False
    assert first["counterfactuals"][2]["feasible"] is True


def test_all_scenarios_return_safe_advisory_plans():
    service = ShieldService()
    for item in service.list_scenarios():
        result = service.analyze(item["scenarioId"], include_quantum=False)
        assert result["recommendation"]["feasible"]
        assert result["recommendation"]["advisoryOnly"]
        assert result["recommendation"]["remainingCriticalPaths"] == []
