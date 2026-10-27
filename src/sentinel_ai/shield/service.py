from __future__ import annotations

from dataclasses import asdict
from time import perf_counter

from .optimizer import solve_exact, solve_greedy
from .paths import enumerate_attack_paths
from .policy import recommendation
from .quantum import run_qaoa, run_qaoa_experiment
from .scenarios import scenarios
from .simulator import simulate


class ShieldService:
    """Pure, deterministic advisory service. It performs no persistence or actions."""

    def list_scenarios(self) -> list[dict]:
        return [{"scenarioId": s.scenario_id, "name": s.name, "summary": s.summary,
                 "riskScore": s.risk_score, "threatClassification": s.threat_classification}
                for s in scenarios().values()]

    def analyze(self, scenario_id: str, include_quantum: bool = True) -> dict:
        scenario = scenarios().get(scenario_id)
        if scenario is None:
            raise KeyError(scenario_id)
        return self.analyze_scenario(scenario, include_quantum)

    def analyze_scenario(self, scenario, include_quantum: bool = True) -> dict:
        """Analyze a validated static or incident-associated modeled scenario."""
        started = perf_counter()
        paths = enumerate_attack_paths(scenario)
        exact = solve_exact(paths, scenario.actions)
        scalable = solve_greedy(paths, scenario.actions)
        qaoa_plan, quantum = run_qaoa(paths, scenario.actions) if include_quantum else (exact, {"executed": False, "fallbackUsed": True, "disclosure": "Quantum execution skipped."})
        production_safe = exact  # validated reference is authoritative
        broad = next(action for action in scenario.actions if action.action_type == "DISABLE_ACCOUNT")
        comparisons = [
            simulate(paths, scenario.actions, set(), "Monitor Only"),
            simulate(paths, scenario.actions, {broad.action_id}, "Broad Containment"),
            simulate(paths, scenario.actions, set(production_safe.selected), "SHIELD Optimized"),
        ]
        max_criticality = max((path.criticality for path in paths), default=0)
        selected_actions = [action for action in scenario.actions if action.action_id in production_safe.selected]
        return {
            "scenario": {"scenarioId": scenario.scenario_id, "name": scenario.name, "summary": scenario.summary,
                         "riskScore": scenario.risk_score, "threatClassification": scenario.threat_classification,
                         "evidence": list(scenario.evidence),
                         "affectedAssets": [n.label for n in scenario.nodes if n.sensitivity >= 3]},
            "graph": {"nodes": [asdict(n) for n in scenario.nodes], "edges": [asdict(e) for e in scenario.edges],
                      "entryPoints": list(scenario.entry_points), "boundedMaxDepth": 6, "boundedMaxPaths": 32},
            "attackPaths": [asdict(path) for path in paths],
            "candidateActions": [asdict(action) for action in scenario.actions],
            "recommendation": {"selectedActions": [asdict(action) for action in selected_actions],
                               "feasible": production_safe.feasible, "objectiveValue": production_safe.objective,
                               "businessDisruptionCost": production_safe.disruption_cost,
                               "remainingCriticalPaths": list(production_safe.remaining_paths),
                               "approvalRequired": any(a.approval_required for a in selected_actions) or bool(selected_actions),
                               "advisoryOnly": True},
            "solvers": {"exact": asdict(exact), "scalable": asdict(scalable), "qaoaCandidate": asdict(qaoa_plan)},
            "quantum": quantum,
            "counterfactuals": comparisons,
            "decisionPolicy": recommendation(scenario.risk_score, len(scenario.evidence), max_criticality,
                                             all(a.reversible for a in selected_actions), production_safe.feasible)
                              if scenario.risk_score is not None else {
                                  "recommendation": "Analyst review required",
                                  "reasoning": ["No numerical incident risk score is invented for the CERT exercise.",
                                                "Exact classical feasibility is authoritative for this modeled scenario."],
                              },
            "limitations": ["Attack-path enumeration is bounded and cannot prove absence of unmodeled routes.",
                            "Effects depend on the explicit token, authorization, and enforcement assumptions shown per action.",
                            "All actions are simulations; no production identity, endpoint, network, or data control is changed.",
                            "Quantum output is experimental and never bypasses classical feasibility validation."],
            "executionTimeMs": round((perf_counter() - started) * 1000, 2),
        }

    def benchmark(self, include_quantum: bool = False) -> dict:
        rows = []
        for scenario_id in scenarios():
            result = self.analyze(scenario_id, include_quantum=include_quantum)
            options = {item["label"]: item for item in result["counterfactuals"]}
            rows.append({"scenarioId": scenario_id, "thresholdPolicy": options["Broad Containment"],
                         "classicalShield": options["SHIELD Optimized"], "quantum": result["quantum"],
                         "latencyMs": result["executionTimeMs"]})
        return {"synthetic": True, "scenarioCount": len(rows), "results": rows,
                "disclosure": "Deterministic synthetic benchmark; not real-world deployment performance."}

    def quantum_experiment(self, scenario_id: str) -> dict:
        scenario = scenarios().get(scenario_id)
        if scenario is None:
            raise KeyError(scenario_id)
        paths = enumerate_attack_paths(scenario)
        return run_qaoa_experiment(paths, scenario.actions)
