"""Matched realized decision-quality comparison for Phase 9.6 predictors."""
from __future__ import annotations
import json
from pathlib import Path
from statistics import mean, stdev
from time import perf_counter
import joblib
import pandas as pd

from generate_graph_consequence_dataset import rollout
from sentinel_ai.shield.adaptive_planner import PlanningWeights, make_problem, run_qaoa, solve_exact
from sentinel_ai.shield.consequence_predictor import GraphAwareConsequencePredictor
from sentinel_ai.shield.graph_integration import graph_action_specs, visible_graph_state
from sentinel_ai.shield.consequence_simulator import MultiStepConsequenceEnvironment
from sentinel_ai.shield.topology import topology_variant


def actual_score(targets, action):
    costs = {item.name: item.cost for item in graph_action_specs()}; w = PlanningWeights()
    return (w.security_damage * targets["target_unresolved"] + w.exposure * targets["target_cumulative_exposure"] / 5 +
            w.disruption * targets["target_cumulative_disruption"] / 5 + w.recovery * targets["target_recovery_burden"] +
            w.severe_tail * targets["target_severe_outcome"] + w.action_cost * costs[action])


def evaluate(predictor, rows, solver="exact"):
    outcomes=[]; actions=tuple(item for item in graph_action_specs() if item.tier == "automatic")
    for _, item in rows.iterrows():
        env=MultiStepConsequenceEnvironment("credential-compromise" if item.incident_family == "benign" else item.incident_family, int(item.seed), max_steps=5, topology=topology_variant(item.topology_family, int(item.topology_variant)))
        visible=visible_graph_state(env)
        problem=make_problem(predictor, visible, actions, ("observation_only","minimally_disruptive","policy_constrained"), allowed_tier="automatic")
        plan,_=(run_qaoa(problem, shots=64, seed=7301) if solver == "qaoa" else (solve_exact(problem), {}))
        _,_,chosen=rollout(item.topology_family, int(item.topology_variant), item.incident_family, int(item.seed), plan.action, plan.policy)
        alternatives=[]
        for candidate in actions:
            for policy in problem.policies:
                _,_,target=rollout(item.topology_family, int(item.topology_variant), item.incident_family, int(item.seed), candidate.name, policy)
                alternatives.append((actual_score(target, candidate.name), target))
        optimum=min(score for score,_ in alternatives)
        outcomes.append({"topology":item.topology_family,"incident":item.incident_family,"action":plan.action,"policy":plan.policy,
                         "contained":int(chosen["target_unresolved"] == 0),"severe":chosen["target_severe_outcome"],"exposure":chosen["target_cumulative_exposure"],
                         "disruption":chosen["target_cumulative_disruption"],"recovery":chosen["target_recovery_burden"],"time_to_containment":chosen["target_time_to_containment"],
                         "regret":actual_score(chosen,plan.action)-optimum})
    metrics=("contained","severe","exposure","disruption","recovery","time_to_containment","regret")
    return {key:{"mean":mean(x[key] for x in outcomes),"std":stdev([x[key] for x in outcomes]) if len(outcomes)>1 else 0.,"n":len(outcomes)} for key in metrics}|{"episodes":outcomes}


def main():
    data=pd.read_parquet("data/processed/shield_graph_consequence_v1/model_table.parquet")
    # One row per matched initial condition; all candidate branches share it.
    held=data[data.split == "test"].drop_duplicates("initial_condition_id").sort_values("initial_condition_id")
    learned=joblib.load("artifacts/models/shield_graph_consequence_v1.joblib")
    report={"version":"shield-phase96-decision-quality-v1","research_only":True,"quantum_advantage_claimed":False,
            "protocol":"same held-out initial conditions, candidate actions, continuation policies, constraints and matched seed/tick randomness"}
    report["learned_graph_exact"]=evaluate(learned, held, "exact")
    # QAOA remains bounded and is evaluated on a deterministic, documented subset.
    report["learned_graph_qaoa_diagnostic"]=evaluate(learned, held.iloc[:4], "qaoa")
    old=Path("artifacts/models/shield_phase7_consequence_v1.joblib")
    if old.exists():
        base=joblib.load(old)
        report["frozen_phase7_exact_diagnostic"]=evaluate(base, held, "exact")
        # The Phase 9.5 heuristic is retained only as a comparison, not promoted.
        heuristic_rows=[]
        for topology in held.topology_family.unique():
            part=held[held.topology_family == topology]
            heuristic_rows.extend(evaluate(GraphAwareConsequencePredictor(base, topology_variant(topology, 0)), part, "exact")["episodes"])
        metrics=("contained","severe","exposure","disruption","recovery","time_to_containment","regret")
        report["phase95_heuristic_exact_diagnostic"]={key:{"mean":mean(x[key] for x in heuristic_rows),"std":stdev([x[key] for x in heuristic_rows]),"n":len(heuristic_rows)} for key in metrics}
    else: report["frozen_phase7_exact_diagnostic"]={"status":"unavailable"}
    target=Path("artifacts/reports/shield_phase96_decision_quality_v1.json"); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report,indent=2))


if __name__ == "__main__": main()
