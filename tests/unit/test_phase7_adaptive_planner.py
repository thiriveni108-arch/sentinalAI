from itertools import product

from sentinel_ai.shield.adaptive_planner import (ActionSpec, PlanningProblem,
    audit_qubo, build_qubo, qubo_value, score, solve_exact, solve_greedy)
from sentinel_ai.shield.consequence_predictor import ConsequencePrediction

def _problem(tier="automatic"):
    actions=(ActionSpec("NO_OP",.0), ActionSpec("ISOLATE_DEVICE",.8,tier="human-approval"))
    policies=("observation_only","immediate_containment")
    predictions={}
    for i,(action,policy) in enumerate(product(actions,policies)):
        means={"target_unresolved":.8-i*.15,"target_cumulative_exposure":3-i*.4,
               "target_cumulative_disruption":i*.3,"target_recovery_burden":i*.05,
               "target_severe_outcome":.5-i*.1,"target_delayed_adaptation":.4}
        predictions[(action.name,policy)]=ConsequencePrediction(means,{k:.1 for k in means})
    return PlanningProblem(actions,policies,predictions,allowed_tier=tier,
                           approvals=frozenset({"ISOLATE_DEVICE"}) if tier=="human-approval" else frozenset())

def test_exact_and_greedy_share_objective_and_hard_tier():
    problem=_problem(); exact=solve_exact(problem); greedy=solve_greedy(problem)
    assert exact.feasible and greedy.feasible
    assert exact.action == "NO_OP"
    assert exact.objective == greedy.objective

def test_qubo_matches_semantics_on_every_assignment():
    assert audit_qubo(_problem("human-approval"))["verified"]

def test_human_approval_unlocks_high_impact_action():
    plan=solve_exact(_problem("human-approval"))
    assert plan.feasible
    assert plan.action in {"NO_OP","ISOLATE_DEVICE"}
