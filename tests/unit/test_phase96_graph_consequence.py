from __future__ import annotations

from scripts.generate_graph_consequence_dataset import generate
from sentinel_ai.shield.adaptive_planner import make_problem, solve_exact
from sentinel_ai.shield.autonomous_defense import Actor, DefenseCoordinator, DefenseStore, Proposal, Status
from sentinel_ai.shield.consequence_predictor import GraphConsequencePredictor
from sentinel_ai.shield.consequence_simulator import MultiStepConsequenceEnvironment
from sentinel_ai.shield.graph_integration import graph_action_specs, visible_graph_state
from sentinel_ai.shield.topology import grouped_split, topology_variant


def test_graph_dataset_has_group_isolation_visible_features_and_counterfactuals() -> None:
    frame, transitions = generate(variants=2, seeds_per_variant=1)
    predictor = GraphConsequencePredictor(trees=20).fit(frame)
    assert frame.initial_condition_id.nunique() * 54 == len(frame)
    assert (frame.groupby("topology_family").split.nunique() == 1).all()
    assert not any("_gt" in feature or "route" in feature for feature in predictor.features)
    assert {"target_severe_outcome", "target_unresolved"}.issubset(frame)
    assert len(transitions) >= len(frame)


def test_graph_predictor_features_are_decision_time_and_planner_consumes_them() -> None:
    frame, _ = generate(variants=2, seeds_per_variant=1); predictor = GraphConsequencePredictor(trees=20).fit(frame)
    environment = MultiStepConsequenceEnvironment("credential-compromise", 96501, topology=topology_variant("small-office", 1))
    visible = visible_graph_state(environment)
    prediction, diagnostic = predictor.predict_with_diagnostics(visible, "REVOKE_SESSION", "policy_constrained")
    assert prediction.means["target_cumulative_exposure"] >= 0 and "attacker_progress_gt" not in visible
    assert diagnostic["model_version"] == predictor.model_version
    plan = solve_exact(make_problem(predictor, visible, graph_action_specs(), ("policy_constrained",), allowed_tier="automatic"))
    assert plan.feasible and plan.action in {item.name for item in graph_action_specs() if item.tier == "automatic"}


def test_graph_phase8_lifecycle_uses_target_scope_and_json_stable_snapshot(tmp_path) -> None:
    environment = MultiStepConsequenceEnvironment("credential-compromise", 96502, topology="small-office")
    proposal = Proposal("graph-incident", "DISABLE_BULK_EXPORT", ("office-session",), 0, "graph-test",
                        {"target_cumulative_disruption": .12, "operationally_suitable": False, "out_of_distribution": False},
                        .1, target_criticality=5, blast_radius=1, reversible=True, recovery_plan=True)
    coordinator = DefenseCoordinator(DefenseStore(tmp_path / "graph.sqlite")); record = coordinator.propose(proposal, "graph-idempotency", environment)
    assert record["status"] == Status.PENDING_HUMAN
    coordinator.approve(record["proposal_id"], Actor("human", "human_authorizer"), "approve")
    result = coordinator.execute(record["proposal_id"], Actor("human", "human_authorizer"))
    assert result["status"] != Status.POLICY_BLOCKED
    assert result["execution"]["actual"]["action_type"] == "DISABLE_BULK_EXPORT"
