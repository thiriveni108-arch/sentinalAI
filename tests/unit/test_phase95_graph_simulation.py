from __future__ import annotations

from sentinel_ai.shield.adaptive_planner import ActionSpec, make_problem, solve_exact
from sentinel_ai.shield.consequence_predictor import ConsequencePrediction, GraphAwareConsequencePredictor
from sentinel_ai.shield.consequence_simulator import MultiStepConsequenceEnvironment, SimulatedAction
from sentinel_ai.shield.qrl import ShieldRLEnvironment
from sentinel_ai.shield.topology import TOPOLOGY_FAMILIES, grouped_split, topology_scenario


class FlatPredictor:
    features = ("state_tick", "service_health", "observed_compromise", "observed_malicious_activity", "evidence_count")
    def predict(self, visible, candidate, policy):
        means = {"target_cumulative_exposure": 5.0, "target_cumulative_disruption": 0.0,
                 "target_recovery_burden": 0.0, "target_time_to_containment": 3.0,
                 "target_severe_outcome": 1.0, "target_delayed_adaptation": 0.0, "target_unresolved": 1.0}
        return ConsequencePrediction(means, {key: 0.0 for key in means})


def test_topology_families_are_structurally_distinct_and_grouped() -> None:
    scenarios = [topology_scenario(name) for name in TOPOLOGY_FAMILIES]
    shapes = {(len(x.nodes), len(x.connections), len(x.routes), len(x.workflows)) for x in scenarios}
    assert len(shapes) >= 4
    split = grouped_split()
    assert set(split["train"]).isdisjoint(split["test"]) and set(split["validation"]).isdisjoint(split["test"])


def test_graph_action_blocks_only_its_routes_and_containment_checks_all_routes() -> None:
    env = MultiStepConsequenceEnvironment("lateral-movement", 11, topology="redundant-services")
    transition = env.step(SimulatedAction("SEGMENT_SERVICE", targets=("primary-api",)))
    assert transition.accessible_route_count_gt == 0
    assert "admin-api" in env.state.latent_routes_gt and not transition.genuinely_contained_gt
    # The delayed attacker may use a remaining valid graph route; a blocked route is not containment.
    env.step(SimulatedAction("NO_OP")); later = env.step(SimulatedAction("NO_OP"))
    assert later.attacker_adapted_gt or env.state.latent_routes_gt


def test_workflow_dependencies_drive_business_disruption_and_selective_recovery() -> None:
    env = MultiStepConsequenceEnvironment("credential-compromise", 12, topology="redundant-services")
    isolated = env.step(SimulatedAction("ISOLATE_DEVICE", targets=("portal",)))
    assert isolated.disruption > .5
    assert "portal" in env.state.disabled_nodes_gt
    env.step(SimulatedAction("ROLLBACK"))
    assert "portal" not in env.state.disabled_nodes_gt
    # No task can restore the unrelated administration route.
    assert "admin-api" not in env.state.accessible_routes_gt


def test_graph_context_is_visible_but_oracle_routes_are_not() -> None:
    env = ShieldRLEnvironment(graph_features=True)
    observation, info = env.reset(13, "lateral-movement", topology="segmented-enterprise")
    assert len(observation) == 19 and info["ground_truth_exposed"] is False
    assert all(not isinstance(value, str) for value in observation)
    assert "corp-vpn" not in repr(observation) and "attacker_progress_gt" not in repr(info)


def test_topology_changes_existing_planner_objective_for_explicit_reason() -> None:
    actions = (ActionSpec("REVOKE_SESSION", .25), ActionSpec("RESTRICT_RESOURCE", .55))
    visible = {"state_tick": 0., "service_health": 1., "observed_compromise": .62,
               "observed_malicious_activity": 1., "evidence_count": 1.}
    office = solve_exact(make_problem(GraphAwareConsequencePredictor(FlatPredictor(), topology_scenario("small-office")), visible, actions, ("policy_constrained",)))
    redundant = solve_exact(make_problem(GraphAwareConsequencePredictor(FlatPredictor(), topology_scenario("redundant-services")), visible, actions, ("policy_constrained",)))
    assert office.action != redundant.action
    assert office.components["disruption"] != redundant.components["disruption"]
