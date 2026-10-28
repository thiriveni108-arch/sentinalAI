from __future__ import annotations

from dataclasses import asdict

import pytest

from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import ActionStatus, ApprovalTier, AttackOutcome, DefenderAction, TerminalReason


def action(action_id: str, action_type: str, effectiveness: float, *targets: str, reversible: bool = True) -> DefenderAction:
    return DefenderAction(action_id, action_type, tuple(targets), {"forced_effectiveness": effectiveness}, reversible=reversible)


def test_reset_exposes_observation_but_keeps_attacker_ground_truth_separate() -> None:
    environment = DynamicShieldEnvironment(stochastic=False)
    observation = environment.reset("credential-compromise", seed=11)
    assert observation.scenario_family == "credential-compromise"
    assert environment.ground_truth().strategy_id == "credential-compromise-v2"
    assert not any(key.endswith("_gt") for key in asdict(observation))
    assert "attacker_footholds_gt" not in asdict(observation)


def test_full_partial_and_failed_containment_have_distinct_causal_results() -> None:
    full = DynamicShieldEnvironment(stochastic=False)
    full.reset("credential-compromise", seed=12)
    contained = full.step(action("revoke", "REVOKE_SESSION", 1.0, "session:suspicious"))
    assert contained.action_result.status == ActionStatus.EXECUTED
    assert contained.attack_outcome == AttackOutcome.CONTAINED
    assert contained.remaining_attack_path_exposure == 0

    partial = DynamicShieldEnvironment(stochastic=False)
    partial.reset("lateral-movement", seed=12)
    reduced = partial.step(action("segment", "SEGMENT_SERVICE", 0.5, "service:admin"))
    assert reduced.action_result.status == ActionStatus.PARTIAL
    assert reduced.attack_outcome == AttackOutcome.PARTIALLY_CONTAINED
    assert 0 < reduced.remaining_attack_path_exposure < 1

    failed = DynamicShieldEnvironment(stochastic=False)
    failed.reset("credential-compromise", seed=12)
    unchanged = failed.step(action("revoke", "REVOKE_SESSION", 0.1, "session:suspicious"))
    assert unchanged.action_result.status == ActionStatus.FAILED
    assert unchanged.remaining_attack_path_exposure == 1
    assert unchanged.next_state.attack_goal_progress_gt > unchanged.current_state.attack_goal_progress_gt


def test_attacker_switches_route_after_partial_containment() -> None:
    environment = DynamicShieldEnvironment(stochastic=False)
    environment.reset("lateral-movement", seed=21)
    initial_route = environment.state.current_attack_path_gt
    transition = environment.step(action("segment", "SEGMENT_SERVICE", 0.5, "service:admin"))
    assert transition.attacker_strategy_gt is not None
    assert transition.attacker_strategy_gt["adapted"] is True
    assert transition.attacker_strategy_gt["selected_path"] != initial_route


def test_business_disruption_is_state_derived_and_rollback_restores_service() -> None:
    environment = DynamicShieldEnvironment(stochastic=False)
    environment.reset("lateral-movement", seed=22)
    disrupted = environment.step(action("segment", "SEGMENT_SERVICE", 0.9, "service:admin"))
    assert disrupted.legitimate_workflow_disruption > 0
    assert "segment" in disrupted.next_state.recoverable_action_ids
    recovered = environment.step(DefenderAction("undo-segment", "ROLLBACK", ("segment",)))
    assert recovered.action_result.status == ActionStatus.EXECUTED
    assert recovered.recovery_cost == 0.25
    assert recovered.legitimate_workflow_disruption < disrupted.legitimate_workflow_disruption


def test_post_action_observation_is_generated_from_next_tick() -> None:
    environment = DynamicShieldEnvironment(stochastic=False)
    environment.reset("malicious-insider", seed=23)
    transition = environment.step(DefenderAction("observe", "NO_OP"))
    assert transition.next_observation
    assert all(item.event_tick == transition.next_state.tick for item in transition.next_observation)
    assert transition.next_observation != transition.observed_evidence
    assert transition.next_state.observed_compromise_probability != transition.current_state.observed_compromise_probability


def test_invalid_actions_are_denied_but_time_and_attacker_continue() -> None:
    environment = DynamicShieldEnvironment(stochastic=False)
    environment.reset("privilege-escalation", seed=24)
    transition = environment.step(DefenderAction("bad", "LIVE_SHELL_COMMAND", ()))
    assert transition.action_result.status == ActionStatus.DENIED
    assert transition.action_result.effectiveness is None
    assert transition.next_state.tick == 1
    assert transition.next_state.attack_goal_progress_gt > transition.current_state.attack_goal_progress_gt


def test_prerequisites_and_approval_are_enforced_without_live_action() -> None:
    approval = DynamicShieldEnvironment(stochastic=False)
    approval.reset("credential-compromise", seed=240)
    denied = approval.step(DefenderAction(
        "disable", "DISABLE_ACCOUNT", ("user:employee",), approval_tier=ApprovalTier.MANUAL_ONLY,
        approved=False, reversible=False,
    ))
    assert denied.action_result.status == ActionStatus.DENIED
    assert denied.approval_status == "DENIED"

    prerequisite = DynamicShieldEnvironment(stochastic=False)
    prerequisite.reset("privilege-escalation", seed=241)
    unmet = prerequisite.step(DefenderAction(
        "remove", "REMOVE_PRIVILEGE", ("privilege:ops",), prerequisites=("investigation-approved",)
    ))
    assert unmet.action_result.status == ActionStatus.DENIED
    assert unmet.prerequisites_satisfied is False


def test_same_action_has_different_outcome_in_different_environment_state() -> None:
    credential = DynamicShieldEnvironment(stochastic=False)
    credential.reset("credential-compromise", seed=25)
    one_route = credential.step(action("segment", "SEGMENT_SERVICE", 0.9, "service:any"))
    lateral = DynamicShieldEnvironment(stochastic=False)
    lateral.reset("lateral-movement", seed=25)
    two_routes = lateral.step(action("segment", "SEGMENT_SERVICE", 0.9, "service:admin"))
    assert one_route.attack_outcome == AttackOutcome.CONTAINED
    assert two_routes.attack_outcome == AttackOutcome.PARTIALLY_CONTAINED


def test_reproducibility_and_state_continuity() -> None:
    def run():
        environment = DynamicShieldEnvironment(stochastic=True)
        environment.reset("sensitive-data-exfiltration", seed=919)
        first = environment.step(DefenderAction("watch", "NO_OP"))
        second = environment.step(action("export-off", "DISABLE_BULK_EXPORT", 0.55, "file:designs"))
        return first, second

    left, right = run(), run()
    assert [item.to_v2_dict() for item in left] == [item.to_v2_dict() for item in right]
    assert left[0].next_state_id == left[1].current_state_id


def test_benign_and_horizon_termination_are_explicit() -> None:
    benign = DynamicShieldEnvironment(stochastic=False)
    benign.reset("benign-alert", seed=31)
    resolved = benign.step(DefenderAction("observe", "NO_OP"))
    assert resolved.terminal_reason == TerminalReason.BENIGN_RESOLVED
    assert resolved.attack_outcome == AttackOutcome.NO_ATTACK
    with pytest.raises(RuntimeError, match="terminal"):
        benign.step(DefenderAction("again", "NO_OP"))
    bounded = DynamicShieldEnvironment(max_steps=1, stochastic=False)
    bounded.reset("malicious-insider", seed=32)
    assert bounded.step(DefenderAction("observe", "NO_OP")).terminal_reason == TerminalReason.MAX_STEPS


def test_transition_record_contains_approved_v2_core_fields() -> None:
    environment = DynamicShieldEnvironment(stochastic=False)
    environment.reset("privilege-escalation", seed=33)
    record = environment.step(DefenderAction("observe", "NO_OP")).to_v2_dict()
    expected = {
        "dataset_version", "generator_version", "episode_id", "time_step", "transition_id", "topology_id",
        "scenario_family", "current_state_id", "current_state", "observed_evidence", "attacker_strategy_gt",
        "defender_action", "action_result", "action_prerequisites", "prerequisites_satisfied", "approval_tier",
        "approval_status", "next_state_id", "next_state", "next_observation",
        "remaining_attack_path_exposure", "legitimate_workflow_disruption", "attack_outcome",
        "response_reversible", "recovery_cost", "incident_unresolved", "terminal", "terminal_reason",
        "ground_truth_incident_label", "transition_random_draw_id", "verification_status", "label_provenance",
        "evidence_source",
    }
    assert expected == set(record)


def test_all_bounded_attacker_families_execute() -> None:
    families = ("credential-compromise", "malicious-insider", "lateral-movement",
                "sensitive-data-exfiltration", "privilege-escalation")
    for family in families:
        environment = DynamicShieldEnvironment(stochastic=False)
        observation = environment.reset(family, seed=44)
        transition = environment.step(DefenderAction("observe", "NO_OP"))
        assert observation.scenario_family == family
        assert transition.attacker_strategy_gt is not None
        assert transition.next_state.attack_goal_progress_gt > transition.current_state.attack_goal_progress_gt
