from __future__ import annotations

import math

from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.downstream import (TARGET_COLUMNS, counterfactual_rollout,
                                           rollout_targets)
from sentinel_ai.shield.downstream_service import DownstreamConsequenceService
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction
from sentinel_ai.shield.world_dataset import feature_columns


def test_counterfactual_branches_are_isolated_and_share_initial_condition() -> None:
    left = counterfactual_rollout("credential-compromise", 63001, "NO_OP", warmup_steps=1)
    right = counterfactual_rollout("credential-compromise", 63001, "REVOKE_SESSION", warmup_steps=1)
    assert left.initial_state_fingerprint == right.initial_state_fingerprint
    assert left.branch_id != right.branch_id
    assert left.records[0].current_state is not right.records[0].current_state
    assert left.records[0].current_state.service_health is not right.records[0].current_state.service_health
    repeated = counterfactual_rollout("credential-compromise", 63001, "NO_OP", warmup_steps=1)
    assert repeated.targets == left.targets
    assert [record.to_v2_dict() for record in repeated.records] == [record.to_v2_dict() for record in left.records]


def test_rollout_targets_are_exact_transition_aggregates() -> None:
    rollout = counterfactual_rollout("lateral-movement", 63002, "SEGMENT_SERVICE")
    targets = rollout_targets(rollout.records, 4)
    assert math.isclose(targets["target_cumulative_exposure"],
                        sum(record.remaining_attack_path_exposure for record in rollout.records))
    assert math.isclose(targets["target_cumulative_disruption"],
                        sum(record.legitimate_workflow_disruption for record in rollout.records))
    assert targets["target_unresolved_at_horizon"] == int(rollout.records[-1].incident_unresolved)
    assert set(targets) == set(TARGET_COLUMNS)


def test_phase6_features_preserve_observability_boundary() -> None:
    columns = feature_columns(True)
    assert not set(columns) & set(TARGET_COLUMNS)
    assert not any("_gt" in column or column.startswith("next_") or "outcome" in column or
                   "forced_effectiveness" in column for column in columns)


def test_read_only_score_is_bounded_and_marks_unsupported_targets() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False, topology_variation=True,
                                                                         attacker_progress_scale=.22))
    observation, belief = combined.reset("credential-compromise", seed=63001, episode_id="phase6-score")
    before = combined.environment.state
    score = DownstreamConsequenceService().predict(observation, belief, DefenderAction("no-op", "NO_OP"))
    assert score.available and score.applicable
    assert combined.environment.state == before
    assert 0 <= score.consequences["expected_cumulative_security_exposure"] <= 4
    assert 0 <= score.consequences["expected_cumulative_operational_disruption"] <= 2.47
    assert 0 <= score.consequences["attacker_adaptation_probability"] <= 1
    assert 0 <= score.consequences["unresolved_at_horizon_probability"] <= 1
    assert score.consequences["severe_outcome_risk"] is None
    assert score.consequences["expected_recovery_burden"] is None
    assert score.validation_status["target_severe_residual_damage"] == "unsupported_constant"
    assert any("no response action was executed" in warning.lower() for warning in score.warnings)

