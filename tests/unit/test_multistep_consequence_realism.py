from __future__ import annotations

import json
from pathlib import Path

from scripts.generate_multistep_realism_dataset import rollout
from sentinel_ai.shield.consequence_simulator import (MultiStepConsequenceEnvironment,
                                                       SimulatedAction, continuation_action)


def test_recovery_cost_and_rollback_restore_service_and_attacker_access() -> None:
    environment = MultiStepConsequenceEnvironment("credential-compromise", 65001)
    isolated = environment.step(SimulatedAction("ISOLATE_DEVICE", approved=True))
    health_after_isolation = environment.state.service_health
    assert isolated.recovery_task_count > 0
    assert health_after_isolation < 1
    rolled_back = environment.step(SimulatedAction("ROLLBACK", approved=True))
    assert rolled_back.recovery_cost > 0
    assert environment.state.service_health > health_after_isolation
    assert rolled_back.accessible_route_count_gt > 0


def test_delayed_adaptation_is_reproducible_and_not_immediate() -> None:
    _, first, targets, _ = rollout("credential-compromise", 65001, "REQUIRE_FRESH_MFA",
                                   "immediate_containment", 5)
    _, second, repeated, _ = rollout("credential-compromise", 65001, "REQUIRE_FRESH_MFA",
                                     "immediate_containment", 5)
    assert not first[0].attacker_adapted_gt
    assert any(record.attacker_adapted_gt for record in first[1:])
    assert targets["target_delayed_adaptation"] == 1
    assert first == second and targets == repeated


def test_severe_outcomes_and_containment_timing_follow_state_sequences() -> None:
    _, severe_records, severe, _ = rollout("credential-compromise", 65001, "NO_OP", "observation_only", 5)
    _, contained_records, contained, _ = rollout("credential-compromise", 65001, "DISABLE_ACCOUNT",
                                                  "observation_only", 5)
    assert severe["target_severe_outcome"] == 1
    assert not any(record.severe_outcome_gt for record in severe_records[:-1])
    assert severe_records[-1].severe_outcome_gt
    assert contained["target_severe_outcome"] == 0
    assert contained["target_time_to_containment"] == 4
    assert contained_records[-1].genuinely_contained_gt


def test_continuation_policy_uses_observation_contract_and_enforces_policy_constraint() -> None:
    environment = MultiStepConsequenceEnvironment("lateral-movement", 65002)
    observation = environment.observe()
    action = continuation_action("policy_constrained", observation, 0, ())
    assert action.action_type in {"REQUIRE_FRESH_MFA", "REVOKE_SESSION"}
    assert set(observation.__dataclass_fields__) == {"tick", "family", "service_health", "workflow_slo_met",
        "observed_compromise", "observed_malicious_activity", "evidence_count", "recovery_active", "terminal"}
    denied = environment.step(SimulatedAction("ISOLATE_DEVICE", approved=False))
    assert not denied.action_valid


def test_counterfactual_environments_are_independent_and_matched() -> None:
    left = MultiStepConsequenceEnvironment("malicious-insider", 65003)
    right = MultiStepConsequenceEnvironment("malicious-insider", 65003)
    assert left.state == right.state and left.state is not right.state
    left.step(SimulatedAction("SEGMENT_SERVICE", approved=True))
    assert right.state.tick == 0 and right.history == []
    right.step(SimulatedAction("SEGMENT_SERVICE", approved=True))
    assert left.history == right.history and left.state == right.state


def test_frozen_pilot_and_release_pass_diversity_contract() -> None:
    root = Path(__file__).resolve().parents[2] / "data/processed/shield_multistep_v2"
    pilot = json.loads((root / "pilot_report.json").read_text(encoding="utf-8"))
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert pilot["passed"] and manifest["quality"]["passed"]
    assert all(pilot["checks"].values())
    assert manifest["historical_phase6_preserved"] is True

