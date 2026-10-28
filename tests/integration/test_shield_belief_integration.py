from __future__ import annotations

from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.beliefs import AttackerMode
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction


def test_complete_phase2_episode_updates_chronological_belief_history() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(max_steps=3, stochastic=False))
    observation, initial = combined.reset("lateral-movement", seed=61, episode_id="belief-integration")
    first = combined.step(DefenderAction("watch-1", "NO_OP"))
    second = combined.step(DefenderAction("watch-2", "NO_OP"))
    third = combined.step(DefenderAction("watch-3", "NO_OP"))

    assert observation.time_step == 0
    assert initial.time_step == 0
    assert third.transition.terminal
    assert [entry.time_step for entry in combined.tracker.history()] == [0, 1, 2, 3]
    assert first.posterior.episode_id == second.posterior.episode_id == third.posterior.episode_id
    assert all(abs(sum(entry.posterior.values()) - 1) < 1e-12 for entry in combined.tracker.history())


def test_false_positive_simulator_episode_remains_benign_leaning() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    _, initial = combined.reset("benign-alert", seed=62)
    final = combined.step(DefenderAction("observe", "NO_OP"))
    assert initial.most_likely_mode == AttackerMode.BENIGN
    assert final.posterior.most_likely_mode == AttackerMode.BENIGN
    assert final.transition.ground_truth_incident_label == "FALSE_POSITIVE"  # evaluation only


def test_tracker_integration_never_calls_ground_truth() -> None:
    class OracleForbiddenEnvironment(DynamicShieldEnvironment):
        def ground_truth(self):
            raise AssertionError("tracker attempted to access simulator ground truth")

    combined = BeliefTrackedDynamicEnvironment(OracleForbiddenEnvironment(stochastic=False))
    combined.reset("credential-compromise", seed=63)
    result = combined.step(DefenderAction("observe", "NO_OP"))
    assert result.posterior.most_likely_mode != AttackerMode.BENIGN


def test_hidden_evidence_is_ignored() -> None:
    from dataclasses import replace
    from sentinel_ai.shield.beliefs import BayesianAttackerBeliefTracker
    from sentinel_ai.shield.dynamic_models import Evidence

    environment = DynamicShieldEnvironment(stochastic=False)
    observation = environment.reset("credential-compromise", seed=64)
    hidden = Evidence("oracle", 0, "oracle", "BULK_EXPORT", True, 1.0, available_to_defender=False)
    observation = replace(observation, evidence=(hidden,))
    tracker = BayesianAttackerBeliefTracker()
    tracker.initialize(observation.episode_id)
    posterior = tracker.update(observation)
    missing = BayesianAttackerBeliefTracker()
    missing.initialize(observation.episode_id)
    expected = missing.update_evidence(observation.episode_id, 0, ())
    assert posterior.probabilities == expected.probabilities
