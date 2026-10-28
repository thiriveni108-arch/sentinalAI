from __future__ import annotations

import math

from sentinel_ai.shield.beliefs import (
    MODES,
    AttackerMode,
    BayesianAttackerBeliefTracker,
    BeliefConfig,
)
from sentinel_ai.shield.dynamic_models import Evidence


def evidence(kind: str, tick: int = 0, value=True, confidence: float = 1.0) -> Evidence:
    return Evidence(f"e-{kind}-{tick}", tick, "test-sensor", kind, value, confidence)


def test_beliefs_are_normalized_after_initialization_and_updates() -> None:
    tracker = BayesianAttackerBeliefTracker()
    initial = tracker.initialize("episode")
    updated = tracker.update_evidence("episode", 0, (evidence("ANOMALOUS_SESSION"),))
    assert math.isclose(sum(initial.probabilities.values()), 1.0, abs_tol=1e-15)
    assert math.isclose(sum(updated.probabilities.values()), 1.0, abs_tol=1e-15)
    assert set(updated.probabilities) == set(MODES)


def test_exact_bayesian_posterior_with_identity_transition() -> None:
    priors = {mode: 1 / len(MODES) for mode in MODES}
    identity = {source: {target: float(source == target) for target in MODES} for source in MODES}
    likelihood = {mode: 0.1 for mode in MODES}
    likelihood[AttackerMode.CREDENTIAL_COMPROMISE] = 0.7
    config = BeliefConfig(priors, identity, {"TEST": likelihood})
    tracker = BayesianAttackerBeliefTracker(config)
    tracker.initialize("episode")
    posterior = tracker.update_evidence("episode", 0, (evidence("TEST"),)).probabilities
    expected_credential = 0.7 / (0.7 + 6 * 0.1)
    assert math.isclose(posterior[AttackerMode.CREDENTIAL_COMPROMISE], expected_credential, rel_tol=1e-12)
    assert math.isclose(posterior[AttackerMode.BENIGN], 0.1 / 1.3, rel_tol=1e-12)


def test_missing_observation_applies_transition_prediction_only() -> None:
    tracker = BayesianAttackerBeliefTracker()
    initial = tracker.initialize("episode")
    updated = tracker.update_evidence("episode", 0, ())
    expected = {
        target: sum(initial.probabilities[source] * tracker.config.transitions[source][target] for source in MODES)
        for target in MODES
    }
    for mode in MODES:
        assert math.isclose(updated.probabilities[mode], expected[mode], rel_tol=1e-12)
    assert updated.normalized_entropy > 0


def test_contradictory_evidence_preserves_uncertainty() -> None:
    single = BayesianAttackerBeliefTracker()
    single.initialize("single")
    one = single.update_evidence("single", 0, (evidence("ANOMALOUS_SESSION"),))
    contradictory = BayesianAttackerBeliefTracker()
    contradictory.initialize("both")
    both = contradictory.update_evidence("both", 0, (
        evidence("ANOMALOUS_SESSION", value=True), evidence("ANOMALOUS_SESSION", value=False),
    ))
    assert both.probabilities[AttackerMode.CREDENTIAL_COMPROMISE] < one.probabilities[AttackerMode.CREDENTIAL_COMPROMISE]
    assert both.normalized_entropy > one.normalized_entropy


def test_unsupported_evidence_increases_unknown_probability() -> None:
    tracker = BayesianAttackerBeliefTracker()
    before = tracker.initialize("episode")
    after = tracker.update_evidence("episode", 0, (evidence("UNMODELED_COVERT_CHANNEL"),))
    assert after.probabilities[AttackerMode.UNKNOWN] > before.probabilities[AttackerMode.UNKNOWN]
    assert tracker.history()[0].unsupported_evidence == ("UNMODELED_COVERT_CHANNEL",)
    assert "favored UNKNOWN" in tracker.history()[0].explanation[-1]


def test_mode_transition_allows_attacker_strategy_switching() -> None:
    tracker = BayesianAttackerBeliefTracker()
    tracker.initialize("episode", priors={mode: float(mode == AttackerMode.CREDENTIAL_COMPROMISE) for mode in MODES})
    first = tracker.update_evidence("episode", 0, (evidence("ANOMALOUS_SESSION"),))
    second = tracker.update_evidence("episode", 1, (
        evidence("LATERAL_CONNECTION", tick=1), evidence("CONTAINMENT_ROUTE_SWITCH", tick=1),
    ))
    assert first.most_likely_mode == AttackerMode.CREDENTIAL_COMPROMISE
    assert second.probabilities[AttackerMode.LATERAL_MOVEMENT] > first.probabilities[AttackerMode.LATERAL_MOVEMENT]


def test_benign_negative_signal_favors_benign_mode() -> None:
    tracker = BayesianAttackerBeliefTracker()
    tracker.initialize("benign")
    posterior = tracker.update_evidence("benign", 0, (evidence("ANOMALOUS_SESSION", value=False, confidence=.9),))
    assert posterior.most_likely_mode == AttackerMode.BENIGN


def test_extremely_small_likelihoods_remain_finite() -> None:
    priors = {mode: 1 / len(MODES) for mode in MODES}
    identity = {source: {target: float(source == target) for target in MODES} for source in MODES}
    tiny = {mode: 0.0 for mode in MODES}
    tiny[AttackerMode.UNKNOWN] = 1e-320
    tracker = BayesianAttackerBeliefTracker(BeliefConfig(priors, identity, {"TINY": tiny}, likelihood_floor=1e-300))
    tracker.initialize("episode")
    posterior = tracker.update_evidence("episode", 0, tuple(evidence("TINY", tick=i) for i in range(100)))
    assert all(math.isfinite(value) for value in posterior.probabilities.values())
    assert math.isclose(sum(posterior.probabilities.values()), 1.0, abs_tol=1e-15)


def test_reproducibility_history_and_exports() -> None:
    def run():
        tracker = BayesianAttackerBeliefTracker()
        tracker.initialize("episode")
        tracker.update_evidence("episode", 0, (evidence("PRIVILEGE_CHANGE"),))
        tracker.update_evidence("episode", 1, (evidence("LATERAL_CONNECTION", tick=1),))
        return tracker

    left, right = run(), run()
    assert left.history() == right.history()
    assert [item.time_step for item in left.history()] == [0, 1]
    export = left.export_world_model()
    assert len(export["posterior"]) == len(MODES)
    assert export["calibrated_real_world_probability"] is False
    assert left.export_planner_uncertainty()["unknown_probability"] >= 0
