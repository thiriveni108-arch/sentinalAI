"""Reproducible Phase 3 belief trajectories over synthetic evidence."""

from __future__ import annotations

import json

from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.beliefs import AttackerMode, BayesianAttackerBeliefTracker
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction, Evidence


def item(kind: str, tick: int, suffix: str = "") -> Evidence:
    return Evidence(f"demo-{tick}-{kind}-{suffix}", tick, "demo-sensor", kind, True, 1.0)


def snapshot(state) -> dict[str, object]:
    return {
        "time_step": state.time_step,
        "most_likely_mode": state.most_likely_mode,
        "mode_probability": round(state.probabilities[state.most_likely_mode], 6),
        "unknown_probability": round(state.probabilities[AttackerMode.UNKNOWN], 6),
        "normalized_entropy": round(state.normalized_entropy, 6),
    }


def switching_trajectory() -> list[dict[str, object]]:
    tracker = BayesianAttackerBeliefTracker()
    tracker.initialize("demo-switching")
    sequence = (
        (item("ANOMALOUS_SESSION", 0),),
        (item("PRIVILEGE_CHANGE", 1, "a"), item("PRIVILEGE_CHANGE", 1, "b")),
        (item("LATERAL_CONNECTION", 2), item("CONTAINMENT_ROUTE_SWITCH", 2)),
        (item("BULK_EXPORT", 3, "a"), item("BULK_EXPORT", 3, "b")),
    )
    return [snapshot(tracker.update_evidence("demo-switching", tick, evidence))
            for tick, evidence in enumerate(sequence)]


def unknown_trajectory() -> list[dict[str, object]]:
    tracker = BayesianAttackerBeliefTracker()
    tracker.initialize("demo-unknown")
    return [snapshot(tracker.update_evidence(
        "demo-unknown", tick, (item("UNMODELED_COVERT_CHANNEL", tick),)
    )) for tick in range(3)]


def benign_simulator_trajectory() -> list[dict[str, object]]:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    _, initial = combined.reset("benign-alert", seed=707, episode_id="demo-benign")
    final = combined.step(DefenderAction("observe", "NO_OP")).posterior
    return [snapshot(initial), snapshot(final)]


def main() -> None:
    print(json.dumps({
        "model": "shield-bayesian-belief-v1.0.0",
        "synthetic_assumptions_not_empirically_calibrated": True,
        "trajectories": {
            "changing_supported_modes": switching_trajectory(),
            "unsupported_behavior": unknown_trajectory(),
            "phase2_false_positive": benign_simulator_trajectory(),
        },
    }, indent=2))


if __name__ == "__main__":
    main()
