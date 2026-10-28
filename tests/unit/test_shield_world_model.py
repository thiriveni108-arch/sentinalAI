from __future__ import annotations

import math
from pathlib import Path

import numpy as np

from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction
from sentinel_ai.shield.world_model import MODEL_VERSION, WorldModelService


def test_read_only_inference_returns_bounded_consistent_predictions() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    observation, belief = combined.reset("credential-compromise", seed=7, episode_id="inference")
    result = WorldModelService().predict(observation, belief, DefenderAction("observe", "NO_OP"))
    assert result.available and result.applicable
    assert result.model_version == MODEL_VERSION
    for target in ("target_contained", "target_route_switched", "target_next_malicious_observation"):
        probabilities = result.predictions[target]
        assert math.isclose(probabilities["false"] + probabilities["true"], 1.0, abs_tol=1e-12)
        assert 0 <= probabilities["true"] <= 1
    assert 0 <= result.predictions["target_residual_exposure"] <= 1
    assert 0 <= result.predictions["target_workflow_disruption"] <= 1
    assert all(value >= 0 for value in result.uncertainty.values())


def test_prediction_is_deterministic_and_does_not_execute_action() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    observation, belief = combined.reset("lateral-movement", seed=8, episode_id="read-only")
    before = combined.environment.state
    service = WorldModelService()
    first = service.predict(observation, belief, DefenderAction("segment", "SEGMENT_SERVICE", ("service:admin",)))
    second = service.predict(observation, belief, DefenderAction("segment", "SEGMENT_SERVICE", ("service:admin",)))
    assert first == second
    assert combined.environment.state == before


def test_missing_invalid_and_out_of_distribution_inputs_are_explicit(tmp_path: Path) -> None:
    missing = WorldModelService(tmp_path)
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    observation, belief = combined.reset("credential-compromise", seed=9, episode_id="invalid")
    assert missing.predict(observation, belief, DefenderAction("observe", "NO_OP")).available is False

    service = WorldModelService()
    invalid = service.predict(observation, {"BENIGN": 1.0}, DefenderAction("observe", "NO_OP"))
    assert invalid.available and not invalid.applicable and "invalid inference input" in invalid.reason

    from dataclasses import replace
    ood = replace(observation, service_health={key: 2.0 for key in observation.service_health})
    rejected = service.predict(ood, belief, DefenderAction("observe", "NO_OP"))
    assert rejected.available and not rejected.applicable
    assert "out-of-distribution" in rejected.reason


def test_calibration_metric_is_normalized() -> None:
    from scripts.train_shield_world_model import ece
    y = np.asarray([0, 0, 1, 1])
    probability = np.asarray([0.1, 0.2, 0.8, 0.9])
    value = ece(y, probability, bins=2)
    assert 0 <= value <= 1
    assert math.isclose(value, 0.15, abs_tol=1e-12)
