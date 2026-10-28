from __future__ import annotations

import math
import json
import pickle
from pathlib import Path

import numpy as np

from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction
from sentinel_ai.shield.quantum_world_model import (MODEL_VERSION, QuantumWorldModelService,
                                                     quantum_features)
from sentinel_ai.shield.world_dataset import TARGET_COLUMNS, feature_columns


def test_four_qubit_circuit_is_seed_reproducible() -> None:
    weights = np.random.default_rng(11).normal(size=(2, 4, 3))
    values = np.asarray([[.1, .2, .3, .4], [.4, .3, .2, .1]])
    assert np.allclose(quantum_features(values, weights), quantum_features(values, weights))


def test_feature_contract_excludes_ground_truth_and_future_values() -> None:
    columns = feature_columns(True)
    assert len(columns) == len(set(columns))
    assert not set(columns) & set(TARGET_COLUMNS)
    assert not any("_gt" in column or column.startswith("next_") or "forced_effectiveness" in column
                   for column in columns)


def test_versioned_artifact_has_train_fitted_alignment() -> None:
    service = QuantumWorldModelService()
    with service.artifact_path.open("rb") as handle:
        artifact = pickle.load(handle)
    assert artifact["model_version"] == MODEL_VERSION
    assert artifact["feature_columns"] == feature_columns(True)
    assert artifact["scaler"].n_features_in_ == len(feature_columns(True))
    assert artifact["reducer"].n_components_ == 4
    assert all(member["weights"].shape == (2, 4, 3) for member in artifact["members"])


def test_frozen_benchmark_records_reproducibility_contract() -> None:
    service = QuantumWorldModelService()
    report = json.loads(service.metadata_path.read_text(encoding="utf-8"))
    assert report["foundation_audit"]["status"] == "pass"
    assert report["foundation_audit"]["manifest_hash_matches"] is True
    assert report["seeds"] == [42073, 42089, 42101]
    assert report["split_rows"] == {"train": 3709, "validation": 697, "test": 813}
    assert report["targets"] == TARGET_COLUMNS


def test_quantum_service_is_bounded_read_only_and_compatible() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    observation, belief = combined.reset("credential-compromise", seed=19, episode_id="q-read-only")
    before = combined.environment.state
    prediction = QuantumWorldModelService().predict(observation, belief, DefenderAction("observe", "NO_OP"))
    assert prediction.available and prediction.applicable
    assert prediction.model_version == MODEL_VERSION
    assert combined.environment.state == before
    for target in ("target_contained", "target_route_switched", "target_next_malicious_observation"):
        probabilities = prediction.predictions[target]
        assert 0 <= probabilities["true"] <= 1
        assert math.isclose(probabilities["true"] + probabilities["false"], 1, abs_tol=1e-9)
    for target in ("target_residual_exposure", "target_workflow_disruption"):
        assert 0 <= prediction.predictions[target] <= 1
    assert all(value >= 0 for value in prediction.uncertainty.values())
    assert any("no response action was executed" in warning.lower() for warning in prediction.warnings)


def test_invalid_belief_is_rejected() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    observation, _ = combined.reset("lateral-movement", seed=20, episode_id="q-invalid")
    result = QuantumWorldModelService().predict(observation, {"BENIGN": 1.0}, DefenderAction("observe", "NO_OP"))
    assert result.available and not result.applicable
    assert "invalid inference input" in (result.reason or "")
