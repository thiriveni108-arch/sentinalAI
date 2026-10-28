from sentinel_ai.shield import ShieldService, WorldModelService
from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction


def test_world_model_is_advisory_and_static_shield_remains_authoritative() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    observation, belief = combined.reset("malicious-insider", seed=10, episode_id="compatibility")
    prediction = WorldModelService().predict(observation, belief, DefenderAction("observe", "NO_OP"))
    assert prediction.applicable
    assert any("no response action was executed" in warning.lower() for warning in prediction.warnings)
    static = ShieldService().analyze("malicious-insider", include_quantum=False)
    assert static["recommendation"]["feasible"]
    assert static["recommendation"]["advisoryOnly"]
