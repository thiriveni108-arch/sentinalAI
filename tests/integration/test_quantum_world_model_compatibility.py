from sentinel_ai.shield import QuantumWorldModelService, ShieldService
from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction


def test_quantum_predictor_does_not_replace_static_shield_or_classical_selection() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False))
    observation, belief = combined.reset("malicious-insider", seed=21, episode_id="q-compatible")
    assert QuantumWorldModelService().predict(observation, belief, DefenderAction("observe", "NO_OP")).applicable
    static = ShieldService().analyze("malicious-insider", include_quantum=False)
    assert static["recommendation"]["feasible"] and static["recommendation"]["advisoryOnly"]

