from sentinel_ai.shield import DownstreamConsequenceService, ShieldService
from sentinel_ai.shield.belief_integration import BeliefTrackedDynamicEnvironment
from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction


def test_downstream_scoring_remains_advisory_and_static_shield_is_unchanged() -> None:
    combined = BeliefTrackedDynamicEnvironment(DynamicShieldEnvironment(stochastic=False, topology_variation=True,
                                                                         attacker_progress_scale=.22))
    observation, belief = combined.reset("lateral-movement", seed=63002, episode_id="phase6-compatible")
    assert DownstreamConsequenceService().predict(observation, belief,
                                                  DefenderAction("segment", "SEGMENT_SERVICE", ("service:admin",))).applicable
    result = ShieldService().analyze("multiple-routes", include_quantum=False)
    assert result["recommendation"]["feasible"] and result["recommendation"]["advisoryOnly"]

