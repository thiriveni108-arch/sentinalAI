from __future__ import annotations

from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction
from sentinel_ai.shield.scenarios import scenarios
from sentinel_ai.shield.service import ShieldService


def test_dynamic_environment_reuses_existing_intervention_semantics_without_changing_static_shield() -> None:
    existing = scenarios()["credential-compromise"]
    revoke = next(action for action in existing.actions if action.action_type == "REVOKE_SESSION")
    environment = DynamicShieldEnvironment(stochastic=False)
    environment.reset("credential-compromise", seed=55)
    transition = environment.step(DefenderAction(
        revoke.action_id, revoke.action_type, (revoke.target,), {"forced_effectiveness": 1.0},
        reversible=revoke.reversible,
    ))
    assert transition.terminal
    assert transition.next_state.reachable_attack_paths_gt == ()

    static_result = ShieldService().analyze("credential-compromise", include_quantum=False)
    assert static_result["recommendation"]["feasible"] is True
    assert static_result["recommendation"]["advisoryOnly"] is True
