"""Run three small, reproducible SHIELD dynamic-simulator incidents."""

from __future__ import annotations

import json

from sentinel_ai.shield.dynamic import DynamicShieldEnvironment
from sentinel_ai.shield.dynamic_models import DefenderAction


def summarize(record) -> dict[str, object]:
    return {
        "episode_id": record.episode_id, "family": record.scenario_family, "step": record.time_step,
        "action": record.defender_action.action_type, "action_status": record.action_result.status,
        "effectiveness": record.action_result.effectiveness,
        "attacker_route": None if record.attacker_strategy_gt is None else record.attacker_strategy_gt["selected_path"],
        "attacker_adapted": False if record.attacker_strategy_gt is None else record.attacker_strategy_gt["adapted"],
        "exposure": record.remaining_attack_path_exposure,
        "workflow_disruption": record.legitimate_workflow_disruption,
        "outcome": record.attack_outcome, "terminal": record.terminal,
    }


def main() -> None:
    results = []
    credential = DynamicShieldEnvironment(stochastic=False)
    credential.reset("credential-compromise", seed=101, episode_id="demo-credential")
    results.append(summarize(credential.step(DefenderAction(
        "demo-revoke", "REVOKE_SESSION", ("session:suspicious",), {"forced_effectiveness": 1.0}
    ))))

    lateral = DynamicShieldEnvironment(stochastic=False)
    lateral.reset("lateral-movement", seed=202, episode_id="demo-lateral")
    results.append(summarize(lateral.step(DefenderAction(
        "demo-segment", "SEGMENT_SERVICE", ("service:admin",), {"forced_effectiveness": 0.55}
    ))))
    results.append(summarize(lateral.step(DefenderAction("demo-observe", "NO_OP"))))

    insider = DynamicShieldEnvironment(stochastic=False)
    insider.reset("malicious-insider", seed=303, episode_id="demo-insider")
    results.append(summarize(insider.step(DefenderAction(
        "demo-restrict-failed", "RESTRICT_RESOURCE", ("file:designs",), {"forced_effectiveness": 0.1}
    ))))
    results.append(summarize(insider.step(DefenderAction(
        "demo-disable", "DISABLE_ACCOUNT", ("user:employee",), {"forced_effectiveness": 1.0}, reversible=False
    ))))
    print(json.dumps({"simulator": "shield-dynamic-v2", "synthetic": True, "transitions": results}, indent=2))


if __name__ == "__main__":
    main()
