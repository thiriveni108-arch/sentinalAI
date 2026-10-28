from sentinel_ai.shield import ShieldService
from sentinel_ai.shield.consequence_simulator import MultiStepConsequenceEnvironment, SimulatedAction


def test_realism_simulator_is_isolated_from_static_shield() -> None:
    environment = MultiStepConsequenceEnvironment("sensitive-data-exfiltration", 65004)
    environment.step(SimulatedAction("DISABLE_BULK_EXPORT", approved=True))
    static = ShieldService().analyze("malicious-insider", include_quantum=False)
    assert static["recommendation"]["feasible"] and static["recommendation"]["advisoryOnly"]

