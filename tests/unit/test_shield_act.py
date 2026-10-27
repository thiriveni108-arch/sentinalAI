from __future__ import annotations

import numpy as np
import pytest

from sentinel_ai.shield.act import (
    AdaptiveScenarioEngine,
    ConsequenceModel,
    ScenarioFamily,
    consequence_features,
    exact_consequence,
)


def test_scenario_families_produce_distinct_graphs_actions_and_outcomes() -> None:
    engine = AdaptiveScenarioEngine()
    file_scenario = engine.build("file-collection", "INC-ONE", {"file_copy_count": 8, "usb_connect_count": 1})
    lateral_scenario = engine.build("lateral-access", "INC-TWO", {"service_signal": 1, "authorization_signal": 1})

    assert len(file_scenario.edges) != len(lateral_scenario.edges)
    assert {action.action_type for action in file_scenario.actions} != {action.action_type for action in lateral_scenario.actions}
    assert exact_consequence(file_scenario, file_scenario.actions[0]) != exact_consequence(lateral_scenario, lateral_scenario.actions[0])


def test_registry_accepts_new_family_without_model_code_change() -> None:
    custom = ScenarioFamily("custom-family", "Custom", "Registry supplied", ("CAN_ACCESS", "CAN_EXPORT"),
                            (("revoke-session", "REVOKE_SESSION", 2.0, True, False),), 4, 1, ("signal",))
    scenario = AdaptiveScenarioEngine({"custom-family": custom}).build("custom-family", "INC-NEW", {"signal": 1})
    result = ConsequenceModel().predict("custom-family", consequence_features(scenario, scenario.actions[0]))

    assert scenario.scenario_id.startswith("act-custom-family")
    assert result["available"] is True
    assert result["applicable"] is False
    assert result["familyValidated"] is False


def test_missing_evidence_and_out_of_range_inputs_degrade_safely() -> None:
    engine = AdaptiveScenarioEngine()
    with pytest.raises(ValueError, match="Insufficient evidence"):
        engine.build("credential-compromise", "INC-NO-EVIDENCE", {}, allow_assumptions=False)

    result = ConsequenceModel().predict("file-collection", np.asarray([999.0, 1.0, 5.0, 2.0]))
    assert result["applicable"] is False
    assert "action_cost" in result["rangeViolations"]


def test_frozen_pennylane_artifact_executes_with_disclosed_raw_score() -> None:
    scenario = AdaptiveScenarioEngine().build("file-collection", "INC-QML", {"file_copy_count": 8, "usb_connect_count": 1})
    result = ConsequenceModel().predict("file-collection", consequence_features(scenario, scenario.actions[0]))

    assert result["available"] is True
    assert result["applicable"] is True
    assert -1.0 <= result["rawScore"] <= 1.0
    assert result["scoreIsProbability"] is False
    assert result["backend"].startswith("PennyLane")
