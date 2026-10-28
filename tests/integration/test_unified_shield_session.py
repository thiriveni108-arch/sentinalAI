from __future__ import annotations

from sentinel_ai.shield.autonomous_defense import DefenseCoordinator, DefenseStore
from sentinel_ai.shield.continuous_learning import ExperienceStore
from sentinel_ai.shield.unified_session import UnifiedSessionService


def test_unified_session_uses_server_derived_plan_and_phase8_authority(tmp_path):
    service=UnifiedSessionService(DefenseCoordinator(DefenseStore(tmp_path/"phase8.db")),ExperienceStore(tmp_path/"memory.db"))
    initial=service.create("credential-compromise","small-office",96001)
    assert initial["origin"]=="simulated-evidence-bridge" and "attacker_progress_gt" not in str(initial)
    plan=service.plan(initial["incident_id"],initial["version"])
    assert plan["plan"]["solver"]=="exact" and plan["diagnostic"]["operationally_suitable"] is False
    submitted=service.submit(initial["incident_id"],initial["version"])
    assert submitted["proposal"]["status"] in {"PENDING_HUMAN","PENDING_ANALYST","AUTO_AUTHORIZED"}
    try: service.approve(initial["incident_id"],"client-supplied-admin","approve",submitted["version"])
    except PermissionError: pass
    else: raise AssertionError("unrecognized client identity must not approve")
