"""Bounded synthetic attacker policies for the SHIELD v2 environment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np

from .dynamic_models import AttackerDecision, CyberState


class AttackerPolicy(Protocol):
    strategy_id: str
    objective: str

    def decide(self, state: CyberState, rng: np.random.Generator) -> AttackerDecision: ...


@dataclass(frozen=True)
class BoundedAttackerPolicy:
    strategy_id: str
    objective: str
    tactic: str
    base_progress: float
    preferred_token: str = ""

    def decide(self, state: CyberState, rng: np.random.Generator) -> AttackerDecision:
        reachable = tuple(sorted(state.reachable_attack_paths_gt))
        previous = state.current_attack_path_gt
        selected = None
        if reachable:
            preferred = [path for path in reachable if self.preferred_token in path]
            selected = (preferred or list(reachable))[0]
        adapted = previous is not None and selected is not None and previous != selected
        # Bounded variability represents environment/attacker execution, while the
        # chosen route and tactic remain deterministic functions of current state.
        variation = float(rng.uniform(0.85, 1.15))
        delta = 0.0 if selected is None else min(0.35, self.base_progress * variation)
        return AttackerDecision(self.strategy_id, self.objective, self.tactic, selected, adapted, delta)


class CredentialCompromisePolicy(BoundedAttackerPolicy):
    def __init__(self) -> None:
        super().__init__("credential-compromise-v2", "account-control", "SESSION_ABUSE", 0.20, "primary")


class MaliciousInsiderPolicy(BoundedAttackerPolicy):
    def __init__(self) -> None:
        super().__init__("malicious-insider-v2", "sensitive-collection", "AUTHORIZED_COLLECTION", 0.16, "resource")


class LateralMovementPolicy(BoundedAttackerPolicy):
    def __init__(self) -> None:
        super().__init__("lateral-movement-v2", "service-pivot", "LATERAL_PIVOT", 0.18, "service")


class SensitiveExfiltrationPolicy(BoundedAttackerPolicy):
    def __init__(self) -> None:
        super().__init__("sensitive-exfiltration-v2", "data-exfiltration", "BULK_EXPORT", 0.24, "export")


class PrivilegeEscalationPolicy(BoundedAttackerPolicy):
    def __init__(self) -> None:
        super().__init__("privilege-escalation-v2", "privileged-control", "PRIVILEGE_ESCALATION", 0.21, "privilege")


POLICIES: dict[str, AttackerPolicy] = {
    "credential-compromise": CredentialCompromisePolicy(),
    "malicious-insider": MaliciousInsiderPolicy(),
    "lateral-movement": LateralMovementPolicy(),
    "sensitive-data-exfiltration": SensitiveExfiltrationPolicy(),
    "privilege-escalation": PrivilegeEscalationPolicy(),
}


def policy_for(family: str) -> AttackerPolicy | None:
    """Return a bounded policy; benign-alert deliberately has no attacker."""
    return POLICIES.get(family)
