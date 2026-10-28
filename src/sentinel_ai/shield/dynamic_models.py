"""Typed contracts for the isolated, time-stepped SHIELD simulator.

These types model synthetic cyber exercises only.  They are intentionally
independent from production response adapters and frozen v1 model artifacts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


DATASET_VERSION = "shield-act-transition-v2.0.0"
GENERATOR_VERSION = "shield-dynamic-simulator-v2.0.0"


class ActionStatus(StrEnum):
    EXECUTED = "EXECUTED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    DENIED = "DENIED"


class AttackOutcome(StrEnum):
    NO_ATTACK = "NO_ATTACK"
    ATTACK_PROGRESS = "ATTACK_PROGRESS"
    ATTACK_SUCCESS = "ATTACK_SUCCESS"
    CONTAINED = "CONTAINED"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"


class TerminalReason(StrEnum):
    ATTACK_SUCCESS = "ATTACK_SUCCESS"
    CONTAINED = "CONTAINED"
    BENIGN_RESOLVED = "BENIGN_RESOLVED"
    MAX_STEPS = "MAX_STEPS"
    IRRECOVERABLE_FAILURE = "IRRECOVERABLE_FAILURE"


class ApprovalTier(StrEnum):
    AUTOMATIC = "TIER_1_AUTOMATIC"
    HUMAN_REVIEW = "TIER_2_HUMAN_REVIEW"
    MANUAL_ONLY = "TIER_3_MANUAL_ONLY"


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    event_tick: int
    source_id: str
    evidence_type: str
    value: str | float | int | bool
    confidence: float
    quality: str = "DIRECT"
    available_to_defender: bool = True


@dataclass(frozen=True)
class WorkflowState:
    workflow_id: str
    required_services: tuple[str, ...]
    demand: float
    served_fraction: float = 1.0

    @property
    def slo_met(self) -> bool:
        return self.served_fraction >= 0.8


@dataclass(frozen=True)
class CyberState:
    """Complete simulator state. Fields suffixed ``_gt`` are oracle-only."""

    tick: int
    active_nodes: tuple[str, ...]
    service_health: dict[str, float]
    identity_status: dict[str, str]
    control_status: dict[str, str]
    observed_compromise_probability: dict[str, float]
    observed_reachable_paths: tuple[str, ...]
    workflows: tuple[WorkflowState, ...]
    attacker_footholds_gt: tuple[str, ...]
    attacker_capabilities_gt: tuple[str, ...]
    compromised_nodes_gt: tuple[str, ...]
    reachable_attack_paths_gt: tuple[str, ...]
    blocked_attack_paths_gt: tuple[str, ...]
    attack_goal_progress_gt: float
    current_attack_path_gt: str | None
    previous_defensive_actions: tuple[str, ...] = ()
    recoverable_action_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DefenderObservation:
    """The only view intended for defender policies; contains no oracle fields."""

    episode_id: str
    time_step: int
    scenario_family: str
    active_nodes: tuple[str, ...]
    service_health: dict[str, float]
    identity_status: dict[str, str]
    control_status: dict[str, str]
    observed_compromise_probability: dict[str, float]
    observed_reachable_paths: tuple[str, ...]
    workflow_demand: dict[str, float]
    workflow_slo_met: dict[str, bool]
    evidence: tuple[Evidence, ...]
    terminal: bool


@dataclass(frozen=True)
class DefenderAction:
    action_id: str
    action_type: str
    target_ids: tuple[str, ...] = ()
    parameters: dict[str, float | str | bool] = field(default_factory=dict)
    approval_tier: ApprovalTier = ApprovalTier.AUTOMATIC
    approved: bool = True
    prerequisites: tuple[str, ...] = ()
    reversible: bool = True
    policy_rule_id: str = "simulation-policy-v2"


@dataclass(frozen=True)
class ActionResult:
    status: ActionStatus
    effectiveness: float | None
    prerequisites_satisfied: bool
    reason: str
    recovery_cost: float = 0.0


@dataclass(frozen=True)
class AttackerDecision:
    strategy_id: str
    objective: str
    tactic: str
    selected_path: str | None
    adapted: bool
    progress_delta: float


@dataclass(frozen=True)
class TransitionRecord:
    dataset_version: str
    generator_version: str
    episode_id: str
    time_step: int
    transition_id: str
    topology_id: str
    scenario_family: str
    current_state_id: str
    current_state: CyberState
    observed_evidence: tuple[Evidence, ...]
    attacker_strategy_gt: dict[str, Any] | None
    defender_action: DefenderAction
    action_result: ActionResult
    action_prerequisites: tuple[str, ...]
    prerequisites_satisfied: bool
    approval_tier: ApprovalTier
    approval_status: str
    next_state_id: str
    next_state: CyberState
    next_observation: tuple[Evidence, ...]
    remaining_attack_path_exposure: float
    legitimate_workflow_disruption: float
    attack_outcome: AttackOutcome
    response_reversible: bool
    recovery_cost: float
    incident_unresolved: bool
    terminal: bool
    terminal_reason: TerminalReason | None
    ground_truth_incident_label: str
    transition_random_draw_id: str
    verification_status: str = "SIMULATOR_VERIFIED"
    label_provenance: dict[str, Any] = field(default_factory=dict)
    evidence_source: tuple[dict[str, str], ...] = ()

    def to_v2_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible record using the approved v2 field names."""
        result = asdict(self)
        result["attacker_strategy_gt"] = self.attacker_strategy_gt
        return result


@dataclass(frozen=True)
class EpisodeGroundTruth:
    episode_id: str
    scenario_family: str
    incident_label: str
    strategy_id: str | None
    objective: str | None
    initial_compromised_nodes: tuple[str, ...]
    seed: int
