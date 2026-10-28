"""Phase 6 isolated counterfactual rollout generation and target derivation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

import numpy as np

from .belief_integration import BeliefTrackedDynamicEnvironment
from .dynamic import DynamicShieldEnvironment
from .dynamic_models import ApprovalTier, DefenderAction, TransitionRecord
from .world_dataset import build_features


DATASET_VERSION = "shield-downstream-counterfactual-v1.0.0"
MODEL_VERSION = "shield-downstream-rf-v1.0.0"
HORIZON = 4

TARGET_COLUMNS = (
    "target_cumulative_exposure", "target_cumulative_disruption", "target_recovery_burden",
    "target_attacker_adapted", "target_severe_residual_damage", "target_time_to_containment",
    "target_unresolved_at_horizon",
)
CLASS_TARGETS = ("target_attacker_adapted", "target_severe_residual_damage", "target_unresolved_at_horizon")
REG_TARGETS = ("target_cumulative_exposure", "target_cumulative_disruption", "target_recovery_burden",
               "target_time_to_containment")


@dataclass(frozen=True)
class DownstreamRollout:
    features: dict[str, float]
    records: tuple[TransitionRecord, ...]
    targets: dict[str, float | int]
    initial_state_fingerprint: str
    branch_id: str


def _fingerprint(observation) -> str:
    payload = repr((observation.active_nodes, sorted(observation.service_health.items()),
                    sorted(observation.identity_status.items()), sorted(observation.control_status.items()),
                    sorted(observation.observed_compromise_probability.items()),
                    observation.observed_reachable_paths, sorted(observation.workflow_demand.items())))
    return hashlib.sha256(payload.encode()).hexdigest()


def rollout_targets(records: tuple[TransitionRecord, ...], horizon: int) -> dict[str, float | int]:
    if not records:
        raise ValueError("a downstream rollout requires at least one transition")
    containment_steps = [index + 1 for index, record in enumerate(records) if record.attack_outcome == "CONTAINED"]
    return {
        "target_cumulative_exposure": float(sum(record.remaining_attack_path_exposure for record in records)),
        "target_cumulative_disruption": float(sum(record.legitimate_workflow_disruption for record in records)),
        "target_recovery_burden": float(sum(record.recovery_cost for record in records)),
        "target_attacker_adapted": int(any(bool(record.attacker_strategy_gt and
                                                   record.attacker_strategy_gt.get("adapted")) for record in records)),
        "target_severe_residual_damage": int(any(record.attack_outcome == "ATTACK_SUCCESS" for record in records)),
        "target_time_to_containment": float(containment_steps[0] if containment_steps else horizon + 1),
        "target_unresolved_at_horizon": int(records[-1].incident_unresolved),
    }


def approved_candidate(action: DefenderAction, effectiveness: float) -> DefenderAction:
    approved = action.approved or action.approval_tier != ApprovalTier.AUTOMATIC
    return replace(action, action_id=f"phase6-{action.action_type.lower()}", approved=approved,
                   parameters={**action.parameters, "forced_effectiveness": float(effectiveness)})


def counterfactual_rollout(scenario_family: str, seed: int, action_type: str, horizon: int = HORIZON,
                           effectiveness: float | None = None, warmup_steps: int = 0) -> DownstreamRollout:
    """Run one fresh branch; no environment or RNG object is shared across actions."""
    if not 2 <= horizon <= 5:
        raise ValueError("horizon must be between 2 and 5")
    if not 0 <= warmup_steps <= 2:
        raise ValueError("warmup_steps must be between 0 and 2")
    branch_id = f"phase6-{scenario_family}-{seed}-warmup-{warmup_steps}-{action_type}"
    environment = DynamicShieldEnvironment(max_steps=12, stochastic=True,
                                           attacker_progress_scale=.22, topology_variation=True)
    combined = BeliefTrackedDynamicEnvironment(environment)
    observation, belief = combined.reset(scenario_family, seed=seed, episode_id=branch_id)
    for step in range(warmup_steps):
        warmup = combined.step(DefenderAction(f"phase6-warmup-noop-{step}", "NO_OP"))
        if warmup.transition.terminal:
            raise RuntimeError("initial-condition warmup unexpectedly reached a terminal state")
        observation, belief = environment.observe(), warmup.posterior
    candidates = [action for action in environment.available_actions() if action.action_type == action_type]
    if not candidates:
        raise ValueError(f"action {action_type} unavailable for {scenario_family}")
    if effectiveness is None:
        digest = hashlib.sha256(f"{scenario_family}:{seed}:{action_type}:effectiveness".encode()).digest()
        effectiveness = (.1, .5, .9)[int.from_bytes(digest[:2], "big") % 3]
    action = approved_candidate(candidates[0], effectiveness)
    features = build_features(observation, belief, action)
    fingerprint = _fingerprint(observation)
    records = []
    for step in range(horizon):
        selected = action if step == 0 else DefenderAction(f"phase6-followup-noop-{step}", "NO_OP")
        result = combined.step(selected)
        records.append(result.transition)
        if result.transition.terminal:
            break
    frozen = tuple(records)
    return DownstreamRollout(features, frozen, rollout_targets(frozen, horizon), fingerprint, branch_id)


def available_action_types(scenario_family: str, seed: int, warmup_steps: int = 0) -> tuple[str, ...]:
    environment = DynamicShieldEnvironment(max_steps=12, stochastic=True,
                                           attacker_progress_scale=.22, topology_variation=True)
    environment.reset(scenario_family, seed=seed)
    for step in range(warmup_steps):
        environment.step(DefenderAction(f"phase6-action-list-warmup-{step}", "NO_OP"))
    return tuple(dict.fromkeys(action.action_type for action in environment.available_actions()
                               if action.action_type != "ROLLBACK"))
