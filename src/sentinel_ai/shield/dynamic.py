"""Isolated, time-stepped SHIELD cyber environment (v2).

The environment is a research simulator. It never invokes production response
adapters, mutates live systems, or changes the frozen v1 VQC/QAOA components.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any

import numpy as np

from .attacker import policy_for
from .dynamic_models import (
    DATASET_VERSION,
    GENERATOR_VERSION,
    ActionResult,
    ActionStatus,
    ApprovalTier,
    AttackOutcome,
    CyberState,
    DefenderAction,
    DefenderObservation,
    EpisodeGroundTruth,
    Evidence,
    TerminalReason,
    TransitionRecord,
    WorkflowState,
)
from .paths import enumerate_attack_paths
from .scenarios import scenarios


SUPPORTED_FAMILIES = (
    "credential-compromise",
    "malicious-insider",
    "lateral-movement",
    "sensitive-data-exfiltration",
    "privilege-escalation",
    "benign-alert",
)

_FAMILY_BASE = {
    "credential-compromise": "credential-compromise",
    "malicious-insider": "malicious-insider",
    "lateral-movement": "multiple-routes",
    "sensitive-data-exfiltration": "malicious-insider",
    "privilege-escalation": "multiple-routes",
    "benign-alert": "credential-compromise",
}

_PATH_TOKEN = {
    "credential-compromise": ("primary",),
    "malicious-insider": ("resource",),
    "lateral-movement": ("service", "alternate"),
    "sensitive-data-exfiltration": ("export", "alternate"),
    "privilege-escalation": ("privilege", "alternate"),
    "benign-alert": (),
}

_ALLOWED_ACTION_TYPES = {
    "NO_OP", "REVOKE_SESSION", "DISABLE_ACCOUNT", "REQUIRE_FRESH_MFA",
    "REMOVE_PRIVILEGE", "RESTRICT_RESOURCE", "DISABLE_BULK_EXPORT",
    "ISOLATE_DEVICE", "SEGMENT_SERVICE", "ROLLBACK",
}


def _bounded(value: float) -> float:
    return round(min(1.0, max(0.0, float(value))), 6)


def _state_id(state: CyberState) -> str:
    payload = json.dumps(asdict(state), sort_keys=True, separators=(",", ":"))
    return "STATE-" + hashlib.sha256(payload.encode()).hexdigest()[:16].upper()


class DynamicShieldEnvironment:
    """A Gym-like, typed simulator with reset/observe/step/ground_truth APIs."""

    def __init__(self, max_steps: int = 12, stochastic: bool = True,
                 attacker_progress_scale: float = 1.0, topology_variation: bool = False) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.max_steps = max_steps
        self.stochastic = stochastic
        if not 0 < attacker_progress_scale <= 1:
            raise ValueError("attacker_progress_scale must be in (0,1]")
        self.attacker_progress_scale = float(attacker_progress_scale)
        self.topology_variation = bool(topology_variation)
        self._rng = np.random.default_rng(0)
        self._state: CyberState | None = None
        self._episode_id = ""
        self._family = ""
        self._topology_id = ""
        self._seed = 0
        self._terminal = False
        self._terminal_reason: TerminalReason | None = None
        self._evidence: tuple[Evidence, ...] = ()
        self._history: list[TransitionRecord] = []
        self._undo: dict[str, dict[str, Any]] = {}

    def reset(self, scenario_family: str, seed: int = 0, episode_id: str | None = None) -> DefenderObservation:
        if scenario_family not in SUPPORTED_FAMILIES:
            raise KeyError(f"Unsupported scenario family: {scenario_family}")
        self._seed = int(seed)
        self._rng = np.random.default_rng(self._seed)
        self._family = scenario_family
        self._episode_id = episode_id or f"episode-{scenario_family}-{seed}"
        topology_variant = seed % (31 if self.topology_variation else 7)
        self._topology_id = f"topology-{_FAMILY_BASE[scenario_family]}-{topology_variant}"
        self._terminal = False
        self._terminal_reason = None
        self._history = []
        self._undo = {}

        base = scenarios()[_FAMILY_BASE[scenario_family]]
        nodes = tuple(sorted(node.node_id for node in base.nodes))
        service_nodes = tuple(node.node_id for node in base.nodes if node.node_type in {"service", "database", "file"})
        if not service_nodes:
            service_nodes = ("service:identity",)
        paths = enumerate_attack_paths(base)
        tokens = _PATH_TOKEN[scenario_family]
        extra_routes = topology_variant % 3 if self.topology_variation else 0
        route_count = (0 if scenario_family == "benign-alert" else
                       max(len(paths), len(tokens)) + extra_routes)
        routes = tuple(
            f"{tokens[index % len(tokens)] if tokens else 'route'}:{paths[index % len(paths)].path_id if paths else index}:{index}"
            for index in range(route_count)
        )
        malicious = scenario_family != "benign-alert"
        entry = base.entry_points[0] if malicious else None
        identity_demand = 0.45 + 0.05 * (topology_variant % 4) if self.topology_variation else 0.55
        workflows = (
            WorkflowState("identity-and-access", tuple(service_nodes[:1]), identity_demand),
            WorkflowState("critical-business-process", service_nodes, 1.0 - identity_demand),
        )
        identities = {"user:employee": "ACTIVE"}
        for entry_id in base.entry_points:
            identities.setdefault(entry_id, "ACTIVE")
        probability = {entry or "user:employee": 0.7 if malicious else 0.18}
        self._state = CyberState(
            tick=0,
            active_nodes=nodes,
            service_health={service: (0.85 + 0.05 * (topology_variant % 4)
                                      if self.topology_variation else 1.0) for service in service_nodes},
            identity_status=identities,
            control_status={"mfa": "ON", "export": "ON", "segmentation": "OFF"},
            observed_compromise_probability=probability,
            observed_reachable_paths=routes[:1] if malicious else (),
            workflows=workflows,
            attacker_footholds_gt=(entry,) if entry else (),
            attacker_capabilities_gt=(policy_for(scenario_family).strategy_id,) if malicious else (),
            compromised_nodes_gt=(entry,) if entry else (),
            reachable_attack_paths_gt=routes,
            blocked_attack_paths_gt=(),
            attack_goal_progress_gt=0.12 if malicious else 0.0,
            current_attack_path_gt=routes[0] if routes else None,
        )
        self._evidence = self._initial_evidence(malicious)
        return self.observe()

    @property
    def state(self) -> CyberState:
        if self._state is None:
            raise RuntimeError("reset must be called before accessing state")
        return self._state

    def observe(self) -> DefenderObservation:
        state = self.state
        return DefenderObservation(
            episode_id=self._episode_id,
            time_step=state.tick,
            scenario_family=self._family,
            active_nodes=state.active_nodes,
            service_health=dict(state.service_health),
            identity_status=dict(state.identity_status),
            control_status=dict(state.control_status),
            observed_compromise_probability=dict(state.observed_compromise_probability),
            observed_reachable_paths=state.observed_reachable_paths,
            workflow_demand={item.workflow_id: item.demand for item in state.workflows},
            workflow_slo_met={item.workflow_id: item.slo_met for item in state.workflows},
            evidence=self._evidence,
            terminal=self._terminal,
        )

    def ground_truth(self) -> EpisodeGroundTruth:
        policy = policy_for(self._family)
        return EpisodeGroundTruth(
            self._episode_id,
            self._family,
            "FALSE_POSITIVE" if policy is None else "TRUE_POSITIVE",
            policy.strategy_id if policy else None,
            policy.objective if policy else None,
            self.state.compromised_nodes_gt if not self._history else self._history[0].current_state.compromised_nodes_gt,
            self._seed,
        )

    def available_actions(self) -> tuple[DefenderAction, ...]:
        base = scenarios()[_FAMILY_BASE[self._family]]
        actions = [DefenderAction("no-op", "NO_OP")]
        for item in base.actions:
            tier = ApprovalTier.MANUAL_ONLY if item.approval_required else ApprovalTier.AUTOMATIC
            actions.append(DefenderAction(item.action_id, item.action_type, (item.target,), approval_tier=tier,
                                          approved=not item.approval_required, prerequisites=item.prerequisites,
                                          reversible=item.reversible))
        actions.extend((
            DefenderAction("segment-service", "SEGMENT_SERVICE", tuple(self.state.service_health)),
            DefenderAction("isolate-device", "ISOLATE_DEVICE", ("device:unknown",)),
        ))
        actions.extend(DefenderAction(f"rollback-{action_id}", "ROLLBACK", (action_id,)) for action_id in self.state.recoverable_action_ids)
        return tuple(actions)

    def step(self, action: DefenderAction) -> TransitionRecord:
        if self._terminal:
            raise RuntimeError("episode is terminal; call reset before applying another action")
        current = self.state
        current_id = _state_id(current)
        draw_id = hashlib.sha256(f"{self._episode_id}:{current.tick}:{self._seed}".encode()).hexdigest()[:16]
        action_state, action_result = self._apply_action(current, action)
        policy = policy_for(self._family)

        if policy is None:
            decision = None
            progress = 0.0
            route = None
        else:
            decision = policy.decide(action_state, self._rng)
            progress = _bounded(action_state.attack_goal_progress_gt + decision.progress_delta * self.attacker_progress_scale)
            route = decision.selected_path

        compromised = set(action_state.compromised_nodes_gt)
        if decision and decision.progress_delta > 0 and route:
            compromised.add(route.split(":", 1)[0] + ":stage")
        provisional = replace(
            action_state,
            tick=current.tick + 1,
            attack_goal_progress_gt=progress,
            current_attack_path_gt=route,
            compromised_nodes_gt=tuple(sorted(compromised)),
            previous_defensive_actions=current.previous_defensive_actions + (action.action_id,),
        )
        workflows = self._recompute_workflows(provisional)
        next_evidence, beliefs, observed_paths = self._generate_observation(provisional, action_result, decision)
        next_state = replace(provisional, workflows=workflows, observed_compromise_probability=beliefs,
                             observed_reachable_paths=observed_paths)

        exposure = self._exposure(next_state)
        disruption = self._disruption(next_state)
        outcome, terminal, reason = self._derive_outcome(next_state, exposure)
        self._terminal, self._terminal_reason = terminal, reason
        self._state, self._evidence = next_state, next_evidence
        next_id = _state_id(next_state)
        strategy = None if decision is None else {
            "strategy_id": decision.strategy_id,
            "objective": decision.objective,
            "current_tactic": decision.tactic,
            "selected_path": decision.selected_path,
            "adapted": decision.adapted,
            "risk_tolerance": 0.5,
            "knowledge_scope": "BOUNDED_LOCAL",
        }
        approval_status = ("NOT_REQUIRED" if action.approval_tier == ApprovalTier.AUTOMATIC
                           else ("APPROVED" if action.approved else "DENIED"))
        record = TransitionRecord(
            dataset_version=DATASET_VERSION,
            generator_version=GENERATOR_VERSION,
            episode_id=self._episode_id,
            time_step=current.tick,
            transition_id=f"transition-{self._episode_id}-{current.tick}",
            topology_id=self._topology_id,
            scenario_family=self._family,
            current_state_id=current_id,
            current_state=current,
            observed_evidence=self._evidence_before(current.tick),
            attacker_strategy_gt=strategy,
            defender_action=action,
            action_result=action_result,
            action_prerequisites=action.prerequisites,
            prerequisites_satisfied=action_result.prerequisites_satisfied,
            approval_tier=action.approval_tier,
            approval_status=approval_status,
            next_state_id=next_id,
            next_state=next_state,
            next_observation=next_evidence,
            remaining_attack_path_exposure=exposure,
            legitimate_workflow_disruption=disruption,
            attack_outcome=outcome,
            response_reversible=action.reversible,
            recovery_cost=action_result.recovery_cost,
            incident_unresolved=(not terminal) or reason == TerminalReason.MAX_STEPS,
            terminal=terminal,
            terminal_reason=reason,
            ground_truth_incident_label="FALSE_POSITIVE" if policy is None else "TRUE_POSITIVE",
            transition_random_draw_id=draw_id,
            label_provenance={
                "derivation_rule_ids": ["dynamic-reachability-v2", "workflow-slo-v2", "terminal-rules-v2"],
                "input_state_hashes": [current_id, next_id], "counterfactual": False, "synthetic": True,
            },
            evidence_source=({"source_id": "shield-sensor-v2", "source_type": "SIMULATOR", "source_version": GENERATOR_VERSION},),
        )
        self._history.append(record)
        return record

    def history(self) -> tuple[TransitionRecord, ...]:
        return tuple(self._history)

    def _evidence_before(self, tick: int) -> tuple[Evidence, ...]:
        if not self._history:
            return self._initial_evidence(self._family != "benign-alert")
        return self._history[-1].next_observation

    def _initial_evidence(self, malicious: bool) -> tuple[Evidence, ...]:
        return (Evidence(f"evidence-{self._episode_id}-0", 0, "identity-sensor", "ANOMALOUS_SESSION",
                         malicious, 0.82 if malicious else 0.42),)

    def _apply_action(self, state: CyberState, action: DefenderAction) -> tuple[CyberState, ActionResult]:
        applied = set(state.previous_defensive_actions)
        prerequisites_ok = set(action.prerequisites).issubset(applied)
        valid_type = action.action_type in _ALLOWED_ACTION_TYPES
        target_ok = action.action_type in {"NO_OP"} or bool(action.target_ids)
        approval_ok = action.approval_tier == ApprovalTier.AUTOMATIC or action.approved
        if not (valid_type and target_ok and prerequisites_ok and approval_ok):
            reason = "invalid action type or target" if not (valid_type and target_ok) else ("prerequisites not satisfied" if not prerequisites_ok else "approval required")
            return state, ActionResult(ActionStatus.DENIED, None, prerequisites_ok, reason)
        if action.action_type == "NO_OP":
            return state, ActionResult(ActionStatus.EXECUTED, 1.0, True, "no defensive state change")
        if action.action_type == "ROLLBACK":
            return self._rollback(state, action)

        forced = action.parameters.get("forced_effectiveness")
        if forced is not None:
            effectiveness = _bounded(float(forced))
        elif self.stochastic:
            health = min(state.service_health.values(), default=1.0)
            effectiveness = _bounded(self._rng.beta(5.0, 1.8) * (0.85 + 0.15 * health))
        else:
            effectiveness = 0.8
        status = ActionStatus.FAILED if effectiveness < 0.2 else (ActionStatus.PARTIAL if effectiveness < 0.7 else ActionStatus.EXECUTED)
        if status == ActionStatus.FAILED:
            return state, ActionResult(status, effectiveness, True, "simulated action execution failed")

        self._undo[action.action_id] = {
            "service_health": dict(state.service_health), "identity_status": dict(state.identity_status),
            "control_status": dict(state.control_status), "blocked_attack_paths_gt": state.blocked_attack_paths_gt,
        }
        services, identities, controls = dict(state.service_health), dict(state.identity_status), dict(state.control_status)
        blocked = set(state.blocked_attack_paths_gt)
        reachable = list(state.reachable_attack_paths_gt)
        count = len(reachable) if status == ActionStatus.EXECUTED else min(1, len(reachable))
        action_type = action.action_type
        if action_type in {"REVOKE_SESSION", "DISABLE_ACCOUNT"}:
            blocked.update(reachable[:count])
            for target in action.target_ids:
                identities[target] = "DISABLED" if action_type == "DISABLE_ACCOUNT" else "REVOKED"
        elif action_type == "REQUIRE_FRESH_MFA":
            controls["mfa"] = "CHALLENGE_REQUIRED"
            for target in action.target_ids:
                identities[target] = "CHALLENGED"
        else:
            token = {"REMOVE_PRIVILEGE": "privilege", "RESTRICT_RESOURCE": "resource",
                     "DISABLE_BULK_EXPORT": "export", "SEGMENT_SERVICE": "service",
                     "ISOLATE_DEVICE": "primary"}.get(action_type, "")
            candidates = [path for path in reachable if token in path] or reachable
            blocked.update(candidates[:count])
            if action_type == "DISABLE_BULK_EXPORT":
                controls["export"] = "OFF" if status == ActionStatus.EXECUTED else "DEGRADED"
            if action_type in {"SEGMENT_SERVICE", "ISOLATE_DEVICE", "RESTRICT_RESOURCE"}:
                degradation = 0.35 * effectiveness
                for service in services:
                    if not action.target_ids or service in action.target_ids or action_type != "RESTRICT_RESOURCE":
                        services[service] = _bounded(services[service] - degradation)
                if action_type == "SEGMENT_SERVICE":
                    controls["segmentation"] = "ON" if status == ActionStatus.EXECUTED else "DEGRADED"
        remaining = tuple(path for path in reachable if path not in blocked)
        updated = replace(state, service_health=services, identity_status=identities, control_status=controls,
                          blocked_attack_paths_gt=tuple(sorted(blocked)), reachable_attack_paths_gt=remaining,
                          recoverable_action_ids=state.recoverable_action_ids + ((action.action_id,) if action.reversible else ()))
        return updated, ActionResult(status, effectiveness, True, "simulated action applied to environment state")

    def _rollback(self, state: CyberState, action: DefenderAction) -> tuple[CyberState, ActionResult]:
        original = action.target_ids[0]
        patch = self._undo.get(original)
        if patch is None or original not in state.recoverable_action_ids:
            return state, ActionResult(ActionStatus.DENIED, None, False, "no recoverable action with that id")
        restored_blocked = tuple(patch["blocked_attack_paths_gt"])
        all_routes = tuple(sorted(set(state.reachable_attack_paths_gt) | set(state.blocked_attack_paths_gt)))
        reachable = tuple(path for path in all_routes if path not in restored_blocked)
        updated = replace(state, service_health=patch["service_health"], identity_status=patch["identity_status"],
                          control_status=patch["control_status"], blocked_attack_paths_gt=restored_blocked,
                          reachable_attack_paths_gt=reachable,
                          recoverable_action_ids=tuple(item for item in state.recoverable_action_ids if item != original))
        return updated, ActionResult(ActionStatus.EXECUTED, 1.0, True, "simulated action rolled back", recovery_cost=0.25)

    def _recompute_workflows(self, state: CyberState) -> tuple[WorkflowState, ...]:
        broad_identity_loss = any(value == "DISABLED" for value in state.identity_status.values())
        result = []
        for workflow in state.workflows:
            health = min((state.service_health.get(service, 1.0) for service in workflow.required_services), default=1.0)
            if broad_identity_loss:
                health *= 0.45
            result.append(replace(workflow, served_fraction=_bounded(health)))
        return tuple(result)

    def _generate_observation(self, state: CyberState, result: ActionResult, decision) -> tuple[tuple[Evidence, ...], dict[str, float], tuple[str, ...]]:
        malicious = bool(state.attacker_footholds_gt)
        detection_probability = 0.9 if malicious and state.attack_goal_progress_gt >= 0.35 else (0.65 if malicious else 0.15)
        detected = bool(self._rng.random() < detection_probability) if self.stochastic else malicious
        event_type = "POST_ACTION_MALICIOUS_ACTIVITY" if detected else "POST_ACTION_NO_CONFIRMED_ACTIVITY"
        evidence = (Evidence(f"evidence-{self._episode_id}-{state.tick}", state.tick, "shield-sensor-v2", event_type,
                             detected, detection_probability, "DIRECT"),)
        beliefs = dict(state.observed_compromise_probability)
        for identity, probability in beliefs.items():
            adjustment = 0.16 if detected else -0.12
            if result.status == ActionStatus.FAILED:
                adjustment += 0.05
            beliefs[identity] = _bounded(probability + adjustment)
        observed_paths = state.reachable_attack_paths_gt[:1] if detected else ()
        return evidence, beliefs, observed_paths

    @staticmethod
    def _exposure(state: CyberState) -> float:
        total = len(state.reachable_attack_paths_gt) + len(state.blocked_attack_paths_gt)
        return 0.0 if total == 0 else round(len(state.reachable_attack_paths_gt) / total, 6)

    @staticmethod
    def _disruption(state: CyberState) -> float:
        demand = sum(item.demand for item in state.workflows)
        unmet = sum(item.demand * (1.0 - item.served_fraction) for item in state.workflows)
        return 0.0 if demand == 0 else round(unmet / demand, 6)

    def _derive_outcome(self, state: CyberState, exposure: float) -> tuple[AttackOutcome, bool, TerminalReason | None]:
        if self._family == "benign-alert":
            return AttackOutcome.NO_ATTACK, True, TerminalReason.BENIGN_RESOLVED
        if state.attack_goal_progress_gt >= 1.0:
            return AttackOutcome.ATTACK_SUCCESS, True, TerminalReason.ATTACK_SUCCESS
        if exposure == 0.0:
            return AttackOutcome.CONTAINED, True, TerminalReason.CONTAINED
        if state.tick >= self.max_steps:
            return AttackOutcome.ATTACK_PROGRESS, True, TerminalReason.MAX_STEPS
        if state.blocked_attack_paths_gt:
            return AttackOutcome.PARTIALLY_CONTAINED, False, None
        return AttackOutcome.ATTACK_PROGRESS, False, None
