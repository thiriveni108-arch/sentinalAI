"""Versioned multi-step consequence simulator for Phase 6.5 research.

This simulator is isolated from production response code and from the frozen v2
transition generator. Random draws are stateless by seed/tick/component so
counterfactual branches receive matched exogenous randomness.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

import numpy as np

from .topology import TopologyScenario, topology_scenario


SIMULATOR_VERSION = "shield-multistep-consequence-v3.1.0"
POLICY_VERSION = "shield-continuation-policies-v1.0.0"
ACTION_TYPES = ("NO_OP", "REQUIRE_FRESH_MFA", "REVOKE_SESSION", "DISABLE_ACCOUNT",
                "REMOVE_PRIVILEGE", "RESTRICT_RESOURCE", "DISABLE_BULK_EXPORT",
                "ISOLATE_DEVICE", "SEGMENT_SERVICE", "ROLLBACK")
POLICY_NAMES = ("observation_only", "immediate_containment", "minimally_disruptive",
                "escalating", "evidence_seeking", "policy_constrained")


@dataclass(frozen=True)
class RecoveryTask:
    source_action: str
    remaining_steps: int
    total_steps: int
    effort_per_step: float
    service_restore_per_step: float
    restores_attacker_access: bool
    route: str | None
    remediation_required: bool = False


@dataclass(frozen=True)
class RealisticState:
    tick: int
    family: str
    service_health: float
    workflow_slo_met: bool
    observed_compromise: float
    observed_malicious_activity: bool
    evidence_count: int
    attacker_progress_gt: float
    attacker_capability_gt: bool
    accessible_routes_gt: tuple[str, ...]
    latent_routes_gt: tuple[str, ...]
    current_route_gt: str | None
    attacker_observations_gt: int
    dormant_until_gt: int
    suppression_until_gt: int
    remediation_steps_gt: int
    recovery_tasks: tuple[RecoveryTask, ...]
    persistent_disruption: float
    severe_outcome_gt: bool
    contained_gt: bool
    terminal: bool
    topology_id: str | None = None
    disabled_nodes_gt: tuple[str, ...] = ()
    blocked_connections_gt: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class RealisticObservation:
    tick: int
    family: str
    service_health: float
    workflow_slo_met: bool
    observed_compromise: float
    observed_malicious_activity: bool
    evidence_count: int
    recovery_active: bool
    terminal: bool


@dataclass(frozen=True)
class SimulatedAction:
    action_type: str
    approved: bool = True
    prerequisite: str | None = None
    targets: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConsequenceTransition:
    tick: int
    action_type: str
    action_valid: bool
    action_effectiveness_gt: float
    exposure: float
    disruption: float
    recovery_cost: float
    attacker_adapted_gt: bool
    attacker_active_gt: bool
    temporary_suppression_gt: bool
    genuinely_contained_gt: bool
    severe_outcome_gt: bool
    unresolved: bool
    service_health: float
    attacker_progress_gt: float
    accessible_route_count_gt: int
    recovery_task_count: int


def _draw(seed: int, tick: int, component: str) -> float:
    digest = hashlib.sha256(f"{seed}:{tick}:{component}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / float(2**64 - 1)


class MultiStepConsequenceEnvironment:
    """Small causal simulator with delayed adaptation, recovery, and severe outcomes."""

    def __init__(self, family: str, seed: int, max_steps: int = 8,
                 topology: TopologyScenario | str | None = None) -> None:
        self.seed, self.max_steps = int(seed), int(max_steps)
        self.topology = topology_scenario(topology) if isinstance(topology, str) else topology
        routes = self.topology.initial_routes() if self.topology else tuple(f"{family}:route-{index}" for index in range(3))
        latent = self.topology.latent_routes() if self.topology else routes[2:]
        self.state = RealisticState(0, family, 1.0, True, .62, True, 1, .10, True,
                                    routes, latent, routes[0] if routes else None, 0, 0, 0, 0, (), 0.0,
                                    False, False, False, self.topology.identifier if self.topology else None)
        self.history: list[ConsequenceTransition] = []
        self.action_history: list[str] = []

    def observe(self) -> RealisticObservation:
        state = self.state
        return RealisticObservation(state.tick, state.family, state.service_health, state.workflow_slo_met,
                                    state.observed_compromise, state.observed_malicious_activity,
                                    state.evidence_count, bool(state.recovery_tasks), state.terminal)

    def topology_posture(self) -> tuple[float, float, float, float]:
        """Defender-safe graph context: no route IDs, attacker ownership, or prerequisites."""
        if not self.topology:
            return (0.0, 0.0, 1.0, 0.0)
        nodes = max(1, len(self.topology.nodes)); routes = max(1, len(self.topology.routes))
        availability = self.topology.workflow_availability(set(self.state.disabled_nodes_gt),
                                                            set(self.state.blocked_connections_gt))
        critical = sum(node.criticality for node in self.topology.nodes) / (5.0 * nodes)
        return (min(1.0, nodes / 12.0), min(1.0, len(self.topology.connections) / 20.0), availability,
                min(1.0, critical + len(self.state.disabled_nodes_gt) / routes))

    def step(self, action: SimulatedAction) -> ConsequenceTransition:
        if self.state.terminal:
            raise RuntimeError("terminal branch")
        current = self.state
        health, routes = current.service_health, list(current.accessible_routes_gt)
        latent, tasks = list(current.latent_routes_gt), []
        disabled_nodes, blocked_connections = set(current.disabled_nodes_gt), set(current.blocked_connections_gt)
        recovery_cost, restored_access = 0.0, False
        for task in current.recovery_tasks:
            health = min(1.0, health + task.service_restore_per_step)
            recovery_cost += task.effort_per_step
            remaining = task.remaining_steps - 1
            if remaining <= 0:
                if task.restores_attacker_access and task.route and current.attacker_capability_gt:
                    routes.append(task.route); restored_access = True
            else:
                tasks.append(replace(task, remaining_steps=remaining))

        valid = action.action_type in ACTION_TYPES and (action.approved or action.action_type in {
            "NO_OP", "REQUIRE_FRESH_MFA", "REVOKE_SESSION"})
        if action.prerequisite and action.prerequisite not in self.action_history:
            valid = False
        effectiveness = .45 + .5 * _draw(self.seed, current.tick, f"effect:{action.action_type}") if valid else 0.0
        capability = current.attacker_capability_gt
        remediation = max(0, current.remediation_steps_gt - 1)
        suppression_until = current.suppression_until_gt
        persistent = max(0.0, current.persistent_disruption * .72)

        if valid and action.action_type not in {"NO_OP", "ROLLBACK"}:
            routes, tasks, health, persistent, suppression_until, remediation, capability = self._apply_action(
                action.action_type, effectiveness, routes, tasks, health, persistent,
                current.tick, remediation, capability)
            if self.topology:
                routes, latent, disabled_nodes, blocked_connections = self._apply_graph_effect(
                    action, routes, latent, disabled_nodes, blocked_connections, current.current_route_gt)
                workflow_availability = self.topology.workflow_availability(disabled_nodes, blocked_connections)
                health = min(health, workflow_availability)
                persistent = max(persistent, 1.0 - workflow_availability)
        elif valid and action.action_type == "ROLLBACK":
            for task in current.recovery_tasks:
                health = min(1.0, health + task.service_restore_per_step * task.remaining_steps)
                recovery_cost += task.effort_per_step * task.remaining_steps + .15
                if task.restores_attacker_access and task.route and capability:
                    routes.append(task.route); restored_access = True
                # A rollback may restore only the route explicitly represented
                # by its approved recovery task; it cannot reopen unrelated
                # graph controls or latent attack paths.
                if self.topology and task.route:
                    route = self.topology.route(task.route)
                    if task.source_action in {"ISOLATE_DEVICE", "RESTRICT_RESOURCE"}:
                        disabled_nodes.difference_update(route.nodes)
                    if task.source_action == "SEGMENT_SERVICE":
                        blocked_connections.difference_update(zip(route.nodes, route.nodes[1:]))
            tasks = []; persistent *= .35

        if self.topology:
            workflow_availability = self.topology.workflow_availability(disabled_nodes, blocked_connections)
            health = min(health, workflow_availability)
            persistent = max(persistent, 1.0 - workflow_availability)

        if remediation == 0 and current.remediation_steps_gt > 0:
            capability = False; routes = []; latent = []

        attacker_observations = current.attacker_observations_gt + int(valid and action.action_type != "NO_OP")
        adapted = False
        delayed_ready = attacker_observations >= 2 and current.tick >= 2
        if capability and not routes and latent and delayed_ready and _draw(self.seed, current.tick, "adapt") < .68:
            routes.append(latent.pop(0)); adapted = True
        elif capability and routes and current.current_route_gt not in routes and delayed_ready:
            adapted = True

        dormant_until = current.dormant_until_gt
        if valid and action.action_type not in {"NO_OP", "ROLLBACK"} and _draw(self.seed, current.tick, "dormancy") < .28:
            dormant_until = max(dormant_until, current.tick + 2)
        active = capability and bool(routes) and current.tick + 1 >= dormant_until
        base = {"sensitive-data-exfiltration": .19, "privilege-escalation": .16,
                "lateral-movement": .15, "credential-compromise": .14,
                "malicious-insider": .13}.get(current.family, .13)
        progress = current.attacker_progress_gt
        if active:
            progress = min(1.0, progress + base * (.82 + .36 * _draw(self.seed, current.tick, "progress")))
        elif not capability:
            progress = max(0.0, progress - .12)

        exposure = 0.0 if not capability else min(1.0, (.18 * len(routes) + .10 * len(latent) + .55 * progress))
        persistent = min(1.0, persistent)
        disruption = min(1.0, max(0.0, 1.0 - health) + persistent)
        workflow_ok = health >= .78 and disruption < .35
        deadline_failure = current.tick + 1 >= 5 and exposure >= .72
        exfiltration = current.family == "sensitive-data-exfiltration" and progress >= .78 and "export-disabled" not in self.action_history
        critical_access = progress >= .88 and exposure >= .72
        critical_service_failure = health < .32 and persistent > .35
        severe = current.severe_outcome_gt or exfiltration or critical_access or critical_service_failure or deadline_failure
        genuine = not capability and not routes and not latent and not any(task.restores_attacker_access for task in tasks)
        suppression = capability and not routes and (bool(latent) or any(task.restores_attacker_access for task in tasks))
        terminal = severe or genuine or current.tick + 1 >= self.max_steps
        observed_activity = active and _draw(self.seed, current.tick, "sensor") < .78
        observed_compromise = float(np.clip(.65 * current.observed_compromise + .28 * exposure +
                                            (.12 if observed_activity else -.08), 0, 1))
        next_state = RealisticState(current.tick + 1, current.family, health, workflow_ok,
            observed_compromise, observed_activity, current.evidence_count + int(observed_activity), progress,
            capability, tuple(sorted(set(routes))), tuple(latent), routes[0] if routes else None,
            attacker_observations, dormant_until, suppression_until, remediation, tuple(tasks), persistent,
            severe, genuine, terminal, current.topology_id, tuple(sorted(disabled_nodes)),
            tuple(sorted(blocked_connections)))
        transition = ConsequenceTransition(current.tick, action.action_type, valid, effectiveness, exposure,
            disruption, recovery_cost, adapted, active, suppression, genuine, severe, not genuine,
            health, progress, len(routes), len(tasks))
        self.state = next_state; self.history.append(transition); self.action_history.append(action.action_type)
        return transition

    def _apply_graph_effect(self, action: SimulatedAction, routes: list[str], latent: list[str],
                            disabled_nodes: set[str], blocked_connections: set[tuple[str, str]],
                            current_route: str | None):
        """Apply a supported control to explicit graph paths; authority was checked by caller."""
        assert self.topology is not None
        affected = self.topology.affected_routes(action.action_type, action.targets, current_route)
        routes = [route for route in routes if route not in affected]
        latent = [route for route in latent if route not in affected]
        selected = set(action.targets)
        if action.action_type in {"ISOLATE_DEVICE", "RESTRICT_RESOURCE"}:
            disabled_nodes.update(selected)
        if action.action_type == "SEGMENT_SERVICE":
            for route_id in affected:
                route = self.topology.route(route_id)
                blocked_connections.update(zip(route.nodes, route.nodes[1:]))
        return routes, latent, disabled_nodes, blocked_connections

    def _apply_action(self, action: str, effectiveness: float, routes: list[str], tasks: list[RecoveryTask],
                      health: float, persistent: float, tick: int, remediation: int,
                      capability: bool):
        route = routes[0] if routes else None
        if action == "REQUIRE_FRESH_MFA":
            if routes: routes = routes[1:]
            persistent += .03; tasks.append(RecoveryTask(action, 1, 1, .04, .02, True, route))
        elif action == "REVOKE_SESSION":
            if routes: routes = routes[1:]
            persistent += .05; tasks.append(RecoveryTask(action, 2, 2, .06, .03, True, route))
            if effectiveness > .86: remediation = max(remediation, 2)
        elif action == "DISABLE_ACCOUNT":
            routes = []; health -= .18; persistent += .22
            tasks.append(RecoveryTask(action, 3, 3, .14, .06, True, route, True)); remediation = max(remediation, 2)
        elif action == "REMOVE_PRIVILEGE":
            routes = [item for item in routes if "route-1" not in item]; persistent += .08
            tasks.append(RecoveryTask(action, 2, 2, .08, .02, False, None)); remediation = max(remediation, 3)
        elif action == "RESTRICT_RESOURCE":
            routes = routes[:1]; health -= .16; persistent += .15
            tasks.append(RecoveryTask(action, 3, 3, .11, .05, True, route))
        elif action == "DISABLE_BULK_EXPORT":
            routes = [item for item in routes if "route-2" not in item]; health -= .08; persistent += .10
            tasks.append(RecoveryTask(action, 2, 2, .09, .04, False, None))
            self.action_history.append("export-disabled")
        elif action == "ISOLATE_DEVICE":
            routes = []; health -= .38; persistent += .32
            tasks.append(RecoveryTask(action, 3, 3, .18, .12, True, route)); remediation = max(remediation, 2)
        elif action == "SEGMENT_SERVICE":
            routes = routes[-1:]; health -= .28; persistent += .26
            tasks.append(RecoveryTask(action, 3, 3, .15, .09, True, route))
        return routes, tasks, max(0.0, health), persistent, max(tick + 1, 0), remediation, capability


def continuation_action(policy: str, observation: RealisticObservation, step: int,
                        previous_actions: tuple[str, ...]) -> SimulatedAction:
    """Defender policy using only RealisticObservation fields."""
    if policy not in POLICY_NAMES:
        raise KeyError(policy)
    if policy == "observation_only": return SimulatedAction("NO_OP")
    if policy == "immediate_containment":
        return SimulatedAction("NO_OP" if observation.recovery_active else "ISOLATE_DEVICE", approved=True)
    if policy == "minimally_disruptive":
        action = "REQUIRE_FRESH_MFA" if observation.observed_compromise < .78 else "REVOKE_SESSION"
        return SimulatedAction("NO_OP" if action in previous_actions else action)
    if policy == "escalating":
        sequence = ("REQUIRE_FRESH_MFA", "REVOKE_SESSION", "SEGMENT_SERVICE", "ISOLATE_DEVICE")
        return SimulatedAction(sequence[min(step, len(sequence) - 1)], approved=True)
    if policy == "evidence_seeking":
        if observation.evidence_count < 2 and not observation.observed_malicious_activity:
            return SimulatedAction("NO_OP")
        return SimulatedAction("REVOKE_SESSION")
    # Manual isolation/segmentation is deliberately withheld; automatic controls only.
    if observation.observed_compromise >= .72:
        return SimulatedAction("REVOKE_SESSION")
    return SimulatedAction("REQUIRE_FRESH_MFA")
