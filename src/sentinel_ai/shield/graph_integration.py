"""Decision-time bridge for validated graph simulation, Phase 7 planning and Phase 8.

No function in this module executes a response.  It only forms visible feature
vectors, advisory planner inputs, and Phase 8 proposals.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Mapping

from .adaptive_planner import ActionSpec, AdaptivePlan
from .autonomous_defense import Proposal
from .beliefs import MODES


def visible_graph_state(environment, belief: Mapping | None = None, active_interventions: tuple[str, ...] = ()) -> dict[str, float]:
    observation = environment.observe(); scale, connectivity, workflow, criticality = environment.topology_posture()
    values = {"state_tick": float(observation.tick), "service_health": observation.service_health,
              "observed_compromise": observation.observed_compromise,
              "observed_malicious_activity": float(observation.observed_malicious_activity),
              "evidence_count": float(observation.evidence_count), "graph_known_node_scale": scale,
              "graph_known_connectivity": connectivity, "graph_workflow_availability": workflow,
              "graph_criticality_posture": criticality, "active_intervention_count": float(len(active_interventions))}
    probability = belief or {}
    for mode in MODES:
        values[f"belief__{mode.value}"] = float(probability.get(mode, probability.get(mode.value, 1.0 / len(MODES))))
    return values


def graph_action_specs() -> tuple[ActionSpec, ...]:
    """Existing actions with explicit advisory scope and Phase 8-compatible tiers."""
    return (ActionSpec("REQUIRE_FRESH_MFA", .12, .20, True, "automatic"),
            ActionSpec("REVOKE_SESSION", .25, .30, True, "automatic"),
            ActionSpec("DISABLE_BULK_EXPORT", .35, .25, True, "automatic"),
            ActionSpec("REMOVE_PRIVILEGE", .45, .45, True, "semi-automatic"),
            ActionSpec("RESTRICT_RESOURCE", .55, .60, True, "semi-automatic"),
            ActionSpec("DISABLE_ACCOUNT", .75, .75, False, "human-approval"),
            ActionSpec("ISOLATE_DEVICE", .90, .90, False, "human-approval"),
            ActionSpec("SEGMENT_SERVICE", .85, .90, True, "human-approval"),
            ActionSpec("NO_OP", .05, .0, True, "automatic"))


def proposal_from_graph_plan(incident_id: str, environment, plan: AdaptivePlan, prediction, diagnostics: Mapping[str, object], state_version: int = 0) -> Proposal:
    topology = environment.topology
    target = defender_visible_target(topology, plan.action) if topology else None
    # Scope is intentionally conservative: an opaque/unsupported graph cannot be auto-authorized.
    criticality = max((node.criticality for node in topology.nodes), default=1) if topology else 5
    graph_supported = bool(topology and not diagnostics.get("out_of_distribution", True))
    values = {**prediction.means, "operationally_suitable": False, "out_of_distribution": not graph_supported,
              "graph_required": True, "graph_supported": graph_supported, "model_version": diagnostics.get("model_version", "unknown")}
    return Proposal(incident_id=incident_id, action=plan.action, targets=(target,) if target else (), state_version=state_version,
                    planner_source="phase96-graph-consequence", prediction=values,
                    uncertainty=max(prediction.uncertainty.values(), default=1.0), target_criticality=criticality,
                    blast_radius=1 if plan.action in {"REQUIRE_FRESH_MFA", "REVOKE_SESSION", "DISABLE_BULK_EXPORT", "NO_OP"} else 2,
                    reversible=plan.action not in {"DISABLE_ACCOUNT", "ISOLATE_DEVICE"},
                    recovery_plan=plan.action != "NO_OP", incident_severity=4 if criticality >= 4 else 2)


def defender_visible_target(topology, action: str) -> str | None:
    """Choose only from declared graph entities; never inspect attacker route/capability state."""
    if topology is None:
        return None
    identity = next((route.required_identity for route in topology.routes if route.required_identity), None)
    if action in {"REQUIRE_FRESH_MFA", "REVOKE_SESSION", "DISABLE_ACCOUNT"}:
        return identity
    kinds = {
        "ISOLATE_DEVICE": {"host"}, "REMOVE_PRIVILEGE": {"identity"},
        "RESTRICT_RESOURCE": {"resource", "service"}, "DISABLE_BULK_EXPORT": {"resource", "service"},
        "SEGMENT_SERVICE": {"service"},
    }.get(action, set())
    candidates = [node for node in topology.nodes if node.kind in kinds]
    return max(candidates, key=lambda node: node.criticality).identifier if candidates else None
