from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ShieldNode:
    node_id: str
    node_type: str
    label: str
    sensitivity: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ShieldEdge:
    source: str
    target: str
    relationship: str
    exploitable: bool
    observed: bool
    evidence: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    nodes: tuple[str, ...]
    relationships: tuple[str, ...]
    criticality: int
    evidence: tuple[str, ...]
    observed_hops: int
    hypothetical_hops: int


@dataclass(frozen=True)
class Intervention:
    action_id: str
    action_type: str
    target: str
    cost: float
    interrupts: tuple[str, ...]
    prerequisites: tuple[str, ...] = ()
    incompatible_with: tuple[str, ...] = ()
    reversible: bool = True
    implementation_impact: str = "low"
    assumptions: tuple[str, ...] = ()
    explanation: str = ""
    approval_required: bool = False


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    summary: str
    risk_score: float | None
    threat_classification: str
    entry_points: tuple[str, ...]
    nodes: tuple[ShieldNode, ...]
    edges: tuple[ShieldEdge, ...]
    actions: tuple[Intervention, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Plan:
    selected: tuple[str, ...]
    feasible: bool
    objective: float
    disruption_cost: float
    covered_paths: tuple[str, ...]
    remaining_paths: tuple[str, ...]
    solver: str
    explanation: str
