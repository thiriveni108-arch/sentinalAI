from __future__ import annotations

from collections import defaultdict
from hashlib import sha256

from .models import AttackPath, Scenario, ShieldEdge


ALLOWED_RELATIONSHIPS = {
    "AUTHENTICATES_AS", "SESSION_ON_DEVICE", "HAS_PRIVILEGE", "CAN_ESCALATE_TO",
    "CAN_ACCESS", "HOSTS", "CAN_EXPORT", "CONNECTS_TO",
}


def enumerate_attack_paths(scenario: Scenario, max_depth: int = 6, max_paths: int = 32) -> tuple[AttackPath, ...]:
    """Enumerate bounded directed paths using only explicitly exploitable semantics."""
    nodes = {node.node_id: node for node in scenario.nodes}
    adjacency: dict[str, list[ShieldEdge]] = defaultdict(list)
    for edge in scenario.edges:
        if edge.exploitable and edge.relationship in ALLOWED_RELATIONSHIPS:
            adjacency[edge.source].append(edge)
    for edges in adjacency.values():
        edges.sort(key=lambda item: (item.target, item.relationship))

    results: list[AttackPath] = []
    for start in sorted(scenario.entry_points):
        stack = [(start, (start,), (), (), 0)]
        while stack and len(results) < max_paths:
            current, visited, rels, evidence, observed = stack.pop()
            if len(visited) - 1 >= max_depth:
                continue
            for edge in reversed(adjacency.get(current, [])):
                if edge.target in visited:  # simple paths make cycles safe
                    continue
                next_nodes = visited + (edge.target,)
                next_rels = rels + (edge.relationship,)
                next_evidence = tuple(dict.fromkeys(evidence + edge.evidence))
                next_observed = observed + int(edge.observed)
                target = nodes.get(edge.target)
                if target and target.sensitivity >= 3:
                    digest = sha256("|".join(next_nodes).encode()).hexdigest()[:10]
                    results.append(AttackPath(
                        path_id=f"PATH-{digest.upper()}", nodes=next_nodes,
                        relationships=next_rels,
                        criticality=min(5, target.sensitivity + (1 if len(next_nodes) <= 4 else 0)),
                        evidence=next_evidence, observed_hops=next_observed,
                        hypothetical_hops=len(next_rels) - next_observed,
                    ))
                    if len(results) >= max_paths:
                        break
                stack.append((edge.target, next_nodes, next_rels, next_evidence, next_observed))
    return tuple(sorted(results, key=lambda item: item.path_id))
