"""Versioned, dependency-free graph scenarios used by the SHIELD simulator.

This is intentionally a SHIELD contract, not a CyberBattleSim runtime adapter.
It borrows only the useful *concept* of an annotated enterprise graph.  All
fields here are scenario metadata; defender observations expose only aggregate
topology posture, never the attacker's route or hidden prerequisites.
"""
from __future__ import annotations

from dataclasses import dataclass


TOPOLOGY_CONTRACT_VERSION = "shield-topology-scenario-v1"


@dataclass(frozen=True)
class TopologyNode:
    identifier: str
    kind: str  # host, identity, service, resource
    criticality: int = 1


@dataclass(frozen=True)
class TopologyConnection:
    source: str
    target: str
    kind: str  # network, authentication, privilege


@dataclass(frozen=True)
class AttackRoute:
    identifier: str
    nodes: tuple[str, ...]
    required_identity: str | None = None
    requires_privilege: bool = False
    sensitive: bool = False
    initial_access: bool = False
    vulnerability_precondition: str = "visible-evidence"


@dataclass(frozen=True)
class BusinessWorkflow:
    identifier: str
    dependencies: tuple[str, ...]
    minimum_availability: float = .90
    critical: bool = False


@dataclass(frozen=True)
class TopologyScenario:
    identifier: str
    family: str
    nodes: tuple[TopologyNode, ...]
    connections: tuple[TopologyConnection, ...]
    routes: tuple[AttackRoute, ...]
    workflows: tuple[BusinessWorkflow, ...]
    version: str = TOPOLOGY_CONTRACT_VERSION

    def initial_routes(self) -> tuple[str, ...]:
        return tuple(route.identifier for route in self.routes if route.initial_access)

    def latent_routes(self) -> tuple[str, ...]:
        return tuple(route.identifier for route in self.routes if not route.initial_access)

    def route(self, identifier: str) -> AttackRoute:
        return next(route for route in self.routes if route.identifier == identifier)

    def workflow_availability(self, disabled_nodes: set[str], blocked_connections: set[tuple[str, str]]) -> float:
        """Fraction of workflows whose explicit dependencies remain reachable."""
        healthy = 0
        for workflow in self.workflows:
            required_edges = tuple(zip(workflow.dependencies, workflow.dependencies[1:]))
            available = not set(workflow.dependencies).intersection(disabled_nodes)
            available = available and not any(edge in blocked_connections for edge in required_edges)
            healthy += int(available)
        return healthy / max(1, len(self.workflows))

    def affected_routes(self, action: str, targets: tuple[str, ...], current_route: str | None) -> set[str]:
        """Map supported SHIELD controls to graph reachability, never authority."""
        selected = set(targets)
        if not selected and current_route:
            selected.add(current_route)
        affected: set[str] = set()
        for route in self.routes:
            if action in {"REQUIRE_FRESH_MFA", "REVOKE_SESSION", "DISABLE_ACCOUNT"}:
                match = route.required_identity in selected or route.identifier in selected
                # A default target is the currently active identity/route, not every account.
                affected |= {route.identifier} if match else set()
            elif action == "REMOVE_PRIVILEGE" and route.requires_privilege:
                affected.add(route.identifier)
            elif action in {"RESTRICT_RESOURCE", "DISABLE_BULK_EXPORT"} and route.sensitive:
                affected.add(route.identifier)
            elif action == "ISOLATE_DEVICE" and (selected.intersection(route.nodes) or route.identifier in selected):
                affected.add(route.identifier)
            elif action == "SEGMENT_SERVICE":
                edges = set(zip(route.nodes, route.nodes[1:]))
                if route.identifier in selected or any(node in selected for node in route.nodes) or not selected:
                    affected |= {route.identifier} if edges else set()
        return affected

    def action_consequence_context(self, action: str) -> tuple[float, float]:
        """Structural coverage and workflow loss for a proposed control.

        This is calculated from the declared graph, not attacker ground truth.
        It is used only as an explicit OOD adjustment around a frozen Phase 7
        predictor until graph-scenario outcome data support retraining.
        """
        if not self.routes:
            return 0.0, 0.0
        probe = self.routes[0].identifier
        affected = self.affected_routes(action, (), probe)
        coverage = len(affected) / len(self.routes)
        disabled: set[str] = set()
        blocked: set[tuple[str, str]] = set()
        if action in {"ISOLATE_DEVICE", "RESTRICT_RESOURCE"}:
            disabled.update(self.route(probe).nodes[-1:])
        if action == "SEGMENT_SERVICE":
            for route_id in affected:
                route = self.route(route_id)
                blocked.update(zip(route.nodes, route.nodes[1:]))
        return coverage, 1.0 - self.workflow_availability(disabled, blocked)


def _scenario(identifier: str, nodes: tuple[TopologyNode, ...], routes: tuple[AttackRoute, ...],
              workflows: tuple[BusinessWorkflow, ...]) -> TopologyScenario:
    connections = tuple(TopologyConnection(a, b, "network") for route in routes for a, b in zip(route.nodes, route.nodes[1:]))
    return TopologyScenario(identifier, identifier, nodes, connections, routes, workflows)


def topology_scenario(identifier: str) -> TopologyScenario:
    """Return structurally distinct, deterministic topology families."""
    if identifier == "small-office":
        return _scenario(identifier,
            (TopologyNode("laptop", "host"), TopologyNode("alice", "identity"), TopologyNode("files", "service", 3), TopologyNode("payroll", "resource", 5)),
            (AttackRoute("office-session", ("laptop", "files", "payroll"), "alice", True, True, True), AttackRoute("office-export", ("laptop", "payroll"), "alice", False, True)),
            (BusinessWorkflow("payroll", ("laptop", "files", "payroll"), critical=True),))
    if identifier == "segmented-enterprise":
        return _scenario(identifier,
            tuple(TopologyNode(x, "service" if x in {"vpn", "erp", "data"} else "host", 5 if x == "data" else 2) for x in ("workstation", "vpn", "erp", "data", "vendor")),
            (AttackRoute("corp-vpn", ("workstation", "vpn", "erp", "data"), "employee", True, True, True), AttackRoute("vendor-path", ("vendor", "erp", "data"), "vendor", False, True)),
            (BusinessWorkflow("order-processing", ("vpn", "erp", "data"), critical=True), BusinessWorkflow("vendor-support", ("vendor", "erp"))))
    if identifier == "multi-department":
        return _scenario(identifier,
            tuple(TopologyNode(x, "service", 4 if x == "finance-db" else 2) for x in ("hr-portal", "finance-db", "research", "directory", "mail")),
            (AttackRoute("hr-to-directory", ("hr-portal", "directory", "finance-db"), "hr-user", True, True, True), AttackRoute("research-to-finance", ("research", "directory", "finance-db"), "research-user", True, True)),
            (BusinessWorkflow("human-resources", ("hr-portal", "directory")), BusinessWorkflow("finance", ("directory", "finance-db"), critical=True), BusinessWorkflow("research", ("research",))))
    if identifier == "privileged-administration":
        return _scenario(identifier,
            tuple(TopologyNode(x, "identity" if x.endswith("admin") else "host", 5 if x == "domain" else 2) for x in ("admin-workstation", "helpdesk-admin", "jump-host", "domain", "backup")),
            (AttackRoute("admin-session", ("admin-workstation", "jump-host", "domain"), "helpdesk-admin", True, True, True), AttackRoute("backup-path", ("backup", "jump-host", "domain"), "backup-operator", True, True)),
            (BusinessWorkflow("administration", ("jump-host", "domain"), critical=True), BusinessWorkflow("backup", ("backup", "domain"), critical=True)))
    if identifier == "critical-service":
        return _scenario(identifier,
            tuple(TopologyNode(x, "service", 5 if x in {"clinical", "records"} else 2) for x in ("gateway", "clinical", "records", "analytics")),
            (AttackRoute("clinical-access", ("gateway", "clinical", "records"), "clinician", True, True, True), AttackRoute("analytics-access", ("analytics", "records"), "analyst", False, True)),
            (BusinessWorkflow("clinical-care", ("gateway", "clinical", "records"), critical=True), BusinessWorkflow("reporting", ("analytics", "records"))))
    if identifier == "redundant-services":
        return _scenario(identifier,
            tuple(TopologyNode(x, "service", 5 if x == "ledger" else 2) for x in ("portal", "api-a", "api-b", "ledger", "admin")),
            (AttackRoute("primary-api", ("portal", "api-a", "ledger"), "customer", False, True, True), AttackRoute("admin-api", ("admin", "api-b", "ledger"), "operator", True, True), AttackRoute("secondary-api", ("portal", "api-b", "ledger"), "customer", False, True)),
            (BusinessWorkflow("customer-service", ("portal", "api-a")), BusinessWorkflow("customer-failover", ("portal", "api-b")), BusinessWorkflow("ledger", ("api-a", "ledger"), critical=True)))
    raise KeyError(f"unknown topology scenario: {identifier}")


TOPOLOGY_FAMILIES = ("small-office", "segmented-enterprise", "multi-department", "privileged-administration", "critical-service", "redundant-services")


def grouped_split() -> dict[str, tuple[str, ...]]:
    """Family-level split; seeds never stand in for structural independence."""
    return {"train": ("small-office", "multi-department", "privileged-administration"),
            "validation": ("segmented-enterprise",), "test": ("critical-service", "redundant-services")}
