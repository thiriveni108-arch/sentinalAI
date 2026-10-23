from __future__ import annotations

from .models import Intervention, Scenario, ShieldEdge, ShieldNode


def _n(node_id: str, kind: str, label: str, sensitivity: int = 0) -> ShieldNode:
    return ShieldNode(node_id, kind, label, sensitivity)


def scenarios() -> dict[str, Scenario]:
    credential = Scenario(
        "credential-compromise", "Credential Compromise",
        "Valid credentials create one unfamiliar session while a verified session remains active.",
        87, "Valid-account compromise", ("session:suspicious",),
        (_n("session:suspicious", "session", "Unfamiliar session"), _n("device:unknown", "device", "Unknown laptop"),
         _n("privilege:analyst", "privilege", "Analyst access"), _n("database:customer", "database", "Customer PII", 5)),
        (ShieldEdge("session:suspicious", "device:unknown", "SESSION_ON_DEVICE", True, True, ("EVT-LOGIN-NEW",)),
         ShieldEdge("session:suspicious", "privilege:analyst", "HAS_PRIVILEGE", True, True, ("EVT-TOKEN",)),
         ShieldEdge("privilege:analyst", "database:customer", "CAN_ACCESS", True, False, ("ACL-PII-READ",))),
        (Intervention("revoke-suspicious-session", "REVOKE_SESSION", "session:suspicious", 2, (), assumptions=("Token invalidation is immediate for this session.",), explanation="Invalidate only the unfamiliar session."),
         Intervention("require-fresh-mfa", "REQUIRE_FRESH_MFA", "user:employee", 0.5, (), assumptions=("Step-up MFA applies only to future authentication and does not revoke the active token.",), explanation="Gather stronger identity evidence; this alone does not interrupt the active-session path."),
         Intervention("isolate-unknown-device", "ISOLATE_DEVICE", "device:unknown", 3, (), assumptions=("Isolation blocks device traffic, but the modeled authorization route is not proven to remain device-bound.",), explanation="Useful defensive action, but not credited with path coverage without a proven device-bound route."),
         Intervention("disable-account", "DISABLE_ACCOUNT", "user:employee", 10, (), implementation_impact="high", approval_required=True, explanation="Disable all legitimate and suspicious activity.")),
        ("Unfamiliar device", "Valid login", "Active authorization token"),
    )
    insider = Scenario(
        "malicious-insider", "Malicious Insider", "Legitimate access is used for abnormal sensitive-file collection.",
        78, "Potential insider collection", ("session:employee",),
        (_n("session:employee", "session", "Verified employee session"), _n("privilege:research", "privilege", "Research read access"),
         _n("file:designs", "file", "Product designs", 4), _n("action:bulk-export", "damaging_action", "Bulk export", 5)),
        (ShieldEdge("session:employee", "privilege:research", "HAS_PRIVILEGE", True, True, ("IAM-ROLE-7",)),
         ShieldEdge("privilege:research", "file:designs", "CAN_ACCESS", True, True, ("EVT-FILE-SPIKE",)),
         ShieldEdge("file:designs", "action:bulk-export", "CAN_EXPORT", True, False, ("POLICY-EXPORT",))),
        (Intervention("restrict-designs", "RESTRICT_RESOURCE", "file:designs", 3, (), assumptions=("Resource ACL changes apply to subsequent reads.",), explanation="Temporarily remove access to the affected design repository."),
         Intervention("disable-export", "DISABLE_BULK_EXPORT", "file:designs", 1.5, (), assumptions=("Export control applies before a new export begins.",), explanation="Preserve normal reads while stopping bulk export."),
         Intervention("disable-account", "DISABLE_ACCOUNT", "user:employee", 10, (), implementation_impact="high", approval_required=True)),
        ("Sensitive access volume exceeds personal and peer baselines", "Access itself is authorized"),
    )
    multi = Scenario(
        "multiple-routes", "Multiple Attack Routes", "Two independent routes reach the payments database; a cheap single action is insufficient.",
        94, "Multi-route privilege compromise", ("session:compromised",),
        (_n("session:compromised", "session", "Compromised session"), _n("privilege:ops", "privilege", "Operations role"),
         _n("service:admin", "service", "Admin API"), _n("drive:shared", "file", "Finance share"),
         _n("database:payments", "database", "Payments database", 5), _n("action:exfil", "damaging_action", "Data exfiltration", 5)),
        (ShieldEdge("session:compromised", "privilege:ops", "HAS_PRIVILEGE", True, True, ("EVT-PRIV",)),
         ShieldEdge("privilege:ops", "service:admin", "CAN_ACCESS", True, False, ("IAM-ADMIN-API",)),
         ShieldEdge("service:admin", "database:payments", "CONNECTS_TO", True, False, ("NET-PAYMENTS",)),
         ShieldEdge("session:compromised", "drive:shared", "CAN_ACCESS", True, True, ("EVT-SHARE",)),
         ShieldEdge("drive:shared", "action:exfil", "CAN_EXPORT", True, False, ("POLICY-EXPORT",))),
        (Intervention("remove-ops-role", "REMOVE_PRIVILEGE", "privilege:ops", 2, (), assumptions=("The service performs live authorization; cached tokens are not accepted.",), explanation="Break the admin API route."),
         Intervention("disable-finance-export", "DISABLE_BULK_EXPORT", "drive:shared", 1, (), assumptions=("The control applies to new exports.",), explanation="Break the finance-share export route."),
         Intervention("revoke-session", "REVOKE_SESSION", "session:compromised", 4, (), assumptions=("All tokens bound to this session are invalidated.",), explanation="Break both routes at their common entry point."),
         Intervention("disable-account", "DISABLE_ACCOUNT", "user:employee", 12, (), implementation_impact="high", approval_required=True, explanation="Emergency broad containment.")),
        ("Privilege elevation", "Sensitive share access", "Independent routes confirmed"),
    )
    raw = {item.scenario_id: item for item in (credential, insider, multi)}
    # Coverage is derived from path membership, never from visual proximity.
    from .paths import enumerate_attack_paths
    result = {}
    for key, scenario in raw.items():
        paths = enumerate_attack_paths(scenario)
        path_ids = tuple(path.path_id for path in paths)
        def covered(action: Intervention) -> tuple[str, ...]:
            if action.action_type in {"REVOKE_SESSION", "DISABLE_ACCOUNT"}:
                return path_ids
            if action.action_type == "REMOVE_PRIVILEGE":
                return tuple(p.path_id for p in paths if action.target in p.nodes)
            if action.action_type == "RESTRICT_RESOURCE":
                return tuple(p.path_id for p in paths if action.target in p.nodes)
            if action.action_type == "DISABLE_BULK_EXPORT":
                return tuple(p.path_id for p in paths if action.target in p.nodes and "CAN_EXPORT" in p.relationships)
            return ()
        actions = tuple(Intervention(**{**a.__dict__, "interrupts": covered(a)}) for a in scenario.actions)
        result[key] = Scenario(**{**scenario.__dict__, "actions": actions})
    return result
