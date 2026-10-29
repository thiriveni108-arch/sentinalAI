# CERT-to-SHIELD integration audit

| Boundary | Before repair | Current contract |
|---|---|---|
| CERT injection and frozen detection | Persisted in `IncidentService.create`; genuinely connected to the incident record. | Preserved unchanged; detector misses remain `MISSED_BY_SELECTED_POLICY`. |
| CERT incident to unified SHIELD | Disconnected. `UnifiedSessionService.create` always generated a new credential-compromise exercise and synthetic evidence. | `create_linked` consumes the persisted incident and `cert-to-shield-evidence-adapter-v1`; standalone creation remains explicitly separate. |
| Identity/evidence continuity | Screens could share query identifiers but the unified session had no CERT identity. | `sentinel-canonical-incident-link-v1` stores stable CERT, session, proposal, execution and experience references in the existing incident record. |
| Evidence semantics | Simulator sensor evidence only. | CERT fields and actual detector decisions are preserved; only supported file activity maps to `BULK_EXPORT`; unsupported topology/capability/route fields are declared unknown. |
| Phase 7 targeting | `proposal_from_graph_plan` selected `current_route_gt` (hidden attacker ground truth). | `defender_visible_target` selects only declared identity/resource/service/host scope by action semantics. |
| Phase 7 to Phase 8 | Server plan already passed through `DefenseCoordinator`, with JIT policy/state checks. | Preserved; linked proposals are keyed to the canonical CERT incident and durable linkage mirrors references only. |
| Verification/recovery | Genuine simulator verification and guarded rollback existed, but only for standalone sessions. | Same implementation is used by both modes; failed containment remains escalation and recovery can be blocked as unsafe. |
| Phase 8 to Phase 10 | One-step feedback ingestion existed for standalone sessions. | Experience payload now includes CERT incident, SHIELD session, proposal and adapter linkage without inventing a trajectory. |
| Frontend journey | Adversary Lab persisted CERT incidents, while the main incident provider launched unrelated standalone sessions. | Investigation exposes **Evaluate SHIELD Response**, selects a hypothetical topology, and navigates the linked session across SHIELD/response/learning workspaces. |
| Approval story | Controls showed action state without complete incident context. | Approval surface shows WHO, WHAT, WHY, WHERE, ACTION, IMPACT, AUTHORITY and RECOVERY from server data. |

Scientific boundary: CERT r4.2 provides employee-day aggregates, not a contemporary enterprise graph. All response topology and simulator consequences remain explicitly hypothetical.
