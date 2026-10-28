"""One correlated, simulator-only Phase 9.6 lifecycle across two organizations."""
from __future__ import annotations
import json, tempfile
from dataclasses import asdict
from pathlib import Path
import joblib

from sentinel_ai.shield.adaptive_planner import make_problem, solve_exact
from sentinel_ai.shield.autonomous_defense import Actor, DefenseCoordinator, DefenseStore, Status
from sentinel_ai.shield.beliefs import BayesianAttackerBeliefTracker
from sentinel_ai.shield.consequence_simulator import MultiStepConsequenceEnvironment
from sentinel_ai.shield.dynamic_models import Evidence
from sentinel_ai.shield.graph_integration import graph_action_specs, proposal_from_graph_plan, visible_graph_state
from sentinel_ai.shield.topology import topology_scenario


CORRELATION_ID = "phase96-shared-observed-threat"


def run_organization(name: str, topology: str, predictor) -> dict:
    incident_id = f"{CORRELATION_ID}:{name}"
    env = MultiStepConsequenceEnvironment("credential-compromise", 96101, max_steps=5, topology=topology_scenario(topology))
    tracker = BayesianAttackerBeliefTracker(); tracker.initialize(incident_id); observation = env.observe()
    evidence = Evidence(f"{incident_id}-signal", observation.tick, "cert-boundary-simulated-evidence",
                        "POST_ACTION_MALICIOUS_ACTIVITY", observation.observed_malicious_activity, .75, available_to_defender=True)
    belief = tracker.update_evidence(incident_id, 1, (evidence,))
    visible = visible_graph_state(env, belief.probabilities)
    plan = solve_exact(make_problem(predictor, visible, graph_action_specs(), ("observation_only", "minimally_disruptive", "policy_constrained"), allowed_tier="automatic"))
    prediction, diagnostic = predictor.predict_with_diagnostics(visible, plan.action, plan.policy)
    proposal = proposal_from_graph_plan(incident_id, env, plan, prediction, diagnostic)
    with tempfile.TemporaryDirectory() as directory:
        coordinator = DefenseCoordinator(DefenseStore(Path(directory) / "phase8.sqlite"))
        record = coordinator.propose(proposal, f"{incident_id}:{plan.action}", env)
        if record["status"] == Status.PENDING_HUMAN:
            record = coordinator.approve(record["proposal_id"], Actor(f"authorizer-{name}", "human_authorizer"), "approve")
        if record["status"] in {Status.AUTO_AUTHORIZED, Status.AUTHORIZED}:
            record = coordinator.execute(record["proposal_id"], Actor(f"authorizer-{name}", "human_authorizer"))
        recovery = None
        if record["status"] == Status.RECOVERY_PENDING:
            recovery = coordinator.recover(record["proposal_id"], Actor(f"authorizer-{name}", "human_authorizer"))
        final = recovery or record
        return {"organization": name, "correlation_id": CORRELATION_ID, "incident_id": incident_id, "topology": topology,
                "structure": {"nodes": len(env.topology.nodes), "routes": len(env.topology.routes), "workflows": len(env.topology.workflows)},
                "visible_observation": visible, "belief": {mode.value: value for mode, value in belief.probabilities.items()},
                "plan": asdict(plan), "prediction": prediction.means, "diagnostic": diagnostic,
                "phase8_status": final["status"], "phase8_events": coordinator.store.events(record["proposal_id"]),
                "actual_state": {"contained": env.state.contained_gt, "severe": env.state.severe_outcome_gt,
                                 "service_health": env.state.service_health, "workflow_availability": env.topology_posture()[2],
                                 "remaining_routes_ground_truth": len(env.state.accessible_routes_gt) + len(env.state.latent_routes_gt)},
                "feedback": final.get("feedback")}


def main() -> None:
    predictor = joblib.load("artifacts/models/shield_graph_consequence_v1.joblib")
    report = {"version": "shield-phase96-unified-demo-v1", "research_only": True,
              "evidence_mapping": "CERT integration is not asserted; a defender-visible simulated evidence boundary is used.",
              "organizations": [run_organization("small-office", "small-office", predictor), run_organization("critical-service", "critical-service", predictor)]}
    report["same_action_observed"] = report["organizations"][0]["plan"]["action"] == report["organizations"][1]["plan"]["action"]
    report["interpretation"] = ("The learned model selected the same constrained automatic action; differing predicted/actual workflow effects are reported without claiming contextual-action separation." if report["same_action_observed"] else "The learned model selected different actions from the same candidate set due to visible graph context.")
    path = Path("artifacts/reports/shield_phase96_unified_demo_v1.json"); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
