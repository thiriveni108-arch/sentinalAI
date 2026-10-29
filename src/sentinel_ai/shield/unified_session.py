"""In-memory, fail-closed simulator incident sessions for the unified UI.

The simulator environment deliberately remains process-local. Durable Phase 8
and Phase 10 records survive a restart, but they are never used to reconstruct
an environment whose trusted state is no longer available.
"""
from __future__ import annotations
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import joblib

from .adaptive_planner import make_problem, solve_exact
from .autonomous_defense import Actor, DefenseCoordinator
from .beliefs import BayesianAttackerBeliefTracker
from .consequence_simulator import MultiStepConsequenceEnvironment
from .continuous_learning import ExperienceStore, experience_from_phase8_record
from .dynamic_models import Evidence
from .graph_integration import graph_action_specs, proposal_from_graph_plan, visible_graph_state
from .topology import TOPOLOGY_FAMILIES


DEMO_IDENTITIES={"simulated-analyst":Actor("simulated-analyst","analyst"),"simulated-human":Actor("simulated-human","human_authorizer")}

@dataclass
class Session:
    incident_id:str; correlation_id:str; topology:str; scenario:str; seed:int; environment:object; tracker:object; version:int=0; proposal_id:str|None=None
    experience_status:dict=field(default_factory=lambda:{"attempted":False,"created":False,"eligible":False,"reasons":[],"fingerprint":None,"coverage_available":False})

class UnifiedSessionService:
    """Sessions deliberately cannot restore after process restart; callers fail closed."""
    def __init__(self, coordinator:DefenseCoordinator, experience:ExperienceStore, model_path="artifacts/models/shield_graph_consequence_v1.joblib"):
        self.coordinator,self.experience,self.sessions=coordinator,experience,{}
        self.predictor=joblib.load(model_path) if Path(model_path).exists() else None
    def create(self,scenario="credential-compromise",topology="small-office",seed=96001):
        if topology not in TOPOLOGY_FAMILIES: raise ValueError("unsupported topology")
        incident=str(uuid.uuid4()); env=MultiStepConsequenceEnvironment(scenario,int(seed),topology=topology)
        tracker=BayesianAttackerBeliefTracker(); tracker.initialize(incident); observation=env.observe()
        evidence=Evidence(f"{incident}-simulated",0,"simulated-evidence-bridge","POST_ACTION_MALICIOUS_ACTIVITY",observation.observed_malicious_activity,.75,available_to_defender=True)
        tracker.update_evidence(incident,1,(evidence,)); self.sessions[incident]=Session(incident,f"session-{incident[:8]}",topology,scenario,int(seed),env,tracker); return self.snapshot(incident)
    def _session(self,incident):
        if incident not in self.sessions: raise KeyError("session unavailable after restart; create a new simulator session")
        return self.sessions[incident]
    def snapshot(self,incident):
        s=self._session(incident); o=s.environment.observe(); b=s.tracker.current
        record=self.coordinator.store.get(s.proposal_id) if s.proposal_id else None
        status=record.get("status") if record else "INVESTIGATING"
        actions=["plan"] if not record else []
        if status in {"PENDING_ANALYST","PENDING_HUMAN"}: actions.extend(("approve","reject"))
        if status in {"AUTHORIZED","AUTO_AUTHORIZED","READY"}: actions.append("execute")
        if status=="RECOVERY_PENDING": actions.append("recover")
        if status in {"VERIFIED","RECOVERED","ESCALATED"}: actions.append("replan")
        return {"incident_id":s.incident_id,"session_id":s.incident_id,"correlation_id":s.correlation_id,"version":s.version,"lifecycle_status":status,"origin":"simulated-evidence-bridge","simulation_only":True,"scenario":s.scenario,"topology":s.topology,
                "observation":{"tick":o.tick,"service_health":o.service_health,"observed_compromise":o.observed_compromise,"observed_malicious_activity":o.observed_malicious_activity,"evidence_count":o.evidence_count,"recovery_active":o.recovery_active,"terminal":o.terminal},
                "topology_state":{"nodes":[asdict(n) for n in s.environment.topology.nodes],"connections":[asdict(e) for e in s.environment.topology.connections],"workflows":[asdict(w) for w in s.environment.topology.workflows],"posture":s.environment.topology_posture()},
                "belief":{m.value:v for m,v in b.probabilities.items()},"proposal":record,"timeline":self.coordinator.store.events(s.proposal_id) if s.proposal_id else [],"predictor_available":self.predictor is not None,
                "pending_authorization":record.get("decision") if record and status in {"PENDING_ANALYST","PENDING_HUMAN"} else None,
                "available_actions":actions,"experience_ingestion":s.experience_status,
                "provenance":{"evidence":"defender-visible simulated sensor","prediction":"frozen graph consequence model" if self.predictor else "unavailable","execution":"Phase 8 simulator coordinator","learning":"Phase 10 audited experience memory"}}
    def plan(self,incident,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if not self.predictor: raise RuntimeError("graph consequence artifact unavailable")
        visible=visible_graph_state(s.environment,s.tracker.current.probabilities); plan=solve_exact(make_problem(self.predictor,visible,graph_action_specs(),("observation_only","minimally_disruptive","policy_constrained"),allowed_tier="automatic")); prediction,diagnostic=self.predictor.predict_with_diagnostics(visible,plan.action,plan.policy)
        return {"version":s.version,"visible_features":visible,"plan":asdict(plan),"prediction":prediction.means,
                "uncertainty":max(prediction.uncertainty.values(),default=1.0),"uncertainty_by_target":prediction.uncertainty,
                "diagnostic":diagnostic,"alternatives":"existing Phase 7 candidate/action set; exact classical planner"}
    def submit(self,incident,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if s.proposal_id:
            return self.snapshot(incident)
        result=self.plan(incident,expected_version); plan=result["plan"]
        from .adaptive_planner import AdaptivePlan
        prediction,diagnostic=self.predictor.predict_with_diagnostics(result["visible_features"],plan["action"],plan["policy"])
        proposal=proposal_from_graph_plan(incident,s.environment,AdaptivePlan(**plan),prediction,diagnostic,s.version)
        record=self.coordinator.propose(proposal,f"{incident}:{s.version}:{proposal.action}",s.environment); s.proposal_id=record["proposal_id"]; s.version+=1; return self.snapshot(incident)
    def approve(self,incident,identity,decision,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if identity not in DEMO_IDENTITIES: raise PermissionError("server-established simulated identity required")
        self.coordinator.approve(s.proposal_id,DEMO_IDENTITIES[identity],decision); s.version+=1; return self.snapshot(incident)
    def execute(self,incident,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        self.coordinator.execute(s.proposal_id,DEMO_IDENTITIES["simulated-human"]); s.version+=1
        record=self.coordinator.store.get(s.proposal_id)
        if record.get("feedback"): self._ingest_feedback(s,record)
        return self.snapshot(incident)

    def _ingest_feedback(self,s,record):
        s.experience_status={"attempted":True,"created":False,"eligible":False,"reasons":[],"fingerprint":None,"coverage_available":False}
        try:
            validation=self.experience.ingest(experience_from_phase8_record(record))
            s.experience_status={"attempted":True,"created":True,"eligible":validation.eligible,"reasons":list(validation.reasons),"fingerprint":validation.fingerprint,"coverage_available":True}
        except (TypeError,ValueError) as error:
            s.experience_status.update({"reasons":[str(error)]})

    def recover(self,incident,identity,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if identity not in DEMO_IDENTITIES: raise PermissionError("server-established simulated identity required")
        record=self.coordinator.recover(s.proposal_id,DEMO_IDENTITIES[identity]); s.version+=1
        if record.get("feedback"): self._ingest_feedback(s,record)
        return self.snapshot(incident)

    def replan(self,incident,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if not self.predictor: raise RuntimeError("graph consequence artifact unavailable")
        return self.coordinator.observe_and_replan(s.incident_id,self.predictor,graph_action_specs(),("observation_only","minimally_disruptive","policy_constrained"))
