"""In-memory, fail-closed simulator incident sessions for the unified UI."""
from __future__ import annotations
import uuid
from dataclasses import asdict, dataclass
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
        return {"incident_id":s.incident_id,"correlation_id":s.correlation_id,"version":s.version,"origin":"simulated-evidence-bridge","simulation_only":True,"scenario":s.scenario,"topology":s.topology,
                "observation":{"tick":o.tick,"service_health":o.service_health,"observed_compromise":o.observed_compromise,"observed_malicious_activity":o.observed_malicious_activity,"evidence_count":o.evidence_count,"recovery_active":o.recovery_active,"terminal":o.terminal},
                "topology_state":{"nodes":[asdict(n) for n in s.environment.topology.nodes],"connections":[asdict(e) for e in s.environment.topology.connections],"workflows":[asdict(w) for w in s.environment.topology.workflows],"posture":s.environment.topology_posture()},
                "belief":{m.value:v for m,v in b.probabilities.items()},"proposal":record,"timeline":self.coordinator.store.events(s.proposal_id) if s.proposal_id else [],"predictor_available":self.predictor is not None}
    def plan(self,incident,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if not self.predictor: raise RuntimeError("graph consequence artifact unavailable")
        visible=visible_graph_state(s.environment,s.tracker.current.probabilities); plan=solve_exact(make_problem(self.predictor,visible,graph_action_specs(),("observation_only","minimally_disruptive","policy_constrained"),allowed_tier="automatic")); prediction,diagnostic=self.predictor.predict_with_diagnostics(visible,plan.action,plan.policy)
        return {"version":s.version,"visible_features":visible,"plan":asdict(plan),"prediction":prediction.means,"uncertainty":prediction.uncertainty,"diagnostic":diagnostic,"alternatives":"existing Phase 7 candidate/action set; exact classical planner"}
    def submit(self,incident,expected_version):
        s=self._session(incident); result=self.plan(incident,expected_version); plan=result["plan"]
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
        if record.get("feedback"):
            try:self.experience.ingest(experience_from_phase8_record(record))
            except ValueError:pass
        return self.snapshot(incident)
