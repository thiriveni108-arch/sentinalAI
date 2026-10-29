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

from .adaptive_planner import make_problem, score, solve_exact
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
    incident_id:str; session_id:str; correlation_id:str; topology:str; scenario:str; seed:int; environment:object; tracker:object
    origin:str="simulated-evidence-bridge"; source:dict=field(default_factory=dict); adapter:dict=field(default_factory=dict)
    version:int=0; proposal_id:str|None=None; proposal_ids:list[str]=field(default_factory=list)
    experience_status:dict=field(default_factory=lambda:{"attempted":False,"created":False,"eligible":False,"reasons":[],"fingerprint":None,"coverage_available":False})

class UnifiedSessionService:
    """Sessions deliberately cannot restore after process restart; callers fail closed."""
    def __init__(self, coordinator:DefenseCoordinator, experience:ExperienceStore, model_path="artifacts/models/shield_graph_consequence_v1.joblib"):
        self.coordinator,self.experience,self.sessions=coordinator,experience,{}
        artifact=Path(model_path)
        if not artifact.is_absolute() and not artifact.exists(): artifact=Path(__file__).resolve().parents[3]/artifact
        self.predictor=joblib.load(artifact) if artifact.exists() else None
    def create(self,scenario="credential-compromise",topology="small-office",seed=96001):
        if topology not in TOPOLOGY_FAMILIES: raise ValueError("unsupported topology")
        incident=str(uuid.uuid4()); env=MultiStepConsequenceEnvironment(scenario,int(seed),topology=topology)
        tracker=BayesianAttackerBeliefTracker(); tracker.initialize(incident); observation=env.observe()
        evidence=Evidence(f"{incident}-simulated",0,"simulated-evidence-bridge","POST_ACTION_MALICIOUS_ACTIVITY",observation.observed_malicious_activity,.75,available_to_defender=True)
        tracker.update_evidence(incident,1,(evidence,)); session_id=f"SHIELD-{uuid.uuid4().hex[:12].upper()}"
        self.sessions[incident]=Session(incident,session_id,f"session-{incident[:8]}",topology,scenario,int(seed),env,tracker,
            adapter={"version":"standalone-graph-exercise-v1","assumptions":["Synthetic exercise evidence only"]}); return self.snapshot(incident)

    def create_linked(self, document, topology="small-office", seed=96001):
        """Create/retrieve a CERT-linked response environment without changing detection evidence."""
        incident=document["incidentId"]
        if incident in self.sessions: return self.snapshot(incident)
        if topology not in TOPOLOGY_FAMILIES: raise ValueError("unsupported topology")
        env=MultiStepConsequenceEnvironment("sensitive-data-exfiltration",int(seed),topology=topology)
        tracker=BayesianAttackerBeliefTracker(); tracker.initialize(incident)
        injected=document["injectedEvidence"]; refs=document["linkage"]["immutableEvidenceRefs"]
        evidence=[]; mappings=[]
        if float(injected.get("file_copy_count",0))>0:
            evidence.append(Evidence(refs[1],0,"cert-to-shield-adapter-v1","BULK_EXPORT",True,.70,available_to_defender=True))
            mappings.append({"source":"injectedEvidence.file_copy_count","type":"BULK_EXPORT","confidence":.70,
                "note":"Categorical simulator likelihood input; not a converted detector probability."})
        else: mappings.append({"source":"injectedEvidence.file_copy_count","type":None,"status":"unsupported-or-absent"})
        tracker.update_evidence(incident,0,tuple(evidence))
        session_id=f"SHIELD-{uuid.uuid4().hex[:12].upper()}"
        adapter={"version":"cert-to-shield-evidence-adapter-v1","mappings":mappings,
            "unknownFields":["actual enterprise topology","attacker capability","attacker route","contemporary resource ownership"],
            "assumptions":[f"{topology} is a hypothetical response-testing environment",
                "Injected file activity is mapped only to the supported BULK_EXPORT evidence category"],
            "detectorOutcomePreserved":document["detection"]["outcome"]}
        source={"certIncidentId":incident,"user":document["canonicalRecord"]["user"],"date":document["canonicalRecord"]["date"],
            "identity":document["canonicalRecord"]["identity"],"detection":document["detection"],
            "scenario":document["scenario"],"initiatedBy":document["linkage"]["initiatedBy"],"evidenceRefs":refs}
        self.sessions[incident]=Session(incident,session_id,f"cert-{incident}",topology,"sensitive-data-exfiltration",int(seed),env,tracker,
            origin="cert-linked-incident",source=source,adapter=adapter)
        return self.snapshot(incident)
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
        linked=s.origin=="cert-linked-incident"; identity=s.source.get("identity",{})
        trigger=(f"Controlled {s.source.get('scenario','CERT')} injection; {s.source.get('detection',{}).get('outcome','unknown')}"
                 if linked else "Defender-visible simulated malicious activity")
        affected=self._visible_scope(s)
        return {"incident_id":s.incident_id,"session_id":s.session_id,"correlation_id":s.correlation_id,"version":s.version,"lifecycle_status":status,"origin":s.origin,"mode":"CERT_LINKED_INCIDENT" if linked else "STANDALONE_GRAPH_EXERCISE","simulation_only":True,"scenario":s.scenario,"topology":s.topology,"seed":s.seed,"adapter":s.adapter,
                "observation":{"tick":o.tick,"service_health":o.service_health,"observed_compromise":o.observed_compromise,"observed_malicious_activity":o.observed_malicious_activity,"evidence_count":o.evidence_count,"recovery_active":o.recovery_active,"terminal":o.terminal},
                "topology_state":{"nodes":[asdict(n) for n in s.environment.topology.nodes],"connections":[asdict(e) for e in s.environment.topology.connections],"workflows":[asdict(w) for w in s.environment.topology.workflows],"posture":s.environment.topology_posture()},
                "belief":{m.value:v for m,v in b.probabilities.items()},"proposal":record,"timeline":self.coordinator.store.events(s.proposal_id) if s.proposal_id else [],"predictor_available":self.predictor is not None,
                "pending_authorization":record.get("decision") if record and status in {"PENDING_ANALYST","PENDING_HUMAN"} else None,
                "available_actions":actions,"experience_ingestion":s.experience_status,
                "context":{"identity":{"established":linked,"display_label":identity.get("displayLabel","Identity not established in this simulation"),"identifier":identity.get("sourceId"),"role":identity.get("role"),"department":identity.get("businessUnit")},
                    "trigger":{"event":trigger,"summary":(f"CERT employee-day {s.source.get('date')} retained with actual detector outcome; SHIELD uses a hypothetical {s.topology.replace('-', ' ')} graph." if linked else f"The {s.scenario.replace('-', ' ')} exercise produced defender-visible evidence in the {s.topology.replace('-', ' ')} topology."),"source_event_ids":s.source.get("evidenceRefs",[f"{s.incident_id}-simulated"])},
                    "evidence_summary":(f"Actual CERT policy outcome {s.source['detection']['outcome']}; adapter supplied {len(s.adapter.get('mappings',[]))} supported mapping(s)." if linked else f"{o.evidence_count} simulated sensor observation(s); observed compromise {o.observed_compromise:.3f} model units."),
                    "affected_resources":affected,"detection_outcome":s.source.get("detection",{}).get("outcome","SIMULATED_ACTIVITY_OBSERVED" if o.observed_malicious_activity else "NO_MALICIOUS_ACTIVITY_OBSERVED"),
                    "network_context":"Hypothetical topology selected for controlled graph simulation; it is not derived from CERT enterprise infrastructure.","approval_scope":"simulation-only"},
                "provenance":{"evidence":"defender-visible simulated sensor","prediction":"frozen graph consequence model" if self.predictor else "unavailable","execution":"Phase 8 simulator coordinator","learning":"Phase 10 audited experience memory"}}

    @staticmethod
    def _visible_scope(s):
        """Specific declared graph resources supported for candidate controls, not the whole topology."""
        nodes=s.environment.topology.nodes
        return [n.identifier for n in nodes if n.kind in {"identity","resource"} or n.criticality>=4]
    def plan(self,incident,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if not self.predictor: raise RuntimeError("graph consequence artifact unavailable")
        visible=visible_graph_state(s.environment,s.tracker.current.probabilities)
        problem=make_problem(self.predictor,visible,graph_action_specs(),("observation_only","minimally_disruptive","policy_constrained"),allowed_tier="automatic")
        plan=solve_exact(problem); prediction,diagnostic=self.predictor.predict_with_diagnostics(visible,plan.action,plan.policy)
        alternatives=[]
        for action in problem.actions:
            choices=[score(problem,action,policy) for policy in problem.policies]
            candidate=min(choices,key=lambda item:item.objective)
            candidate_prediction=problem.predictions[(candidate.action,candidate.policy)]
            alternatives.append({"action":candidate.action,"policy":candidate.policy,"objective":candidate.objective,
                "feasible":candidate.feasible,"reason":candidate.reason,"reversible":action.reversible,"tier":action.tier,
                "prediction":candidate_prediction.means,"uncertainty":max(candidate_prediction.uncertainty.values(),default=1.0)})
        alternatives.sort(key=lambda item:(not item["feasible"],item["objective"],item["action"]))
        return {"version":s.version,"visible_features":visible,"plan":asdict(plan),"prediction":prediction.means,
                "uncertainty":max(prediction.uncertainty.values(),default=1.0),"uncertainty_by_target":prediction.uncertainty,
                "diagnostic":diagnostic,"alternatives":alternatives}
    def submit(self,incident,expected_version):
        s=self._session(incident)
        if s.version!=expected_version: raise RuntimeError("stale incident version")
        if s.proposal_id:
            current=self.coordinator.store.get(s.proposal_id)
            if current["status"] not in {"VERIFIED","RECOVERED","ESCALATED","REJECTED","POLICY_BLOCKED","EXECUTION_FAILED"}:
                return self.snapshot(incident)
            s.proposal_id=None
        result=self.plan(incident,expected_version); plan=result["plan"]
        from .adaptive_planner import AdaptivePlan
        prediction,diagnostic=self.predictor.predict_with_diagnostics(result["visible_features"],plan["action"],plan["policy"])
        proposal=proposal_from_graph_plan(incident,s.environment,AdaptivePlan(**plan),prediction,diagnostic,s.version)
        record=self.coordinator.propose(proposal,f"{incident}:{s.version}:{proposal.action}",s.environment); s.proposal_id=record["proposal_id"]; s.proposal_ids.append(s.proposal_id); s.version+=1; return self.snapshot(incident)
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
            experience=experience_from_phase8_record(record)
            experience["linkage"]={"cert_incident_id":s.source.get("certIncidentId"),"shield_session_id":s.session_id,
                "proposal_id":s.proposal_id,"origin":s.origin,"adapter_version":s.adapter.get("version")}
            validation=self.experience.ingest(experience)
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
