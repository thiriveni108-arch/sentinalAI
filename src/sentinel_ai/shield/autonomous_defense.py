"""Phase 8 simulator-only, policy-governed SHIELD execution lifecycle.

This module deliberately has no dependency on production response services.  A
proposal is only actionable through ``DefenseCoordinator`` and every durable
record is bound to one incident, state version, scope, policy version and
idempotency key.
"""
from __future__ import annotations

import hashlib, json, sqlite3, uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

from .consequence_simulator import MultiStepConsequenceEnvironment, SimulatedAction
from .beliefs import BayesianAttackerBeliefTracker
from .dynamic_models import Evidence

POLICY_VERSION = "shield-phase8-policy-v1"
FEEDBACK_VERSION = "shield-qrl-feedback-v1"

class Tier(StrEnum): AUTOMATIC="TIER_1_AUTOMATIC"; ANALYST="TIER_2_ANALYST"; HUMAN="TIER_3_HUMAN"
class Status(StrEnum):
    PROPOSED="PROPOSED"; POLICY_EVALUATED="POLICY_EVALUATED"; AUTO_AUTHORIZED="AUTO_AUTHORIZED"; PENDING_ANALYST="PENDING_ANALYST"; PENDING_HUMAN="PENDING_HUMAN"; AUTHORIZED="AUTHORIZED"; READY="READY"; EXECUTING="EXECUTING"; EXECUTED="EXECUTED"; VERIFYING="VERIFYING"; VERIFIED="VERIFIED"; REJECTED="REJECTED"; CANCELLED="CANCELLED"; EXPIRED="EXPIRED"; POLICY_BLOCKED="POLICY_BLOCKED"; EXECUTION_FAILED="EXECUTION_FAILED"; RECOVERY_PENDING="RECOVERY_PENDING"; RECOVERING="RECOVERING"; RECOVERED="RECOVERED"; ESCALATED="ESCALATED"

TERMINAL={Status.VERIFIED,Status.REJECTED,Status.CANCELLED,Status.EXPIRED,Status.POLICY_BLOCKED,Status.EXECUTION_FAILED,Status.RECOVERED,Status.ESCALATED}
TRANSITIONS={
 Status.PROPOSED:{Status.POLICY_EVALUATED,Status.CANCELLED}, Status.POLICY_EVALUATED:{Status.AUTO_AUTHORIZED,Status.PENDING_ANALYST,Status.PENDING_HUMAN,Status.POLICY_BLOCKED},
 Status.AUTO_AUTHORIZED:{Status.READY,Status.CANCELLED}, Status.PENDING_ANALYST:{Status.AUTHORIZED,Status.REJECTED,Status.EXPIRED,Status.CANCELLED}, Status.PENDING_HUMAN:{Status.AUTHORIZED,Status.REJECTED,Status.EXPIRED,Status.CANCELLED},
 Status.AUTHORIZED:{Status.READY,Status.EXPIRED,Status.CANCELLED}, Status.READY:{Status.EXECUTING,Status.POLICY_BLOCKED,Status.EXPIRED}, Status.EXECUTING:{Status.EXECUTED,Status.EXECUTION_FAILED}, Status.EXECUTED:{Status.VERIFYING}, Status.VERIFYING:{Status.VERIFIED,Status.RECOVERY_PENDING,Status.ESCALATED}, Status.RECOVERY_PENDING:{Status.RECOVERING,Status.ESCALATED}, Status.RECOVERING:{Status.RECOVERED,Status.ESCALATED}}

@dataclass(frozen=True)
class Actor: actor_id:str; role:str
@dataclass(frozen=True)
class Proposal:
    incident_id:str; action:str; targets:tuple[str,...]; state_version:int; planner_source:str
    prediction:Mapping[str,float]; uncertainty:float; target_criticality:int=1; blast_radius:int=1; reversible:bool=True; recovery_plan:bool=True; incident_severity:int=1; policy:str="policy_constrained"; proposal_id:str=""
@dataclass(frozen=True)
class PolicyDecision: tier:Tier; allowed:bool; reasons:tuple[str,...]; automatic_eligible:bool
@dataclass(frozen=True)
class Approval: proposal_id:str; actor_id:str; decision:str; state_version:int; policy_version:str; expires_at:str; scope_hash:str; token:str
@dataclass(frozen=True)
class FeedbackRecord:
    version:str; episode_id:str; incident_id:str; observable_pre_action:Mapping[str,Any]; belief:Mapping[str,float]; candidate_actions:tuple[str,...]; planner_source:str; predictions:Mapping[str,float]; uncertainty:float; policy_tier:str; approval_status:str; executed_action:str|None; observable_post_action:Mapping[str,Any]|None; actual:Mapping[str,Any]|None; verification:str; recovery:Mapping[str,Any]; evidence_provenance:tuple[str,...]; evaluation_ground_truth:Mapping[str,Any]|None

def _now(): return datetime.now(timezone.utc)
def _scope(p:Proposal): return hashlib.sha256(json.dumps({"i":p.incident_id,"a":p.action,"t":p.targets,"v":p.state_version},sort_keys=True).encode()).hexdigest()
def _obs(o, environment=None):
    value={"tick":o.tick,"service_health":o.service_health,"observed_compromise":o.observed_compromise,"observed_malicious_activity":o.observed_malicious_activity,"evidence_count":o.evidence_count,"terminal":o.terminal}
    if environment is not None and getattr(environment, "topology", None): value["graph_posture"]=list(environment.topology_posture())
    return value

class PolicyEngine:
    """Deterministic policy: prediction can restrict automation but never grant it."""
    tier1=frozenset({"REQUIRE_FRESH_MFA","DISABLE_BULK_EXPORT","REVOKE_SESSION"})
    def evaluate(self,p:Proposal,active_actions:set[str]=set())->PolicyDecision:
        reasons=[]
        missing=not p.targets or not p.recovery_plan or not p.planner_source or not p.prediction or "operationally_suitable" not in p.prediction
        critical=p.target_criticality>=4 or p.blast_radius>1 or not p.reversible or p.incident_severity>=4
        unreliable=p.uncertainty>.30 or bool(p.prediction.get("out_of_distribution",False)) or bool(p.prediction.get("operationally_suitable",False)) is False
        conflict=p.action in active_actions or (p.action=="ROLLBACK" and not p.recovery_plan)
        if missing: reasons.append("missing required authorization or recovery context")
        if conflict: reasons.append("conflicting active intervention")
        if critical: reasons.append("critical, broad, or irreversible action")
        if unreliable: reasons.append("prediction reliability restricts autonomy")
        auto=p.action in self.tier1 and p.reversible and p.blast_radius==1 and p.target_criticality<3 and p.prediction.get("target_cumulative_disruption",1)>0 and p.prediction.get("target_cumulative_disruption",1)<=.20 and not unreliable and not missing and not conflict
        if missing or conflict: return PolicyDecision(Tier.HUMAN,False,tuple(reasons),False)
        if critical: return PolicyDecision(Tier.HUMAN,True,tuple(reasons),False)
        if auto: return PolicyDecision(Tier.AUTOMATIC,True,("allowlisted, narrow, reversible and within strict disruption limit",),True)
        return PolicyDecision(Tier.ANALYST,True,tuple(reasons or ["analyst confirmation required by default"]),False)

class DefenseStore:
    def __init__(self,path:str|Path):
        self.path=str(path); Path(path).parent.mkdir(parents=True,exist_ok=True)
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS phase8_records (proposal_id TEXT PRIMARY KEY, incident_id TEXT, state TEXT, version INTEGER, payload TEXT NOT NULL, idempotency_key TEXT UNIQUE, created_at TEXT, updated_at TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS phase8_events (id INTEGER PRIMARY KEY, proposal_id TEXT, state TEXT, actor TEXT, detail TEXT, created_at TEXT)")
    @contextmanager
    def _conn(self):
        connection=sqlite3.connect(self.path)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
    def create(self,p:Proposal,key:str):
        pid=p.proposal_id or str(uuid.uuid4()); p=Proposal(**{**asdict(p),"proposal_id":pid}); now=_now().isoformat()
        with self._conn() as c:
            existing=c.execute("SELECT proposal_id FROM phase8_records WHERE idempotency_key=?",(key,)).fetchone()
            if existing:return self.get(existing[0]),True
            payload={"proposal":asdict(p),"decision":None,"approval":None,"execution":None,"feedback":None,"active":False}
            c.execute("INSERT INTO phase8_records VALUES (?,?,?,?,?,?,?,?)",(pid,p.incident_id,Status.PROPOSED,0,json.dumps(payload),key,now,now)); self.event(c,pid,Status.PROPOSED,"system","proposal created")
        return self.get(pid),False
    def event(self,c,pid,state,actor,detail): c.execute("INSERT INTO phase8_events(proposal_id,state,actor,detail,created_at) VALUES(?,?,?,?,?)",(pid,state,actor,detail,_now().isoformat()))
    def get(self,pid):
        with self._conn() as c:
            row=c.execute("SELECT state,version,payload FROM phase8_records WHERE proposal_id=?",(pid,)).fetchone()
            if not row: raise KeyError(pid)
            value=json.loads(row[2]); value.update({"proposal_id":pid,"status":row[0],"version":row[1]}); return value
    def transition(self,pid,to:Status,actor="system",detail="",patch:dict|None=None):
        with self._conn() as c:
            row=c.execute("SELECT state,version,payload FROM phase8_records WHERE proposal_id=?",(pid,)).fetchone()
            if not row: raise KeyError(pid)
            old=Status(row[0]);
            if to not in TRANSITIONS.get(old,set()): raise ValueError(f"invalid transition {old}->{to}")
            payload=json.loads(row[2]); payload.update(patch or {}); version=row[1]+1
            c.execute("UPDATE phase8_records SET state=?,version=?,payload=?,updated_at=? WHERE proposal_id=?",(to,version,json.dumps(payload),_now().isoformat(),pid)); self.event(c,pid,to,actor,detail)
        return self.get(pid)
    def amend(self,pid,patch:dict):
        """Persist non-lifecycle context without bypassing lifecycle transitions."""
        with self._conn() as c:
            row=c.execute("SELECT payload FROM phase8_records WHERE proposal_id=?",(pid,)).fetchone()
            if not row: raise KeyError(pid)
            payload=json.loads(row[0]); payload.update(patch)
            c.execute("UPDATE phase8_records SET payload=?,updated_at=? WHERE proposal_id=?",(json.dumps(payload),_now().isoformat(),pid))
        return self.get(pid)
    def events(self,pid):
        with self._conn() as c:return [{"state":r[0],"actor":r[1],"detail":r[2],"created_at":r[3]} for r in c.execute("SELECT state,actor,detail,created_at FROM phase8_events WHERE proposal_id=? ORDER BY id",(pid,))]

class SimulatorExecutor:
    """Private-permit executor; production response interfaces are never imported."""
    def execute(self, environment, proposal:Proposal, permit:object):
        if not isinstance(permit,_Permit): raise PermissionError("simulated executor requires coordinator authorization")
        pre=_obs(environment.observe(), environment); transition=environment.step(SimulatedAction(proposal.action,approved=True,targets=proposal.targets)); post=_obs(environment.observe(), environment)
        return {"pre":pre,"post":post,"actual":asdict(transition),"effective":transition.action_valid and (transition.exposure < .70),"contained":transition.genuinely_contained_gt,"resolved":transition.genuinely_contained_gt and not transition.severe_outcome_gt,"recovery_pending":transition.recovery_task_count>0}
class _Permit: pass

class DefenseCoordinator:
    def __init__(self,store:DefenseStore,policy:PolicyEngine|None=None): self.store,self.policy,self.executor=store,policy or PolicyEngine(),SimulatorExecutor(); self.environments={}; self.emergency_stop=False
    def propose(self,p:Proposal,key:str,environment:MultiStepConsequenceEnvironment):
        record,replayed=self.store.create(p,key); pid=record["proposal_id"]; self.environments[p.incident_id]=environment
        if replayed:return record
        self.store.amend(pid,{"environment_snapshot":_obs(environment.observe(), environment)})
        decision=self.policy.evaluate(p,self.active_actions(p.incident_id)); record=self.store.transition(pid,Status.POLICY_EVALUATED,detail="deterministic policy evaluated",patch={"decision":asdict(decision)})
        next_state=Status.AUTO_AUTHORIZED if decision.tier==Tier.AUTOMATIC and decision.allowed else Status.PENDING_ANALYST if decision.tier==Tier.ANALYST and decision.allowed else Status.PENDING_HUMAN if decision.allowed else Status.POLICY_BLOCKED
        return self.store.transition(pid,next_state,detail="authority determined")
    def active_actions(self,incident): return {r["proposal"]["action"] for r in self.list_incident(incident) if r["active"]}
    def list_incident(self,incident):
        with self.store._conn() as c: ids=[r[0] for r in c.execute("SELECT proposal_id FROM phase8_records WHERE incident_id=?",(incident,))]
        return [self.store.get(i) for i in ids]
    def approve(self,pid,actor:Actor,decision:str):
        r=self.store.get(pid); p=Proposal(**r["proposal"]); status=Status(r["status"])
        if status not in {Status.PENDING_ANALYST,Status.PENDING_HUMAN}: raise ValueError("proposal is not awaiting approval")
        required="analyst" if status==Status.PENDING_ANALYST else "human_authorizer"
        if actor.role!=required or actor.actor_id==p.incident_id: raise PermissionError("actor is not authorized for this approval")
        if decision not in {"approve","reject","reevaluate"}: raise ValueError("invalid decision")
        if decision!="approve": return self.store.transition(pid,Status.REJECTED if decision=="reject" else Status.CANCELLED,actor.actor_id,decision)
        expiry=(_now()+timedelta(minutes=10)).isoformat(); approval=Approval(pid,actor.actor_id,decision,r["version"],POLICY_VERSION,expiry,_scope(p),str(uuid.uuid4()))
        return self.store.transition(pid,Status.AUTHORIZED,actor.actor_id,"approval bound to exact proposal",{"approval":asdict(approval)})
    def execute(self,pid,actor:Actor|None=None):
        actor = actor or Actor("system", "system")
        r=self.store.get(pid); p=Proposal(**r["proposal"]); status=Status(r["status"])
        if self.emergency_stop: raise PermissionError("emergency stop is active")
        if status==Status.AUTO_AUTHORIZED:r=self.store.transition(pid,Status.READY,"system","automatic authorization ready")
        elif status==Status.AUTHORIZED:r=self.store.transition(pid,Status.READY,actor.actor_id,"approved action ready")
        elif status!=Status.READY: raise ValueError("proposal is not authorized for execution")
        # JIT check: version/scope/policy/approval and live policy are revalidated.
        r=self.store.get(pid); decision=self.policy.evaluate(p,self.active_actions(p.incident_id)-{p.action})
        approval=r["approval"]
        if not decision.allowed or (decision.tier!=Tier.AUTOMATIC and (not approval or approval["scope_hash"]!=_scope(p) or approval["policy_version"]!=POLICY_VERSION or _now()>=datetime.fromisoformat(approval["expires_at"]))): return self.store.transition(pid,Status.POLICY_BLOCKED,"system","JIT authorization failed")
        env=self.environments.get(p.incident_id)
        if env is None:return self.store.transition(pid,Status.EXECUTION_FAILED,"system","simulator state unavailable; fail closed")
        if r.get("environment_snapshot") != _obs(env.observe(), env): return self.store.transition(pid,Status.POLICY_BLOCKED,"system","simulator state changed after proposal")
        self.store.transition(pid,Status.EXECUTING,actor.actor_id,"simulator execution started")
        try: result=self.executor.execute(env,p,_Permit())
        except Exception as exc:return self.store.transition(pid,Status.EXECUTION_FAILED,"system",f"{type(exc).__name__}: {exc}")
        self.store.transition(pid,Status.EXECUTED,actor.actor_id,"action completed",{"execution":result,"active":result["recovery_pending"]})
        self.store.transition(pid,Status.VERIFYING,"system","visible post-action verification")
        terminal=Status.RECOVERY_PENDING if result["recovery_pending"] else Status.VERIFIED if result["contained"] else Status.ESCALATED
        feedback=FeedbackRecord(FEEDBACK_VERSION,p.incident_id,p.incident_id,result["pre"],{},(),p.planner_source,p.prediction,p.uncertainty,decision.tier.value,"approved" if approval else "automatic",p.action,result["post"],result["actual"],"resolved" if result["resolved"] else "contained" if result["contained"] else "not-contained",{},("simulator-visible-observation",),{"simulator_ground_truth":result["actual"]})
        return self.store.transition(pid,terminal,"system","outcome verified",{"feedback":asdict(feedback)})
    def recover(self,pid,actor:Actor):
        r=self.store.get(pid); p=Proposal(**r["proposal"])
        if Status(r["status"])!=Status.RECOVERY_PENDING: raise ValueError("recovery is not pending")
        if actor.role not in {"analyst","human_authorizer"}: raise PermissionError("recovery review required")
        # Rollback can reopen access; only allow when visible activity is absent and no severe outcome.
        ex=r["execution"]; unsafe=ex["post"]["observed_malicious_activity"] or ex["actual"]["severe_outcome_gt"]
        if unsafe:return self.store.transition(pid,Status.ESCALATED,actor.actor_id,"unsafe rollback blocked")
        self.store.transition(pid,Status.RECOVERING,actor.actor_id,"approved safe recovery")
        env=self.environments[p.incident_id]; result=self.executor.execute(env,Proposal(p.incident_id,"ROLLBACK",p.targets,p.state_version,"recovery",{},0),_Permit())
        return self.store.transition(pid,Status.RECOVERED,actor.actor_id,"workflow restoration verified",{"active":False,"recovery":result})
    def stop(self,actor:Actor):
        if actor.role!="human_authorizer":raise PermissionError("only human authorizer may change emergency stop")
        self.emergency_stop=True
    def observe_and_replan(self,incident_id:str,predictor,actions,policies,planner_source="classical"):
        """Bounded Phase 7 replan recommendation; it never bypasses Phase 8 policy."""
        from .adaptive_planner import make_problem, solve_exact
        env=self.environments.get(incident_id)
        if env is None: raise KeyError("simulator state unavailable")
        observation=env.observe(); tracker=BayesianAttackerBeliefTracker(); tracker.initialize(f"phase8-{incident_id}")
        evidence=Evidence(f"phase8-{observation.tick}",observation.tick,"phase8-visible-sensor",
          "POST_ACTION_MALICIOUS_ACTIVITY" if observation.observed_malicious_activity else "POST_ACTION_NO_CONFIRMED_ACTIVITY",
          observation.observed_malicious_activity,.75,available_to_defender=True)
        belief=tracker.update_evidence(f"phase8-{incident_id}",observation.tick,(evidence,))
        visible={"state_tick":observation.tick,"service_health":observation.service_health,"observed_compromise":observation.observed_compromise,"observed_malicious_activity":float(observation.observed_malicious_activity),"evidence_count":observation.evidence_count}
        if getattr(env, "topology", None):
            from .graph_integration import visible_graph_state
            visible = visible_graph_state(env, belief.probabilities, tuple(self.active_actions(incident_id)))
        plan=solve_exact(make_problem(predictor,visible,actions,policies,belief_entropy=belief.normalized_entropy))
        return {"plan":asdict(plan),"planner_source":planner_source,"belief":{k.value:v for k,v in belief.probabilities.items()},"evidence_provenance":"defender-visible simulated sensor","requires_new_policy_authorization":True}
