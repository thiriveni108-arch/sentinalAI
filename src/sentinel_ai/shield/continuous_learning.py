"""Phase 10 durable, simulator-only experience learning and governance lifecycle."""
from __future__ import annotations

import hashlib, json, sqlite3, uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, stdev
from time import perf_counter
from typing import Any, Mapping

import numpy as np

from .qrl import ACTIONS, ClassicalQRLPolicy, HybridQuantumQRLPolicy, PolicyRegistry, ShieldRLEnvironment
from .topology import grouped_split


EXPERIENCE_VERSION="shield-experience-v1"; CYCLE_VERSION="shield-learning-cycle-v1"


def _now(): return datetime.now(timezone.utc).isoformat()
def _hash(value): return hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()


@dataclass(frozen=True)
class ExperienceValidation:
    eligible: bool
    reasons: tuple[str,...]
    fingerprint: str


class ExperienceStore:
    """Durable audit memory. It never exposes oracle fields as policy inputs."""
    def __init__(self,path:str|Path):
        self.path=str(path); Path(path).parent.mkdir(parents=True,exist_ok=True)
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS phase10_experiences (fingerprint TEXT PRIMARY KEY, episode_id TEXT, eligibility INTEGER, reasons TEXT, payload TEXT, created_at TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS phase10_cycles (cycle_id TEXT PRIMARY KEY, state TEXT, payload TEXT, created_at TEXT, updated_at TEXT)")
    @contextmanager
    def _conn(self):
        c=sqlite3.connect(self.path)
        try: yield c; c.commit()
        except Exception: c.rollback(); raise
        finally: c.close()
    def validate(self, episode:Mapping[str,Any])->ExperienceValidation:
        reasons=[]; transitions=episode.get("transitions")
        if episode.get("version")!=EXPERIENCE_VERSION: reasons.append("unsupported experience version")
        if not episode.get("episode_id") or not isinstance(transitions,list) or not transitions: reasons.append("missing trajectory")
        if episode.get("simulator_version") is None: reasons.append("missing simulator version")
        if episode.get("status") not in {"VERIFIED","RECOVERED","ESCALATED","REJECTED","EXPIRED"}: reasons.append("unfinished incident")
        seen=[]
        for index,item in enumerate(transitions or []):
            if item.get("step")!=index: reasons.append("non-sequential transition ordering"); break
            if len(item.get("observation",())) not in {15,19}: reasons.append("invalid observable state"); break
            if item.get("action") not in ACTIONS: reasons.append("unknown action"); break
            if item.get("approval") in {"pending","rejected","expired"} and item.get("executed_action"): reasons.append("approval outcome contradicts execution"); break
            if "reward" not in item or "reward_parts" not in item: reasons.append("missing reward provenance"); break
            seen.append(item["step"])
        # Rejected/censored records are retained but excluded from policy learning.
        if episode.get("status") in {"REJECTED","EXPIRED"}: reasons.append("censored approval outcome")
        fingerprint=_hash({k:episode.get(k) for k in ("episode_id","simulator_version","transitions","scenario_id")})
        return ExperienceValidation(not reasons,tuple(reasons),fingerprint)
    def ingest(self, episode:Mapping[str,Any])->ExperienceValidation:
        result=self.validate(episode); payload=dict(episode); payload["validation"]={"eligible":result.eligible,"reasons":result.reasons}; payload.setdefault("provenance","simulated")
        with self._conn() as c:
            c.execute("INSERT OR IGNORE INTO phase10_experiences VALUES(?,?,?,?,?,?)",(result.fingerprint,str(episode.get("episode_id")),int(result.eligible),json.dumps(result.reasons),json.dumps(payload,default=str),_now()))
        return result
    def eligible(self):
        with self._conn() as c: rows=c.execute("SELECT payload FROM phase10_experiences WHERE eligibility=1").fetchall()
        return [json.loads(row[0]) for row in rows]
    def history(self):
        with self._conn() as c: rows=c.execute("SELECT fingerprint,eligibility,reasons,payload FROM phase10_experiences ORDER BY created_at").fetchall()
        return [{"fingerprint":r[0],"eligible":bool(r[1]),"reasons":json.loads(r[2]),"episode":json.loads(r[3])} for r in rows]
    def drift(self, baseline:Mapping[str,float]|None=None):
        records=self.eligible(); values=[x for e in records for x in e["transitions"]]
        if not values:return {"status":"insufficient_data","eligible_episodes":0}
        current={"observed_compromise":mean(x["observation"][2] for x in values),"service_health":mean(x["observation"][1] for x in values),"approval_rate":mean(float(x.get("approval")!="automatic") for x in values)}
        delta={key:abs(current[key]-baseline.get(key,current[key])) for key in current} if baseline else {}
        return {"status":"monitoring","eligible_episodes":len(records),"current":current,"delta":delta,"investigate":any(x>.20 for x in delta.values())}


def experience_from_environment(env:ShieldRLEnvironment, episode_id:str, status="VERIFIED"):
    transitions=[]
    for step,item in enumerate(env.trajectory):
        transitions.append({"step":step,"observation":item.observation,"action":ACTIONS[item.action],"executed_action":item.executed_action,
                            "approval":item.approval,"reward":item.reward,"reward_parts":dict(item.reward_parts),"next_observation":item.next_observation,
                            "terminal":item.terminated or item.truncated,"provenance":"simulated-visible"})
    return {"version":EXPERIENCE_VERSION,"episode_id":episode_id,"incident_id":episode_id,"scenario_id":env.scenario,"topology":getattr(env,"topology",None),"simulator_version":"shield-multistep-consequence-v3.1.0","status":status,"transitions":transitions,"ground_truth_provenance":"simulator-evaluation-only"}


def experience_from_phase8_record(record:Mapping[str,Any]) -> dict[str,Any]:
    """Convert completed Phase 8 feedback without inventing a multi-step history.

    The result is a validated, one-step trajectory with explicit limited
    provenance. It may support coverage analysis but callers can require richer
    episodes for training snapshots.
    """
    feedback=record.get("feedback") or {}; actual=feedback.get("actual") or {}; pre=feedback.get("observable_pre_action") or {}; post=feedback.get("observable_post_action") or pre
    action=feedback.get("executed_action")
    if not action: raise ValueError("Phase 8 record has no executed action")
    def observation(value):
        return (float(value.get("tick",0))/5,float(value.get("service_health",1)),float(value.get("observed_compromise",0)),float(value.get("observed_malicious_activity",False)),min(1.,float(value.get("evidence_count",0))/5),*([1/7]*7),0.,0.,0.)
    reward=2*float(actual.get("genuinely_contained_gt",False))-.7*float(actual.get("exposure",0))-.6*float(actual.get("disruption",0))-.4*float(actual.get("recovery_cost",0))-3*float(actual.get("severe_outcome_gt",False))
    return {"version":EXPERIENCE_VERSION,"episode_id":feedback.get("episode_id",record.get("proposal_id","phase8")),"incident_id":feedback.get("incident_id"),"scenario_id":"phase8-feedback","simulator_version":"shield-multistep-consequence-v3.1.0","status":record.get("status","ESCALATED"),"transitions":[{"step":0,"observation":observation(pre),"action":action,"executed_action":action,"approval":feedback.get("approval_status","unknown"),"reward":reward,"reward_parts":{"verified_actual":reward},"next_observation":observation(post),"terminal":True,"provenance":"phase8-feedback-single-step"}],"ground_truth_provenance":"simulator-evaluation-only","limitations":["single-step feedback conversion; no missing history inferred"]}


class LearningCoordinator:
    """Serial, fresh-on-policy learning; history determines eligibility, not gradients."""
    def __init__(self, store:ExperienceStore, registry:PolicyRegistry|None=None): self.store,self.registry=store,registry or PolicyRegistry()
    def _evaluate(self,policy,seeds=(3101,3102,3103)):
        rows=[]
        for topology in grouped_split()["test"]:
            for seed in seeds:
                env=ShieldRLEnvironment(graph_features=True); obs,_=env.reset(seed,"credential-compromise",topology=topology); total=0.; done=False; started=perf_counter()
                while not done:
                    rec=policy.recommend_response(obs,action_constraints=env.action_mask()); action=int(np.argmax(rec.probabilities)); obs,reward,t,u,_=env.step(action); total+=reward; done=t or u
                rows.append({"reward":total,"contained":float(env.env.state.contained_gt),"severe":float(env.env.state.severe_outcome_gt),"disruption":1-env.env.state.service_health,"latency_ms":(perf_counter()-started)*1000/max(1,len(env.trajectory))})
        return {key:{"mean":mean(x[key] for x in rows),"std":stdev([x[key] for x in rows]) if len(rows)>1 else 0.,"n":len(rows)} for key in rows[0]}|{"episodes":rows}
    def run(self,algorithm="classical",episodes=8,seed=100,minimum_episodes=3):
        eligible=self.store.eligible(); cycle_id=str(uuid.uuid4())
        with self.store._conn() as c:
            active=c.execute("SELECT cycle_id FROM phase10_cycles WHERE state='RUNNING'").fetchone()
            if active: raise RuntimeError("learning cycle already running")
            c.execute("INSERT INTO phase10_cycles VALUES(?,?,?,?,?)",(cycle_id,"RUNNING",json.dumps({}),_now(),_now()))
        if len(eligible)<minimum_episodes:
            report={"version":CYCLE_VERSION,"cycle_id":cycle_id,"state":"SKIPPED","reason":"insufficient eligible complete experiences","eligible_episodes":len(eligible)}; self._finish(cycle_id,"SKIPPED",report); return report
        features=19; factory=HybridQuantumQRLPolicy if algorithm=="hybrid" else ClassicalQRLPolicy
        candidate=factory(features=features,seed=seed); reference=factory(features=features,seed=seed+1)
        environment=ShieldRLEnvironment(graph_features=True,topology_cycle=grouped_split()["train"])
        # Historical data are deliberately audit/coverage input only. Gradients use fresh trajectories.
        training=candidate.train(environment,episodes=episodes,seed=seed); evaluation=self._evaluate(candidate); baseline=self._evaluate(reference)
        better=evaluation["severe"]["mean"]<=baseline["severe"]["mean"] and evaluation["disruption"]["mean"]<=baseline["disruption"]["mean"]*1.10 and evaluation["reward"]["mean"]>baseline["reward"]["mean"]+.02
        name=f"{algorithm}-{cycle_id[:8]}"; checksum=_hash(getattr(candidate,"weights",[]).tolist())
        self.registry.register(name,candidate,"PENDING_APPROVAL" if better else "VALIDATION_FAILED",{"cycle_id":cycle_id,"checksum":checksum,"on_policy_fresh":True,"experience_snapshot":len(eligible)})
        report={"version":CYCLE_VERSION,"cycle_id":cycle_id,"state":"PENDING_APPROVAL" if better else "VALIDATION_FAILED","algorithm":algorithm,"eligible_episodes":len(eligible),"training":training,"candidate":evaluation,"fresh_reference":baseline,"policy_name":name,"promotion_criteria":{"better":better,"higher_reward_only_is_insufficient":True},"simulator_only":True}
        self._finish(cycle_id,report["state"],report); return report
    def _finish(self,cycle_id,state,report):
        with self.store._conn() as c:c.execute("UPDATE phase10_cycles SET state=?,payload=?,updated_at=? WHERE cycle_id=?",(state,json.dumps(report,default=str),_now(),cycle_id))
    def cycles(self):
        with self.store._conn() as c: rows=c.execute("SELECT cycle_id,state,payload FROM phase10_cycles ORDER BY created_at").fetchall()
        return [{"cycle_id":r[0],"state":r[1],"report":json.loads(r[2])} for r in rows]
