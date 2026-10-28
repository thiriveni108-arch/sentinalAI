"""Phase 9 bounded hybrid QRL research adapter, advisory recommendations only."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from hashlib import sha256
from time import perf_counter
from typing import Any, Mapping

import numpy as np

from .beliefs import BayesianAttackerBeliefTracker, MODES
from .consequence_simulator import ACTION_TYPES, MultiStepConsequenceEnvironment, SimulatedAction
from .dynamic_models import Evidence

QRL_VERSION="shield-qrl-v1"; REPLAY_VERSION="shield-qrl-replay-v1"; ACTIONS=("NO_OP","REQUIRE_FRESH_MFA","REVOKE_SESSION","REMOVE_PRIVILEGE","RESTRICT_RESOURCE","DISABLE_BULK_EXPORT","DISABLE_ACCOUNT","ISOLATE_DEVICE","SEGMENT_SERVICE","REQUEST_HUMAN_REVIEW","REQUEST_RECOVERY")
HIGH_IMPACT=frozenset({"DISABLE_ACCOUNT","ISOLATE_DEVICE","SEGMENT_SERVICE"})

@dataclass(frozen=True)
class RewardWeights:
    containment:float=2.; exposure:float=.7; severe:float=3.; disruption:float=.6; recovery:float=.4; action:float=.15; repeat:float=.25; ineligible:float=.5; waiting:float=.8; rejected:float=.7
@dataclass(frozen=True)
class Transition:
    observation:tuple[float,...]; mask:tuple[bool,...]; action:int; reward:float; reward_parts:Mapping[str,float]; next_observation:tuple[float,...]; terminated:bool; truncated:bool; provenance:str="simulated"
@dataclass(frozen=True)
class Recommendation:
    version:str; action:str; probabilities:tuple[float,...]; action_mask:tuple[bool,...]; observable_inputs:tuple[float,...]; warnings:tuple[str,...]; out_of_distribution:bool; advisory_only:bool=True

class ShieldRLEnvironment:
    """POMDP adapter: oracle state affects post-event reward only, never observation."""
    def __init__(self,horizon:int=5,reward:RewardWeights=RewardWeights()): self.horizon,self.weights=horizon,reward
    def reset(self,seed:int=0,scenario:str="credential-compromise"):
        supported=("credential-compromise","malicious-insider","lateral-movement","sensitive-data-exfiltration","privilege-escalation")
        family="credential-compromise" if scenario=="benign" else scenario
        if family not in supported: raise ValueError(f"unsupported scenario: {scenario}")
        self.env=MultiStepConsequenceEnvironment(family,seed,max_steps=self.horizon)
        if scenario=="benign":
            # Minimal validated false-positive adapter: no attacker capability/routes, but interventions still disrupt workflows.
            self.env.state=replace(self.env.state,attacker_capability_gt=False,accessible_routes_gt=(),latent_routes_gt=(),current_route_gt=None,observed_compromise=.10,observed_malicious_activity=False)
        self.scenario=scenario; self.tracker=BayesianAttackerBeliefTracker(); self.tracker.initialize(f"qrl-{scenario}-{seed}")
        self.last_action="NO_OP"; self.active=(); self.steps=0; self.trajectory=[]; self.pending_action=None; self.approval_attempted=False; self._last_observation=self._observation(); return self._last_observation,{"scenario":scenario,"ground_truth_exposed":False}
    def _observation(self):
        o=self.env.observe(); evidence=Evidence(f"qrl-{o.tick}",o.tick,"qrl-visible-sensor","POST_ACTION_MALICIOUS_ACTIVITY" if o.observed_malicious_activity else "POST_ACTION_NO_CONFIRMED_ACTIVITY",o.observed_malicious_activity,.75,available_to_defender=True)
        if self.tracker.current.time_step < o.tick: self.tracker.update_evidence(self.tracker.current.episode_id,o.tick,(evidence,))
        b=self.tracker.current
        return tuple([o.tick/self.horizon,o.service_health,o.observed_compromise,float(o.observed_malicious_activity),min(1,o.evidence_count/5),*([b.probabilities[m] for m in MODES]),float(o.recovery_active),min(1,len(self.active)/5),ACTIONS.index(self.last_action)/len(ACTIONS)])
    def action_mask(self):
        o=self.env.observe(); mask=[]
        if self.pending_action:
            return tuple(action=="NO_OP" for action in ACTIONS)
        for action in ACTIONS:
            executable=action in ACTION_TYPES and not o.terminal and (action not in self.active or action=="NO_OP") and not self.pending_action
            # Recommendations may include high impact, but those produce explicit pending events.
            request_allowed=action=="REQUEST_HUMAN_REVIEW" and not self.pending_action and not self.approval_attempted and not o.terminal
            recovery_allowed=action=="REQUEST_RECOVERY" and not self.pending_action and o.recovery_active and not o.terminal
            if action in HIGH_IMPACT: executable=executable and not self.approval_attempted
            mask.append(executable or request_allowed or recovery_allowed)
        return tuple(mask)
    def step(self,action:int):
        if not 0<=action<len(ACTIONS): raise ValueError("invalid action")
        mask=self.action_mask(); selected=ACTIONS[action]; before=self.env.observe(); parts={}
        if not mask[action]:
            parts["ineligible"]=-self.weights.ineligible; reward=sum(parts.values()); result={"approval":"blocked"}; terminated=False
        elif self.pending_action:
            # Approval delay is an attacker turn. This compact adapter denies it by default; Phase 8 remains authoritative.
            transition=self.env.step(SimulatedAction("NO_OP")); self.pending_action=None; self.approval_attempted=True
            parts=self._actual_parts(transition,extra={"waiting":-self.weights.waiting,"rejected":-self.weights.rejected}); reward=float(sum(parts.values())); result={"approval":"rejected","actual":asdict(transition)}; terminated=transition.genuinely_contained_gt or transition.severe_outcome_gt
        elif selected in HIGH_IMPACT or selected=="REQUEST_HUMAN_REVIEW":
            # Requesting authority is not containment. One simulated delay passes before an explicit rejection event.
            transition=self.env.step(SimulatedAction("NO_OP")); self.pending_action=selected; self.approval_attempted=True
            parts=self._actual_parts(transition,extra={"waiting":-self.weights.waiting}); reward=float(sum(parts.values())); result={"approval":"pending","actual":asdict(transition)}; terminated=transition.genuinely_contained_gt or transition.severe_outcome_gt
        elif selected=="REQUEST_RECOVERY":
            self.env.step(SimulatedAction("ROLLBACK")); result={"approval":"recovery-review-required"}; reward=-self.weights.recovery; parts["recovery"]=-self.weights.recovery; terminated=self.env.state.terminal
        else:
            transition=self.env.step(SimulatedAction(selected)); result={"approval":"automatic-candidate","actual":asdict(transition)}
            parts=self._actual_parts(transition,extra={"action":-self.weights.action*(selected!="NO_OP"),"repeat":-self.weights.repeat*(selected==self.last_action and selected!="NO_OP")})
            reward=float(sum(parts.values())); terminated=transition.genuinely_contained_gt or transition.severe_outcome_gt
            if selected!="NO_OP": self.active=tuple(sorted(set(self.active+(selected,))))
        self.last_action=selected if selected in ACTIONS else self.last_action; self.steps+=1; truncated=self.steps>=self.horizon and not terminated; next_obs=self._observation()
        item=Transition(tuple(self._last_observation if hasattr(self,"_last_observation") else next_obs),mask,action,reward,parts,next_obs,terminated,truncated)
        self.trajectory.append(item); self._last_observation=next_obs
        return next_obs,reward,terminated,truncated,{"result":result,"reward_components":parts,"oracle_available_to_policy":False}
    def export_trajectory(self): return tuple(self.trajectory)
    def _actual_parts(self,transition,extra=None):
        return {"exposure":-self.weights.exposure*transition.exposure,"disruption":-self.weights.disruption*transition.disruption,"recovery":-self.weights.recovery*transition.recovery_cost,"severe":-self.weights.severe*transition.severe_outcome_gt,"containment":self.weights.containment*(transition.genuinely_contained_gt and self.scenario!="benign"),**(extra or {})}

class ReplayBuffer:
    def __init__(self): self.items:dict[str,Transition]={}
    def add(self,item:Transition):
        key=sha256(repr(item).encode()).hexdigest(); self.items[key]=item
    def extend(self,items):
        for item in items:
            if item.provenance!="simulated": continue
            self.add(item)
    def export(self): return {"version":REPLAY_VERSION,"count":len(self.items),"provenance":"simulated_only","transitions":[asdict(x) for x in self.items.values()]}

def masked_softmax(logits,mask):
    values=np.where(np.asarray(mask),np.asarray(logits,dtype=float),-1e9); values-=values.max(); p=np.exp(values); return p/p.sum()

class ClassicalQRLPolicy:
    """Compact on-policy masked REINFORCE baseline; replay is audit-only."""
    def __init__(self,features:int=15,seed:int=17): self.rng=np.random.default_rng(seed); self.weights=self.rng.normal(0,.03,(len(ACTIONS),features)); self.version=QRL_VERSION+"-classical"
    def recommend_response(self,observation,belief_state=None,active_interventions=(),action_constraints=None):
        mask=tuple(action_constraints or [True]*len(ACTIONS)); p=masked_softmax(self.weights@np.asarray(observation),mask)
        return Recommendation(self.version,ACTIONS[int(np.argmax(p))],tuple(map(float,p)),mask,tuple(observation),("experimental model; Phase 8 authorization required",),False)
    def train(self,environment:ShieldRLEnvironment,episodes:int=40,seed:int=1,lr:float=.04,gamma:float=.92):
        returns=[]
        for ep in range(episodes):
            obs,_=environment.reset(seed+ep,("credential-compromise","lateral-movement","malicious-insider")[ep%3]); episode=[]; done=False
            while not done:
                mask=environment.action_mask(); p=masked_softmax(self.weights@np.asarray(obs),mask); a=int(self.rng.choice(len(ACTIONS),p=p)); nxt,r,term,trunc,_=environment.step(a); episode.append((obs,mask,a,r)); obs=nxt; done=term or trunc
            g=0.; total=0.
            for obs,mask,a,r in reversed(episode):
                g=r+gamma*g; p=masked_softmax(self.weights@np.asarray(obs),mask); grad=-np.outer(p,obs); grad[a]+=np.asarray(obs); self.weights+=lr*g*grad; total+=r
            returns.append(total)
        return {"episodes":episodes,"returns":returns,"algorithm":"on-policy masked REINFORCE","replay_used_for_updates":False}

class StaticRulePolicy:
    """Matched non-learning Phase 7 action reference, never an execution authority."""
    def __init__(self,action="REVOKE_SESSION"): self.action=action; self.version="phase7-static-reference"
    def recommend_response(self,observation,belief_state=None,active_interventions=(),action_constraints=None):
        mask=tuple(action_constraints or [True]*len(ACTIONS)); index=ACTIONS.index(self.action)
        if not mask[index]: index=ACTIONS.index("NO_OP")
        probabilities=[0.]*len(ACTIONS); probabilities[index]=1.
        return Recommendation(self.version,ACTIONS[index],tuple(probabilities),mask,tuple(observation),("static reference; Phase 8 authorization required",),False)

class HybridQuantumQRLPolicy(ClassicalQRLPolicy):
    """Four-qubit VQC encoder with a classical masked policy head (experimental)."""
    def __init__(self,features:int=15,seed:int=19):
        super().__init__(4,seed); self.input_features=features; self.quantum_weights=np.random.default_rng(seed).normal(0,.1,(1,4,3)); self.version=QRL_VERSION+"-hybrid-q4"
        import pennylane as qml
        self.qml=qml; self.device=qml.device("default.qubit",wires=4,shots=None)
        @qml.qnode(self.device,interface="autograd",diff_method="backprop")
        def circuit(x,w):
            qml.AngleEmbedding(x,wires=range(4),rotation="Y"); qml.StronglyEntanglingLayers(w,wires=range(4),ranges=[1]); return tuple(qml.expval(qml.PauliZ(i)) for i in range(4))
        self.circuit=circuit
    def encode(self,observation): return np.asarray(self.circuit(np.asarray(observation[:4])*np.pi,self.quantum_weights),dtype=float)
    def quantum_gradient(self,observation):
        pnp=self.qml.numpy; x=pnp.array(np.asarray(observation[:4])*np.pi,requires_grad=False); w=pnp.array(self.quantum_weights,requires_grad=True); return np.asarray(self.qml.grad(lambda z:self.circuit(x,z)[0])(w))
    def recommend_response(self,observation,belief_state=None,active_interventions=(),action_constraints=None): return super().recommend_response(self.encode(observation),belief_state,active_interventions,action_constraints)
    def train(self,environment,episodes:int=20,seed:int=1,lr:float=.03,gamma:float=.92):
        # Train policy head on fresh trajectories; VQC remains differentiable and bounded proof-of-concept encoder.
        original=environment.reset
        returns=[]
        for ep in range(episodes):
            obs,_=original(seed+ep,("credential-compromise","lateral-movement")[ep%2]); trajectory=[]; done=False
            while not done:
                encoded=self.encode(obs); mask=environment.action_mask(); p=masked_softmax(self.weights@encoded,mask); a=int(self.rng.choice(len(ACTIONS),p=p)); next_obs,r,t,u,_=environment.step(a); trajectory.append((encoded,mask,a,r)); obs=next_obs; done=t or u
            g=0.; total=0.
            for x,m,a,r in reversed(trajectory):
                g=r+gamma*g; p=masked_softmax(self.weights@x,m); grad=-np.outer(p,x); grad[a]+=x; self.weights+=lr*g*grad; total+=r
            returns.append(total)
        return {"episodes":episodes,"returns":returns,"algorithm":"on-policy masked REINFORCE with differentiable four-qubit VQC encoder","replay_used_for_updates":False}

class PolicyRegistry:
    states=frozenset({"BASELINE","EXPERIMENTAL","VALIDATED","REJECTED","APPROVED_FOR_SIMULATION"})
    def __init__(self): self.entries={}
    def register(self,name,policy,stage="EXPERIMENTAL"): 
        if stage not in self.states: raise ValueError(stage)
        self.entries[name]={"policy":policy,"stage":stage,"auto_promote":False}
    def get(self,name): return self.entries[name]

def phase8_proposal_from_recommendation(recommendation:Recommendation, incident_id:str, targets:tuple[str,...], state_version:int, prediction:Mapping[str,float]):
    """Convert advisory output to a Phase 8 proposal; it conveys no authority."""
    from .autonomous_defense import Proposal
    return Proposal(incident_id=incident_id,action=recommendation.action,targets=targets,state_version=state_version,
        planner_source="qrl",prediction={**prediction,"operationally_suitable":False,"out_of_distribution":recommendation.out_of_distribution},
        uncertainty=1.0 if recommendation.out_of_distribution else .5,reversible=recommendation.action not in HIGH_IMPACT,
        recovery_plan=recommendation.action not in {"NO_OP","REQUEST_HUMAN_REVIEW"},blast_radius=2 if recommendation.action in HIGH_IMPACT else 1,
        target_criticality=4 if recommendation.action in HIGH_IMPACT else 1)
