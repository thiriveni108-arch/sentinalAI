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
from .topology import TOPOLOGY_FAMILIES
from .dynamic_models import Evidence

QRL_VERSION="shield-qrl-v1"; REPLAY_VERSION="shield-qrl-replay-v1"; ACTIONS=("NO_OP","REQUIRE_FRESH_MFA","REVOKE_SESSION","REMOVE_PRIVILEGE","RESTRICT_RESOURCE","DISABLE_BULK_EXPORT","DISABLE_ACCOUNT","ISOLATE_DEVICE","SEGMENT_SERVICE","REQUEST_HUMAN_REVIEW","REQUEST_RECOVERY")
HIGH_IMPACT=frozenset({"DISABLE_ACCOUNT","ISOLATE_DEVICE","SEGMENT_SERVICE"})

@dataclass(frozen=True)
class RewardWeights:
    containment:float=2.; exposure:float=.7; severe:float=3.; disruption:float=.6; recovery:float=.4; action:float=.15; repeat:float=.25; ineligible:float=.5; waiting:float=.8; rejected:float=.7
@dataclass(frozen=True)
class Transition:
    observation:tuple[float,...]; mask:tuple[bool,...]; action:int; reward:float; reward_parts:Mapping[str,float]; next_observation:tuple[float,...]; terminated:bool; truncated:bool; provenance:str="simulated"; approval:str="unknown"; executed_action:str|None=None
@dataclass(frozen=True)
class Recommendation:
    version:str; action:str; probabilities:tuple[float,...]; action_mask:tuple[bool,...]; observable_inputs:tuple[float,...]; warnings:tuple[str,...]; out_of_distribution:bool; advisory_only:bool=True

class ShieldRLEnvironment:
    """POMDP adapter: oracle state affects post-event reward only, never observation."""
    def __init__(self,horizon:int=5,reward:RewardWeights=RewardWeights(),graph_features:bool=False,
                 topology_cycle:tuple[str,...]=()):
        self.horizon,self.weights,self.graph_features,self.topology_cycle=horizon,reward,graph_features,tuple(topology_cycle)
    def reset(self,seed:int=0,scenario:str="credential-compromise",topology:str|None=None):
        supported=("credential-compromise","malicious-insider","lateral-movement","sensitive-data-exfiltration","privilege-escalation")
        family="credential-compromise" if scenario=="benign" else scenario
        if family not in supported: raise ValueError(f"unsupported scenario: {scenario}")
        if topology is None and self.topology_cycle: topology=self.topology_cycle[int(seed)%len(self.topology_cycle)]
        if topology is not None and topology not in TOPOLOGY_FAMILIES: raise ValueError(f"unsupported topology: {topology}")
        self.env=MultiStepConsequenceEnvironment(family,seed,max_steps=self.horizon,topology=topology)
        if scenario=="benign":
            # Minimal validated false-positive adapter: no attacker capability/routes, but interventions still disrupt workflows.
            self.env.state=replace(self.env.state,attacker_capability_gt=False,accessible_routes_gt=(),latent_routes_gt=(),current_route_gt=None,observed_compromise=.10,observed_malicious_activity=False)
        self.scenario=scenario; self.tracker=BayesianAttackerBeliefTracker(); self.tracker.initialize(f"qrl-{scenario}-{seed}")
        self.last_action="NO_OP"; self.active=(); self.steps=0; self.trajectory=[]; self.pending_action=None; self.approval_attempted=False; self.topology=topology; self._last_observation=self._observation(); return self._last_observation,{"scenario":scenario,"topology":topology,"ground_truth_exposed":False}
    def _observation(self):
        o=self.env.observe(); evidence=Evidence(f"qrl-{o.tick}",o.tick,"qrl-visible-sensor","POST_ACTION_MALICIOUS_ACTIVITY" if o.observed_malicious_activity else "POST_ACTION_NO_CONFIRMED_ACTIVITY",o.observed_malicious_activity,.75,available_to_defender=True)
        if self.tracker.current.time_step < o.tick: self.tracker.update_evidence(self.tracker.current.episode_id,o.tick,(evidence,))
        b=self.tracker.current
        visible=[o.tick/self.horizon,o.service_health,o.observed_compromise,float(o.observed_malicious_activity),min(1,o.evidence_count/5),*([b.probabilities[m] for m in MODES]),float(o.recovery_active),min(1,len(self.active)/5),ACTIONS.index(self.last_action)/len(ACTIONS)]
        # Aggregate topology posture is defender-provided asset/dependency inventory,
        # never the hidden attacker route, capability, latent paths, or ground truth.
        if self.graph_features: visible.extend(self.env.topology_posture())
        return tuple(visible)
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
        approval=result.get("approval","unknown"); executed_action=selected if approval=="automatic-candidate" else None
        item=Transition(tuple(self._last_observation if hasattr(self,"_last_observation") else next_obs),mask,action,reward,parts,next_obs,terminated,truncated,"simulated",approval,executed_action)
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

class Phase7PlannerAdapter:
    """Recommendation-only bridge to the real Phase 7 exact or QAOA planner."""
    def __init__(self,predictor,mode="classical",seed=7301):
        if mode not in {"classical","qaoa"}: raise ValueError(mode)
        self.predictor,self.mode,self.seed=predictor,mode,seed; self.version=f"phase7-{mode}-adapter"
    @staticmethod
    def _visible(observation):
        return {"state_tick":observation[0]*5,"service_health":observation[1],"observed_compromise":observation[2],"observed_malicious_activity":observation[3],"evidence_count":observation[4]*5}
    def recommend_response(self,observation,belief_state=None,active_interventions=(),action_constraints=None):
        from .adaptive_planner import ActionSpec, make_problem, run_qaoa, solve_exact
        mask=tuple(action_constraints or [True]*len(ACTIONS)); candidates=[]
        costs={"NO_OP":0,"REQUIRE_FRESH_MFA":.12,"REVOKE_SESSION":.25,"REMOVE_PRIVILEGE":.45,"RESTRICT_RESOURCE":.55,"DISABLE_BULK_EXPORT":.35}
        for action,cost in costs.items():
            if mask[ACTIONS.index(action)]: candidates.append(ActionSpec(action,cost,disruption_budget=.5,reversible=True,tier="automatic"))
        if not candidates:
            probabilities=[0.]*len(ACTIONS); probabilities[0]=1.; return Recommendation(self.version,"NO_OP",tuple(probabilities),mask,tuple(observation),("Phase 7 adapter has no feasible automatic action",),True)
        problem=make_problem(self.predictor,self._visible(observation),tuple(candidates),("policy_constrained",),allowed_tier="automatic")
        plan,_ = run_qaoa(problem,shots=64,seed=self.seed) if self.mode=="qaoa" else (solve_exact(problem),{})
        index=ACTIONS.index(plan.action); probabilities=[0.]*len(ACTIONS); probabilities[index]=1.
        return Recommendation(self.version,plan.action,tuple(probabilities),mask,tuple(observation),("Real Phase 7 predictor/planner adapter; dynamic observations after tick zero are out of training support",),True)

class HybridQuantumQRLPolicy(ClassicalQRLPolicy):
    """End-to-end trainable projection → four-qubit VQC → masked policy head."""
    def __init__(self,features:int=15,seed:int=19):
        super().__init__(4,seed); self.input_features=features; rng=np.random.default_rng(seed)
        # All defender-visible fields are projected: state (0:5), Bayesian beliefs
        # (5:12), recovery (12), intervention history (13:15). No oracle inputs.
        self.projection_weights=rng.normal(0,.12,(4,features)); self.projection_bias=np.zeros(4)
        self.quantum_weights=rng.normal(0,.1,(1,4,3)); self.version=QRL_VERSION+"-hybrid-q4-e2e"
        import pennylane as qml
        self.qml=qml; self.device=qml.device("default.qubit",wires=4,shots=None)
        @qml.qnode(self.device,interface="autograd",diff_method="backprop")
        def circuit(x,w):
            qml.AngleEmbedding(x,wires=range(4),rotation="Y"); qml.StronglyEntanglingLayers(w,wires=range(4),ranges=[1]); return tuple(qml.expval(qml.PauliZ(i)) for i in range(4))
        self.circuit=circuit
    def _project(self,observation,weights=None,bias=None):
        w=self.projection_weights if weights is None else weights; b=self.projection_bias if bias is None else bias
        return self.qml.numpy.tanh(self.qml.numpy.dot(w,self.qml.numpy.array(observation))+b)*np.pi
    def encode(self,observation): return np.asarray(self.circuit(self._project(observation),self.quantum_weights),dtype=float)
    def quantum_gradient(self,observation):
        pnp=self.qml.numpy; x=pnp.array(observation,requires_grad=False); p=pnp.array(self.projection_weights,requires_grad=False); b=pnp.array(self.projection_bias,requires_grad=False); w=pnp.array(self.quantum_weights,requires_grad=True)
        return np.asarray(self.qml.grad(lambda z:self.circuit(pnp.tanh(pnp.dot(p,x)+b)*np.pi,z)[0])(w))
    def recommend_response(self,observation,belief_state=None,active_interventions=(),action_constraints=None): return super().recommend_response(self.encode(observation),belief_state,active_interventions,action_constraints)
    def train(self,environment,episodes:int=20,seed:int=1,lr:float=.03,gamma:float=.92):
        """REINFORCE differentiates projection, VQC parameters and classical head."""
        pnp=self.qml.numpy; projection=pnp.array(self.projection_weights,requires_grad=True); bias=pnp.array(self.projection_bias,requires_grad=True); quantum=pnp.array(self.quantum_weights,requires_grad=True); head=pnp.array(self.weights,requires_grad=True)
        returns=[]; quantum_gradient_norms=[]; projection_gradient_norms=[]
        for ep in range(episodes):
            obs,_=environment.reset(seed+ep,("credential-compromise","lateral-movement","malicious-insider","sensitive-data-exfiltration","benign")[ep%5]); trajectory=[]; done=False
            while not done:
                encoded=np.asarray(self.circuit(self._project(obs,projection,bias),quantum),dtype=float); mask=environment.action_mask(); p=masked_softmax(np.asarray(head)@encoded,mask); a=int(self.rng.choice(len(ACTIONS),p=p)); next_obs,r,t,u,_=environment.step(a); trajectory.append((tuple(obs),mask,a,r)); obs=next_obs; done=t or u
            returns_to_go=[]; g=0.; total=0.
            for _,_,_,r in reversed(trajectory): g=r+gamma*g; returns_to_go.append(g); total+=r
            returns_to_go=list(reversed(returns_to_go)); baseline=float(np.mean(returns_to_go))
            def loss(p,b,q,h):
                value=0.
                for (obs,mask,action,_),ret in zip(trajectory,returns_to_go):
                    encoded=self.circuit(pnp.tanh(pnp.dot(p,pnp.array(obs))+b)*np.pi,q)
                    logits=pnp.dot(h,pnp.stack(encoded)); masked=pnp.where(pnp.array(mask),logits,-1e9); probabilities=pnp.exp(masked-pnp.max(masked)); probabilities=probabilities/pnp.sum(probabilities)
                    value-= (ret-baseline)*pnp.log(probabilities[action]+1e-12)
                return value/len(trajectory)
            grads=self.qml.grad(loss,argnum=(0,1,2,3))(projection,bias,quantum,head)
            projection-=lr*grads[0]; bias-=lr*grads[1]; quantum-=lr*grads[2]; head-=lr*grads[3]
            projection_gradient_norms.append(float(np.linalg.norm(grads[0]))); quantum_gradient_norms.append(float(np.linalg.norm(grads[2])));
            returns.append(total)
        self.projection_weights=np.asarray(projection); self.projection_bias=np.asarray(bias); self.quantum_weights=np.asarray(quantum); self.weights=np.asarray(head)
        return {"episodes":episodes,"returns":returns,"algorithm":"end-to-end masked REINFORCE: classical projection + four-qubit VQC + policy head","replay_used_for_updates":False,"quantum_gradient_norms":quantum_gradient_norms,"projection_gradient_norms":projection_gradient_norms,"quantum_parameters_updated":bool(any(x>1e-10 for x in quantum_gradient_norms))}

class PolicyRegistry:
    """In-memory policy metadata; policies remain advisory and simulator-only."""
    states=frozenset({"BASELINE","EXPERIMENTAL","TRAINED","VALIDATION_FAILED","VALIDATED","PENDING_APPROVAL","APPROVED_FOR_SIMULATION","ACTIVE_SIMULATION","ROLLED_BACK","ARCHIVED","REJECTED"})
    def __init__(self): self.entries={}; self.active_name=None
    def register(self,name,policy,stage="EXPERIMENTAL",provenance=None):
        if stage not in self.states: raise ValueError(stage)
        self.entries[name]={"policy":policy,"stage":stage,"auto_promote":False,"provenance":provenance or {},"approval":None,"previous":None}
    def get(self,name): return self.entries[name]
    def set_stage(self,name,stage):
        if stage not in self.states: raise ValueError(stage)
        self.entries[name]["stage"]=stage
    def approve_for_simulation(self,name,actor_id,actor_role):
        if actor_role!="model_governor": raise PermissionError("model-governor approval required")
        if self.entries[name]["stage"]!="PENDING_APPROVAL": raise ValueError("candidate is not pending approval")
        self.entries[name]["stage"]="APPROVED_FOR_SIMULATION"; self.entries[name]["approval"]={"actor_id":actor_id,"role":actor_role}
    def activate(self,name,actor_id,actor_role):
        if actor_role!="model_governor": raise PermissionError("model-governor activation required")
        if self.entries[name]["stage"]!="APPROVED_FOR_SIMULATION": raise ValueError("candidate is not approved")
        previous=self.active_name
        if previous: self.entries[previous]["stage"]="ROLLED_BACK"
        self.entries[name]["previous"]=previous; self.entries[name]["stage"]="ACTIVE_SIMULATION"; self.entries[name]["activation_actor"]=actor_id; self.active_name=name
    def rollback(self,actor_id,actor_role):
        if actor_role!="model_governor": raise PermissionError("model-governor rollback required")
        if not self.active_name: raise ValueError("no active simulation policy")
        active=self.active_name; previous=self.entries[active]["previous"]
        self.entries[active]["stage"]="ROLLED_BACK"; self.active_name=previous
        if previous: self.entries[previous]["stage"]="ACTIVE_SIMULATION"
        return active,previous

def phase8_proposal_from_recommendation(recommendation:Recommendation, incident_id:str, targets:tuple[str,...], state_version:int, prediction:Mapping[str,float]):
    """Convert advisory output to a Phase 8 proposal; it conveys no authority."""
    from .autonomous_defense import Proposal
    return Proposal(incident_id=incident_id,action=recommendation.action,targets=targets,state_version=state_version,
        planner_source="qrl",prediction={**prediction,"operationally_suitable":False,"out_of_distribution":recommendation.out_of_distribution},
        uncertainty=1.0 if recommendation.out_of_distribution else .5,reversible=recommendation.action not in HIGH_IMPACT,
        recovery_plan=recommendation.action not in {"NO_OP","REQUEST_HUMAN_REVIEW"},blast_radius=2 if recommendation.action in HIGH_IMPACT else 1,
        target_criticality=4 if recommendation.action in HIGH_IMPACT else 1)
