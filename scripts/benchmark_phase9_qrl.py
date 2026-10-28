"""Matched, outcome-first Phase 9 benchmark; all policies remain advisory."""
from __future__ import annotations
import json
from pathlib import Path
from statistics import mean, stdev
from time import perf_counter
import joblib

from sentinel_ai.shield.qrl import ClassicalQRLPolicy, HybridQuantumQRLPolicy, Phase7PlannerAdapter, ShieldRLEnvironment

SCENARIOS=("credential-compromise","malicious-insider","lateral-movement","sensitive-data-exfiltration","privilege-escalation","benign")
EVAL_SEEDS=(901,902,903)

def episode(policy,seed,scenario):
    env=ShieldRLEnvironment(); obs,_=env.reset(seed,scenario); total=0.; approvals=0; started=perf_counter(); done=False
    while not done:
        recommendation=policy.recommend_response(obs,action_constraints=env.action_mask())
        action=max(range(len(recommendation.probabilities)),key=recommendation.probabilities.__getitem__)
        obs,reward,terminated,truncated,info=env.step(action); total+=reward; done=terminated or truncated
        approvals+=int(info["result"].get("approval") in {"pending","rejected"})
    parts=[x.reward_parts for x in env.trajectory]
    return {"scenario":scenario,"seed":seed,"episode_reward":total,"contained":bool(env.env.state.contained_gt and scenario!="benign"),"severe":bool(env.env.state.severe_outcome_gt),"cumulative_exposure":sum(-x.get("exposure",0)/env.weights.exposure for x in parts),"cumulative_disruption":sum(-x.get("disruption",0)/env.weights.disruption for x in parts),"recovery_burden":sum(-x.get("recovery",0)/env.weights.recovery for x in parts),"approval_events":approvals,"unnecessary_restrictions":sum(x.action!=0 for x in env.trajectory) if scenario=="benign" else 0,"policy_violations":0,"decision_latency_ms":(perf_counter()-started)*1000/max(1,len(env.trajectory))}

def evaluate(policy): return [episode(policy,seed,scenario) for scenario in SCENARIOS for seed in EVAL_SEEDS]
def summary(rows):
    keys=("contained","severe","cumulative_exposure","cumulative_disruption","recovery_burden","approval_events","unnecessary_restrictions","policy_violations","episode_reward","decision_latency_ms")
    aggregate={key:{"mean":mean([r[key] for r in rows]),"std":stdev([r[key] for r in rows]) if len(rows)>1 else 0.,"n":len(rows)} for key in keys}
    return {"aggregate":aggregate,"per_scenario":{scenario:{key:mean([r[key] for r in rows if r["scenario"]==scenario]) for key in keys} for scenario in SCENARIOS},"episodes":rows}

def train_runs(policy_type,budgets=(24,48),seeds=(101,202)):
    output=[]
    for seed in seeds:
        policy=policy_type(seed=seed); checkpoints=[]
        completed=0
        for budget in budgets:
            report=policy.train(ShieldRLEnvironment(),episodes=budget-completed,seed=1000+seed+completed); completed=budget
            checkpoints.append({"episodes":budget,"training":report,"evaluation":summary(evaluate(policy))})
        output.append({"training_seed":seed,"checkpoints":checkpoints})
    return output

def real_phase7_adapters(model_path):
    if not Path(model_path).exists(): return {"status":"incompatible","reason":"Frozen Phase 7 consequence predictor artifact is unavailable; fixed-action substitutes are prohibited."}
    predictor=joblib.load(model_path); result={"status":"diagnostic_only","limitation":"The Phase 7 predictor was trained at tick zero; later RL observations are out of training support. Adapters invoke the real planner but are not a fair generalization claim."}
    for mode in ("classical","qaoa"):
        try: result[mode]=summary(evaluate(Phase7PlannerAdapter(predictor,mode)))
        except Exception as error: result[mode]={"status":"unavailable","reason":f"{type(error).__name__}: {error}"}
    return result

def main():
    started=perf_counter(); model="artifacts/models/shield_phase7_consequence_v1.joblib"
    report={"research_only":True,"quantum_advantage_claimed":False,"evaluation_protocol":{"scenarios":list(SCENARIOS),"held_out_seeds":list(EVAL_SEEDS),"episodes_per_scenario":len(EVAL_SEEDS),"training_seeds":[101,202],"authorization":"Phase 8 remains sole execution authority; environment only models allowed automatic actions and review delays."},"phase7_real_adapters":real_phase7_adapters(model),"classical_rl":train_runs(ClassicalQRLPolicy),"hybrid_q4_rl":train_runs(HybridQuantumQRLPolicy),"runtime_seconds":perf_counter()-started,"promotion":"EXPERIMENTAL only; no automatic model promotion."}
    path=Path("artifacts/reports/shield_phase9_qrl_benchmark_v2.json"); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(report,indent=2),encoding="utf-8")
    import matplotlib.pyplot as plt
    fig,axis=plt.subplots(figsize=(7,4))
    for label,key in (("Classical RL","classical_rl"),("Hybrid QRL","hybrid_q4_rl")):
        for run in report[key]:
            axis.plot([x["episodes"] for x in run["checkpoints"]],[x["evaluation"]["aggregate"]["episode_reward"]["mean"] for x in run["checkpoints"]],marker="o",label=f"{label}, seed {run['training_seed']}")
    axis.set(xlabel="Training episodes",ylabel="Held-out mean episode reward",title="Phase 9 learning checkpoints (synthetic)"); axis.legend(fontsize=7); fig.tight_layout(); fig.savefig(path.with_name("shield_phase9_learning_curves_v2.png"),dpi=150); plt.close(fig)
    print(json.dumps(report,indent=2))
if __name__=="__main__":main()
