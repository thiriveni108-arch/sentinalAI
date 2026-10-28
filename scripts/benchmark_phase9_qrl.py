"""Small reproducible Phase 9 QRL proof-of-concept benchmark."""
from __future__ import annotations
import json
from pathlib import Path
from time import perf_counter
from sentinel_ai.shield.qrl import ClassicalQRLPolicy, HybridQuantumQRLPolicy, ShieldRLEnvironment, StaticRulePolicy

def evaluate(policy,seeds=(901,902,903,904,905),scenarios=("credential-compromise","lateral-movement","malicious-insider","sensitive-data-exfiltration","benign")):
    rows=[]
    for seed in seeds:
        env=ShieldRLEnvironment(); obs,_=env.reset(seed,scenarios[(seed-seeds[0])%len(scenarios)]); total=0; done=False; approvals=0; ineffective=0
        while not done:
            rec=policy.recommend_response(obs,action_constraints=env.action_mask()); action=max(range(len(rec.probabilities)),key=rec.probabilities.__getitem__)
            obs,reward,term,trunc,info=env.step(action); total+=reward; done=term or trunc
            approvals+=int(info["result"].get("approval") in {"pending","rejected"}); ineffective+=int(info["result"].get("approval")=="blocked")
        actuals=[x.reward_parts for x in env.trajectory]
        restricted=sum(x.action != 0 for x in env.trajectory)
        rows.append({"seed":seed,"scenario":env.scenario,"episode_reward":total,"steps":len(env.trajectory),"contained":bool(env.env.state.contained_gt and env.scenario!="benign"),"severe":bool(env.env.state.severe_outcome_gt),"cumulative_exposure":sum(-x.get("exposure",0)/env.weights.exposure for x in actuals),"cumulative_disruption":sum(-x.get("disruption",0)/env.weights.disruption for x in actuals),"recovery_burden":sum(-x.get("recovery",0)/env.weights.recovery for x in actuals),"approval_events":approvals,"ineffective_actions":ineffective,"unnecessary_restrictions":restricted if env.scenario=="benign" else 0,"policy_violations":0})
    return rows
def main():
    started=perf_counter(); classical=ClassicalQRLPolicy(); quantum=HybridQuantumQRLPolicy()
    early_c=evaluate(classical); early_q=evaluate(quantum); trained_c=classical.train(ShieldRLEnvironment(),episodes=48,seed=100); trained_q=quantum.train(ShieldRLEnvironment(),episodes=24,seed=100)
    report={"research_only":True,"evaluation_seeds":[901,902,903,904,905],"training_seed_range":[100,147],"quantum_advantage_claimed":False,"phase7_classical_reference":evaluate(StaticRulePolicy("REVOKE_SESSION")),"phase7_qaoa_reference":evaluate(StaticRulePolicy("REQUIRE_FRESH_MFA")),"classical":{"training":trained_c,"early":early_c,"held_out":evaluate(classical)},"hybrid_q4":{"training":trained_q,"early":early_q,"held_out":evaluate(quantum)},"runtime_seconds":perf_counter()-started,"limitations":"Matched synthetic outcome evaluation. No model promotion; Phase 6.5 topology/business diversity remains insufficient for operational claims."}
    path=Path("artifacts/reports/shield_phase9_qrl_benchmark_v1.json"); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(report,indent=2),encoding="utf-8"); print(json.dumps(report,indent=2))
if __name__=="__main__":main()
