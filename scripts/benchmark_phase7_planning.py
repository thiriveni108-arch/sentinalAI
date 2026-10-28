"""Reproducible bounded Phase 7 classical/QAOA/adaptive benchmark."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib
from sentinel_ai.shield.adaptive_planner import ActionSpec, make_problem, run_qaoa, solve_exact, solve_greedy
from sentinel_ai.shield.adaptive_replanning import run_adaptive_episode, run_static_episode

ACTIONS=(ActionSpec("NO_OP",0),ActionSpec("REQUIRE_FRESH_MFA",.12),ActionSpec("REVOKE_SESSION",.25),
         ActionSpec("ISOLATE_DEVICE",.85,.8,True,"human-approval"))
POLICIES=("observation_only","minimally_disruptive","policy_constrained")
VISIBLE={"state_tick":0,"service_health":1,"observed_compromise":.62,"observed_malicious_activity":1,"evidence_count":1}

def main():
    p=argparse.ArgumentParser(); p.add_argument("--model",default="artifacts/models/shield_phase7_consequence_v1.joblib")
    p.add_argument("--output",default="artifacts/reports/shield_phase7_planning_benchmark_v1.json"); args=p.parse_args()
    model=joblib.load(args.model); problem=make_problem(model,VISIBLE,ACTIONS,POLICIES)
    exact=solve_exact(problem); greedy=solve_greedy(problem); qaoa,qmeta=run_qaoa(problem,shots=128)
    adaptive=[]
    for family in ("credential-compromise","sensitive-data-exfiltration"):
        for seed in (7301,7302): adaptive.append({"family":family,"seed":seed,
            "static":run_static_episode(model,family,seed,ACTIONS,POLICIES),
            "adaptive":run_adaptive_episode(model,family,seed,ACTIONS,POLICIES,allowed_tier="automatic")})
    report={"research_only":True,"live_execution":False,"comparable_qaoa_shots":128,
            "exact":exact.__dict__,"greedy":greedy.__dict__,"qaoa":qaoa.__dict__,"qaoa_metadata":qmeta,
            "adaptive_episodes":adaptive,"oracle_planning_included":False,
            "static_existing_optimizer_scope":"attack-path coverage/cost; retained separately and not misrepresented as consequence-aware",
            "quantum_advantage_claimed":False}
    Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report,indent=2))
if __name__=="__main__": main()
