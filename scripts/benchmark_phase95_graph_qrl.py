"""Reproducible, grouped Phase 9.5 graph-generalization benchmark.

This remains a simulator-only experiment.  Phase 7 graph results are labelled
diagnostic because the frozen predictor has no graph-scenario training data.
"""
from __future__ import annotations

import json
from pathlib import Path
from statistics import mean, stdev
from time import perf_counter

import joblib

from sentinel_ai.shield.consequence_predictor import GraphAwareConsequencePredictor
from sentinel_ai.shield.qrl import (ACTIONS, ClassicalQRLPolicy, HybridQuantumQRLPolicy,
                                    Phase7PlannerAdapter, ShieldRLEnvironment)
from sentinel_ai.shield.topology import grouped_split, topology_scenario


EVAL_SEEDS = (1901, 1902, 1903)
SCENARIOS = ("credential-compromise", "lateral-movement", "sensitive-data-exfiltration", "benign")


def episode(policy, seed: int, scenario: str, topology: str) -> dict:
    env = ShieldRLEnvironment(graph_features=True)
    observation, _ = env.reset(seed, scenario, topology=topology)
    total, approvals, started, done = 0.0, 0, perf_counter(), False
    while not done:
        recommendation = policy.recommend_response(observation, action_constraints=env.action_mask())
        action = max(range(len(recommendation.probabilities)), key=recommendation.probabilities.__getitem__)
        observation, reward, terminated, truncated, info = env.step(action)
        total += reward; done = terminated or truncated
        approvals += int(info["result"].get("approval") in {"pending", "rejected"})
    parts = [item.reward_parts for item in env.trajectory]
    return {"topology": topology, "scenario": scenario, "seed": seed, "contained": bool(env.env.state.contained_gt and scenario != "benign"),
            "severe": bool(env.env.state.severe_outcome_gt), "exposure": sum(-x.get("exposure", 0) / env.weights.exposure for x in parts),
            "disruption": sum(-x.get("disruption", 0) / env.weights.disruption for x in parts),
            "recovery_burden": sum(-x.get("recovery", 0) / env.weights.recovery for x in parts),
            "approval_events": approvals, "episode_reward": total,
            "policy_violations": 0, "decision_latency_ms": (perf_counter() - started) * 1000 / max(1, len(env.trajectory))}


def summarize(rows: list[dict]) -> dict:
    metrics = ("contained", "severe", "exposure", "disruption", "recovery_burden", "approval_events", "episode_reward", "policy_violations", "decision_latency_ms")
    def stats(items): return {key: {"mean": mean(x[key] for x in items), "std": stdev([x[key] for x in items]) if len(items) > 1 else 0.0, "n": len(items)} for key in metrics}
    return {"aggregate": stats(rows), "per_topology": {name: stats([x for x in rows if x["topology"] == name]) for name in grouped_split()["test"]}, "episodes": rows}


def evaluate(policy) -> dict:
    return summarize([episode(policy, seed, scenario, topology)
                      for topology in grouped_split()["test"] for scenario in SCENARIOS for seed in EVAL_SEEDS])


def learned_runs(policy_type, budgets=(12, 24), seeds=(101, 202)) -> list[dict]:
    result = []
    training_topologies = grouped_split()["train"]
    for seed in seeds:
        policy = policy_type(features=19, seed=seed)
        environment = ShieldRLEnvironment(graph_features=True, topology_cycle=training_topologies)
        checkpoints, completed = [], 0
        for budget in budgets:
            training = policy.train(environment, episodes=budget-completed, seed=10_000 + seed + completed)
            completed = budget; checkpoints.append({"episodes": budget, "training": training, "held_out": evaluate(policy)})
        result.append({"training_seed": seed, "checkpoints": checkpoints})
    return result


def phase7_results(model_path: str) -> dict:
    path = Path(model_path)
    if not path.exists(): return {"status": "unavailable", "reason": "Frozen Phase 7 predictor artifact is unavailable; no substitute policy was used."}
    base = joblib.load(path); output = {"status": "diagnostic_only", "reason": "Frozen Phase 7 predictor lacks graph-grouped training/validation; structural wrapper is explicit, not learned."}
    for mode in ("classical", "qaoa"):
        rows = []
        for topology in grouped_split()["test"]:
            adapter = Phase7PlannerAdapter(GraphAwareConsequencePredictor(base, topology_scenario(topology)), mode)
            rows.extend(episode(adapter, seed, scenario, topology) for scenario in SCENARIOS for seed in EVAL_SEEDS)
        output[mode] = summarize(rows)
    return output


def main() -> None:
    started = perf_counter()
    report = {"version": "shield-phase9.5-graph-benchmark-v1", "research_only": True, "quantum_advantage_claimed": False,
              "split": grouped_split(), "held_out_seeds": EVAL_SEEDS,
              "authorization": "Phase 8 remains sole authority; QRL and planner outputs are advisory only.",
              "phase7": phase7_results("artifacts/models/shield_phase7_consequence_v1.joblib"),
              "classical_rl": learned_runs(ClassicalQRLPolicy), "hybrid_qrl": learned_runs(HybridQuantumQRLPolicy),
              "runtime_seconds": perf_counter() - started,
              "limitation": "The graph-aware Phase 7 adjustment is diagnostic-only pending graph-grouped predictor retraining and calibration."}
    target = Path("artifacts/reports/shield_phase95_graph_benchmark_v1.json"); target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    import matplotlib.pyplot as plt
    figure, axis = plt.subplots(figsize=(7, 4))
    for label, key in (("Classical RL", "classical_rl"), ("Hybrid QRL", "hybrid_qrl")):
        for run in report[key]:
            axis.plot([point["episodes"] for point in run["checkpoints"]],
                      [point["held_out"]["aggregate"]["episode_reward"]["mean"] for point in run["checkpoints"]],
                      marker="o", label=f"{label}, seed {run['training_seed']}")
    axis.set(xlabel="Training episodes", ylabel="Held-out mean episode reward",
             title="Phase 9.5 topology-family held-out learning curves")
    axis.legend(fontsize=7); figure.tight_layout()
    figure.savefig(target.with_name("shield_phase95_graph_learning_curves_v1.png"), dpi=150)
    plt.close(figure)
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
