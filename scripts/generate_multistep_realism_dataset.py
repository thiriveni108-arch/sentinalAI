"""Pilot and materialize the versioned Phase 6.5 multi-step release."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import numpy as np
import pandas as pd

from sentinel_ai.shield.consequence_simulator import (ACTION_TYPES, POLICY_NAMES, POLICY_VERSION,
                                                       SIMULATOR_VERSION, MultiStepConsequenceEnvironment,
                                                       SimulatedAction, continuation_action)
from sentinel_ai.shield.world_dataset import sha256


DATASET_VERSION = "shield-multistep-counterfactual-v2.0.0"
FAMILIES = ("credential-compromise", "malicious-insider", "lateral-movement",
            "sensitive-data-exfiltration", "privilege-escalation")
CANDIDATES = tuple(action for action in ACTION_TYPES if action not in {"ROLLBACK", "NO_OP"}) + ("NO_OP",)


def rollout(family: str, seed: int, candidate: str, policy: str, horizon: int = 5):
    env = MultiStepConsequenceEnvironment(family, seed, max_steps=horizon)
    initial = env.observe()
    records = []
    for step in range(horizon):
        action = (SimulatedAction(candidate, approved=True) if step == 0 else
                  continuation_action(policy, env.observe(), step - 1, tuple(env.action_history)))
        records.append(env.step(action))
        if env.state.terminal: break
    containment = [index + 1 for index, record in enumerate(records) if record.genuinely_contained_gt]
    targets = {
        "target_cumulative_exposure": sum(item.exposure for item in records),
        "target_cumulative_disruption": sum(item.disruption for item in records),
        "target_recovery_burden": sum(item.recovery_cost for item in records),
        "target_delayed_adaptation": int(any(item.attacker_adapted_gt for item in records[1:])),
        "target_severe_outcome": int(any(item.severe_outcome_gt for item in records)),
        "target_time_to_containment": containment[0] if containment else horizon + 1,
        "target_unresolved": int(records[-1].unresolved),
    }
    features = {"state_tick": initial.tick, "service_health": initial.service_health,
                "observed_compromise": initial.observed_compromise,
                "observed_malicious_activity": int(initial.observed_malicious_activity),
                "evidence_count": initial.evidence_count,
                **{f"candidate__{action}": int(candidate == action) for action in CANDIDATES},
                **{f"policy__{name}": int(policy == name) for name in POLICY_NAMES}}
    return initial, tuple(records), targets, features


def diversity(frame: pd.DataFrame):
    targets = [column for column in frame if column.startswith("target_")]
    distribution = {column: {"unique": int(frame[column].nunique()), "mean": float(frame[column].mean()),
                             "std": float(frame[column].std()), "min": float(frame[column].min()),
                             "max": float(frame[column].max())} for column in targets}
    delayed = int(frame.target_delayed_adaptation.sum())
    severe = int(frame.target_severe_outcome.sum())
    correlation = float(frame[["first_step_exposure_audit", "target_cumulative_exposure"]].corr(method="spearman").iloc[0, 1])
    reversals = 0
    minimal_better = 0
    for _, group in frame.groupby("initial_condition_id"):
        records = group.to_dict("records")
        for left in records:
            for right in records:
                short_better = (left["first_step_exposure_audit"] <= right["first_step_exposure_audit"] and
                                left["first_step_disruption_audit"] <= right["first_step_disruption_audit"] and
                                (left["first_step_exposure_audit"] < right["first_step_exposure_audit"] or
                                 left["first_step_disruption_audit"] < right["first_step_disruption_audit"]))
                long_worse = (left["target_cumulative_exposure"] > right["target_cumulative_exposure"] and
                              left["target_cumulative_disruption"] >= right["target_cumulative_disruption"])
                reversals += int(short_better and long_worse)
        minimal = group[group.continuation_policy == "minimally_disruptive"]
        immediate = group[group.continuation_policy == "immediate_containment"]
        for _, left in minimal.iterrows():
            matched = immediate[immediate.candidate_action == left.candidate_action]
            if len(matched):
                right = matched.iloc[0]
                minimal_better += int(left.target_cumulative_exposure <= right.target_cumulative_exposure and
                                      left.target_cumulative_disruption < right.target_cumulative_disruption)
    checks = {"nonzero_recovery": bool((frame.target_recovery_burden > 0).any()),
              "delayed_adaptation": delayed > 0,
              "containment_timing_diversity": frame.target_time_to_containment.nunique() >= 3,
              "severe_and_nonsevere": 0 < severe < len(frame),
              "exposure_not_first_step_deterministic": abs(correlation) < .98,
              "short_term_reversal_cases": reversals > 0,
              "minimal_disruption_security_preserved_cases": minimal_better > 0}
    return {"target_distributions": distribution, "action_support": frame.candidate_action.value_counts().to_dict(),
            "policy_support": frame.continuation_policy.value_counts().to_dict(),
            "delayed_adaptation_count": delayed, "severe_count": severe,
            "first_vs_cumulative_exposure_spearman": correlation,
            "short_term_reversal_pair_count": reversals,
            "minimal_disruption_security_preserved_count": minimal_better,
            "checks": checks, "passed": all(checks.values())}


def generate(initial_conditions: int, seed_base: int, horizon: int):
    rows, transitions = [], []
    for index in range(initial_conditions):
        family = FAMILIES[index % len(FAMILIES)]; seed = seed_base + index * 104729
        initial_id = f"phase65-{family}-{seed}"
        topology_id = f"topology-{family}-{seed % 31}"
        digest = int.from_bytes(__import__("hashlib").sha256(topology_id.encode()).digest()[:2], "big") % 100
        split = "train" if digest < 70 else "validation" if digest < 85 else "test"
        for candidate in CANDIDATES:
            for policy in POLICY_NAMES:
                initial, records, targets, features = rollout(family, seed, candidate, policy, horizon)
                branch_id = f"{initial_id}-{candidate}-{policy}"
                rows.append({"dataset_version": DATASET_VERSION, "simulator_version": SIMULATOR_VERSION,
                    "policy_version": POLICY_VERSION, "branch_id": branch_id, "initial_condition_id": initial_id,
                    "topology_id": topology_id, "split": split, "scenario_family_audit": family,
                    "candidate_action": candidate, "continuation_policy": policy, "horizon": horizon,
                    "rollout_steps": len(records), "first_step_exposure_audit": records[0].exposure,
                    "first_step_disruption_audit": records[0].disruption, **features, **targets})
                transitions.extend({"branch_id": branch_id, "step": step + 1,
                                    "transition_json": json.dumps(asdict(record), sort_keys=True)}
                                   for step, record in enumerate(records))
    return pd.DataFrame(rows), pd.DataFrame(transitions)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--pilot-conditions", type=int, default=30)
    parser.add_argument("--full-conditions", type=int, default=120); parser.add_argument("--seed", type=int, default=65001)
    parser.add_argument("--horizon", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("data/processed/shield_multistep_v2")); args = parser.parse_args()
    pilot, _ = generate(args.pilot_conditions, args.seed, args.horizon); pilot_report = diversity(pilot)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "pilot_report.json").write_text(json.dumps(pilot_report, indent=2), encoding="utf-8")
    if not pilot_report["passed"]:
        print(json.dumps({"pilot": pilot_report, "full_release_generated": False}, indent=2)); return
    frame, transitions = generate(args.full_conditions, args.seed, args.horizon); quality = diversity(frame)
    data_path, transition_path = args.output / "model_table.parquet", args.output / "rollout_transitions.parquet"
    frame.to_parquet(data_path, index=False); transitions.to_parquet(transition_path, index=False)
    manifest = {"dataset_version": DATASET_VERSION, "simulator_version": SIMULATOR_VERSION,
        "policy_version": POLICY_VERSION, "generation_seed": args.seed, "horizon": args.horizon,
        "rows": len(frame), "initial_conditions": frame.initial_condition_id.nunique(),
        "split_rows": frame.split.value_counts().to_dict(), "quality": quality,
        "topology_overlap_count": int((frame.groupby("topology_id").split.nunique() > 1).sum()),
        "initial_condition_overlap_count": int((frame.groupby("initial_condition_id").split.nunique() > 1).sum()),
        "files": {"model_table.parquet": sha256(data_path), "rollout_transitions.parquet": sha256(transition_path)},
        "branch_isolation": "fresh environment per candidate/policy; stateless seed/tick/component random draws",
        "input_observability": "continuation policies receive RealisticObservation only",
        "historical_phase6_preserved": True, "synthetic_not_operational": True}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"pilot": pilot_report, "full_release_generated": True, "manifest": manifest}, indent=2))


if __name__ == "__main__": main()
