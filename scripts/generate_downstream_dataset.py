"""Generate the frozen Phase 6 isolated counterfactual rollout release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from sentinel_ai.shield.downstream import (DATASET_VERSION, HORIZON, TARGET_COLUMNS,
                                           available_action_types, counterfactual_rollout)
from sentinel_ai.shield.dynamic import SUPPORTED_FAMILIES
from sentinel_ai.shield.world_dataset import feature_columns, sha256


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--initial-states", type=int, default=240)
    parser.add_argument("--seed", type=int, default=63001)
    parser.add_argument("--horizon", type=int, default=HORIZON)
    parser.add_argument("--output", type=Path, default=Path("data/processed/shield_downstream_v1"))
    args = parser.parse_args()
    phase4 = pd.read_parquet("data/processed/shield_world_v2/model_table.parquet")
    topology_split = phase4[["topology_id", "split"]].drop_duplicates().set_index("topology_id").split.to_dict()
    families = tuple(family for family in SUPPORTED_FAMILIES if family != "benign-alert")
    rows, transition_rows = [], []
    for index in range(args.initial_states):
        family = families[index % len(families)]
        seed = args.seed + index * 104729
        warmup_steps = index % 3
        for action_type in available_action_types(family, seed, warmup_steps):
            rollout = counterfactual_rollout(family, seed, action_type, args.horizon, warmup_steps=warmup_steps)
            topology_id = rollout.records[0].topology_id
            row = {"dataset_version": DATASET_VERSION, "branch_id": rollout.branch_id,
                   "initial_condition_id": f"phase6-{family}-{seed}", "scenario_family_audit": family,
                   "topology_id": topology_id, "split": topology_split[topology_id],
                   "action_type_audit": action_type, "horizon": args.horizon,
                   "warmup_steps_audit": warmup_steps,
                   "rollout_steps": len(rollout.records), "initial_state_fingerprint": rollout.initial_state_fingerprint,
                   "one_step_exposure_audit": rollout.records[0].remaining_attack_path_exposure,
                   "one_step_disruption_audit": rollout.records[0].legitimate_workflow_disruption,
                   "one_step_contained_audit": int(rollout.records[0].attack_outcome == "CONTAINED"),
                   "one_step_route_switched_audit": int(bool(rollout.records[0].attacker_strategy_gt and
                                                               rollout.records[0].attacker_strategy_gt.get("adapted"))),
                   "one_step_next_malicious_observation_audit": int(any(
                       evidence.evidence_type == "POST_ACTION_MALICIOUS_ACTIVITY"
                       for evidence in rollout.records[0].next_observation)),
                   **rollout.features, **rollout.targets}
            rows.append(row)
            transition_rows.extend({"branch_id": rollout.branch_id, "step": step + 1,
                                    "transition_json": json.dumps(record.to_v2_dict(), sort_keys=True)}
                                   for step, record in enumerate(rollout.records))
    frame, transitions = pd.DataFrame(rows), pd.DataFrame(transition_rows)
    args.output.mkdir(parents=True, exist_ok=True)
    data_path, transitions_path = args.output / "model_table.parquet", args.output / "rollout_transitions.parquet"
    frame.to_parquet(data_path, index=False); transitions.to_parquet(transitions_path, index=False)
    feature_list = feature_columns(True)
    manifest = {"dataset_version": DATASET_VERSION, "generation_seed": args.seed, "horizon": args.horizon,
                "rows": len(frame), "initial_conditions": int(frame.initial_condition_id.nunique()),
                "branches_per_initial_condition": frame.groupby("initial_condition_id").size().describe().to_dict(),
                "feature_columns": feature_list, "target_columns": list(TARGET_COLUMNS),
                "split_rows": frame.split.value_counts().to_dict(),
                "split_initial_conditions": frame.groupby("split").initial_condition_id.nunique().to_dict(),
                "topology_overlap_count": int((frame.groupby("topology_id").split.nunique() > 1).sum()),
                "initial_condition_overlap_count": int((frame.groupby("initial_condition_id").split.nunique() > 1).sum()),
                "files": {"model_table.parquet": sha256(data_path), "rollout_transitions.parquet": sha256(transitions_path)},
                "observability": "Phase 4 defender-observable feature allow-list only; oracle/future values are labels/audit only",
                "branch_isolation": "fresh simulator, belief tracker, state, history, undo map and RNG per action branch",
                "matched_randomness": "same reset/attacker seed per initial condition; action effectiveness is deterministic by condition/action",
                "synthetic_not_operational": True}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__": main()
