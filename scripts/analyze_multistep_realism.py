"""Compare the Phase 6.5 release with frozen Phase 6 target quality."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("data/processed/shield_multistep_v2/model_table.parquet"))
    parser.add_argument("--manifest", type=Path, default=Path("data/processed/shield_multistep_v2/manifest.json"))
    parser.add_argument("--phase6-report", type=Path, default=Path("artifacts/reports/shield_downstream_consequence_v1.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/reports/shield_multistep_realism_v2.json"))
    args = parser.parse_args()
    frame = pd.read_parquet(args.data)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    phase6 = json.loads(args.phase6_report.read_text(encoding="utf-8"))
    rank_correlations = []
    for _, group in frame.groupby(["initial_condition_id", "continuation_policy"]):
        coefficient = spearmanr(group.first_step_exposure_audit, group.target_cumulative_exposure).statistic
        if not np.isnan(coefficient): rank_correlations.append(coefficient)
    per_action = frame.groupby("candidate_action").agg(
        rows=("branch_id", "count"), exposure_mean=("target_cumulative_exposure", "mean"),
        disruption_mean=("target_cumulative_disruption", "mean"), recovery_mean=("target_recovery_burden", "mean"),
        delayed_adaptation_rate=("target_delayed_adaptation", "mean"), severe_rate=("target_severe_outcome", "mean"),
        containment_time_mean=("target_time_to_containment", "mean"), unresolved_rate=("target_unresolved", "mean")).to_dict(orient="index")
    per_policy = frame.groupby("continuation_policy").agg(
        rows=("branch_id", "count"), exposure_mean=("target_cumulative_exposure", "mean"),
        disruption_mean=("target_cumulative_disruption", "mean"), recovery_mean=("target_recovery_burden", "mean"),
        delayed_adaptation_rate=("target_delayed_adaptation", "mean"), severe_rate=("target_severe_outcome", "mean"),
        containment_time_mean=("target_time_to_containment", "mean"), unresolved_rate=("target_unresolved", "mean")).to_dict(orient="index")
    old_quality = phase6["target_quality"]["targets"]
    comparison = {
        "recovery_burden": {"phase6_unique": old_quality["target_recovery_burden"]["unique"],
                            "phase65_unique": frame.target_recovery_burden.nunique(),
                            "phase6_mean": old_quality["target_recovery_burden"]["mean"],
                            "phase65_mean": frame.target_recovery_burden.mean()},
        "severe_outcome": {"phase6_positive": old_quality["target_severe_residual_damage"].get("positive", 0),
                           "phase65_positive": int(frame.target_severe_outcome.sum()),
                           "phase65_rate": frame.target_severe_outcome.mean()},
        "delayed_adaptation": {"phase6_beyond_first_step": phase6["target_quality"]["relationship_to_phase4_one_step_targets"]["adaptation_beyond_first_step_rows"],
                               "phase65_positive": int(frame.target_delayed_adaptation.sum()),
                               "phase65_rate": frame.target_delayed_adaptation.mean()},
        "containment_time_unique": {"phase6": old_quality["target_time_to_containment"]["unique"],
                                    "phase65": frame.target_time_to_containment.nunique()},
        "first_vs_cumulative_exposure_spearman": {
            "phase6": phase6["target_quality"]["relationship_to_phase4_one_step_targets"]["cumulative_exposure_vs_one_step_exposure_spearman"],
            "phase65": manifest["quality"]["first_vs_cumulative_exposure_spearman"]},
    }
    report = {"dataset_version": manifest["dataset_version"], "simulator_version": manifest["simulator_version"],
              "pilot_passed": json.loads((args.manifest.parent / "pilot_report.json").read_text(encoding="utf-8"))["passed"],
              "rows": len(frame), "initial_conditions": frame.initial_condition_id.nunique(),
              "split_rows": frame.split.value_counts().to_dict(), "quality": manifest["quality"],
              "comparison_to_frozen_phase6": comparison, "per_candidate_action": per_action,
              "per_continuation_policy": per_policy,
              "mean_action_rank_spearman_first_vs_cumulative_exposure": float(np.mean(rank_correlations)),
              "rank_groups": len(rank_correlations),
              "phase7_readiness": "conditional_research_ready_not_operational",
              "recommendation": "Proceed to a bounded classical adaptive-planning formulation study before any QAOA change; validate constraints and uncertainty on held-out topology groups.",
              "limitations": ["Synthetic environment with deliberately bounded causal rules, not an operational digital twin.",
                 "Recovery dependencies are aggregate rather than a full service dependency graph.",
                 "Approval is modeled as a constraint but human response-time distributions are not yet modeled.",
                 "Continuation policies are deterministic functions of defender observations.",
                 "Severe outcomes follow explicit simulator predicates but require external domain validation.",
                 "No predictive model, VQC, quantum kernel, QAOA, or live action integration was trained or changed."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "comparison": comparison,
                      "phase7_readiness": report["phase7_readiness"]}, indent=2))


if __name__ == "__main__": main()
