"""Train/evaluate the frozen Phase 6.5 consequence predictor."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib
from sentinel_ai.shield.consequence_predictor import ConsequencePredictor, load_phase65

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--data", default="data/processed/shield_multistep_v2/model_table.parquet")
    parser.add_argument("--model", default="artifacts/models/shield_phase7_consequence_v1.joblib")
    parser.add_argument("--report", default="artifacts/reports/shield_phase7_consequence_v1.json")
    args=parser.parse_args(); frame=load_phase65(args.data); model=ConsequencePredictor().fit(frame); report=model.evaluate(frame)
    report.update({"dataset_version": str(frame.dataset_version.iloc[0]), "training_partition":"train only",
                   "calibration_partition":"validation only", "test_partition":"evaluation only",
                   "privileged_features_excluded":["scenario_family_audit","topology_id","initial_condition_id","first_step_*_audit","future transitions","simulator ground truth"]})
    Path(args.model).parent.mkdir(parents=True, exist_ok=True); Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model,args.model); Path(args.report).write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report,indent=2))
if __name__ == "__main__": main()
