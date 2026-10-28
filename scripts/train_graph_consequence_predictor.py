"""Train/evaluate the Phase 9.6 learned graph-aware consequence predictor."""
from __future__ import annotations
import json
from pathlib import Path
import joblib
import pandas as pd

from sentinel_ai.shield.consequence_predictor import GraphConsequencePredictor


def main() -> None:
    source = Path("data/processed/shield_graph_consequence_v1/model_table.parquet")
    target = Path("artifacts/models/shield_graph_consequence_v1.joblib"); report_path = Path("artifacts/reports/shield_graph_consequence_v1_report.json")
    if not source.exists(): raise FileNotFoundError("Generate the graph consequence dataset first.")
    frame = pd.read_parquet(source); predictor = GraphConsequencePredictor().fit(frame)
    target.parent.mkdir(parents=True, exist_ok=True); report_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(predictor, target)
    report = predictor.evaluate(frame)
    report.update({"dataset": str(source), "artifact": str(target), "rows": len(frame), "promotion": "SIMULATOR_VALIDATED_ONLY",
                   "acceptance_gates": {"split_integrity": bool(frame.groupby("topology_family").split.nunique().max() == 1),
                                        "no_oracle_features": bool(not any("_gt" in f or "route" in f for f in predictor.features)),
                                        "test_severe_calibration": bool(report["splits"]["test"]["target_severe_outcome"]["ece"] <= .15),
                                        "simulator_only": True}})
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
