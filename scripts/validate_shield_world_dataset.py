"""Read-only integrity validation for a frozen SHIELD world dataset release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from sentinel_ai.shield.world_dataset import quality_report, sha256, split_integrity


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path("data/processed/shield_world_v2"))
    args = parser.parse_args()
    manifest = json.loads((args.directory / "manifest.json").read_text(encoding="utf-8"))
    table_path, records_path = args.directory / "model_table.parquet", args.directory / "transitions.parquet"
    frame = pd.read_parquet(table_path)
    result = {
        "hashes_match": {
            "model_table.parquet": sha256(table_path) == manifest["files"]["model_table.parquet"],
            "transitions.parquet": sha256(records_path) == manifest["files"]["transitions.parquet"],
        },
        "quality": quality_report(frame), "split_integrity": split_integrity(frame),
        "feature_manifest_matches": manifest["feature_columns"] == [item for item in manifest["feature_columns"]],
    }
    result["valid"] = all(result["hashes_match"].values()) and not result["quality"]["forbidden_model_features"] and not result["split_integrity"]["episode_overlap_count"] and not result["split_integrity"]["topology_overlap_count"]
    print(json.dumps(result, indent=2))
    if not result["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
