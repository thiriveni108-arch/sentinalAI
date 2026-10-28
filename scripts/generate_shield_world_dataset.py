"""Pilot, validate, and generate the frozen SHIELD world-model dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel_ai.shield.world_dataset import generate_episodes, quality_report, write_release


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", type=int, default=600)
    parser.add_argument("--pilot-episodes", type=int, default=60)
    parser.add_argument("--output", type=Path, default=Path("data/processed/shield_world_v2"))
    args = parser.parse_args()
    pilot, _ = generate_episodes(args.pilot_episodes)
    pilot_report = quality_report(pilot)
    gates = {
        "minimum_topologies": pilot_report["topologies"] >= 15,
        "all_families": len(pilot_report["families"]) == 6,
        "partial_containment": pilot_report["partial_containments"] > 0,
        "failures": pilot_report["response_failures"] > 0,
        "route_switches": pilot_report["route_switches"] > 0,
        "disruption": pilot_report["disruption_nonzero"] > 0,
        "no_forbidden_features": not pilot_report["forbidden_model_features"],
        "duplicate_fraction_below_half": pilot_report["duplicate_feature_fraction"] < 0.5,
    }
    pilot_payload = {"pilot": pilot_report, "gates": gates, "passed": all(gates.values())}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "pilot_report.json").write_text(json.dumps(pilot_payload, indent=2), encoding="utf-8")
    if not pilot_payload["passed"]:
        raise SystemExit(json.dumps(pilot_payload, indent=2))
    model_frame, records = generate_episodes(args.episodes)
    manifest = write_release(model_frame, records, args.output)
    print(json.dumps({"pilot": pilot_payload, "release": manifest}, indent=2))


if __name__ == "__main__":
    main()
