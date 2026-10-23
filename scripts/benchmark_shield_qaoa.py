"""Run the bounded, reproducible SHIELD QAOA comparison matrix."""

from __future__ import annotations

import argparse
import json

from sentinel_ai.shield import ShieldService


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", nargs="?", default="multiple-routes")
    args = parser.parse_args()
    print(json.dumps(ShieldService().quantum_experiment(args.scenario), indent=2))


if __name__ == "__main__":
    main()
