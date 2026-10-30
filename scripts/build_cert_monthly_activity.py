"""Precompute compact monthly counts from genuine CERT r4.2 telemetry.

The browser never receives raw records. The generated cache records source sizes,
coverage, and exact row counts so the dashboard can state its denominator.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


SOURCES = {
    "login": "logon.csv",
    "file": "file.csv",
    "removableMedia": "device.csv",
    "email": "email.csv",
}


def count_months(path: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    with path.open("rb", buffering=1024 * 1024) as handle:
        next(handle)
        for line in handle:
            first = line.find(b",")
            second = line.find(b",", first + 1)
            if first < 0 or second < 0:
                continue
            date = line[first + 1 : second]
            if len(date) >= 10:
                # CERT uses MM/DD/YYYY HH:MM:SS.
                month = date[6:10].decode("ascii") + "-" + date[0:2].decode("ascii")
                counts[month] += 1
    return counts


def build(root: Path) -> dict[str, object]:
    raw = root / "data" / "raw" / "cert_r4_2" / "r4.2"
    results = {key: count_months(raw / filename) for key, filename in SOURCES.items()}
    months = sorted(set().union(*(counter.keys() for counter in results.values())))
    points = [{"month": month, **{key: results[key][month] for key in SOURCES}} for month in months]
    return {
        "dataset": "CERT Insider Threat r4.2",
        "unit": "raw telemetry events per calendar month",
        "reportingPeriod": {"start": months[0], "end": months[-1], "months": len(months)},
        "categories": [
            {"key": "login", "label": "Logon activity", "source": "logon.csv"},
            {"key": "file", "label": "File activity", "source": "file.csv"},
            {"key": "removableMedia", "label": "Removable-media activity", "source": "device.csv"},
            {"key": "email", "label": "Email activity", "source": "email.csv"},
        ],
        "points": points,
        "totals": {key: sum(counter.values()) for key, counter in results.items()},
        "provenance": {
            "aggregation": "Exact row counts grouped by the source event timestamp month; header rows excluded.",
            "rawSources": list(SOURCES.values()),
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "httpExcluded": "HTTP telemetry is not included because it is not represented by the prepared behavioural feature schema used by SentinelAI-Q.",
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    output = args.root / "data" / "processed" / "cert_monthly_activity.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build(args.root), indent=2), encoding="utf-8")
    print(output)
