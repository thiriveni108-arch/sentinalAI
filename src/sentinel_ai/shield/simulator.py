from __future__ import annotations

from dataclasses import asdict

from .models import AttackPath, Intervention
from .optimizer import evaluate


def simulate(paths: tuple[AttackPath, ...], actions: tuple[Intervention, ...], selected: set[str], label: str) -> dict:
    result = evaluate(selected, paths, actions)
    total_exposure = sum(path.criticality for path in paths)
    remaining = {path.path_id for path in paths if path.path_id in result.remaining_paths}
    residual = sum(path.criticality for path in paths if path.path_id in remaining)
    return {
        "label": label, "selectedActions": list(result.selected), "feasible": result.feasible,
        "disruptionCost": result.disruption_cost, "interruptedPaths": list(result.covered_paths),
        "remainingPaths": list(result.remaining_paths), "remainingExposure": residual,
        "exposureReduction": 0 if not total_exposure else round(1 - residual / total_exposure, 4),
        "accepted": result.feasible,
        "explanation": result.explanation,
        "boundedAnalysis": True,
    }
