"""Reproducible transition generation and leakage-safe world-model features."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from .belief_integration import BeliefTrackedDynamicEnvironment
from .beliefs import MODES, BeliefState
from .dynamic import DynamicShieldEnvironment, SUPPORTED_FAMILIES
from .dynamic_models import ApprovalTier, DefenderAction, DefenderObservation, TransitionRecord


DATASET_RELEASE = "shield-world-transitions-v2.0.0"
GENERATION_SEED = 42073
ACTION_TYPES = (
    "NO_OP", "REVOKE_SESSION", "DISABLE_ACCOUNT", "REQUIRE_FRESH_MFA", "REMOVE_PRIVILEGE",
    "RESTRICT_RESOURCE", "DISABLE_BULK_EXPORT", "ISOLATE_DEVICE", "SEGMENT_SERVICE", "ROLLBACK",
)
EVIDENCE_TYPES = (
    "ANOMALOUS_SESSION", "POST_ACTION_MALICIOUS_ACTIVITY", "POST_ACTION_NO_CONFIRMED_ACTIVITY",
    "SENSITIVE_ACCESS_SPIKE", "LATERAL_CONNECTION", "BULK_EXPORT", "PRIVILEGE_CHANGE",
    "CONTAINMENT_ROUTE_SWITCH", "UNSUPPORTED",
)


def feature_columns(include_beliefs: bool = True) -> list[str]:
    columns = [
        "state_tick", "active_node_count", "service_health_min", "service_health_mean",
        "identity_active_fraction", "identity_restricted_fraction", "control_on_fraction",
        "observed_compromise_max", "observed_compromise_mean", "observed_path_count",
        "workflow_count", "workflow_slo_fraction", "workflow_total_demand", "action_target_count",
        "action_reversible", "action_approved", "approval_tier_code",
    ]
    columns += [f"action__{item}" for item in ACTION_TYPES]
    columns += [f"evidence__{item}" for item in EVIDENCE_TYPES]
    if include_beliefs:
        columns += [f"belief__{mode.value}" for mode in MODES] + ["belief_entropy"]
    return columns


TARGET_COLUMNS = [
    "target_contained", "target_residual_exposure", "target_route_switched",
    "target_workflow_disruption", "target_next_malicious_observation",
]


def build_features(observation: DefenderObservation, belief: BeliefState,
                   action: DefenderAction) -> dict[str, float]:
    health = list(observation.service_health.values()) or [1.0]
    identities = list(observation.identity_status.values()) or ["ACTIVE"]
    controls = list(observation.control_status.values()) or ["OFF"]
    compromise = list(observation.observed_compromise_probability.values()) or [0.0]
    slos = list(observation.workflow_slo_met.values()) or [True]
    result = {
        "state_tick": float(observation.time_step),
        "active_node_count": float(len(observation.active_nodes)),
        "service_health_min": float(min(health)),
        "service_health_mean": float(np.mean(health)),
        "identity_active_fraction": identities.count("ACTIVE") / len(identities),
        "identity_restricted_fraction": sum(item != "ACTIVE" for item in identities) / len(identities),
        "control_on_fraction": sum(item == "ON" for item in controls) / len(controls),
        "observed_compromise_max": float(max(compromise)),
        "observed_compromise_mean": float(np.mean(compromise)),
        "observed_path_count": float(len(observation.observed_reachable_paths)),
        "workflow_count": float(len(observation.workflow_demand)),
        "workflow_slo_fraction": sum(slos) / len(slos),
        "workflow_total_demand": float(sum(observation.workflow_demand.values())),
        "action_target_count": float(len(action.target_ids)),
        "action_reversible": float(action.reversible),
        "action_approved": float(action.approved),
        "approval_tier_code": float(list(ApprovalTier).index(action.approval_tier)),
    }
    result.update({f"action__{item}": float(action.action_type == item) for item in ACTION_TYPES})
    evidence_types = {item.evidence_type if item.evidence_type in EVIDENCE_TYPES else "UNSUPPORTED"
                      for item in observation.evidence if item.available_to_defender}
    result.update({f"evidence__{item}": float(item in evidence_types) for item in EVIDENCE_TYPES})
    result.update({f"belief__{mode.value}": belief.probabilities[mode] for mode in MODES})
    result["belief_entropy"] = belief.normalized_entropy
    return result


def _choose_action(environment: DynamicShieldEnvironment, rng: np.random.Generator, step: int) -> DefenderAction:
    available = environment.available_actions()
    draw = rng.random()
    if draw < 0.72:
        return DefenderAction(f"noop-{step}", "NO_OP")
    candidates = [item for item in available if item.action_type not in {"NO_OP", "ROLLBACK"}]
    if environment.state.recoverable_action_ids and draw > 0.96:
        original = environment.state.recoverable_action_ids[-1]
        return DefenderAction(f"rollback-{step}", "ROLLBACK", (original,))
    chosen = candidates[int(rng.integers(0, len(candidates)))]
    effectiveness = float(rng.choice([0.1, 0.5, 0.9], p=[0.30, 0.45, 0.25]))
    approved = chosen.approved or bool(rng.random() < 0.35)
    return replace(chosen, action_id=f"{chosen.action_id}-step-{step}",
                   parameters={"forced_effectiveness": effectiveness}, approved=approved)


def _targets(record: TransitionRecord) -> dict[str, float | int]:
    next_types = {item.evidence_type for item in record.next_observation}
    return {
        "target_contained": int(record.attack_outcome == "CONTAINED"),
        "target_residual_exposure": record.remaining_attack_path_exposure,
        "target_route_switched": int(bool(record.attacker_strategy_gt and record.attacker_strategy_gt.get("adapted"))),
        "target_workflow_disruption": record.legitimate_workflow_disruption,
        "target_next_malicious_observation": int("POST_ACTION_MALICIOUS_ACTIVITY" in next_types),
    }


def generate_episodes(episode_count: int, seed: int = GENERATION_SEED,
                      max_steps: int = 12) -> tuple[pd.DataFrame, pd.DataFrame]:
    rng = np.random.default_rng(seed)
    model_rows, records = [], []
    malicious_families = tuple(item for item in SUPPORTED_FAMILIES if item != "benign-alert")
    for episode_index in range(episode_count):
        family = ("benign-alert" if episode_index % 20 == 19 else
                  malicious_families[episode_index % len(malicious_families)])
        episode_seed = seed + episode_index * 104729
        episode_id = f"world-v2-{episode_index:05d}"
        environment = DynamicShieldEnvironment(max_steps=max_steps, stochastic=True,
                                               attacker_progress_scale=0.22, topology_variation=True)
        combined = BeliefTrackedDynamicEnvironment(environment)
        observation, belief = combined.reset(family, episode_seed, episode_id)
        for step in range(max_steps):
            action = _choose_action(environment, rng, step)
            inputs = build_features(observation, belief, action)
            result = combined.step(action)
            record = result.transition
            row = {
                "dataset_release": DATASET_RELEASE, "episode_id": episode_id,
                "time_step": record.time_step, "transition_id": record.transition_id,
                "topology_id": record.topology_id, "scenario_family_audit": family,
                "action_status_audit": record.action_result.status,
                "attack_outcome_audit": record.attack_outcome,
                **inputs, **_targets(record),
            }
            model_rows.append(row)
            payload = record.to_v2_dict()
            records.append({
                "dataset_release": DATASET_RELEASE, "episode_id": episode_id,
                "time_step": record.time_step, "transition_id": record.transition_id,
                "topology_id": record.topology_id, "scenario_family": family,
                "record_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
            })
            observation, belief = environment.observe(), result.posterior
            if record.terminal:
                break
    return pd.DataFrame(model_rows), pd.DataFrame(records)


def assign_grouped_splits(frame: pd.DataFrame, seed: int = GENERATION_SEED) -> pd.DataFrame:
    topologies = sorted(frame.topology_id.unique())
    rng = np.random.default_rng(seed)
    shuffled = list(np.asarray(topologies)[rng.permutation(len(topologies))])
    train_cut = max(1, int(len(shuffled) * 0.70))
    val_cut = max(train_cut + 1, int(len(shuffled) * 0.85))
    mapping = {item: ("train" if index < train_cut else "validation" if index < val_cut else "test")
               for index, item in enumerate(shuffled)}
    result = frame.copy()
    result["split"] = result.topology_id.map(mapping)
    return result


def quality_report(frame: pd.DataFrame) -> dict[str, object]:
    features = feature_columns(True)
    duplicate_count = int(frame.duplicated(features).sum())
    forbidden = [item for item in features if (
        "_gt" in item.lower() or "ground_truth" in item.lower() or item.lower().startswith("next_")
        or item.lower().startswith("target_") or "outcome" in item.lower()
        or "scenario_family" in item.lower() or "topology" in item.lower() or "episode" in item.lower()
    )]
    return {
        "rows": len(frame), "episodes": int(frame.episode_id.nunique()),
        "topologies": int(frame.topology_id.nunique()),
        "families": frame.scenario_family_audit.value_counts().sort_index().to_dict(),
        "actions": frame[[item for item in features if item.startswith("action__")]].sum().astype(int).to_dict(),
        "action_status": frame.action_status_audit.value_counts().to_dict(),
        "outcomes": frame.attack_outcome_audit.value_counts().to_dict(),
        "route_switches": int(frame.target_route_switched.sum()),
        "containments": int(frame.target_contained.sum()),
        "partial_containments": int((frame.attack_outcome_audit == "PARTIALLY_CONTAINED").sum()),
        "response_failures": int((frame.action_status_audit == "FAILED").sum()),
        "disruption_nonzero": int((frame.target_workflow_disruption > 0).sum()),
        "disruption_range": [float(frame.target_workflow_disruption.min()), float(frame.target_workflow_disruption.max())],
        "unique_feature_vectors": int(frame.drop_duplicates(features).shape[0]),
        "duplicate_feature_rows": duplicate_count,
        "duplicate_feature_fraction": duplicate_count / len(frame),
        "forbidden_model_features": forbidden,
    }


def split_integrity(frame: pd.DataFrame) -> dict[str, object]:
    episode_counts = frame.groupby("episode_id").split.nunique()
    topology_counts = frame.groupby("topology_id").split.nunique()
    return {
        "episode_overlap_count": int((episode_counts > 1).sum()),
        "topology_overlap_count": int((topology_counts > 1).sum()),
        "rows": frame.split.value_counts().to_dict(),
        "episodes": frame.groupby("split").episode_id.nunique().to_dict(),
        "topologies": frame.groupby("split").topology_id.nunique().to_dict(),
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_release(model_frame: pd.DataFrame, record_frame: pd.DataFrame, output: Path,
                  seed: int = GENERATION_SEED) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    model_frame = assign_grouped_splits(model_frame, seed)
    split_map = model_frame[["episode_id", "topology_id", "split"]].drop_duplicates()
    records = record_frame.merge(split_map, on=["episode_id", "topology_id"], validate="many_to_one")
    model_path, records_path = output / "model_table.parquet", output / "transitions.parquet"
    model_frame.to_parquet(model_path, index=False)
    records.to_parquet(records_path, index=False)
    split_map.to_csv(output / "split_manifest.csv", index=False)
    report = quality_report(model_frame)
    integrity = split_integrity(model_frame)
    manifest = {
        "dataset_release": DATASET_RELEASE, "generation_seed": seed,
        "rows": len(model_frame), "episodes": int(model_frame.episode_id.nunique()),
        "feature_columns": feature_columns(True), "target_columns": TARGET_COLUMNS,
        "quality": report, "split_integrity": integrity,
        "files": {"model_table.parquet": sha256(model_path), "transitions.parquet": sha256(records_path)},
        "frozen_before_training": True,
        "synthetic_not_operational_effectiveness": True,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
