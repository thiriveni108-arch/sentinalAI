"""Generate leakage-resistant graph-aware consequence data from SHIELD rollouts."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import pandas as pd

from sentinel_ai.shield.beliefs import BayesianAttackerBeliefTracker, MODES
from sentinel_ai.shield.consequence_simulator import (ACTION_TYPES, POLICY_NAMES, POLICY_VERSION,
                                                       SIMULATOR_VERSION, MultiStepConsequenceEnvironment,
                                                       SimulatedAction, continuation_action)
from sentinel_ai.shield.dynamic_models import Evidence
from sentinel_ai.shield.topology import TOPOLOGY_CONTRACT_VERSION, grouped_split, topology_variant
from sentinel_ai.shield.world_dataset import sha256


DATASET_VERSION = "shield-graph-consequence-counterfactual-v1"
INCIDENTS = ("credential-compromise", "malicious-insider", "lateral-movement", "sensitive-data-exfiltration", "privilege-escalation", "benign")
CANDIDATES = tuple(action for action in ACTION_TYPES if action not in {"ROLLBACK"})


def _split(family: str) -> str:
    return next(name for name, families in grouped_split().items() if family in families)


def _visible_features(env: MultiStepConsequenceEnvironment, episode: str) -> dict[str, float]:
    observation = env.observe()
    tracker = BayesianAttackerBeliefTracker(); tracker.initialize(episode)
    evidence = Evidence(f"{episode}-initial", 0, "graph-visible-sensor",
                        "POST_ACTION_MALICIOUS_ACTIVITY" if observation.observed_malicious_activity else "POST_ACTION_NO_CONFIRMED_ACTIVITY",
                        observation.observed_malicious_activity, .75, available_to_defender=True)
    # The belief is derived from the defender-visible sensor only. It is not a route oracle.
    belief = tracker.update_evidence(episode, 1, (evidence,))
    scale, connectivity, workflow, criticality = env.topology_posture()
    return {"state_tick": observation.tick, "service_health": observation.service_health,
            "observed_compromise": observation.observed_compromise,
            "observed_malicious_activity": float(observation.observed_malicious_activity),
            "evidence_count": float(observation.evidence_count), "graph_known_node_scale": scale,
            "graph_known_connectivity": connectivity, "graph_workflow_availability": workflow,
            "graph_criticality_posture": criticality, "active_intervention_count": 0.0,
            **{f"belief__{mode.value}": belief.probabilities[mode] for mode in MODES}}


def rollout(family: str, variant: int, incident: str, seed: int, candidate: str, policy: str, horizon: int = 5):
    topology = topology_variant(family, variant)
    simulated_family = "credential-compromise" if incident == "benign" else incident
    env = MultiStepConsequenceEnvironment(simulated_family, seed, max_steps=horizon, topology=topology)
    if incident == "benign":
        from dataclasses import replace
        env.state = replace(env.state, attacker_capability_gt=False, accessible_routes_gt=(), latent_routes_gt=(), current_route_gt=None,
                            observed_compromise=.10, observed_malicious_activity=False)
    initial = _visible_features(env, f"graph-{family}-{variant}-{incident}-{seed}")
    records = []
    for step in range(horizon):
        action = SimulatedAction(candidate, approved=True) if step == 0 else continuation_action(policy, env.observe(), step - 1, tuple(env.action_history))
        records.append(env.step(action))
        if env.state.terminal: break
    containment = [index + 1 for index, record in enumerate(records) if record.genuinely_contained_gt]
    targets = {"target_cumulative_exposure": sum(item.exposure for item in records),
               "target_cumulative_disruption": sum(item.disruption for item in records),
               "target_recovery_burden": sum(item.recovery_cost for item in records),
               "target_delayed_adaptation": int(any(item.attacker_adapted_gt for item in records[1:])),
               "target_severe_outcome": int(any(item.severe_outcome_gt for item in records)),
               "target_time_to_containment": containment[0] if containment else horizon + 1,
               "target_unresolved": int(records[-1].unresolved)}
    return initial, records, targets


def generate(variants: int = 4, seeds_per_variant: int = 3, horizon: int = 5, seed_base: int = 96001):
    rows, transitions = [], []
    index = 0
    for split, families in grouped_split().items():
        for family in families:
            for variant in range(variants):
                for replicate in range(seeds_per_variant):
                    incident = INCIDENTS[index % len(INCIDENTS)]; seed = seed_base + index * 104729; index += 1
                    initial_id = f"graph-{family}-v{variant}-{incident}-{seed}"
                    for candidate in CANDIDATES:
                        for policy in POLICY_NAMES:
                            features, records, targets = rollout(family, variant, incident, seed, candidate, policy, horizon)
                            branch = f"{initial_id}-{candidate}-{policy}"
                            rows.append({"dataset_version": DATASET_VERSION, "simulator_version": SIMULATOR_VERSION,
                                         "topology_contract_version": TOPOLOGY_CONTRACT_VERSION, "policy_version": POLICY_VERSION,
                                         "branch_id": branch, "initial_condition_id": initial_id, "split": split,
                                         "topology_family": family, "topology_variant": variant, "incident_family": incident,
                                         "seed": seed, "candidate_action": candidate, "continuation_policy": policy,
                                         "horizon": horizon, "rollout_steps": len(records),
                                         **features,
                                         **{f"candidate__{action}": float(candidate == action) for action in CANDIDATES},
                                         **{f"policy__{name}": float(policy == name) for name in POLICY_NAMES}, **targets})
                            transitions.extend({"branch_id": branch, "step": step + 1, "transition_json": json.dumps(asdict(record), sort_keys=True)} for step, record in enumerate(records))
    return pd.DataFrame(rows), pd.DataFrame(transitions)


def manifest(frame: pd.DataFrame, data_path: Path, transition_path: Path, seed: int, variants: int) -> dict:
    targets = [name for name in frame if name.startswith("target_")]
    return {"dataset_version": DATASET_VERSION, "simulator_version": SIMULATOR_VERSION,
            "topology_contract_version": TOPOLOGY_CONTRACT_VERSION, "generation_seed": seed, "variants_per_family": variants,
            "rows": len(frame), "initial_conditions": frame.initial_condition_id.nunique(),
            "split_manifest": grouped_split(), "split_rows": frame.split.value_counts().to_dict(),
            "family_overlap_count": int((frame.groupby("topology_family").split.nunique() > 1).sum()),
            "initial_condition_overlap_count": int((frame.groupby("initial_condition_id").split.nunique() > 1).sum()),
            "counterfactual_branching": "candidate/policy branches share a seed and fresh environment; no branch crosses a split",
            "target_distribution": {target: {"mean": float(frame[target].mean()), "positive": int(frame[target].sum()) if frame[target].dropna().isin([0, 1]).all() else None} for target in targets},
            "files": {data_path.name: sha256(data_path), transition_path.name: sha256(transition_path)},
            "feature_observability": "only visible sensors, belief state, declared topology posture and active interventions; ground truth is target-only",
            "synthetic_not_operational": True}


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--variants", type=int, default=4); parser.add_argument("--seeds-per-variant", type=int, default=3)
    parser.add_argument("--horizon", type=int, default=5); parser.add_argument("--seed", type=int, default=96001)
    parser.add_argument("--output", type=Path, default=Path("data/processed/shield_graph_consequence_v1")); args = parser.parse_args()
    frame, transitions = generate(args.variants, args.seeds_per_variant, args.horizon, args.seed)
    args.output.mkdir(parents=True, exist_ok=True); data_path = args.output / "model_table.parquet"; transition_path = args.output / "rollout_transitions.parquet"
    frame.to_parquet(data_path, index=False); transitions.to_parquet(transition_path, index=False)
    report = manifest(frame, data_path, transition_path, args.seed, args.variants)
    (args.output / "manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
