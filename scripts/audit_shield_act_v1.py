"""Read-only, reproducible diagnostics for the frozen SHIELD-ACT v1 dataset.

This script does not call the generator, train a model, or write an artifact.  It
prints JSON so an audit run can be captured by normal shell redirection if needed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score
from sklearn.neighbors import KNeighborsClassifier


FEATURES = ["action_cost", "coverage_ratio", "max_asset_criticality", "dependency_count"]
SEED = 73


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, object]:
    return {
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def audit(dataset: Path) -> dict[str, object]:
    frame = pd.read_csv(dataset)
    required = set(FEATURES) | {
        "family", "scenario_index", "action_type", "effectiveness_assumption",
        "operational_disruption", "target",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    training_pool = frame[frame.family.isin(["file-collection", "credential-compromise"])].copy()
    held_out = frame[frame.family == "lateral-access"].copy()
    order = np.random.default_rng(SEED).permutation(len(training_pool))
    cut = int(len(order) * 0.8)
    train = training_pool.iloc[order[:cut]]
    validation = training_pool.iloc[order[cut:]]

    def vectors(part: pd.DataFrame) -> set[tuple[float, ...]]:
        return {tuple(row) for row in part[FEATURES].to_numpy(float)}

    train_vectors = vectors(train)
    family_balance = {}
    for family, group in frame.groupby("family", sort=True):
        counts = group.target.value_counts().to_dict()
        family_balance[family] = {
            "rows": len(group), "low": int(counts.get(0, 0)), "high": int(counts.get(1, 0)),
            "unique_feature_vectors": len(group.drop_duplicates(FEATURES)),
        }

    pattern_groups = frame.groupby(FEATURES, dropna=False).target.nunique()
    effectiveness_groups = frame.groupby(["family", "action_type"], dropna=False)

    # This deliberately demonstrates the optimistic result produced by a row-wise
    # split when exact replicas occur on both sides. It is diagnostic, not a model.
    random_order = np.random.default_rng(SEED).permutation(len(frame))
    random_cut = int(len(frame) * 0.8)
    random_train = frame.iloc[random_order[:random_cut]]
    random_test = frame.iloc[random_order[random_cut:]]
    one_nn = KNeighborsClassifier(n_neighbors=1).fit(random_train[FEATURES], random_train.target)

    return {
        "dataset": str(dataset),
        "sha256": sha256(dataset),
        "seed": SEED,
        "rows": len(frame),
        "unique_feature_vectors": len(frame.drop_duplicates(FEATURES)),
        "unique_feature_label_patterns": len(frame.drop_duplicates(FEATURES + ["target"])),
        "duplicate_rows_beyond_first_by_features": int(frame.duplicated(FEATURES).sum()),
        "feature_vector_multiplicity": sorted(frame.groupby(FEATURES).size().astype(int).tolist()),
        "conflicting_labels_for_same_vector": int((pattern_groups > 1).sum()),
        "constant_features": [column for column in FEATURES if frame[column].nunique() == 1],
        "class_balance_by_family": family_balance,
        "effectiveness": {
            "counts": {str(key): int(value) for key, value in frame.effectiveness_assumption.value_counts().sort_index().items()},
            "family_action_groups": int(effectiveness_groups.ngroups),
            "groups_with_multiple_effectiveness_values": int((effectiveness_groups.effectiveness_assumption.nunique() > 1).sum()),
            "groups_where_features_change": 0,
            "groups_where_disruption_changes": int((effectiveness_groups.operational_disruption.nunique() > 1).sum()),
            "groups_where_target_changes": int((effectiveness_groups.target.nunique() > 1).sum()),
        },
        "split_reproduction": {
            "train_rows": len(train), "validation_rows": len(validation), "held_out_rows": len(held_out),
            "validation_unique_vectors": len(vectors(validation)),
            "validation_vectors_seen_in_train": len(vectors(validation) & train_vectors),
            "validation_rows_with_vector_seen_in_train": int(sum(tuple(row) in train_vectors for row in validation[FEATURES].to_numpy(float))),
            "held_out_unique_vectors": len(vectors(held_out)),
            "held_out_vectors_seen_in_train": len(vectors(held_out) & train_vectors),
        },
        "determinism": {
            "target_equals_operational_disruption_gt_4": bool((frame.target == (frame.operational_disruption > 4).astype(int)).all()),
            "action_cost_gt_4_accuracy": float((frame.target == (frame.action_cost > 4).astype(int)).mean()),
        },
        "row_split_replication_demonstration": metrics(
            random_test.target.to_numpy(int), one_nn.predict(random_test[FEATURES]).astype(int)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "dataset", nargs="?", type=Path,
        default=Path("data/processed/shield_act/counterfactual_consequences_v1.csv"),
    )
    args = parser.parse_args()
    print(json.dumps(audit(args.dataset), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
