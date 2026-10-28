from __future__ import annotations

from pandas.testing import assert_frame_equal

from sentinel_ai.shield.world_dataset import (assign_grouped_splits, feature_columns, generate_episodes,
                                               quality_report, split_integrity)


def test_generation_is_reproducible_and_chronological() -> None:
    first, first_records = generate_episodes(8, seed=991)
    second, second_records = generate_episodes(8, seed=991)
    assert_frame_equal(first, second)
    assert_frame_equal(first_records, second_records)
    for _, episode in first.groupby("episode_id"):
        assert episode.time_step.tolist() == list(range(len(episode)))


def test_topology_and_episode_grouped_splits_are_isolated() -> None:
    frame, _ = generate_episodes(30, seed=992)
    split = assign_grouped_splits(frame, seed=992)
    integrity = split_integrity(split)
    assert integrity["episode_overlap_count"] == 0
    assert integrity["topology_overlap_count"] == 0
    assert set(split.split) == {"train", "validation", "test"}


def test_model_feature_allowlist_excludes_oracle_future_and_labels() -> None:
    frame, _ = generate_episodes(10, seed=993)
    report = quality_report(frame)
    assert report["forbidden_model_features"] == []
    assert not any("_gt" in item or item.startswith("target_") or item.startswith("next_") for item in feature_columns())


def test_pilot_contains_diverse_transition_mechanisms() -> None:
    frame, _ = generate_episodes(60)
    report = quality_report(frame)
    assert report["topologies"] >= 15
    assert len(report["families"]) == 6
    assert report["partial_containments"] > 0
    assert report["response_failures"] > 0
    assert report["route_switches"] > 0
    assert report["disruption_nonzero"] > 0
    assert report["duplicate_feature_fraction"] < 0.5
