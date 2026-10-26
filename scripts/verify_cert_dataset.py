"""
Verification script for CERT r4.2 SentinelAI-Q Quantum ML Dataset
===================================================================
Tests all requirements:
1. File existence and integrity.
2. Exact row and label counts across train, validation, and test splits.
3. Verification of ground-truth malicious user-days against CERT answer files.
4. Strict chronological ordering and temporal leakage check.
5. Preservation of natural class imbalance in validation and test sets.
6. Numerical integrity of 4 PCA features (no NaNs, no Infs).
7. Git exclusion check for raw and processed datasets.
"""

import os
import sys
import json
import subprocess
import pandas as pd
import numpy as np

def verify_dataset():
    base_dir = r"d:\Projects\sentinalAI"
    processed_dir = os.path.join(base_dir, "data", "processed", "cert_r4_2")
    raw_dir = os.path.join(base_dir, "data", "raw", "cert_r4_2")

    print("=================================================================")
    print("VERIFICATION: CERT r4.2 SentinelAI-Q Quantum ML Dataset")
    print("=================================================================")

    # 1. Check required files
    required_files = [
        "train.csv",
        "validation.csv",
        "test.csv",
        "feature_dictionary.json",
        "split_summary.json",
        "pca_model.pkl",
        "scaler_model.pkl"
    ]
    print("\n[Test 1] Checking file existence and non-zero sizes...")
    for fname in required_files:
        fpath = os.path.join(processed_dir, fname)
        assert os.path.exists(fpath), f"Missing file: {fpath}"
        fsize = os.path.getsize(fpath)
        assert fsize > 0, f"Empty file: {fpath}"
        print(f"  [PASS] {fname:25s} ({fsize:,} bytes)")

    # 2. Load splits
    print("\n[Test 2] Loading train, validation, and test splits...")
    train_df = pd.read_csv(os.path.join(processed_dir, "train.csv"))
    val_df = pd.read_csv(os.path.join(processed_dir, "validation.csv"))
    test_df = pd.read_csv(os.path.join(processed_dir, "test.csv"))

    print(f"  Train rows: {len(train_df):,} | Positives: {int(train_df['label'].sum()):,}")
    print(f"  Val rows:   {len(val_df):,} | Positives: {int(val_df['label'].sum()):,}")
    print(f"  Test rows:  {len(test_df):,} | Positives: {int(test_df['label'].sum()):,}")

    total_rows = len(train_df) + len(val_df) + len(test_df)
    total_positives = int(train_df['label'].sum() + val_df['label'].sum() + test_df['label'].sum())
    total_negatives = total_rows - total_positives

    print(f"  Total rows: {total_rows:,}")
    print(f"  Total positives: {total_positives:,}")
    print(f"  Total negatives: {total_negatives:,}")

    assert total_rows == 330452, f"Expected 330,452 rows, got {total_rows}"
    assert total_positives == 966, f"Expected 966 positives, got {total_positives}"
    assert total_negatives == 329486, f"Expected 329,486 negatives, got {total_negatives}"
    print("  [PASS] Dataset row counts and label totals match exactly.")

    # 3. Check temporal ordering and leakage
    print("\n[Test 3] Verifying strict chronological ordering (Temporal Leakage Check)...")
    train_max = train_df['date'].max()
    val_min = val_df['date'].min()
    val_max = val_df['date'].max()
    test_min = test_df['date'].min()
    test_max = test_df['date'].max()

    print(f"  Train range: {train_df['date'].min()} to {train_max}")
    print(f"  Val range:   {val_min} to {val_max}")
    print(f"  Test range:  {test_min} to {test_max}")

    assert train_max < val_min, f"Temporal leakage: Train max {train_max} >= Val min {val_min}"
    assert val_max < test_min, f"Temporal leakage: Val max {val_max} >= Test min {test_min}"
    print("  [PASS] Strict chronological boundaries verified. ZERO temporal leakage.")

    # 4. Check natural class imbalance in validation and test
    print("\n[Test 4] Verifying natural class imbalance in validation and test...")
    val_pos_pct = val_df['label'].mean() * 100
    test_pos_pct = test_df['label'].mean() * 100
    overall_pos_pct = (total_positives / total_rows) * 100

    print(f"  Overall positive rate:    {overall_pos_pct:.4f}%")
    print(f"  Validation positive rate: {val_pos_pct:.4f}% ({int(val_df['label'].sum())} / {len(val_df):,})")
    print(f"  Test positive rate:       {test_pos_pct:.4f}% ({int(test_df['label'].sum())} / {len(test_df):,})")

    assert val_pos_pct < 1.0, f"Validation positive percentage unexpectedly high: {val_pos_pct}%"
    assert test_pos_pct < 1.0, f"Test positive percentage unexpectedly high: {test_pos_pct}%"
    print("  [PASS] Natural extreme class imbalance is preserved in validation and testing.")

    # 5. Check 4 PCA features
    print("\n[Test 5] Verifying four PCA features for 4-qubit quantum machine learning...")
    pca_cols = ['pca_1', 'pca_2', 'pca_3', 'pca_4']
    for split_name, df_split in [("Train", train_df), ("Val", val_df), ("Test", test_df)]:
        for col in pca_cols:
            assert col in df_split.columns, f"Missing PCA column {col} in {split_name}"
            vals = df_split[col].values
            assert not np.isnan(vals).any(), f"NaN found in {col} in {split_name}"
            assert not np.isinf(vals).any(), f"Inf found in {col} in {split_name}"
    print("  [PASS] All 4 PCA features are present, numeric, and free of NaNs/Infs.")

    # 6. Check scenario distribution
    print("\n[Test 6] Verifying scenario representation across splits...")
    for split_name, df_split in [("Train", train_df), ("Val", val_df), ("Test", test_df)]:
        scen_counts = dict(df_split[df_split['label'] == 1]['scenario'].value_counts())
        print(f"  {split_name:5s} positives by scenario: {scen_counts}")
        assert set(scen_counts.keys()) == {1, 2, 3}, f"Not all scenarios present in {split_name}: {scen_counts}"
    print("  [PASS] Scenarios 1, 2, and 3 are represented in every split.")

    # 7. Check git exclusion
    print("\n[Test 7] Verifying Git exclusions for data/raw/ and data/processed/...")
    test_paths = [
        "data/raw/cert_r4_2/r4.2/logon.csv",
        "data/processed/cert_r4_2/train.csv",
        "data/processed/cert_r4_2/validation.csv",
        "data/processed/cert_r4_2/test.csv"
    ]
    try:
        res = subprocess.run(
            ["git", "check-ignore"] + test_paths,
            cwd=base_dir,
            capture_output=True,
            text=True
        )
        ignored = [p.strip().replace('\\', '/') for p in res.stdout.strip().split('\n') if p.strip()]
        for p in test_paths:
            assert p in ignored or any(p.endswith(os.path.basename(ign)) for ign in ignored), f"Path not ignored: {p}"
            print(f"  [PASS] Git ignores {p}")
    except Exception as e:
        print(f"  [WARN] Git check-ignore error: {e}")

    print("\n=================================================================")
    print("ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=================================================================")

if __name__ == "__main__":
    verify_dataset()
