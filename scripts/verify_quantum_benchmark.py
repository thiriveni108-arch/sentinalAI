"""
Verification script for SentinelAI-Q Quantum Benchmark
======================================================
Verifies:
1. Label counts, IDs, feature columns, and finite PCA values.
2. Zero row/ID overlap across cohorts.
3. Strict chronological partition bounds.
4. Byte-for-byte SHA-256 identity between QSVC and VQC data.
5. Preservation of full classical preprocessed partitions.
"""

import os
import hashlib
import pandas as pd
import numpy as np


def file_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_quantum_benchmark():
    base_dir = r"d:\Projects\sentinalAI"
    processed_dir = os.path.join(base_dir, "data", "processed", "cert_r4_2")
    bench_dir = os.path.join(processed_dir, "quantum_benchmark")
    qsvc_dir = os.path.join(bench_dir, "qsvc")
    vqc_dir = os.path.join(bench_dir, "vqc")

    print("=================================================================")
    print("VERIFYING SENTINELAI-Q QUANTUM BENCHMARK")
    print("=================================================================")

    # 1. Verify preservation of original full preprocessed files
    print("\n[Test 1] Verifying preservation of original full partitions...")
    orig_files = {
        "train.csv": (227954, 660),
        "validation.csv": (55302, 233),
        "test.csv": (47196, 73)
    }
    for fname, (exp_rows, exp_pos) in orig_files.items():
        fpath = os.path.join(processed_dir, fname)
        assert os.path.exists(fpath), f"Original file missing: {fpath}"
        df_orig = pd.read_csv(fpath)
        assert len(df_orig) == exp_rows, f"Row count changed for {fname}: expected {exp_rows}, got {len(df_orig)}"
        assert int(df_orig['label'].sum()) == exp_pos, f"Positive count changed for {fname}: expected {exp_pos}, got {int(df_orig['label'].sum())}"
        print(f"  [PASS] {fname:15s} preserved: {len(df_orig):,} rows ({exp_pos} positives)")

    # 2. Verify quantum benchmark cohorts
    print("\n[Test 2] Verifying quantum benchmark cohort sizes and label counts...")
    q_train = pd.read_csv(os.path.join(bench_dir, "quantum_train.csv"))
    q_val = pd.read_csv(os.path.join(bench_dir, "quantum_val.csv"))
    q_test = pd.read_csv(os.path.join(bench_dir, "quantum_test.csv"))

    assert len(q_train) == 250, f"Expected 250 train rows, got {len(q_train)}"
    assert int(q_train['label'].sum()) == 125, f"Expected 125 train positives, got {int(q_train['label'].sum())}"
    assert int((q_train['label'] == 0).sum()) == 125, f"Expected 125 train negatives"
    print(f"  [PASS] quantum_train.csv: 250 rows (125 positive, 125 negative)")

    assert len(q_val) == 100, f"Expected 100 val rows, got {len(q_val)}"
    assert int(q_val['label'].sum()) == 50, f"Expected 50 val positives, got {int(q_val['label'].sum())}"
    assert int((q_val['label'] == 0).sum()) == 50, f"Expected 50 val negatives"
    print(f"  [PASS] quantum_val.csv:   100 rows (50 positive, 50 negative)")

    assert len(q_test) == 100, f"Expected 100 test rows, got {len(q_test)}"
    assert int(q_test['label'].sum()) == 50, f"Expected 50 test positives, got {int(q_test['label'].sum())}"
    assert int((q_test['label'] == 0).sum()) == 50, f"Expected 50 test negatives"
    print(f"  [PASS] quantum_test.csv:  100 rows (50 positive, 50 negative)")

    # 3. Check IDs and no row overlap
    print("\n[Test 3] Verifying unique IDs and zero overlap across cohorts...")
    train_ids = set(zip(q_train['user'], q_train['date']))
    val_ids = set(zip(q_val['user'], q_val['date']))
    test_ids = set(zip(q_test['user'], q_test['date']))

    assert len(train_ids) == len(q_train), "Duplicate IDs within training cohort"
    assert len(val_ids) == len(q_val), "Duplicate IDs within validation cohort"
    assert len(test_ids) == len(q_test), "Duplicate IDs within test cohort"

    assert len(train_ids.intersection(val_ids)) == 0, "Overlap between train and val IDs"
    assert len(train_ids.intersection(test_ids)) == 0, "Overlap between train and test IDs"
    assert len(val_ids.intersection(test_ids)) == 0, "Overlap between val and test IDs"
    print("  [PASS] Zero ID overlap across cohorts. All IDs strictly distinct.")

    # 4. Chronological partition integrity
    print("\n[Test 4] Verifying chronological partition boundaries...")
    assert q_train['date'].max() < q_val['date'].min(), f"Temporal leakage: train max {q_train['date'].max()} >= val min {q_val['date'].min()}"
    assert q_val['date'].max() < q_test['date'].min(), f"Temporal leakage: val max {q_val['date'].max()} >= test min {q_test['date'].min()}"
    print(f"  [PASS] Chronological integrity verified: {q_train['date'].min()} to {q_train['date'].max()} < {q_val['date'].min()} to {q_val['date'].max()} < {q_test['date'].min()} to {q_test['date'].max()}")

    # 5. Check PCA feature columns and finiteness
    print("\n[Test 5] Verifying 4 PCA features and numerical finiteness...")
    pca_cols = ['pca_1', 'pca_2', 'pca_3', 'pca_4']
    for name, df_c in [('quantum_train', q_train), ('quantum_val', q_val), ('quantum_test', q_test)]:
        for c in pca_cols:
            assert c in df_c.columns, f"Missing {c} in {name}"
            vals = df_c[c].values
            assert not np.isnan(vals).any(), f"NaN found in {c} in {name}"
            assert not np.isinf(vals).any(), f"Inf found in {c} in {name}"
    print("  [PASS] All PCA features present, numeric, and 100% finite.")

    # 6. Verify QSVC and VQC byte-for-byte identity
    print("\n[Test 6] Verifying byte-for-byte SHA-256 identity between QSVC and VQC files...")
    for clean_name in ["train.csv", "val.csv", "test.csv"]:
        shared_file = f"quantum_{clean_name}"
        h_shared = file_sha256(os.path.join(bench_dir, shared_file))
        h_qsvc = file_sha256(os.path.join(qsvc_dir, clean_name))
        h_vqc = file_sha256(os.path.join(vqc_dir, clean_name))

        assert h_shared == h_qsvc == h_vqc, f"Hash mismatch for {clean_name}: shared={h_shared}, qsvc={h_qsvc}, vqc={h_vqc}"
        print(f"  [PASS] {clean_name:10s} SHA-256 match: {h_shared}")

    # 7. Check manifest existence
    print("\n[Test 7] Verifying manifest existence...")
    assert os.path.exists(os.path.join(bench_dir, "quantum_benchmark_manifest.json"))
    assert os.path.exists(os.path.join(bench_dir, "quantum_benchmark_manifest.md"))
    print("  [PASS] JSON and Markdown manifests verified.")

    print("\n=================================================================")
    print("ALL QUANTUM BENCHMARK VERIFICATION CHECKS PASSED!")
    print("=================================================================")


if __name__ == "__main__":
    verify_quantum_benchmark()
