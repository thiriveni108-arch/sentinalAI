"""
Create Shared Quantum Benchmark for SentinelAI-Q
=================================================
Generates reproducible, bounded training, validation, and test cohorts for
PennyLane QSVC and PennyLane VQC insider-threat detection experiments.

Uses existing preprocessed files:
- data/processed/cert_r4_2/train.csv
- data/processed/cert_r4_2/validation.csv
- data/processed/cert_r4_2/test.csv

Constraints:
1. Training subset bounded to 200-300 rows (250 rows: 125 malicious, 125 benign).
2. Sampling drawn strictly from training data only.
3. Validation and test cohorts bounded for quantum simulation, strictly from
   their respective chronological partitions.
4. Exactly identical cohorts saved for QSVC and VQC.
5. No row overlap between train, validation, and test.
6. Original full validation and test partitions remain untouched for classical baselines.
7. SHA-256 verification and detailed manifest generated.
"""

import os
import json
import hashlib
import pandas as pd
import numpy as np


def file_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def create_quantum_benchmark(random_seed: int = 42):
    base_dir = r"d:\Projects\sentinalAI"
    processed_dir = os.path.join(base_dir, "data", "processed", "cert_r4_2")
    bench_dir = os.path.join(processed_dir, "quantum_benchmark")
    qsvc_dir = os.path.join(bench_dir, "qsvc")
    vqc_dir = os.path.join(bench_dir, "vqc")

    os.makedirs(bench_dir, exist_ok=True)
    os.makedirs(qsvc_dir, exist_ok=True)
    os.makedirs(vqc_dir, exist_ok=True)

    print("=================================================================")
    print("CREATING SHARED QUANTUM BENCHMARK (QSVC & VQC)")
    print("=================================================================")

    # 1. Load existing splits
    print("[-] Loading existing preprocessed splits...")
    train_path = os.path.join(processed_dir, "train.csv")
    val_path = os.path.join(processed_dir, "validation.csv")
    test_path = os.path.join(processed_dir, "test.csv")

    assert os.path.exists(train_path), f"Missing {train_path}"
    assert os.path.exists(val_path), f"Missing {val_path}"
    assert os.path.exists(test_path), f"Missing {test_path}"

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    print(f"    Loaded train: {len(train_df):,} rows ({train_df['label'].sum()} positives)")
    print(f"    Loaded val:   {len(val_df):,} rows ({val_df['label'].sum()} positives)")
    print(f"    Loaded test:  {len(test_df):,} rows ({test_df['label'].sum()} positives)")

    rng = np.random.RandomState(random_seed)

    # 2. Sample Training Subset (Target: 250 rows = 125 pos + 125 neg)
    print("\n[-] Sampling Training Cohort (250 rows: 125 malicious, 125 benign)...")
    train_pos = train_df[train_df['label'] == 1].copy()
    train_neg = train_df[train_df['label'] == 0].copy()

    # Stratified positive sample across scenarios in train:
    # Train positives: scen 1: 64, scen 2: 580, scen 3: 16 (Total 660)
    # Target 125 positives: Scen 1: 15, Scen 2: 100, Scen 3: 10 = 125
    pos_samples = []
    scen_targets = {1: 15, 2: 100, 3: 10}
    for scen, count in scen_targets.items():
        subset = train_pos[train_pos['scenario'] == scen]
        sampled = subset.sample(n=count, random_state=random_seed)
        pos_samples.append(sampled)
    sampled_train_pos = pd.concat(pos_samples, axis=0)

    sampled_train_neg = train_neg.sample(n=125, random_state=random_seed)

    q_train = pd.concat([sampled_train_pos, sampled_train_neg], axis=0)
    # Shuffle training cohort deterministically
    q_train = q_train.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    print(f"    q_train: {len(q_train)} rows | Positives: {int(q_train['label'].sum())} | Negatives: {int((q_train['label'] == 0).sum())}")
    print(f"    q_train scenarios: {dict(q_train[q_train['label'] == 1]['scenario'].value_counts())}")

    # 3. Sample Validation Cohort (Target: 100 rows = 50 malicious, 50 benign)
    print("\n[-] Sampling Validation Cohort (100 rows: 50 malicious, 50 benign)...")
    val_pos = val_df[val_df['label'] == 1].copy()
    val_neg = val_df[val_df['label'] == 0].copy()

    # Val positives: scen 1: 19, scen 2: 212, scen 3: 2 (Total 233)
    # Target 50 positives: Scen 1: 8, Scen 2: 40, Scen 3: 2 = 50
    val_pos_samples = []
    val_scen_targets = {1: 8, 2: 40, 3: 2}
    for scen, count in val_scen_targets.items():
        subset = val_pos[val_pos['scenario'] == scen]
        sampled = subset.sample(n=count, random_state=random_seed)
        val_pos_samples.append(sampled)
    sampled_val_pos = pd.concat(val_pos_samples, axis=0)

    sampled_val_neg = val_neg.sample(n=50, random_state=random_seed)

    q_val = pd.concat([sampled_val_pos, sampled_val_neg], axis=0)
    q_val = q_val.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    print(f"    q_val: {len(q_val)} rows | Positives: {int(q_val['label'].sum())} | Negatives: {int((q_val['label'] == 0).sum())}")
    print(f"    q_val scenarios: {dict(q_val[q_val['label'] == 1]['scenario'].value_counts())}")

    # 4. Sample Test Cohort (Target: 100 rows = 50 malicious, 50 benign)
    print("\n[-] Sampling Test Cohort (100 rows: 50 malicious, 50 benign)...")
    test_pos = test_df[test_df['label'] == 1].copy()
    test_neg = test_df[test_df['label'] == 0].copy()

    # Test positives: scen 1: 2, scen 2: 69, scen 3: 2 (Total 73)
    # Target 50 positives: Scen 1: 2, Scen 2: 46, Scen 3: 2 = 50
    test_pos_samples = []
    test_scen_targets = {1: 2, 2: 46, 3: 2}
    for scen, count in test_scen_targets.items():
        subset = test_pos[test_pos['scenario'] == scen]
        sampled = subset.sample(n=count, random_state=random_seed)
        test_pos_samples.append(sampled)
    sampled_test_pos = pd.concat(test_pos_samples, axis=0)

    sampled_test_neg = test_neg.sample(n=50, random_state=random_seed)

    q_test = pd.concat([sampled_test_pos, sampled_test_neg], axis=0)
    q_test = q_test.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    print(f"    q_test: {len(q_test)} rows | Positives: {int(q_test['label'].sum())} | Negatives: {int((q_test['label'] == 0).sum())}")
    print(f"    q_test scenarios: {dict(q_test[q_test['label'] == 1]['scenario'].value_counts())}")

    # 5. Verification checks before saving
    print("\n[-] Running integrity and leakage verifications...")

    # Unique user-day keys
    train_keys = set(zip(q_train['user'], q_train['date']))
    val_keys = set(zip(q_val['user'], q_val['date']))
    test_keys = set(zip(q_test['user'], q_test['date']))

    assert len(train_keys) == len(q_train), "Duplicate rows found in q_train"
    assert len(val_keys) == len(q_val), "Duplicate rows found in q_val"
    assert len(test_keys) == len(q_test), "Duplicate rows found in q_test"

    # Cross-cohort overlap
    assert len(train_keys.intersection(val_keys)) == 0, "Overlap between train and val cohorts!"
    assert len(train_keys.intersection(test_keys)) == 0, "Overlap between train and test cohorts!"
    assert len(val_keys.intersection(test_keys)) == 0, "Overlap between val and test cohorts!"
    print("    [V] No row overlap between train, val, and test cohorts.")

    # Chronological partition integrity
    assert q_train['date'].max() < q_val['date'].min(), f"Temporal leakage: train max {q_train['date'].max()} >= val min {q_val['date'].min()}"
    assert q_val['date'].max() < q_test['date'].min(), f"Temporal leakage: val max {q_val['date'].max()} >= test min {q_test['date'].min()}"
    print(f"    [V] Temporal boundaries strictly preserved: Train ({q_train['date'].min()} to {q_train['date'].max()}) < Val ({q_val['date'].min()} to {q_val['date'].max()}) < Test ({q_test['date'].min()} to {q_test['date'].max()}).")

    # PCA feature check
    pca_cols = ['pca_1', 'pca_2', 'pca_3', 'pca_4']
    for name, df_c in [('q_train', q_train), ('q_val', q_val), ('q_test', q_test)]:
        for c in pca_cols:
            assert c in df_c.columns, f"Missing {c} in {name}"
            vals = df_c[c].values
            assert not np.isnan(vals).any(), f"NaN in {c} in {name}"
            assert not np.isinf(vals).any(), f"Inf in {c} in {name}"
    print("    [V] All 4 PCA feature columns present with 100% finite values.")

    # 6. Save identical files in shared quantum_benchmark, qsvc, and vqc dirs
    files_to_save = {
        "quantum_train.csv": q_train,
        "quantum_val.csv": q_val,
        "quantum_test.csv": q_test
    }

    # Save shared
    shared_paths = {}
    for fname, df_c in files_to_save.items():
        fpath = os.path.join(bench_dir, fname)
        df_c.to_csv(fpath, index=False)
        shared_paths[fname] = fpath

    # Save qsvc copies
    qsvc_paths = {}
    for fname, df_c in files_to_save.items():
        clean_name = fname.replace("quantum_", "") # train.csv, val.csv, test.csv
        fpath = os.path.join(qsvc_dir, clean_name)
        df_c.to_csv(fpath, index=False)
        qsvc_paths[clean_name] = fpath

    # Save vqc copies
    vqc_paths = {}
    for fname, df_c in files_to_save.items():
        clean_name = fname.replace("quantum_", "")
        fpath = os.path.join(vqc_dir, clean_name)
        df_c.to_csv(fpath, index=False)
        vqc_paths[clean_name] = fpath

    print("\n[-] Verifying SHA-256 byte-for-byte identity between QSVC and VQC cohorts...")
    for clean_name in ["train.csv", "val.csv", "test.csv"]:
        hash_qsvc = file_sha256(qsvc_paths[clean_name])
        hash_vqc = file_sha256(vqc_paths[clean_name])
        assert hash_qsvc == hash_vqc, f"Hash mismatch for {clean_name}: QSVC={hash_qsvc} vs VQC={hash_vqc}"
        print(f"    [V] {clean_name}: SHA-256 match = {hash_qsvc[:16]}...")

    # 7. Create Manifest
    manifest = {
        "benchmark_name": "CERT r4.2 SentinelAI-Q Shared Quantum ML Benchmark",
        "purpose": "Identical, reproducible evaluation for PennyLane QSVC and PennyLane VQC insider threat detection",
        "random_seed": random_seed,
        "source_preprocessed_files": {
            "train": os.path.relpath(train_path, base_dir),
            "validation": os.path.relpath(val_path, base_dir),
            "test": os.path.relpath(test_path, base_dir)
        },
        "target_quantum_features": pca_cols,
        "classical_baseline_preservation_note": (
            "The full original preprocessed partitions (train.csv: 227,954 rows; validation.csv: 55,302 rows; "
            "test.csv: 47,196 rows) remain untouched at data/processed/cert_r4_2/ for classical baseline evaluation "
            "(XGBoost, Random Forest, Isolation Forest). The quantum benchmark cohorts represent bounded, "
            "balanced subsets designed for computationally viable statevector simulation."
        ),
        "class_balancing_documentation": {
            "is_balanced_or_enriched": True,
            "train_ratio": "1:1 (125 Malicious, 125 Benign)",
            "val_ratio": "1:1 (50 Malicious, 50 Benign)",
            "test_ratio": "1:1 (50 Malicious, 50 Benign)",
            "rationale": (
                "Quantum statevector simulation of kernel matrices in QSVC scales O(N^2) in samples, "
                "and VQC parameter optimization scales linearly in batch evaluations. Simulating 330k samples "
                "is computationally intractable on quantum simulators. Class-balanced cohorts ensure meaningful "
                "decision boundary learning and standard quantum metric comparisons (Balanced Accuracy, AUC-ROC, "
                "F1-score) without minority class vanishing."
            ),
            "distinction_from_natural_prevalence": (
                "In natural-prevalence evaluation, positive incidence is 0.2923% (~1 positive per 341 benign days). "
                "Metrics measured on these quantum cohorts reflect discriminative capability under balanced/enriched "
                "settings. Deployment metrics under natural prevalence can be projected using Bayes theorem or "
                "evaluated via classical baselines on the full preserved validation/test partitions."
            )
        },
        "cohort_statistics": {
            "training_cohort": {
                "total_samples": len(q_train),
                "positive_samples": int(q_train['label'].sum()),
                "negative_samples": int((q_train['label'] == 0).sum()),
                "positive_rate": float(q_train['label'].mean()),
                "scenario_breakdown": {str(k): int(v) for k, v in q_train[q_train['label'] == 1]['scenario'].value_counts().items()},
                "date_range": [str(q_train['date'].min()), str(q_train['date'].max())],
                "sha256": file_sha256(shared_paths["quantum_train.csv"])
            },
            "validation_cohort": {
                "total_samples": len(q_val),
                "positive_samples": int(q_val['label'].sum()),
                "negative_samples": int((q_val['label'] == 0).sum()),
                "positive_rate": float(q_val['label'].mean()),
                "scenario_breakdown": {str(k): int(v) for k, v in q_val[q_val['label'] == 1]['scenario'].value_counts().items()},
                "date_range": [str(q_val['date'].min()), str(q_val['date'].max())],
                "sha256": file_sha256(shared_paths["quantum_val.csv"])
            },
            "test_cohort": {
                "total_samples": len(q_test),
                "positive_samples": int(q_test['label'].sum()),
                "negative_samples": int((q_test['label'] == 0).sum()),
                "positive_rate": float(q_test['label'].mean()),
                "scenario_breakdown": {str(k): int(v) for k, v in q_test[q_test['label'] == 1]['scenario'].value_counts().items()},
                "date_range": [str(q_test['date'].min()), str(q_test['date'].max())],
                "sha256": file_sha256(shared_paths["quantum_test.csv"])
            }
        },
        "file_paths": {
            "shared": {k: os.path.relpath(v, base_dir) for k, v in shared_paths.items()},
            "qsvc": {k: os.path.relpath(v, base_dir) for k, v in qsvc_paths.items()},
            "vqc": {k: os.path.relpath(v, base_dir) for k, v in vqc_paths.items()}
        }
    }

    manifest_json_path = os.path.join(bench_dir, "quantum_benchmark_manifest.json")
    with open(manifest_json_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[-] Saved manifest: {manifest_json_path}")

    # Generate markdown manifest as well
    manifest_md_path = os.path.join(bench_dir, "quantum_benchmark_manifest.md")
    with open(manifest_md_path, 'w') as f:
        f.write(f"""# SentinelAI-Q Quantum ML Benchmark Manifest

## Overview
This benchmark provides a shared, reproducible dataset for evaluating **PennyLane QSVC** (Quantum Support Vector Classifier) and **PennyLane VQC** (Variational Quantum Classifier) on insider threat detection using four numeric PCA features.

- **Random Seed:** `{random_seed}`
- **Feature Set:** `pca_1, pca_2, pca_3, pca_4` (derived strictly from training data scaling and PCA)
- **Target Label:** `label` (0 = Benign, 1 = Malicious)

---

## Cohort Summary

| Cohort | Source Split | Total Samples | Malicious (1) | Benign (0) | Balance Ratio | Date Range | SHA-256 (first 16 hex) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`quantum_train.csv`** | `train.csv` | **250** | 125 | 125 | 1 : 1 | {q_train['date'].min()} to {q_train['date'].max()} | `{file_sha256(shared_paths['quantum_train.csv'])[:16]}...` |
| **`quantum_val.csv`** | `validation.csv` | **100** | 50 | 50 | 1 : 1 | {q_val['date'].min()} to {q_val['date'].max()} | `{file_sha256(shared_paths['quantum_val.csv'])[:16]}...` |
| **`quantum_test.csv`** | `test.csv` | **100** | 50 | 50 | 1 : 1 | {q_test['date'].min()} to {q_test['date'].max()} | `{file_sha256(shared_paths['quantum_test.csv'])[:16]}...` |

---

## Scenario Distribution Across Cohorts

| Cohort | Scenario 1 (Wikileaks) | Scenario 2 (USB Exfiltration) | Scenario 3 (Keylogger / Admin) | Total Positives |
| :--- | :---: | :---: | :---: | :---: |
| **Train** | 15 | 100 | 10 | **125** |
| **Validation** | 8 | 40 | 2 | **50** |
| **Test** | 2 | 46 | 2 | **50** |
| **TOTAL** | **25** | **186** | **14** | **225** |

---

## Class Balancing Documentation & Natural-Prevalence Distinction

1. **Why Balancing was Performed:**
   - Quantum kernel calculation ($N \times N$) in PennyLane QSVC scales quadratically with dataset size.
   - VQC variational parameter updates scale linearly with sample evaluations per epoch.
   - A training size of 250 rows allows rapid, deterministic convergence on quantum simulators while maintaining sufficient statistical power.
2. **Distinction from Natural Prevalence:**
   - In natural operational deployment (represented by the full CERT r4.2 splits), benign days vastly outnumber malicious days (0.2923% positive prevalence).
   - In this benchmark, cohorts are balanced 1:1 to measure **discriminative capability and decision boundary fidelity** without minority-class vanishing.
   - The full preprocessed partitions (`train.csv`, `validation.csv`, `test.csv`) remain completely untouched at `data/processed/cert_r4_2/` for classical baseline evaluations (e.g., XGBoost, Isolation Forest) under natural prevalence.

---

## Exact File Locations

### Shared Directory: `data/processed/cert_r4_2/quantum_benchmark/`
- `quantum_train.csv` (250 rows)
- `quantum_val.csv` (100 rows)
- `quantum_test.csv` (100 rows)
- `quantum_benchmark_manifest.json`
- `quantum_benchmark_manifest.md`

### QSVC Directory: `data/processed/cert_r4_2/quantum_benchmark/qsvc/`
- `train.csv`, `val.csv`, `test.csv`

### VQC Directory: `data/processed/cert_r4_2/quantum_benchmark/vqc/`
- `train.csv`, `val.csv`, `test.csv` *(Bit-for-bit identical to QSVC, verified via SHA-256)*
""")
    print(f"[-] Saved markdown manifest: {manifest_md_path}")
    print("\n[+] Benchmark creation completed successfully!")
    return manifest


if __name__ == "__main__":
    create_quantum_benchmark()
