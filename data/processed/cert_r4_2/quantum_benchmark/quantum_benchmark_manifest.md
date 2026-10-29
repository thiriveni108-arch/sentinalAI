# SentinelAI-Q Quantum ML Benchmark Manifest

## Overview
This benchmark provides a shared, reproducible dataset for evaluating **PennyLane QSVC** (Quantum Support Vector Classifier) and **PennyLane VQC** (Variational Quantum Classifier) on insider threat detection using four numeric PCA features.

- **Random Seed:** `42`
- **Feature Set:** `pca_1, pca_2, pca_3, pca_4` (derived strictly from training data scaling and PCA)
- **Target Label:** `label` (0 = Benign, 1 = Malicious)

---

## Cohort Summary

| Cohort | Source Split | Total Samples | Malicious (1) | Benign (0) | Balance Ratio | Date Range | SHA-256 (first 16 hex) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`quantum_train.csv`** | `train.csv` | **250** | 125 | 125 | 1 : 1 | 2010-01-06 to 2010-11-30 | `506142fbfd76870c...` |
| **`quantum_val.csv`** | `validation.csv` | **100** | 50 | 50 | 1 : 1 | 2010-12-01 to 2011-02-28 | `60115f48e39df387...` |
| **`quantum_test.csv`** | `test.csv` | **100** | 50 | 50 | 1 : 1 | 2011-03-01 to 2011-05-11 | `722ec7b0947e31f6...` |

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
   - Quantum kernel calculation ($N 	imes N$) in PennyLane QSVC scales quadratically with dataset size.
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
