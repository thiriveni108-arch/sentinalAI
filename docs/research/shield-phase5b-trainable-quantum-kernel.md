# SHIELD Phase 5B: trainable projected quantum kernel

## Decision and experimental controls

Phase 5B investigated containment success only. The containment result did not justify paying the additional cost to expand to route switching. No operational SHIELD component, Phase 4 Random Forest, Phase 5 VQC, QAOA, Bayesian tracker, dataset, or split was changed.

The exact Phase 4 target (`target_contained`) and topology-grouped splits were retained. Containment prevalence is 6.98% in train (259/3,709), 8.18% in validation (57/697), and 6.89% in test (56/813). NO_OP has no positive containment examples in any split. The 320-row quantum training subset was selected deterministically from training data only, preserving prevalence (22 positives, 6.88%). Test outcomes were not used for selection, tuning, threshold choice, or ensemble weighting.

Rare action support is a major constraint. The selected subset has only 5 REVOKE_SESSION rows, 3 ROLLBACK rows, and 6 REQUIRE_FRESH_MFA rows. Complete split-by-action counts and positives are frozen in the report.

## Methods

All models use the same 44 Phase 4 observable inputs. A scaler and four-component PCA are fit only on the selected training subset. The controlled quantum set is:

1. A standard four-qubit fidelity kernel from a fixed depth-two re-uploading feature map.
2. An RBF projected quantum kernel over four local Z and four neighbouring ZZ expectation values.
3. A trainable projected kernel with 16 variational RY/RZ parameters. Three seeded maps are optimized for centered kernel-target alignment on 160 training-only rows using six bounded SPSA steps.

Kernel SVM C, projected-kernel gamma, decision thresholds, and RF/kernel ensemble weight are selected on validation data only. Threshold-independent probability metrics remain based on untouched probabilities. Matched RF, RBF-SVM, and MLP baselines train on exactly the same 320 rows. Full-data RF and the Phase 5 hybrid are reported separately and are not presented as subset-matched comparisons.

## Untouched test results

| Subset-trained method | F1 | Balanced accuracy | ROC-AUC | PR-AUC | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.4143 | **0.8698** | **0.9028** | 0.3033 | 0.0849 | 0.1132 |
| RBF-SVM | **0.4536** | 0.8308 | 0.8897 | 0.2775 | **0.0572** | 0.0345 |
| Neural network | 0.3523 | 0.7355 | 0.8249 | **0.3239** | 0.1901 | 0.3652 |
| Standard fidelity kernel | 0.3256 | 0.7306 | 0.8365 | 0.2060 | 0.0594 | 0.0298 |
| Projected quantum kernel | 0.2462 | 0.6383 | 0.7757 | 0.2049 | 0.0605 | 0.0227 |
| Trainable projected kernel | 0.2182 | 0.6006 | 0.7260 | 0.1988 | 0.0623 | **0.0132** |

The learned representation did not improve over the fixed fidelity map and underperformed every matched classical baseline on F1, balanced accuracy, ROC-AUC, and PR-AUC. Its low ECE partly reflects conservative probabilities under severe imbalance; it is not evidence of superior classification. Across trainable seeds, test F1 standard deviation was 0.0326, ROC-AUC 0.0402, PR-AUC 0.0068, and Brier 0.0011. Learned alignment remained weak (0.053–0.059).

The full-data frozen RF achieved F1 0.4645, ROC-AUC 0.9228, and PR-AUC 0.3435. The prior Phase 5 hybrid achieved F1 0.3213, ROC-AUC 0.8518, and PR-AUC 0.1924. These are context only because their training set is larger.

## Complementarity

At their evaluated operating rules, RF and trainable-kernel errors overlap on only 7 test rows; RF alone is wrong on 106 and the kernel alone on 49. A validation-selected blend assigns 30% weight to RF and 70% to the trainable kernel. It reaches ROC-AUC 0.9244, PR-AUC 0.3963, Brier 0.0505, and ECE 0.0455, but F1 is only 0.3797 versus 0.4645 for the frozen RF. One held-out result is insufficient to establish that the ranking improvement is reliable. Integration is therefore rejected.

## Cost, limitations, and recommendation

Fixed state construction took about 7.83 seconds across train, validation, and test. Test inference took 2.48 seconds for the standard fidelity and projected kernels; trainable members took 3.80–4.09 seconds each. Three-seed trainable optimization and fitting took about 63.68 seconds for only 320 training rows, versus 0.34 seconds for the matched RF, 0.015 seconds for RBF-SVM, and 0.057 seconds for the MLP. Kernel storage and evaluation scale quadratically with training size; the experiment was not expanded.

The data are synthetic, positives are scarce, action-conditioned positives are very sparse, SVC probability calibration is not operationally validated, and three seeds do not provide confidence intervals. There is no evidence of quantum advantage. Further development is not recommended unless a larger, better-balanced consequence dataset becomes available and the complementary ranking signal replicates across multiple independently generated topology holdouts. No route-switch experiment, promotion, QRL, or live automation is warranted from these results.

Reproduce with:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\train_quantum_kernel.py
.\.venv\Scripts\python.exe -m pytest tests\unit\test_quantum_kernel.py
```
