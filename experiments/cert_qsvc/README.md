# CERT r4.2 PennyLane QSVC benchmark

This isolated experiment compares a four-qubit PennyLane fidelity-kernel SVC
with a classical RBF-SVM on the existing chronological 250/100/100 QSVC
partitions. It does not modify or integrate with SHIELD or any production path.

## Reproduce

From the project root on Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe experiments\cert_qsvc\benchmark.py
```

The script discovers the binary label column, explicitly selects only
`pca_1` through `pca_4`, and fits a bounded angle transformation on training
data only. It encodes every row once on PennyLane `default.qubit` and computes
the exact noiseless fidelity kernel from cached 16-amplitude statevectors.
Hyperparameters and decision thresholds are selected only on validation data.
Decision scores are uncalibrated margins, not probabilities.

Generated artifacts are under `results/`: metrics and runtime JSON,
configuration JSON, row-level test predictions, and confusion-matrix images.

## Scientific scope

The shared benchmark is artificially balanced. Its results cannot establish
deployment precision or false-alert burden at CERT's natural malicious
prevalence of approximately 0.29%. Temporal partitions may contain recurring
employee identities. The 100-row test cohort is too small to support a claim
of quantum advantage, and exact statevector simulation is not hardware
execution. No optional natural-prevalence evaluation is included because no
separately identified untouched chronological subset was supplied in the
bounded QSVC directory; manufacturing one would violate the partition rules.
