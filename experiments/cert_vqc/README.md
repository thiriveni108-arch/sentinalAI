# CERT r4.2 PennyLane VQC benchmark

This isolated experiment trains a genuine four-qubit PennyLane variational
classifier and a modest classical MLP on the same chronological cohorts used
by the existing QSVC experiment. It imports the existing QSVC and RBF-SVM
metrics and predictions without retraining or modifying them.

From the repository root:

```powershell
.\.venv\Scripts\python.exe experiments\cert_vqc\benchmark.py
```

The script uses the QSVC-compatible training-fitted `[-pi, pi]` feature
transformation. VQC early stopping monitors validation loss; model thresholds
and the small MLP choice use validation data only. The test partition is scored
only after these choices are fixed. Continuous scores are not calibrated
probabilities.

Artifacts are written to `experiments/cert_vqc/results/`. This benchmark does
not alter production code, datasets, or existing QSVC results.
