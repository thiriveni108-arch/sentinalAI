# Benchmark results

The exact PennyLane statevector QSVC ran successfully. On the fixed balanced
100-row test partition it produced balanced accuracy 0.930,
F1 0.931, ROC-AUC 0.907, and average precision
0.904. The classical RBF-SVM produced balanced
accuracy 0.910, F1 0.909, ROC-AUC
0.916, and average precision 0.916.

QSVC used 4 qubits, circuit depth 8, and 20 gates.
The 250x250 training kernel was finite and symmetric, had maximum diagonal error
3.109e-15, and minimum eigenvalue
3.878e-16. See `metrics.json` and `config.json`
for full timings, selections, and limitations. These small balanced-sample results
do not demonstrate quantum advantage or realistic deployment alert burden.
