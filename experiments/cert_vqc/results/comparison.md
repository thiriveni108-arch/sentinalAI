# Four-model comparison

All models use the identical chronological 250/100/100 cohorts. QSVC and
RBF-SVM values and predictions are copied unchanged from `cert_qsvc/results`.

| Model | Precision | Recall | F1 | Balanced accuracy | ROC-AUC | Average precision | Train s | Infer s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| qsvc | 0.922 | 0.940 | 0.931 | 0.930 | 0.907 | 0.904 | 0.491 | 0.228 |
| vqc | 0.918 | 0.900 | 0.909 | 0.910 | 0.908 | 0.922 | 5.422 | 0.005 |
| rbf_svm | 0.918 | 0.900 | 0.909 | 0.910 | 0.916 | 0.916 | 0.001 | 0.001 |
| mlp | 0.922 | 0.940 | 0.931 | 0.930 | 0.928 | 0.878 | 0.046 | 0.000 |

Model comparisons should consider thresholded and ranking metrics together;
no winner is declared from accuracy or F1 alone. The balanced 100-row test set
cannot estimate natural-prevalence alert burden or demonstrate quantum
advantage. Temporal partitions may also contain recurring identities.
