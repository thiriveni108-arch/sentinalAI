"""Materialize the already-selected CERT QSVC as a frozen inference artifact.

This performs one fit with the persisted benchmark configuration.  It does not
rerun tuning, alter prepared data, or inspect test labels.
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import SVC

from sentinel_ai.cert.qsvc import fidelity_kernel, make_state_circuit, states

FEATURES = ["pca_1", "pca_2", "pca_3", "pca_4"]


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    result_config = json.loads((root / "experiments/cert_qsvc/results/config.json").read_text(encoding="utf-8"))
    train = pd.read_csv(root / "data/processed/cert_r4_2/quantum_benchmark/qsvc/train.csv")
    x = train.loc[:, FEATURES].to_numpy(dtype=float)
    y = train[result_config["label_column_discovered"]].to_numpy(dtype=int)
    scaler = MinMaxScaler(feature_range=(-np.pi, np.pi), clip=True).fit(x)
    train_states = states(make_state_circuit(), scaler.transform(x))
    model = SVC(C=float(result_config["quantum"]["selected"]["C"]), kernel="precomputed")
    model.fit(fidelity_kernel(train_states, train_states), y)
    classical = SVC(C=float(result_config["classical"]["selected"]["C"]),
                    gamma=result_config["classical"]["selected"]["gamma"], kernel="rbf")
    classical.fit(scaler.transform(x), y)
    artifact = {"schema": "cert-r4.2-user-day-pca4-v1", "features": FEATURES,
                "input_scaler": scaler, "train_states": train_states, "model": model,
                "threshold": float(result_config["quantum"]["selected"]["threshold"]),
                "classical_model": classical,
                "classical_threshold": float(result_config["classical"]["selected"]["threshold"])}
    target = root / "artifacts/models/cert_r4_2_qsvc.pkl"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        pickle.dump(artifact, handle, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"Wrote frozen QSVC inference artifact: {target}")


if __name__ == "__main__":
    main()
