"""Generate simulator-derived SHIELD-ACT data and train frozen VQC/classical models."""

from __future__ import annotations

import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pennylane as qml
from pennylane import numpy as pnp
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, classification_report, confusion_matrix, f1_score

from sentinel_ai.shield.act import (DATASET_VERSION, FEATURES, MODEL_VERSION, AdaptiveScenarioEngine,
                                    consequence_features, exact_consequence)

SEED=73

def generate(rows_per_family: int = 120) -> pd.DataFrame:
    rng=np.random.default_rng(SEED); engine=AdaptiveScenarioEngine(); rows=[]
    for family_id,family in engine.families.items():
        for index in range(rows_per_family):
            scenario=engine.build(family_id,f"train-{family_id}-{index}",{key:1 for key in family.evidence_requirements})
            action=scenario.actions[index%len(scenario.actions)]; effectiveness=float(rng.choice([0.6,0.8,1.0],p=[0.2,0.3,0.5]))
            outcome=exact_consequence(scenario,action,effectiveness); values=consequence_features(scenario,action)
            rows.append({"family":family_id,"scenario_index":index,"action_type":action.action_type,
                         **dict(zip(FEATURES,values)),"effectiveness_assumption":effectiveness,
                         "operational_disruption":outcome["operationalDisruption"],"target":outcome["target"]})
    return pd.DataFrame(rows)

def main() -> None:
    root=Path(__file__).resolve().parents[1]; data_dir=root/"data"/"processed"/"shield_act"; reports=root/"artifacts"/"reports"; models=root/"artifacts"/"models"
    data_dir.mkdir(parents=True,exist_ok=True); reports.mkdir(parents=True,exist_ok=True); models.mkdir(parents=True,exist_ok=True)
    frame=generate(); frame.to_csv(data_dir/"counterfactual_consequences_v1.csv",index=False)
    train=frame[frame.family.isin(["file-collection","credential-compromise"])].copy(); test=frame[frame.family=="lateral-access"].copy()
    order=np.random.default_rng(SEED).permutation(len(train)); cut=int(len(order)*0.8); train_idx,val_idx=order[:cut],order[cut:]
    x_train=train.iloc[train_idx][list(FEATURES)].to_numpy(float); y_train=train.iloc[train_idx].target.to_numpy(int)
    x_val=train.iloc[val_idx][list(FEATURES)].to_numpy(float); y_val=train.iloc[val_idx].target.to_numpy(int)
    x_test=test[list(FEATURES)].to_numpy(float); y_test=test.target.to_numpy(int)
    low=x_train.min(axis=0); high=x_train.max(axis=0); scale=lambda x: 2*(x-low)/np.where(high-low==0,1,high-low)-1
    dev=qml.device("default.qubit",wires=4,shots=None)
    @qml.qnode(dev,interface="autograd",diff_method="backprop")
    def circuit(x,w):
        qml.AngleEmbedding(x,wires=range(4),rotation="Y"); qml.StronglyEntanglingLayers(w,wires=range(4),ranges=[1,1]); return qml.expval(qml.PauliZ(0))
    weights=pnp.array(np.random.default_rng(SEED).normal(0,.15,size=(2,4,3)),requires_grad=True); optimizer=qml.AdamOptimizer(.04)
    xs=scale(x_train); targets=2*y_train-1; started=time.perf_counter()
    for _ in range(14):
        weights=optimizer.step(lambda w:pnp.mean((pnp.stack([circuit(x,w) for x in xs])-targets)**2),weights)
    training_seconds=time.perf_counter()-started
    val_scores=np.asarray([circuit(x,weights) for x in scale(x_val)],float); candidates=np.unique(val_scores)
    threshold=max(candidates,key=lambda t:(balanced_accuracy_score(y_val,val_scores>=t),-abs(float(t))))
    test_started=time.perf_counter(); test_scores=np.asarray([circuit(x,weights) for x in scale(x_test)],float); inference_seconds=time.perf_counter()-test_started
    vqc_pred=(test_scores>=threshold).astype(int)
    classical=LogisticRegression(random_state=SEED,max_iter=1000).fit(x_train,y_train); classical_pred=classical.predict(x_test)
    np.savez(models/"shield_act_consequence_v1.npz",weights=np.asarray(weights),threshold=float(threshold),feature_min=low,feature_max=high)
    with (models/"shield_act_classical_v1.pkl").open("wb") as handle: pickle.dump(classical,handle)
    metadata={"model_version":MODEL_VERSION,"dataset_version":DATASET_VERSION,"seed":SEED,"features":list(FEATURES),
              "task":"Binary modeled operational disruption category; raw circuit score is not probability.",
              "training_families":["file-collection","credential-compromise"],"held_out_family":"lateral-access",
              "validated_families":["file-collection","credential-compromise","lateral-access"],
              "rows":{"total":len(frame),"train":len(x_train),"validation":len(x_val),"held_out_test":len(x_test)},
              "circuit":{"backend":"PennyLane default.qubit exact","qubits":4,"layers":2,"trainable_parameters":24},
              "vqc":{"balanced_accuracy":balanced_accuracy_score(y_test,vqc_pred),"f1":f1_score(y_test,vqc_pred),
                     "confusion_matrix":confusion_matrix(y_test,vqc_pred).tolist(),"classification_report":classification_report(y_test,vqc_pred,output_dict=True,zero_division=0),
                     "training_seconds":training_seconds,"held_out_inference_seconds":inference_seconds,"threshold":float(threshold)},
              "classical":{"model":"LogisticRegression","balanced_accuracy":balanced_accuracy_score(y_test,classical_pred),"f1":f1_score(y_test,classical_pred),
                           "confusion_matrix":confusion_matrix(y_test,classical_pred).tolist(),"classification_report":classification_report(y_test,classical_pred,output_dict=True,zero_division=0)},
              "limitations":["Synthetic modeled consequences only; not real operational outcomes.","Held-out family evaluation is small and does not establish quantum advantage.","Exact simulation and policy constraints remain authoritative."]}
    (reports/"shield_act_consequence_v1.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
    (data_dir/"metadata.json").write_text(json.dumps({"dataset_version":DATASET_VERSION,"seed":SEED,"generator":"actual SHIELD-ACT scenario simulator","rows":len(frame)},indent=2),encoding="utf-8")
    print(json.dumps(metadata,indent=2))

if __name__=="__main__": main()
