# SHIELD-ACT v1 dataset and consequence-model audit

**Audit date:** 2026-10-27  
**Scope:** frozen dataset, generator, scenario construction, consequence rule, preprocessing, PennyLane VQC, classical comparator, and reported evaluation. No dataset/model artifact was changed and no model was retrained.

## Executive finding

The v1 artifact is internally reproducible, but it is not evidence that the VQC learns generalizable intervention consequences. The 360 rows collapse to **12 genuinely distinct input vectors**, each repeated exactly 30 times. The binary target is defined directly as `operational_disruption > 4.0`, where disruption is a deterministic sum of configured action cost, a target-local dependency penalty, and a fixed irreversibility penalty. It is not an observed post-intervention outcome.

Effectiveness (`0.6`, `0.8`, or `1.0`) can alter simulated path interruption, but it is excluded from the four VQC inputs and cannot alter either disruption or its target. Consequently, v1 is best described as a small deterministic template-classification benchmark. It must not be interpreted as learned operational effectiveness or causal consequence prediction.

## Audited assets and reproducibility

| Asset | Role | SHA-256 |
|---|---|---|
| `data/processed/shield_act/counterfactual_consequences_v1.csv` | 360-row dataset | `b2f55f8b2c6a66a782994c7e5425a6fc1329856d7c872204c6c9f9249b315556` |
| `artifacts/models/shield_act_consequence_v1.npz` | frozen VQC weights, threshold, feature bounds | `2de017ca6ccf1c9db205da48222746fd2efa676664211c83302f4c931d67ce0f` |
| `artifacts/models/shield_act_classical_v1.pkl` | frozen logistic-regression comparator | `791e69f72b0ad145f6d796d2da8a147246f795357bcbbeb19e7cda51348145dd` |

The audit can be repeated without generation or training:

```powershell
.\.venv\Scripts\python.exe scripts\audit_shield_act_v1.py
```

The script reads the CSV and prints JSON; it does not write artifacts. The split reproduction uses seed 73, matching the training script.

## Implementation traced

1. `scripts/train_shield_act_consequence.py::generate` creates 120 rows for each of three families. Within a family it cycles deterministically over four action templates (`index % 4`), so each family/action template occurs 30 times. Randomness affects only the recorded effectiveness assumption.
2. `AdaptiveScenarioEngine.build` changes node IDs using `scenario_index`, but graph structure, costs, coverage, sensitivities, and dependency counts remain fixed per family/action template.
3. `consequence_features` emits only action cost, path coverage ratio, maximum asset criticality, and count of unobserved edges.
4. `exact_consequence` optionally removes one interrupted path below effectiveness 0.75, then separately computes disruption as `action.cost + 0.75 * target_adjacent_unobserved_edges + (0 if reversible else 3)` and assigns target 1 iff disruption exceeds 4.0.
5. The first two families form a 240-row pool. A seeded row permutation creates 192 training and 48 validation rows. The entire 120-row lateral-access family is the test set.
6. Min/max scaling is fit on training rows. The four scaled values enter a four-qubit `AngleEmbedding`, followed by two `StronglyEntanglingLayers` (24 parameters) and a Pauli-Z expectation. Fourteen full-batch Adam steps minimize squared error against `{-1,+1}`. A validation-selected raw-score threshold creates the class prediction.
7. The published held-family result is balanced accuracy 0.75 and F1 0.80 for the VQC; logistic regression also has balanced accuracy 0.75 but F1 0.667. Neither comparison establishes quantum advantage.

## Diagnostic results

### Diversity and duplication

| Measure | Finding |
|---|---:|
| Rows | 360 |
| Unique four-feature vectors | **12** |
| Unique feature-plus-label patterns | **12** |
| Duplicate rows beyond first, by model inputs | **348 (96.7%)** |
| Multiplicity of every distinct vector | **30** |
| Vectors with conflicting labels | **0** |
| Globally constant feature | `max_asset_criticality = 5.0` |

“Near duplicate” requires a declared metric. Here an arbitrary distance threshold is unnecessary: 348 rows are already exact duplicates in model space. Non-model identifiers and sampled effectiveness make CSV rows look different while adding no feature diversity. The twelve vectors are exactly the twelve family/action templates.

### Class balance

Each family contains 120 rows, split 60 low and 60 high. The global balance is therefore 180/180. This balance is imposed by the chosen four templates and deterministic threshold, rather than emerging from incident dynamics. It does not imply coverage of realistic prevalence or consequence severity.

### Target construction and leakage

For all 360 rows:

```text
target == 1[operational_disruption > 4.0]
```

This relation has 100% agreement by construction. `operational_disruption` itself is not passed to the VQC, so there is no literal target column in the input tensor. However, `action_cost` is a direct term in that formula and action cost alone with the rule `cost > 4` predicts 300/360 rows (**83.3% accuracy**). Fixed family templates make the remaining features stable proxies for action identity and the hidden reversibility/dependency adjustments. No identical feature vector ever has a different target.

This is structural target leakage/proxy leakage: the label is derived from substantially the same configuration values offered to the model. The model is approximating a known cost-category rule, not estimating a future consequence from a transition.

### Effectiveness

The sampled effectiveness counts are 68 at 0.6, 130 at 0.8, and 162 at 1.0. All 12 family/action groups contain multiple effectiveness values, yet:

- zero groups change their VQC feature vector;
- zero groups change `operational_disruption`;
- zero groups change target.

At effectiveness 0.6, `exact_consequence` can reduce `effective_interrupts`, changing feasibility, remaining paths, exposure reduction, or acceptance. Those outputs are discarded by the training table. Thus changing effectiveness assumptions can change path-state simulation output but **cannot change what the VQC sees or is trained to predict**.

### Split leakage and evaluation validity

- Every one of the 48 validation rows has an exact model-input twin in training; all eight validation vectors are present in training. Validation therefore measures replicated-template recognition and is not independent. It is also used to select the threshold.
- The lateral-access test set has four unique vectors, repeated 30 times each. None is an exact training vector, so there is no exact train/test vector collision.
- Holding out the family is directionally better than a random row test, but there is only one fixed topology and one graph template for that family. Reported sample size 120 overstates the effective independent support of four input patterns.
- As a diagnostic, seeded row-wise 80/20 splitting across all rows followed by 1-nearest-neighbor classification scores balanced accuracy and F1 of 1.0 because replicas cross the split. This is a leakage demonstration, not a candidate model result.
- Scenario identifiers differ across rows, but identifiers do not generate varying model state. They cannot establish episode independence.

### What the VQC learned

The evidence supports only this claim: the frozen VQC approximates the simulator's deterministic high/low disruption rule on a twelve-point feature domain and attains 0.75 balanced accuracy on four unseen lateral-template points. It does not support claims of:

- predicting action effectiveness, containment, residual exposure, recovery, or workflow disruption observed after action;
- generalizing across independent incidents, topologies, or attacker strategies;
- calibrated outcome probability;
- causal effect estimation; or
- quantum advantage.

The VQC raw Pauli-Z expectation is correctly disclosed as not being a probability. The runtime guard checks per-feature ranges and registered family membership, but it does not detect unseen joint feature combinations or distribution shift.

## Audit disposition

Preserve v1 as a versioned regression fixture and demonstration artifact. Do not combine it with v2 transitions, do not use its repeated rows as independent evidence, and do not market its scores as operational consequence performance. V2 should replace cost-threshold labels with outcomes computed from chronological pre/action/post state transitions as specified in the companion documents.

## Limitations of this audit

This is a code-and-artifact audit of a synthetic prototype. It does not validate the realism of costs, path semantics, or assumed control behavior against production incidents. No causal conclusion can be obtained from the current data. A future simulator can support counterfactual ground truth in simulation, but synthetic results must still be labeled synthetic and externally validated before operational claims.
