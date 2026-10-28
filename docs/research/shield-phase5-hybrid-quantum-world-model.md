# SHIELD Phase 5: hybrid quantum world model

## Scope and foundation audit

Phase 5 adds an experimental consequence predictor; it does not replace the Phase 4 Random Forest, the consequence VQC, Qiskit QAOA, the simulator, or static SHIELD policy. The frozen `shield-world-transitions-v2.0.0` release contains 5,219 transitions from 650 episodes and 93 topologies. Its SHA-256 (`b57763d...bac5`) matches the manifest and the Phase 4 report. Topology-grouped train/validation/test counts remain 3,709/697/813, with zero episode or topology overlap.

The 44 inputs exactly match Phase 4: defender-observable aggregates, proposed-action attributes, visible evidence, and Bayesian belief probabilities/entropy. Audit-only scenario, topology, action result, outcome, simulator ground truth, future observations, and all five labels are excluded. `forced_effectiveness` is sampled inside the simulator and is intentionally hidden from the model, so action effectiveness is a source of latent uncertainty.

Coverage is imbalanced: NO_OP is 3,751/5,219 (71.87%). REQUIRE_FRESH_MFA has only 43 examples and ROLLBACK 67; their per-action results must not be read as stable operational estimates. No Phase 4 data or artifact was changed.

## Architecture and training

The pipeline fits `StandardScaler` and four-component PCA only on training data. PCA supplies four bounded angles to a four-qubit PennyLane `default.qubit` circuit. Each ensemble member uses two `StronglyEntanglingLayers` (24 variational parameters). The four PCA values and four expectation values form an eight-dimensional hybrid representation. Three logistic classification heads predict containment, route switching, and next malicious observation; two ridge heads predict residual exposure and workflow disruption.

Variational parameters are trained with a reproducible SPSA-style supervised search. Its objective averages three Brier losses and two MSE losses on an inner, training-only holdout. Three seeds (42073, 42089, 42101) form the uncertainty ensemble. Raw expectation values are features—not probabilities. Classification probabilities come from classical heads; model uncertainty is cross-seed prediction dispersion.

The classical NN baseline uses the same 44 inputs, train split, and five targets with small 16/8-unit MLP heads. The frozen Phase 4 Random Forest is evaluated directly on the same test rows. All test topologies are unseen during training.

## Actual held-out results

| Target | Metric | Random Forest | Classical NN | Hybrid Q4 |
|---|---:|---:|---:|---:|
| Containment | F1 | 0.4645 | 0.0968 | 0.3213 |
| Containment | Brier | 0.0826 | **0.0475** | 0.1583 |
| Route switch | F1 | **0.5789** | 0.1220 | 0.4698 |
| Route switch | Brier | 0.0808 | **0.0667** | 0.1470 |
| Next malicious observation | F1 | 0.6828 | **0.8740** | 0.7308 |
| Next malicious observation | Brier | 0.2375 | **0.1895** | 0.2351 |
| Residual exposure | MAE / RMSE | **0.1129 / 0.1964** | 0.1242 / 0.2026 | 0.2185 / 0.2923 |
| Workflow disruption | MAE / RMSE | 0.0200 / 0.0577 | **0.0234 / 0.0546** | 0.0672 / 0.1042 |

Hybrid precision/recall were 0.2073/0.7143 for containment, 0.3143/0.9296 for route switching, and 0.8350/0.6498 for next malicious observation. Its 10-bin ECE values (0.2466, 0.2371, 0.2575) show poor calibration; these probabilities must not be treated as calibrated operational risk. The four PCA components retain 51.00% of standardized feature variance, a likely information bottleneck.

The hybrid underperforms the best classical result on every target. It is therefore not promoted. The final recorded run took 96.6 seconds to train versus 4.0 seconds for the NN and 2.39 seconds for the Phase 4 RF. Hybrid circuit evaluation over validation plus test took 20.69 seconds, and the measured three-member one-row transform/circuit path took about 81.6 ms. Circuit simulation and ensemble evaluation materially increase compute cost. There is no evidence of quantum advantage.

Per-action and per-attacker-scenario metrics, held-out topology IDs, calibration, ensemble dispersion, parameter counts, and timing are frozen in `artifacts/reports/shield_quantum_world_model_q4_v1.json`.

## Uncertainty semantics

- Predicted probability: mean probability emitted by a classical classification head.
- Model uncertainty: standard deviation across three independently seeded hybrid members. This is a heuristic epistemic indicator, not a confidence interval.
- Bayesian attacker-belief uncertainty: the separately computed belief distribution and normalized entropy supplied as inputs.
- Simulator stochasticity: aleatoric variation in generated transitions, not separately identified by this ensemble.

## Integration and Phase 6 readiness

`QuantumWorldModelService` accepts the same observation, belief, and proposed action contract as Phase 4, validates feature ranges and versions, and returns bounded consequences plus ensemble dispersion. It has no action executor and does not alter the environment. Static SHIELD and classical model selection remain unchanged; the best validated predictor remains available for later QAOA work.

The interfaces are consequence-oriented and can feed future candidate-action scoring. They are not sufficient for model-based RL rollouts. Before imagined rollouts, Phase 6 would need a joint, temporally consistent next-state model for graph/topology state, service health, identity/control states, workflows, observations/evidence, attacker belief updates, terminal state, and stochastic correlations across outputs. It would also need multi-step validation, uncertainty propagation, off-support detection, and policies preventing simulator/model exploitation. QRL is intentionally not implemented here.

Reproduce with:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\train_quantum_world_model.py
.\.venv\Scripts\python.exe -m pytest tests/unit/test_quantum_world_model.py tests/integration/test_quantum_world_model_compatibility.py
```
