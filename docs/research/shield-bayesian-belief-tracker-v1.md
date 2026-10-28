# SHIELD Bayesian attacker belief tracker — Phase 3

## Scope and status

Phase 3 adds a versioned Bayesian filter over attacker modes and a composition layer for the Phase 2 simulator. It does not alter static SHIELD, response adapters, APIs, frontend, the frozen PennyLane VQC, Qiskit QAOA, datasets, or model weights. All probabilities are consequences of declared synthetic assumptions; they are **not empirically calibrated probabilities of real attacks**.

Implementation:

- `src/sentinel_ai/shield/beliefs.py`: typed hypotheses, configuration, state, history, filtering, explanations, and future-model exports.
- `src/sentinel_ai/shield/belief_integration.py`: Phase 2 composition that reads only defender observations.
- `scripts/demo_shield_beliefs.py`: reproducible supported-mode switching, unknown behavior, and false-positive trajectories.
- focused unit and integration tests under `tests/unit/test_shield_beliefs.py` and `tests/integration/test_shield_belief_integration.py`.

## Belief representation

The normalized state space is ordered as:

1. `BENIGN`
2. `CREDENTIAL_COMPROMISE`
3. `MALICIOUS_INSIDER`
4. `LATERAL_MOVEMENT`
5. `SENSITIVE_DATA_EXFILTRATION`
6. `PRIVILEGE_ESCALATION`
7. `UNKNOWN`

Default priors are 0.45 benign, 0.10 unknown, and 0.09 for each of the five supported malicious modes. These values express simulator assumptions only.

`BeliefState` records episode, time, all seven probabilities, normalized Shannon entropy, most likely mode, model version, and configuration version. Exported probabilities sum to one (within floating-point arithmetic, with residual correction).

## Bayesian filter

For prior mode distribution `p(z[t-1])`, transition matrix `T`, and visible evidence `e[t]`:

```text
predicted(z[t]) = sum_z[t-1] T(z[t-1], z[t]) p(z[t-1])
posterior(z[t]) proportional to p(e[t] | z[t]) predicted(z[t])
```

Every supported non-unknown source mode has transition probability 0.84 to remain, 0.06 to unknown, and 0.02 to each other mode. Unknown remains unknown with probability 0.70 and moves to each other mode with probability 0.05. Nonzero cross-mode mass allows strategies to change during an episode.

Multiple conditionally independent evidence records multiply likelihoods. Computation uses log likelihoods, a configurable `1e-300` floor, max-log subtraction, and stable summation. Missing evidence uses likelihood one for every mode, so the step performs transition prediction only.

Evidence confidence mixes its configured likelihood with neutral likelihood one. Defender-invisible evidence is discarded. For positive signal types, boolean false uses the complementary likelihood. The explicitly negative `POST_ACTION_NO_CONFIRMED_ACTIVITY` type is not inverted again.

## Observation assumptions

The versioned default likelihood table is intentionally small and transparent:

| Evidence | Strongest supported hypothesis | Likelihood |
|---|---|---:|
| `ANOMALOUS_SESSION` | Credential compromise | 0.86 |
| `SENSITIVE_ACCESS_SPIKE` | Malicious insider | 0.88 |
| `LATERAL_CONNECTION` | Lateral movement | 0.90 |
| `BULK_EXPORT` | Sensitive-data exfiltration | 0.93 |
| `PRIVILEGE_CHANGE` | Privilege escalation | 0.91 |
| `POST_ACTION_MALICIOUS_ACTIVITY` | Generic malicious modes | 0.62–0.72 |
| `POST_ACTION_NO_CONFIRMED_ACTIVITY` | Benign | 0.78 |
| `CONTAINMENT_ROUTE_SWITCH` | Lateral movement | 0.90 |

The complete per-mode rows are defined in `_default_likelihoods()` and captured in every configuration version. No VQC output, anomaly rank, risk score, simulator family label, or attacker oracle field is interpreted as a likelihood.

### Unsupported observations

An unknown evidence type receives likelihood 0.72 under `UNKNOWN` and 0.04 under every other mode. Repeated unexplained evidence therefore raises unknown probability rather than forcing a known category. The update history records each unsupported evidence type. This is a modeling decision, not anomaly calibration.

### Contradictory observations

Contradictory records are retained and jointly evaluated. For example, presence and absence of an anomalous session reduce the concentration produced by a positive signal alone. The filter does not silently discard either record. Dependence between duplicated/correlated sensors is not modeled and must be addressed before larger-scale generation.

## Integration and leakage boundary

`BeliefTrackedDynamicEnvironment` composes, rather than modifies, `DynamicShieldEnvironment`:

```python
combined = BeliefTrackedDynamicEnvironment()
observation, posterior = combined.reset("lateral-movement", seed=61)
result = combined.step(DefenderAction("observe", "NO_OP"))
```

Reset and step call only `environment.observe()`, which returns `DefenderObservation`. The tracker API intentionally does not accept `CyberState`, `EpisodeGroundTruth`, `TransitionRecord.attacker_strategy_gt`, or ground-truth incident labels. `ground_truth_for_evaluation()` is separate and never called internally. Integration tests replace the oracle method with an exception to verify this boundary.

Phase 2's per-identity `observed_compromise_probability` remains unchanged for backward compatibility. It is a heuristic simulator observation and is not consumed by this attacker-mode filter. This avoids relabeling an old heuristic as Bayesian probability or duplicating its update rule.

## Audit history and explainability

Every `BeliefUpdate` stores:

- episode and time step;
- prior and transition-predicted distributions;
- defender-visible evidence actually considered;
- the complete applied transition matrix;
- combined per-mode observation likelihoods;
- posterior and normalized entropy;
- unsupported evidence types;
- largest positive and negative belief changes; and
- model/configuration versions.

Histories are immutable chronological tuples. Non-increasing time steps and episode mismatches are rejected.

## Future-model interfaces

- `initialize(...)`: initialize standard or experiment-specific priors.
- `update(DefenderObservation)`: safe simulator integration.
- `update_evidence(...)`: typed filtering for evidence pipelines and tests.
- `current` and `history()`: posterior and audit retrieval.
- `export_world_model()`: stable mode order, posterior vector, entropy, and versions.
- `export_planner_uncertainty()`: posterior map, top mode/confidence, unknown mass, and entropy for a future planner.

The planner export supplies information only; no adaptive QAOA behavior is implemented.

## Reproducible demonstration

Run:

```powershell
.\.venv\Scripts\python.exe scripts\demo_shield_beliefs.py
```

The supported-mode trajectory changes its leading hypothesis as evidence changes:

| Step | Evidence theme | Leading mode | Probability | Entropy |
|---:|---|---|---:|---:|
| 0 | anomalous session | credential compromise | 0.271 | 0.964 |
| 1 | privilege changes | privilege escalation | 0.513 | 0.705 |
| 2 | lateral connection/route switch | lateral movement | 0.449 | 0.626 |
| 3 | bulk exports | sensitive-data exfiltration | 0.280 | 0.811 |

A second trajectory drives `UNKNOWN` upward with unmodeled covert-channel evidence. A third consumes a complete Phase 2 benign/false-positive episode and remains benign-leading. Simulator ground truth is read only in tests/demonstration evaluation, never in filtering.

## Limitations

- Priors, transitions, likelihoods, conditional independence, and confidence mixing are expert-designed synthetic assumptions without empirical calibration.
- Generic Phase 2 post-action evidence distinguishes malicious activity from no confirmed activity but often cannot identify a specific strategy; richer defender-visible sensors are needed.
- Repeated correlated evidence can be over-counted because sensor dependence is not modeled.
- The transition matrix is stationary and does not yet condition on defensive action or topology. Those extensions belong with the future probabilistic world model.
- Unknown is a single catch-all mode, not a nonparametric discovery model.
- Entropy and highest posterior describe model uncertainty under these assumptions, not operational confidence.
- Offline calibration, drift detection, real incident validation, and decision-utility evaluation remain future work.

Phase 3 stops here. No classical/quantum world model, adaptive QAOA, continuous retraining, full v2 dataset, or live security integration was started.
