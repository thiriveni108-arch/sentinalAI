# SHIELD Phase 6: downstream consequence modeling

## Outcome

Phase 6 produced an isolated four-step counterfactual rollout dataset, a target-quality audit, classical consequence benchmarks, and a read-only candidate-action scorer. The scientific gate for a new consequence VQC failed. No VQC was trained, and no existing VQC, Random Forest, quantum kernel, QAOA, Bayesian model, policy, or execution path was replaced.

## Counterfactual rollout design

The release contains 1,536 branches from 240 initial conditions over five malicious scenario families. Each condition evaluates 6–7 available actions. Decision states include zero, one, or two reproducible observed warmup steps, followed by the candidate intervention and up to four downstream transitions. The continuation policy is NO_OP, making the measured effect specifically “candidate action followed by observation,” not an optimized multi-action policy.

Every action branch constructs a fresh simulator, Bayesian tracker, state, history, undo map, and random generator. Branches share the same reset/attacker seed. Action effectiveness is deterministically sampled by condition and action, preventing action-effect sampling from shifting the subsequent attacker random stream. Initial-state fingerprints verify that alternatives start from the same defender-visible condition.

The frozen Phase 4 topology split mapping is reused: 1,085 train, 214 validation, and 237 test branches, with zero topology or initial-condition overlap. Inputs are exactly the 44 Phase 4 defender-observable features. Simulator ground truth, realized effectiveness, future observations, and outcomes are excluded.

## Target derivation and quality

Targets are direct aggregates or predicates over actual rollout transitions:

- cumulative exposure: sum of transition residual exposure;
- cumulative disruption: sum of transition workflow disruption;
- recovery burden: sum of transition recovery costs;
- adaptation: any recorded attacker adaptation during the rollout;
- severe residual damage: any simulator-derived `ATTACK_SUCCESS` outcome;
- time to containment: first contained transition, otherwise horizon + 1;
- unresolved: final transition’s simulator-derived incident status.

The release contains meaningful action-dependent variation in cumulative exposure (99.6% of initial conditions), cumulative disruption (97.5%), adaptation (88.3%), and unresolved status (79.6%). Adaptation prevalence is 32.23%; unresolved prevalence is 77.73%. Action support ranges from 48 REQUIRE_FRESH_MFA branches to 240 each for NO_OP, DISABLE_ACCOUNT, ISOLATE_DEVICE, and SEGMENT_SERVICE. Full support and per-action target distributions are in the frozen report.

Three proposed targets fail validation:

- Recovery burden is constant zero because the current simulator emits zero recovery cost for these actions.
- Severe residual damage has zero positive cases within four steps, so recall, calibration, and risk prediction cannot be evaluated.
- Time to containment takes only 1 or 5 and is an exact transform of unresolved-at-horizon.

Downstream independence is also weak. Cumulative exposure has Spearman correlation 1.0 with one-step exposure. Unresolved status has correlation -1.0 with one-step containment. There are zero rows where adaptation first appears after step one. Cumulative disruption is the only materially downstream target, though it still correlates 0.811 with one-step disruption.

Because several requested targets are trivial and the remaining security targets are redundant with Phase 4 outputs, training another four-qubit VQC would not answer a meaningful new question.

## Classical benchmark

Random Forest and Extra Trees heads were tuned using validation only; Random Forest was selected for all supported targets. Results on held-out topologies are:

| Target | Metric | Result |
|---|---:|---:|
| Attacker adaptation | F1 | 0.5076 |
| Attacker adaptation | ROC-AUC / Brier / ECE | 0.6756 / 0.2292 / 0.1582 |
| Unresolved at horizon | F1 | 0.7314 |
| Unresolved at horizon | ROC-AUC / Brier / ECE | 0.7235 / 0.2096 / 0.1909 |
| Cumulative exposure | MAE / RMSE / Spearman | 1.1292 / 1.4765 / 0.3806 |
| Cumulative disruption | MAE / RMSE / Spearman | 0.2806 / 0.4699 / 0.7051 |

Within held-out initial conditions, predicted action ordering accuracy is 69.40% for exposure and 81.86% for disruption. Mean within-condition Spearman correlation is 0.361 and 0.593 respectively. This is promising for experimental disruption-aware ranking, but security-exposure ordering and probability calibration remain too weak for automatic planning.

## Read-only scoring contract

`DownstreamConsequenceService` accepts a defender observation, Bayesian belief, and proposed action. It returns expected cumulative exposure, expected cumulative disruption, adaptation probability, unresolved probability, a censored derived time-to-containment estimate, tree-dispersion uncertainty, model provenance, and per-target validation status.

Severe risk and recovery burden return `null`, explicitly marked unsupported. They are not returned as zero-risk estimates. The service validates artifact version and input ranges and has no reference to response execution.

## Limitations and Phase 7 recommendation

The data are synthetic; the continuation policy is fixed NO_OP; horizon is four; several targets collapse to one-step outcomes; and tree dispersion is not a confidence interval. Severe-outcome recall cannot be reported because the class is absent. The scorer must remain experimental and must not become the adaptive QAOA objective yet.

Before Phase 7 adaptive QAOA, revise and validate simulator semantics—not arbitrary label thresholds—to produce:

1. nonzero recovery costs tied to actual restoration transitions;
2. naturally occurring severe outcomes within supported 2–5 step horizons;
3. delayed containment and delayed attacker adaptation;
4. continuation policies representing plausible follow-up defense rather than NO_OP only;
5. downstream exposure that is not a deterministic scaling of the first transition;
6. calibrated held-out predictors with stronger action-order accuracy.

Until those conditions hold, the Phase 4 classical predictor remains the validated security consequence model, while the Phase 6 model is useful only for read-only downstream research, especially workflow-disruption ranking.

Reproduce with:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\generate_downstream_dataset.py
.\.venv\Scripts\python.exe scripts\train_downstream_consequence.py
.\.venv\Scripts\python.exe -m pytest tests\unit\test_downstream_consequence.py tests\integration\test_downstream_consequence_compatibility.py
```
