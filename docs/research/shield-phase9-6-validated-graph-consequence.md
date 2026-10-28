# SHIELD Phase 9.6 — validated graph-aware consequence intelligence

## Lifecycle architecture

`visible threat evidence -> Bayesian belief -> graph-visible state -> learned graph consequence predictor -> exact/QAOA advisory planner -> Phase 8 independent policy -> simulated execution -> verification/recovery -> versioned feedback`.

The graph simulator remains inside `MultiStepConsequenceEnvironment`. The Phase 7 planning interface (`make_problem`) is unchanged. `graph_integration` creates only decision-time observable features and Phase 8 proposals; it cannot execute an action. Phase 8 retains all tiering, approval, idempotency, JIT state validation, executor permit, verification, and recovery controls.

## Data and model

The new `shield-graph-consequence-counterfactual-v1` dataset contains 3,888 counterfactual branches from 72 initial conditions. It uses six family-level groups, four structurally altered variants per family, six incident classes (including benign), every candidate action, and six continuation policies. Each candidate/policy branch is a fresh simulator environment with the same seed/tick/component randomness as its siblings.

| Split | Families | Rows |
| --- | --- | ---: |
| Train | small office, multi-department, privileged administration | 1,944 |
| Validation | segmented enterprise | 648 |
| Test | critical service, redundant services | 1,296 |

Features include only defender-visible evidence, Bayesian belief values, declared graph scale/connectivity/criticality/workflow posture, active interventions, candidate action, and continuation policy. Route identifiers, hidden capability, attacker progress, latent routes, and outcome labels are not predictor features.

`GraphConsequencePredictor` is a calibrated random-forest ensemble using the existing Phase 7 target semantics. It estimates tree dispersion as uncertainty and reports feature-range OOD diagnostics. The legacy frozen Phase 7 predictor and Phase 9.5 structural heuristic are retained as diagnostic comparisons.

## Results

On the held-out topology families, severe-outcome calibration was Brier 0.0534, ECE 0.0359, and AUROC 0.9689. These are simulator-data results only; they do not establish operational calibration.

Matched realized exact-planning rollouts (24 held-out initial conditions) were:

| Predictor | Containment | Severe | Exposure | Disruption | Objective regret |
| --- | ---: | ---: | ---: | ---: | ---: |
| Learned graph model | 0.167 | 0.000 | 0.229 | 0.370 | 0.058 |
| Frozen Phase 7 model, diagnostic | 0.000 | 0.000 | 1.304 | 0.371 | 0.135 |
| Phase 9.5 heuristic, diagnostic | 0.000 | 0.000 | 1.304 | 0.371 | 0.135 |

The bounded QAOA check used four deterministic held-out conditions: containment 0.25, severe rate 0, exposure 0.206, disruption 0.410, and regret 0.067. This small comparison supports no quantum-advantage claim.

The two-organization incident demonstration completed the real simulated Phase 8 lifecycle for a shared observed-threat correlation ID. Both the small office and critical-service organizations selected `DISABLE_BULK_EXPORT` from the constrained automatic candidate set. This is reported honestly: the current model distinguishes predicted context but did not yet produce contextual action separation for that incident. Both recommendations required human approval due to graph criticality and synthetic-model operational restrictions; no authority was bypassed.

## Acceptance and limitations

Passed gates: grouped split integrity, no oracle predictor features, held-out severe calibration threshold (ECE <= 0.15), reproducible artifacts, Phase 8 target-scope execution, and stale-snapshot behavior. The model is eligible for the **simulator decision path only**, not operational promotion: data are synthetic, templates remain compact, rare incident behavior is limited, and QRL has not been retrained or promoted.

CERT-to-topology inference is not claimed. The demonstration uses an explicit simulated-evidence boundary. Phase 10 continuous learning is not implemented.
