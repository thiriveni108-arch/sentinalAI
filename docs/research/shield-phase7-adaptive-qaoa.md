# SHIELD Phase 7: adaptive consequence-aware response planning

## Outcome and safety boundary

Phase 7 adds a bounded, read-only research planner. It can apply actions only in
`MultiStepConsequenceEnvironment`; it has no production response adapter and no
live execution path. Exact classical optimization remains the authority. QAOA
samples are independently checked against hard constraints. No quantum
advantage, operational readiness, attacker learning, QRL, or continuous
retraining is claimed.

## Phase 6.5 audit

The frozen release has 6,480 branches, a five-step horizon, nine initial
candidate actions and six deterministic continuation policies. Outcomes are
derived by the versioned simulator and transitions retain their provenance.
Initial-condition and topology identifiers do not cross train, validation and
test partitions. Candidate feasibility is checked for action name, approval and
prerequisites; continuation policies consume `RealisticObservation`, not route,
capability, progress, adaptation or severe-outcome ground truth.

`scenario_family_audit` is privileged for this prediction task: family controls
simulator progress and an exfiltration severe predicate, while it is not a
validated defender inference. Phase 7 excludes it, all identifiers, topology
labels, first-step audit outcomes and future transitions. This exposes a major
limitation: all frozen initial defender-visible feature values are effectively
constant. Most learnable variation is action and continuation-policy identity.
Later replanning observations are consequently out of training support.

Topology IDs are hash-derived labels over family and seed. There is no explicit
service/network graph, dependency structure, organization, correlated failure
domain or enterprise sampling process. Zero topology-ID overlap prevents direct
row leakage but does **not** represent independent enterprise networks or strong
topology generalization.

## Predictor and calibration

`ConsequencePredictor` uses only five visible state fields plus one-hot candidate
and policy fields. Random-forest regressors predict cumulative exposure,
disruption, recovery burden and censored containment time. Random-forest
classifiers predict severe outcome, delayed adaptation and unresolved outcome;
Platt scaling is fitted on validation predictions only. Training uses only the
frozen training split; test is evaluation-only. Tree dispersion and Bernoulli
standard deviation provide explicit model-risk indicators. The report includes
MAE/RMSE, Spearman ranking, Brier score, ECE, AUC and per-action errors.

Although the synthetic severe probability passes the preregistered numerical
ECE/Brier gate, it is marked unsuitable for operational risk constraints: the
data are synthetic and structurally homogeneous and provide no empirical
calibration against real incidents.

## Objective and constraints

For action `a`, continuation policy `p`, visible observation `o` and belief
summary `b`, the minimized objective is

`J(a,p|o,b) = .20 U + .20 E/5 + .15 D/5 + .10 R + .20 S + .08 C + .04 I + .03 Q`.

`U` is unresolved probability, `E` cumulative exposure, `D` cumulative workflow
disruption, `R` recovery burden, `S` severe-tail probability, `C` normalized
action cost, `I` the irreversible-action indicator and `Q` predictive severe
uncertainty plus half normalized belief entropy, clipped to one. The constants
5, 5 and 1 are declared normalizers matching the bounded five-step simulator.
Weights are a visible immutable configuration, must be non-negative and sum to
one, and are not presented as empirically learned utilities.

Execution tier, approval, prerequisites, incompatible completed controls and
disruption limits are hard feasibility constraints. Fully automatic planning
cannot choose semi-automatic or human-approval actions. Phase 7 never interprets
synthetic Bayesian posteriors as real calibrated attacker probabilities.

## Classical and quantum formulation

Exact enumeration and a separable scalable heuristic use the identical score
and feasibility function. The QUBO has one-hot action variables `x_a`, one-hot
continuation variables `y_p`, pairwise predicted cost `J(a,p)x_a y_p`, and
quadratic one-hot penalties. Infeasible action variables receive a penalty, but
sampled candidates are still rejected independently of penalties. Every one of
the 128 assignments in the benchmark formulation is compared with the semantic
objective; maximum encoding error is approximately `3.6e-15`.

The bounded p=1 QAOA benchmark used seven qubits, circuit depth 22 and 128 shots.
Exact and heuristic selected `REVOKE_SESSION/policy_constrained` at 0.352883.
QAOA returned a feasible `REQUIRE_FRESH_MFA/policy_constrained` plan at 0.389766,
an optimality gap of 0.036883. This is evidence against, not for, a quantum
advantage claim.

## Sequential replanning and limitations

After each simulated action, the planner constructs evidence solely from visible
malicious-activity status, updates the Phase 3 belief tracker, recomputes hard
feasibility, predicts consequences and replans. Static and adaptive runs are
recorded under matched family/seed conditions. Hidden simulator state is used
only after execution to score evaluation outcomes, never as planner input.

The current learned model cannot represent arbitrary second-stage action pairs:
the Phase 6.5 data identify a first action followed by a named deterministic
policy. Accordingly the QUBO selects an initial action and continuation policy,
not two unconstrained action identities. Repeated replanning is exploratory and
out-of-distribution because training rows begin at tick zero. Containment is
rare, and one of four small benchmark episodes reaches a severe outcome. These
facts, plus aggregate recovery dependencies, no approval latency, simplified
topologies, synthetic beliefs and simulator-defined severe predicates, block
deployment. A future dataset needs diverse visible initial and intermediate
states, explicit graph topology, policy/action sequence coverage and external
cyber-domain validation before operational constraints can use these estimates.

Reproduce with:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\train_phase7_consequence.py
.\.venv\Scripts\python.exe scripts\benchmark_phase7_planning.py
.\.venv\Scripts\python.exe -m pytest tests/unit/test_phase7_adaptive_planner.py
```
