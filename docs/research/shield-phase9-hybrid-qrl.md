# SHIELD Phase 9: hybrid quantum reinforcement learning

## Result

Phase 9 adds an experimental, advisory QRL recommendation source. It does not
replace Phase 7 planning and cannot execute anything. `phase8_proposal_from_recommendation`
marks QRL recommendations operationally unsuitable by default, so Phase 8's
independent policy authority restricts them to review rather than allowing them
to self-authorize.

## POMDP formulation

The hidden state is the Phase 6.5 simulator state, including attacker routes,
capability, progress, adaptation and severe predicates. The policy receives only
tick, service health, observed compromise/activity, evidence count, recovery
activity, active-intervention count, prior action and the Phase 3 Bayesian mode
posterior. Oracle state is never included in the observation. It is read after a
simulated transition only to calculate actual reward/evaluation.

The bounded action space maps to existing simulator actions plus human-review
and recovery requests. A high-impact selection creates a pending-approval event
and performs one actual simulated `NO_OP` attacker turn. The next available
action is a wait step that records an explicit rejection in this compact research
adapter; repeat requests are masked for the rest of the episode. Thus approval
never means containment, cannot terminate a dangerous incident, and cannot farm
reward. Action masks reject terminal, duplicate-active and non-simulator actions
but never grant Phase 8 authority. Episodes end on simulated severe outcome or
genuine containment, and truncate at five steps. The discount is 0.92.

Reward is the documented sum of containment `+2`, exposure `-0.7`, severe
damage `-3`, disruption `-0.6`, recovery `-0.4`, intervention `-0.15`, repeated
ineffective action `-0.25`, ineligible selection `-0.5`, approval waiting
`-0.8`, and approval rejection `-0.7`. It uses post-action actual transition
consequences. This discourages
broad containment, waiting, reward farming and unsafe restoration but remains a
synthetic research utility, not business policy.

## Models and experience

The baseline is compact on-policy masked REINFORCE. The hybrid model uses a
four-qubit differentiable PennyLane `AngleEmbedding` plus one entangling layer,
four Pauli-Z expectations and a classical masked policy head. Only fresh
simulated on-policy trajectories update either policy; versioned replay is
deduplicated audit/training-data infrastructure, not naively used for off-policy
updates. Feedback provenance is separated as simulated, validated investigation,
unverified observation and evaluation-only ground truth.

Both learned policies are registered `EXPERIMENTAL` by default. The registry
does not auto-promote. Promotion would need predefined held-out severe-outcome,
disruption, stability, latency and policy-boundary criteria.

## Limitations

Phase 6.5 does not provide a genuinely diverse topology or full benign/false
positive dynamic-state contract. The adapter therefore supports its existing
five attacker families plus a minimal explicit benign adapter that removes
attacker capability/routes while preserving intervention disruption. It only represents review events for high-impact actions;
it does not claim full approval-delay, live recovery, or enterprise-topology
coverage. Learning-curve reward is distinct from security effectiveness. The
small VQC is CPU simulation, not hardware performance or quantum advantage.

## Corrected evaluation

`shield_phase9_qrl_benchmark_v2.json` uses two independent training seeds
(101, 202), checkpoints at 24 and 48 episodes, six matched scenario classes,
and three separate held-out seeds per class (18 episodes/policy). It reports
per-scenario rows, aggregate means/standard deviations, containment, severe
outcomes, exposure, disruption, recovery, approvals, unnecessary restrictions,
policy violations and decision latency. The accompanying PNG is a learning
checkpoint curve, not evidence of deployment readiness.

The earlier fixed-action “Phase 7” rows were removed. The replacement adapters
invoke the real Phase 7 exact classical solver or QAOA solver with the frozen
Phase 7 predictor, current visible observation, the same automatic-action mask,
and a shared Phase 8-safe action mapping. This is explicitly **diagnostic only**:
the predictor was trained at tick zero, so later sequential states are outside
its support. It must not be read as a fair generalization comparison.

| Policy / protocol | Containment | Severe | Exposure | Disruption | Mean latency |
|---|---:|---:|---:|---:|---:|
| Real Phase 7 exact adapter (diagnostic) | 0.833 | 0.000 | 0.729 | 0.281 | 244 ms |
| Real Phase 7 QAOA adapter (diagnostic) | 0.833 | 0.000 | 0.729 | 0.324 | 502 ms |
| Classical RL, seed 101, 48 episodes | 0.833 | 0.000 | 0.822 | 0.287 | <1 ms |
| Hybrid QRL, seed 101, 48 episodes | 0.000 | 0.833 | 2.142 | 0.223 | 5.4 ms |

The hybrid QRL policy is unstable across training seeds and worsens substantially
at the later checkpoint for seed 101. It is therefore **not** an improvement,
has no evidence of quantum advantage, and remains `EXPERIMENTAL`. Classical RL
is also not promoted: its performance is small-sample synthetic evidence only.
The VQC, projection and policy head now receive end-to-end gradients, but
optimization correctness does not establish defensive usefulness. Phase 7 stays
the reference planner, and Phase 8 stays the sole execution authority.

Phase 10 is not ready. Required prerequisites are a topology/business-dependency
simulator with genuinely diverse initial conditions, a validated benign/approval
contract, a prespecified statistical evaluation plan and stable multi-seed QRL
results.

Reproduce:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\benchmark_phase9_qrl.py
.\.venv\Scripts\python.exe -m pytest tests/unit/test_phase9_qrl.py
```
