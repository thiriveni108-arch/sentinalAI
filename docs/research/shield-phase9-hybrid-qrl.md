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

## Finalization evaluation

The reproducible report uses training seeds 100–147 and separate matched
evaluation seeds 901–905 over credential compromise, lateral movement, insider
misuse, exfiltration and benign conditions. It includes Phase 7 classical and
QAOA action references, early and late RL checkpoints, raw learning returns and
actual outcome metrics.

| Policy | Containment | Severe | Exposure | Disruption | Approval events |
|---|---:|---:|---:|---:|---:|
| Phase 7 classical reference | 0.0 | 0.8 | 2.492 | 0.135 | 0.0 |
| Phase 7 QAOA reference | 0.0 | 0.8 | 2.636 | 0.078 | 0.0 |
| Classical RL | 0.0 | 0.4 | 1.880 | 0.075 | 1.8 |
| Hybrid QRL, four qubits | 0.8 | 0.0 | 0.747 | 0.273 | 1.6 |

The hybrid policy improves from its early checkpoint (0.0 containment, 0.8
severe rate and 2.059 exposure) on this *small synthetic protocol*. Its higher
reward is therefore accompanied by better simulated security outcomes, not only
approval waiting. However it also creates more disruption and approvals than the
static references, and the sample is too small and structurally homogeneous for
promotion. It remains `EXPERIMENTAL`; Phase 7 remains the reference planner and
Phase 8 remains the sole execution authority. Phase 10 continuous learning is
not ready until a diverse topology/business-dependency simulator and a
pre-registered larger held-out study exist.

Reproduce:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\benchmark_phase9_qrl.py
.\.venv\Scripts\python.exe -m pytest tests/unit/test_phase9_qrl.py
```
