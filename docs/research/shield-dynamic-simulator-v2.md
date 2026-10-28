# SHIELD dynamic simulator v2 — Phase 2 implementation

## Status and scope

Phase 2 adds an isolated, time-stepped synthetic cyber environment without changing the static SHIELD simulator, response adapters, API contracts, frontend, PennyLane VQC, Qiskit QAOA, model weights, or v1 dataset. It is a research data-generation substrate, not a live-response system and not evidence of real control effectiveness.

Primary implementation:

- `src/sentinel_ai/shield/dynamic_models.py`: typed state, observation, action, result, transition, ground-truth, outcome, approval, and termination contracts.
- `src/sentinel_ai/shield/attacker.py`: bounded state-dependent attacker policies.
- `src/sentinel_ai/shield/dynamic.py`: reset/observe/step/history/ground-truth environment.
- `scripts/demo_shield_dynamic_v2.py`: reproducible three-incident demonstration.

## Public interface

```python
from sentinel_ai.shield import DefenderAction, DynamicShieldEnvironment

environment = DynamicShieldEnvironment(max_steps=12, stochastic=True)
observation = environment.reset("lateral-movement", seed=202)
available = environment.available_actions()
transition = environment.step(DefenderAction("observe", "NO_OP"))
oracle = environment.ground_truth()       # simulator/evaluation use only
history = environment.history()
```

`reset` returns only `DefenderObservation`. Its serialized fields contain no `_gt` oracle keys. `ground_truth` is a separate explicit call. `step` returns a typed `TransitionRecord` with `to_v2_dict()` for JSON-compatible v2 records. Calling `step` after a terminal transition is rejected.

The environment never imports or calls a production response adapter. Defensive actions mutate only in-memory synthetic state.

## Implemented environment semantics

### State and chronology

Each transition advances exactly one tick. A `CyberState` holds active nodes, service health, identity/control state, defender beliefs, workflows, oracle footholds/capabilities/compromise, dynamic reachable and blocked routes, attacker progress, current route, action history, and rollback availability. State hashes establish continuity: `next_state_id(t) == current_state_id(t+1)`.

Existing static scenarios seed nodes, paths, and intervention semantics:

- credential compromise reuses `credential-compromise`;
- malicious insider and sensitive exfiltration reuse `malicious-insider`;
- lateral movement and privilege escalation reuse `multiple-routes`;
- benign alert reuses topology only and has no attacker.

The v2 environment owns separate mutable route/control state; it does not alter the existing scenario registry.

### Attacker policies

Five bounded policies cover credential compromise, malicious insider activity, lateral movement, sensitive-data exfiltration, and privilege escalation. Each chooses only among routes currently reachable in oracle state. If a defensive action blocks the current route while an alternate remains, the policy selects the alternate and records `adapted=true`. Progress magnitude has bounded seeded variation when stochastic mode is enabled.

Policies are deliberately transparent rules, not trained agents. They cannot communicate externally, execute code, scan networks, or leave the simulator.

### Defensive actions and effectiveness

Supported action types are `NO_OP`, session revocation, account disablement, MFA challenge, privilege removal, resource restriction, bulk-export disablement, device isolation, service segmentation, and rollback. Existing intervention action types and targets can be passed directly.

The simulator validates action type, target presence, prerequisites, and approval. Invalid/denied actions create a factual denied transition while time and attacker behavior continue. This avoids silently dropping adverse decisions.

Effectiveness is either:

- sampled reproducibly from a bounded distribution affected by current service health; or
- explicitly forced through `forced_effectiveness` for tests and controlled experiments.

Below 0.2 is failure, `[0.2,0.7)` is partial, and at least 0.7 is executed. Failure leaves defensive state unchanged. Partial execution blocks a subset of applicable routes. Full broad controls can contain all routes. An identical action can therefore produce different outcomes from topology, route count, service condition, and effectiveness.

### Business workflows and recovery

Each episode has an identity/access workflow and a critical business workflow with demand weights and service dependencies. Service-affecting controls reduce service health; broad identity disablement reduces served work. Disruption is:

```text
sum(workflow demand * (1 - served fraction)) / sum(workflow demand)
```

It is derived from post-transition workflow state and is not derived from action cost. Reversible actions save a bounded environment patch. `ROLLBACK` restores the affected service, identity, control, and blocked-route state while retaining elapsed time and attacker progress; recovery cost is recorded as synthetic normalized units.

### Observations and outcomes

After action application and attacker evolution, the sensor emits next-tick evidence with source, confidence, quality, and defender availability. Beliefs and defender-visible routes update from this evidence. Sensor draws are seeded and replayable.

Residual exposure is the fraction of total modeled routes still reachable. Outcomes are state predicates:

- no attacker -> `NO_ATTACK` and benign resolution;
- progress reaches 1 -> attack success;
- no reachable routes -> containment;
- some routes blocked but some reachable -> partial containment;
- otherwise -> attack progress;
- reaching the configured horizon terminates unresolved with `MAX_STEPS`.

Labels therefore follow post-action state, not arbitrary class sampling.

## V2 schema compatibility

`TransitionRecord` implements the approved core identifiers, current/action/next chronology, evidence, separated attacker ground truth, prerequisites, approval tier/status, realized effectiveness, exposure, disruption, outcome, reversibility, recovery, resolution/terminal state, incident truth, random-draw trace, verification, and provenance. State structs use the approved defender/oracle naming boundary.

The record is designed for a future materializer. Phase 2 intentionally does not emit the full dataset or assign train/validation/test splits. Dataset-wide relational tables and Parquet/JSON Schema validation remain Phase 3 work after review.

## Reproducible demonstration

Run:

```powershell
.\.venv\Scripts\python.exe scripts\demo_shield_dynamic_v2.py
```

The fixed demonstration produces:

| Incident | Intervention | Result |
|---|---|---|
| Credential compromise | Full session revocation | Exposure 0.0, disruption 0.0, contained and terminal |
| Lateral movement | Partial service segmentation | Attacker switches to alternate route, exposure 0.5, disruption 0.1925, partially contained |
| Malicious insider | Failed resource restriction, then account disablement | First transition preserves exposure 1.0 and attack progress; second contains at exposure 0.0 with disruption 0.55 |

These outcomes demonstrate different effectiveness, adaptation, residual exposure, and workflow consequences. They are synthetic mechanism checks, not operational performance measurements.

## Assumptions and limitations

- Routes are bounded abstractions derived from small existing SHIELD graphs; this is not packet-, host-, or protocol-level emulation.
- Path blocking is rule-based. Reachability is dynamic in simulator state, but the underlying topology does not yet create novel nodes/edges during an episode.
- Attacker strategies are transparent bounded heuristics with one tactic per family; they do not learn.
- Sensor behavior is a compact probability model. Belief updates are transparent increments, not the future Bayesian tracker.
- Workflow served fraction is a compact dependency/health model with two workflows per episode. Recovery cost uses normalized synthetic units.
- Forced effectiveness is available only as a controlled simulation parameter and must be identified in generated experiment metadata.
- Action approval is modeled, not connected to human or production systems.
- The transition record is schema-compatible in field semantics, but canonical Parquet tables, formal JSON Schema, dataset-level split manifests, and large-scale statistical calibration have not been implemented.
- Synthetic verification establishes reproducibility and internal causal consistency only.

## Readiness and next gate

The simulator is ready for a reviewed **small pilot** to validate factor coverage, formal serialization, topology-level splits, duplicate/state-distance audits, and empirical transition distributions. It is not yet ready to generate the complete 5,000-transition dataset. Before scaling, add canonical schema validation/materialization, richer topology variation, calibrated probability configurations, episode/topology split tooling, and pilot diversity gates.

Phase 2 stops here. No world model, Bayesian tracker, quantum retraining, new QAOA controller, complete dataset, or live action integration was started.
