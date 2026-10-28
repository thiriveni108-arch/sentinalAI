# SHIELD simulator gap analysis for chronological consequence data

## Current capability

The current SHIELD-ACT engine builds a static graph from one of three family templates. Node IDs vary by context, but topology and parameters do not. Path enumeration finds bounded paths, intervention coverage is declared deterministically, and `simulate` evaluates a selected set once. `exact_consequence` can remove one path interruption under a coarse effectiveness threshold, but no state is mutated and no subsequent attacker/environment step occurs.

The incident workflow tracks applied action IDs and remaining path IDs for UI orchestration, but this bookkeeping is not a probabilistic cyber world. There is no chronological attacker agent, sensor process, business workflow, transition kernel, or outcome verification against a next state.

## Capability gaps

| Required capability | Current behavior | Consequence | Minimum upgrade |
|---|---|---|---|
| Multi-step incidents | One static evaluate/simulate call | No temporal credit assignment or delayed outcomes | Episode runner with immutable `State`, tick, horizon, terminal predicates, and transition log |
| Attacker adaptation | No attacker policy/state | Actions cannot cause rerouting, delay, or tactic changes | Small versioned strategy registry and policy conditioned on attacker-visible state/action effects |
| Partial effectiveness | `<0.75` removes at most one declared interrupt | Coarse, order-dependent, not reflected in target | Per-action/target effectiveness distribution and partial state effects |
| Dynamic attack paths | Static graph and predeclared `interrupts` | No new/closed routes after state change | Recompute reachability after every transition from current control/node/credential state |
| Business dependencies | Count of unobserved graph edges | “Disruption” is not workflow impact | Workflow graph, demand/SLO model, service dependencies and criticality weights |
| Legitimate disruption | Deterministic action cost/penalties | Label is a configured cost threshold | Simulate legitimate demand served, denied, delayed, and degraded |
| Response failure/recovery | No failure/delay/rollback transition | Cannot learn failed actions or recovery cost | Execution status, delays, failure modes, reversible rollback and repair actions |
| Post-action evidence | None | Cannot update beliefs or verify effect | Sensor emission model after transition, with noise/delay/source provenance |
| Terminal conditions | Feasible iff all current critical paths covered | No attack success, benign resolution, timeout, or unresolved end | Explicit success, containment, benign, irrecoverable and horizon predicates |
| Ground truth vs observation | Graph mixes observed and assumed edges | Oracle leakage risk | Separate oracle world state, attacker view, and defender belief/observation |
| Reproducibility | Global/template seed in generator | Cannot replay individual transitions | Hierarchical episode/transition RNG seeds or trace keys and immutable configs |
| Topology diversity | Three fixed templates | Replicas masquerade as sample size | Parameterized topology generator plus held-out topology families/instances |

## Minimum viable simulator upgrade

Implement only what is needed to produce defensible v2 transitions; do not build the future learned world model or QAOA controller yet.

1. **Typed state and episode engine.** Add immutable topology, oracle state, defender observation/belief state, workflow state, and attacker state. `step(state, action, rng) -> next_state, observation, outcome_trace` is the sole transition interface.
2. **Parameterized scenario/topology generation.** Retain the three existing families for regression, add at least two more families including benign/false-positive cases, and vary graph size, routes, asset criticality, identities, services, controls, and workflow demand. IDs alone do not count as variation.
3. **Small attacker strategy registry.** Begin with 2–4 explicit policies per malicious family (e.g., fast objective pursuit, stealth/delay, alternate-route seeking, privilege-first). Strategies react to defender-visible effects using declared rules; oracle strategy stays hidden from defender features.
4. **Action execution model.** Version prerequisites, approval tier, delay, success/failure and effectiveness distributions by action type and relevant state. Represent `NO_OP`, denied, failed, and partial actions. Preserve the current policy engine as authority; simulator policy is experimental data generation only.
5. **Dynamic reachability.** Derive paths from current graph/control/credential state at every tick. An intervention mutates state, not a stored coverage list.
6. **Business/workflow layer.** Model a bounded set of workflows with demand, service dependencies, SLOs, and recovery. Derive disruption from unmet legitimate work.
7. **Observation and verification layer.** Emit noisy/delayed evidence after intervention. Use it to update defender beliefs and to mark simulator/replay verification; never equate simulator verification with real-world validation.
8. **Outcome and terminal rules.** Version declarative predicates for success, progress, partial containment, containment, benign resolution, maximum horizon, and irrecoverable failure.
9. **Event/provenance recorder.** Emit the v2 schema atomically with state hashes, rule IDs, RNG trace keys, action execution details, and label provenance.

## Tests required before generation

- Deterministic replay for a fixed episode seed and config.
- State continuity and terminal invariants across multi-step episodes.
- Unit tests showing effectiveness changes next state and can change outcomes without directly setting labels.
- Attacker reroutes when a route is blocked and cannot use a route absent from its view/capabilities.
- Action failure, partial success, delayed effect, rollback, and recovery paths.
- Disruption increases only through simulated workflow effects; configured action cost alone cannot set it.
- Sensor evidence is derived from next state and respects noise/delay.
- Defender feature export contains no oracle attacker state or future observation.
- Topology/episode split checker rejects overlaps.
- Distribution/property tests for action success, sensors, and transition probabilities against configured expectations.

## What is explicitly not required for this upgrade

No learned probabilistic world model, Bayesian implementation beyond a transparent baseline updater, quantum transition model, new VQC training, QAOA controller, production action execution, or full-scale dataset generation is part of the minimum simulator milestone.
