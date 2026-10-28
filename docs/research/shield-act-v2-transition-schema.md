# SHIELD-ACT dataset v2: chronological transition schema

## Design contract

Dataset version `shield-act-transition-v2.0.0` represents one applied or deliberately withheld defender decision as:

```text
current state S_t -> defender action A_t -> stochastic attacker/environment transition -> next state S_t+1 -> observed outcome O_t+1
```

One row is one transition. Rows are ordered by `(episode_id, time_step)`, and `(episode_id, time_step)` is unique. `next_state_id` on step `t` must equal `current_state_id` on step `t+1` within an episode unless the prior row is terminal. Counterfactual alternatives must live in a separate table and must never be represented as additional observed transitions.

The canonical storage recommendation is typed Parquet plus a JSON Schema data contract. JSON objects below may be stored as structs; list fields are ordered arrays. Times are simulator ticks, not fabricated wall-clock timestamps.

## Observability boundary

- **Defender-observable at decision time:** fields marked `D0`. These are eligible inputs for deployed decision/consequence models after a task-specific allow-list is frozen.
- **Observable only after the action:** fields marked `D1`. These are labels or next-step inputs and must not enter a time-`t` decision model.
- **Simulator-only:** fields marked `S`. These support generation, diagnostics, and oracle evaluation only. They must be physically excluded from deployable feature views.
- **Governance/metadata:** fields marked `M`. They may define grouping, provenance, or audits, but IDs and split assignments are not predictive features.

## Core transition table

| Field | Type / nullability | Valid values or range | Visibility | Meaning / relation |
|---|---|---|---|---|
| `dataset_version` | string, required | semantic version, fixed per release | M | Schema/generator contract version. |
| `generator_version` | string, required | immutable code/config revision | M | Reproduces transition logic. |
| `episode_id` | UUID/string, required | unique episode identifier | M | FK to episode table. |
| `time_step` | int32, required | `0..episode.max_steps-1` | M | Strictly contiguous within episode. |
| `transition_id` | UUID/string, required | globally unique | M | Primary key. |
| `topology_id` | string, required | immutable topology instance | M | FK to topology table; split grouping key. |
| `scenario_family` | enum, required | registry value such as `credential_compromise`, `file_collection`, `lateral_movement`, `malware`, `benign_alert` | D0/M | Stratification field; registry is versioned. |
| `current_state_id` | string, required | content-addressed state key | M | FK to state snapshot at `t`. |
| `current_state` | struct, required | state schema below | mixed | Pre-action world snapshot. |
| `observed_evidence` | list<evidence>, required | may be empty | D0 | Evidence available before decision. |
| `attacker_strategy_gt` | struct, nullable | strategy schema below | S | Oracle strategy; null for genuinely benign episodes. |
| `defender_action` | struct, required | action schema below, including `NO_OP` | D0 | Action actually selected/executed. |
| `action_prerequisites` | list<string>, required | registry prerequisite IDs | D0 | Requirements evaluated at `t`. |
| `prerequisites_satisfied` | bool, required | true/false | D0 | Evaluated before execution. |
| `approval_tier` | enum, required | `TIER_1_AUTOMATIC`, `TIER_2_HUMAN_REVIEW`, `TIER_3_MANUAL_ONLY` | D0 | Required policy tier. |
| `approval_status` | enum, required | `NOT_REQUIRED`, `REQUESTED`, `APPROVED`, `DENIED`, `TIMED_OUT` | D0 | State when transition occurs. |
| `action_effectiveness` | float32, nullable | `[0,1]` | S/D1 | Realized causal fraction in simulator; null if not executed/not applicable. It is an outcome, not a decision-time feature. |
| `transition_random_draw_id` | string, required | opaque RNG trace key | S/M | Enables exact replay without leaking draws. |
| `next_state_id` | string, required | content-addressed state key | M | FK to post-transition state. |
| `next_state` | struct, required | state schema below | D1/S | Post-action/post-attacker world snapshot. |
| `next_observation` | list<evidence>, required | may be empty | D1 | Evidence emitted after the transition. |
| `remaining_attack_path_exposure` | float32, required | `[0,1]` | D1 label | Criticality-weighted reachable malicious goals divided by predeclared maximum. |
| `legitimate_workflow_disruption` | float32, required | `[0,1]` | D1 label | Weighted fraction of legitimate service demand that missed its SLO during the transition window. |
| `attack_outcome` | enum, required | `NO_ATTACK`, `ATTACK_PROGRESS`, `ATTACK_SUCCESS`, `CONTAINED`, `PARTIALLY_CONTAINED` | D1/S | Derived from state predicates, never sampled directly. |
| `response_reversible` | bool, required | registry/present state | D0 | Whether the applied state change has a modeled rollback. |
| `recovery_cost` | float32, required | `>=0`, declared normalized cost units | D1 label | Resources/time consumed to restore legitimate capability; zero only if none. |
| `incident_unresolved` | bool, required | true/false | D1 label | True unless benign adjudication or containment/terminal resolution predicate holds. |
| `terminal` | bool, required | true/false | D1 | Episode ends after this row. |
| `terminal_reason` | enum, nullable | `ATTACK_SUCCESS`, `CONTAINED`, `BENIGN_RESOLVED`, `MAX_STEPS`, `IRRECOVERABLE_FAILURE` | D1 | Required iff terminal. |
| `ground_truth_incident_label` | enum, required | `TRUE_POSITIVE`, `FALSE_POSITIVE`, `TRUE_NEGATIVE`; reserve `FALSE_NEGATIVE` for detection-study joins | S | Episode-level oracle label; constant within episode. |
| `evidence_source` | list<source_ref>, required | source IDs and simulator component | M | Provenance for observations. |
| `label_provenance` | struct, required | rule IDs, state fields, generator version | M | Exact derivation trace for every label. |
| `verification_status` | enum, required | `UNVERIFIED`, `SIMULATOR_VERIFIED`, `REPLAY_VERIFIED`, `HUMAN_REVIEWED`, `REJECTED` | M | Quality gate; synthetic verification is not operational validation. |
| `split` | enum, nullable before release | `TRAIN`, `VALIDATION`, `TEST` | M | Assigned by group manifest, never row-random. |

## State snapshot

`current_state` and `next_state` share the same shape. To enforce observability, materialization creates two views: `*_defender_view` and `*_oracle_view`.

| Field | Type | Range / constraints | Visibility |
|---|---|---|---|
| `active_nodes` | list<string> | topology node IDs | D0/D1 |
| `service_health` | map<string,float32> | each `[0,1]` | D0/D1 |
| `identity_status` | map<string,enum> | `ACTIVE`, `CHALLENGED`, `REVOKED`, `DISABLED` | D0/D1 |
| `control_status` | map<string,enum> | `ON`, `DEGRADED`, `OFF`, `PENDING` | D0/D1 |
| `observed_compromise_probability` | map<string,float32> | each `[0,1]`; Bayesian belief, not oracle truth | D0/D1 |
| `observed_reachable_paths` | list<string> | paths inferable from defender knowledge | D0/D1 |
| `workflow_demand` | map<string,float32> | non-negative normalized demand | D0/D1 |
| `workflow_slo_met` | map<string,bool> | observed SLO status | D0/D1 |
| `attacker_footholds_gt` | list<string> | topology node IDs | S |
| `attacker_capabilities_gt` | list<string> | strategy registry values | S |
| `compromised_nodes_gt` | list<string> | topology node IDs | S |
| `reachable_attack_paths_gt` | list<string> | oracle path IDs | S |
| `attack_goal_progress_gt` | float32 | `[0,1]` | S |

No oracle field may be copied into a defender view. Belief fields must be computed only from evidence available at or before the relevant step.

## Nested records

### `evidence`

`evidence_id:string`, `event_tick:int32`, `source_id:string`, `evidence_type:enum`, `value:typed union`, `confidence:float32 [0,1]`, `quality:enum {DIRECT, INFERRED, ASSUMED}`, and `available_to_defender:bool`. For `observed_evidence`, the final flag must be true and `event_tick <= time_step`.

### `attacker_strategy_gt`

`strategy_id:enum`, `objective:enum`, `risk_tolerance:float32 [0,1]`, `adaptation_policy_id:string`, `current_tactic:enum`, `target_preferences:map<string,float32>` with non-negative weights summing to 1, and `knowledge_scope:enum`. This struct is simulator-only.

### `defender_action`

`action_id:string`, `action_type:enum`, `target_ids:list<string>`, `parameters:map<string,typed value>`, `requested_tick:int32`, `executed_tick:int32|null`, `execution_status:enum {NOT_REQUESTED, PENDING, EXECUTED, FAILED, PARTIAL, DENIED}`, `policy_rule_id:string`, and `selection_propensity:float32|null (0,1]`. Propensity is required for stochastic behavior policies and supports later off-policy evaluation; it is not an outcome label.

### Provenance records

`source_ref` contains `source_id`, `source_type`, and `source_version`. `label_provenance` contains `derivation_rule_ids:list<string>`, `input_state_hashes:list<string>`, `counterfactual:false`, and `synthetic:true`. Any future real observation must use a different source type and cannot silently replace synthetic data.

## Relational companion tables

- **episodes:** `episode_id`, seed, scenario family, ground-truth label, attacker strategy ID, topology ID, start state ID, horizon, terminal reason, generator/config versions.
- **topologies:** topology graph, asset criticality, identity/service/business dependencies, workflow definitions, topology family and generation seed. Immutable and content-addressed.
- **states:** normalized snapshots keyed by `state_id`; enables continuity/hash validation without duplicating large graphs.
- **action_registry:** action types, parameter schemas, prerequisites, tier, reversibility, delay/failure distributions, targets, and versioned semantics.
- **counterfactuals (optional, separate):** `(transition_id, candidate_action, next_state_distribution, rollout_count, oracle_expected_outcomes)`. Never mix rollouts with factual transitions or train/test groups.
- **split_manifest:** dataset release, topology IDs, episode IDs, assigned split, assignment seed, stratification diagnostics, and integrity hashes.

## Outcome derivation

Labels are computed after the simulator applies the action and attacker/environment kernels:

1. Validate approval/prerequisites; sample execution delay, failure, and partial effectiveness from declared mechanisms.
2. Apply action effects to controls, identities, nodes, and workflows.
3. Let the attacker observe what its strategy permits, adapt, and choose a tactic.
4. Apply stochastic environment/attacker transition to produce `S_t+1`.
5. Generate `next_observation` from `S_t+1` through sensor detection/noise models.
6. Compute exposure by enumerating oracle-reachable goal paths in `S_t+1` with fixed criticality weights.
7. Compute disruption from simulated workflow demand and achieved service, not action cost.
8. Derive success/containment/unresolved and terminal status from explicit state predicates.
9. Record realized recovery work from rollback/repair transitions.

Action cost may remain a decision-time resource constraint, but it cannot define the consequence label. Every derived label stores its rule ID and state hashes.

## Validation invariants

- Unique `(episode_id,time_step)` and `transition_id`; contiguous steps.
- State continuity across consecutive rows and no rows after terminal.
- Stable topology/scenario/oracle label within an episode.
- No `D1` or `S` field in released time-`t` feature manifests.
- Valid enum/range/foreign-key checks; normalized probability maps.
- Terminal reason iff terminal; effectiveness null unless execution occurred.
- Split manifest contains disjoint episode and topology IDs as required.
- Re-running the transition with recorded seed/config reproduces state hashes.
