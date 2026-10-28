# SHIELD-ACT v2 dataset generation methodology

## Experimental target

Generate approximately 500 independent episodes and 5,000 factual chronological transitions after the simulator milestone passes its tests. Counts are planning targets, not quotas. An episode may terminate early; no rows should be cloned or padded to hit 5,000.

The unit of independence is the episode generated from a sampled topology/scenario/strategy seed—not the transition row. Repeated time steps are correlated and must remain grouped.

## Factor design

Use a preregistered, seeded coverage matrix and adapt sampling only to fill missing cells, recording all acceptance/rejection decisions.

- **Threat families:** credential compromise, file collection/exfiltration, lateral movement, malware/service compromise, and benign/false-positive investigation. Add families only when their transition semantics are implemented and tested.
- **Attacker strategies:** at least 2–4 applicable strategies per malicious family, including alternate-route adaptation and stealth. Benign episodes have no attacker strategy.
- **Topologies:** multiple topology families (e.g., hub-and-spoke, segmented, multi-route) with independently sampled instances, sizes, business dependencies, identities, controls, and critical assets.
- **Actions:** targeted restrictions, session revocation, MFA challenge, privilege removal, segmentation/isolation, export restriction, account disable, rollback/recovery, and `NO_OP`, subject to applicability and policy.
- **Action results:** executed success, partial effect, failure, denial, and delay. Do not force outcomes after the fact; tune documented mechanisms if pilot coverage is poor.
- **Outcomes:** success, progress, partial containment, containment, benign resolution, and unresolved-at-horizon; include both low and high measured workflow disruption.
- **Incident labels:** true-positive and false-positive episodes are required. “Unresolved” is a temporal outcome, not a truth class. True negatives may be included for observation baselines. False negatives require a separate detection trigger study because SHIELD response cannot select an action for an incident it never receives.

A reasonable starting allocation is 100 topology instances with about five episodes each and a median ten transitions, while allowing uneven lengths and family-specific applicability. Prefer more independent topologies/episodes over longer rollouts when compute is constrained.

## Generation procedure

1. Freeze schema, action/strategy/scenario registries, topology generator, transition rules, outcome definitions, and root seed in a release manifest.
2. Generate a topology bank first and assign topology groups to splits before episode rollout.
3. Sample episode factors from the coverage matrix. Store sampling probabilities and seeds.
4. Initialize oracle state and defender observation separately. For malicious episodes, sample attacker strategy only into oracle state.
5. At every step, compute defender features from current/past observations only. Select an action through a mixture of safe policy behavior: policy-recommended actions, approved exploratory alternatives, and `NO_OP`. Log selection propensity where known.
6. Enforce the three-tier policy. Simulation can record denied/manual actions but must not relabel them as executed.
7. Execute the simulator transition, produce next observation, derive labels from next state, validate invariants, and append one factual row.
8. End only on declared terminal predicates or horizon. Retain unresolved horizon episodes rather than converting them to negative/contained.
9. Replay a sample (target 10% of episodes plus all anomalous validation failures) and compare state hashes.
10. Publish an immutable dataset card, schema, release manifest, split manifest, factor counts, exclusions, and integrity hashes.

Counterfactual rollouts, if generated later, use independent RNG branches and the separate counterfactual table. They cannot inflate factual transition counts and cannot cross episode/topology split boundaries.

## Split strategy

Assign splits before simulation using group keys, approximately 70/15/15 by episode count while prioritizing topology isolation:

- **Train:** topology instances and all their episodes allocated to training.
- **Validation:** different topology instances, used for model/hyperparameter/threshold selection.
- **Test:** sealed topology instances and episodes never used in selection.

No `episode_id` may occur in more than one split. Prefer no `topology_id` overlap at all. If topology families are few, hold out instances within every family for the primary test and add a secondary **family-OOD** test that holds out an entire topology family or threat family; report these separately. All steps, factual/counterfactual branches, and derived windows from one episode inherit its split.

Run automated leakage checks for:

- episode/topology/state/transition ID overlap;
- exact and near-identical initial-state hashes across splits;
- duplicated transition feature vectors with shared generator seeds;
- future/post-action/oracle fields in feature manifests;
- preprocessing fit outside training only;
- registry/config information inadvertently encoding split or outcome;
- counterfactual siblings separated across splits.

Near-duplicate checks should compare canonical graph hashes and a declared topology/state distance, with thresholds fixed before model evaluation.

## Quality and diversity gates

Do not release merely because row count is met. Require:

- at least the preregistered minimum number of independent episodes and topology instances per reported stratum;
- no single family, strategy, action, or topology family dominating without documented weighting;
- sufficient examples of partial/failed actions, unresolved episodes, false positives, and both disruption bands;
- outcome distributions produced by mechanisms rather than label resampling;
- unique-state/transition ratios and duplicate multiplicities reported;
- all schema, replay, chronology, observability, and split tests passing;
- confidence intervals clustered or bootstrapped at episode/topology level, not row level.

Pilot runs may reveal infeasible cells. Document and revise mechanisms or targets transparently; never duplicate rows or directly flip labels to balance a cell.

## Evaluation protocol for later modeling

Freeze task-specific feature/label manifests. Fit all scalers, encoders, feature selection, calibration, and thresholds on training/validation only. Use episode/topology-aware metrics and confidence intervals. Compare future VQC models against transparent rules, logistic/linear models, trees, and suitable sequence baselines using identical splits and budgets. Report discrimination, calibration, per-family/per-action performance, unresolved handling, and operational utility. Do not claim quantum advantage without controlled resource-matched evidence.

Synthetic transition quality establishes simulator consistency, not real operational effectiveness. External validation and monitored deployment evidence would be separate later stages.

## Clearly defined next implementation milestone

**Milestone M2: v2 simulator contract and pilot, pending review approval.**

After review—and not as part of this task—implement the typed v2 state/action/transition contracts, a deterministic episode runner, dynamic reachability, one business workflow model, post-action observations, and explicit terminal rules. Support two threat families plus one benign/false-positive family, at least two topology instances per family, and partial/failing action execution. Add invariant and replay tests, then generate a **small pilot of 10–20 episodes only** to validate schema, chronology, observability separation, outcome derivation, and split tooling.

Exit criteria: all simulator tests pass; pilot transitions validate against the schema; replay hashes match; no oracle/future fields appear in defender views; disruption is state-derived; and a pilot audit demonstrates genuine state/action/outcome variation. Stop for review before scaling toward 500 episodes or training any model.
