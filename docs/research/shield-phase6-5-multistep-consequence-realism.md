# SHIELD Phase 6.5: multi-step consequence realism

## Outcome

Phase 6.5 replaces the weak Phase 6 rollout assumptions with a separately versioned, causally richer research simulator. The frozen Phase 6 dataset, benchmark, and model remain unchanged as historical records. No VQC, quantum kernel, QAOA component, QRL policy, live response path, or continuously trained model was created or modified.

The preregistered 30-condition pilot passed all seven diversity checks, so a full release was generated. The full release contains 6,480 five-step branches from 120 initial conditions, nine candidate actions, and six defender continuation policies. Splits contain 4,374 train, 1,296 validation, and 810 test rows, with zero topology or initial-condition overlap.

## Architectural evolution

The Phase 6 simulator produced constant recovery cost and severe-outcome labels, immediate-only adaptation, and downstream exposure that was a deterministic extension of step one. Rather than altering those frozen results, Phase 6.5 introduces `shield-multistep-consequence-v3.0.0` with:

- explicit recovery tasks with duration, per-step effort, service restoration, and persistent disruption;
- rollback that accelerates legitimate restoration but can reopen attacker routes;
- remediation steps capable of removing attacker capability rather than merely suppressing activity;
- stateless seed/tick/component random draws, ensuring matched counterfactual randomness without action-dependent RNG drift;
- attacker dormancy, accumulated defensive observations, delayed route discovery, and renewed activity;
- distinct temporary suppression and genuine capability removal;
- state-derived severe outcomes for sensitive exfiltration completion, high-progress critical access, critical service failure, or failure to contain high exposure by the simulated deadline;
- approval and prerequisite checks;
- continuation policies restricted to a defender-visible observation contract.

The severe predicates are explicit simulator conditions. Outcome frequencies were not resampled, reweighted, or forced.

## Continuation policies

Six reproducible policies are evaluated:

- observation-only;
- immediate containment;
- minimally disruptive response;
- escalating response;
- evidence-seeking response;
- policy-constrained automatic response.

Policies receive only tick, service health/SLO state, observed compromise, visible malicious activity, evidence count, recovery activity, family, and terminal status. Oracle routes, attacker progress, capabilities, adaptation state, and severe predicates are unavailable to policy logic. Manual isolation and segmentation are withheld by the policy-constrained policy.

## Pilot and full-release results

| Check | Pilot result | Full-release result |
|---|---:|---:|
| Recovery burden | mean 0.3822, 46 values | mean 0.3820, 47 values |
| Delayed adaptation | 871 branches (53.77%) | 3,392 branches (52.35%) |
| Severe outcome | 368 branches (22.72%) | 1,439 branches (22.21%) |
| Containment timing | 4 values, steps 3–6 | 4 values, steps 3–6 |
| Unresolved | 78.70% | 78.40% |
| First-step vs cumulative exposure Spearman | 0.6976 | 0.7049 |
| Short-term Pareto ranking reversals | 1,374 pairs | 5,455 pairs |
| Minimal-disruption security-preserving cases | 84 | 323 |

Full-release target ranges are:

- cumulative exposure: 0.31–4.1472, 3,432 unique values;
- cumulative disruption: 0–3.2889, 108 unique values;
- recovery burden: 0–0.85, 47 unique values;
- delayed adaptation: 52.35% positive;
- severe outcome: 22.21% positive;
- containment time: steps 3, 4, 5, or censored at 6;
- unresolved: 78.40% positive.

Every candidate action has 720 branches and every continuation policy has 1,080. This balance comes from the factorial rollout design, not from altering outcomes.

## Causal examples and ranking changes

Recovery costs arise only while recovery tasks execute or when rollback performs remaining restoration work. In the tested isolation/rollback sequence, isolation lowers service health and creates a three-step task; rollback incurs the outstanding effort, restores service, and reopens an attacker route when capability survives.

Delayed adaptation is not guaranteed. For the reproducible credential-compromise seed 65001, fresh MFA followed by immediate containment has no adaptation on step one, then route adaptation on step three after the attacker accumulates defensive observations.

For the same seed, observation-only NO_OP reaches a severe deadline-derived outcome only on step five. DISABLE_ACCOUNT instead reaches genuine containment on step four without a severe outcome.

The full release includes 5,455 strict Pareto reversals where a branch that looks no worse on both step-one exposure and disruption becomes worse in cumulative exposure and no better in cumulative disruption. It also includes 323 matched cases where the minimally disruptive policy preserves or improves cumulative security exposure while reducing business disruption relative to immediate containment.

## Comparison with frozen Phase 6

| Property | Phase 6 | Phase 6.5 |
|---|---:|---:|
| Recovery-burden values | 1 (always zero) | 47 |
| Severe positives | 0 | 1,439 |
| Delayed adaptations | 0 | 3,392 |
| Containment-time values | 2 | 4 |
| First-step/cumulative exposure Spearman | 1.000 | 0.705 |

Phase 6.5 therefore resolves the specific diversity failures that blocked meaningful downstream research.

## Limitations and Phase 7 recommendation

This remains a bounded synthetic simulator, not an operational digital twin. Recovery dependencies are aggregate rather than a full service graph. Human approval latency is not modeled. Continuation policies are deterministic functions of observations. Severe predicates require external cyber-domain review, and no predictive model has yet been validated on the new release.

Recommendation: Phase 7 is **conditionally research-ready, not operationally ready**. The next step should be a bounded classical formulation study that trains and calibrates predictors on the new frozen splits, propagates uncertainty, validates candidate-action constraints, and tests whether multi-step rankings generalize on held-out topologies. Adaptive QAOA changes should wait until that classical planning objective and its uncertainty behavior are validated. Quantum advantage must not be presumed.

Reproduce with:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\generate_multistep_realism_dataset.py
.\.venv\Scripts\python.exe scripts\analyze_multistep_realism.py
.\.venv\Scripts\python.exe -m pytest tests\unit\test_multistep_consequence_realism.py tests\integration\test_multistep_realism_compatibility.py
```
