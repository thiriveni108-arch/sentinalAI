# SHIELD Phase 10 — controlled experience-based learning

Phase 10 closes the simulator-only lifecycle: verified simulated response trajectories enter a durable experience store; validation marks their training eligibility; a serialized learning cycle uses history for audit/coverage and fresh controlled trajectories for on-policy updates; independent held-out evaluation determines whether a candidate can await human model-governance approval.

## Safety boundary

`ExperienceStore` preserves rejected, expired, incomplete, duplicate, and incompatible records with their exclusion reasons. Oracle simulator ground truth is stored only as outcome provenance and is never returned as a QRL observation. Pending/rejected approvals cannot be recorded as executed actions.

The learning cycle does not replay arbitrary historical transitions into REINFORCE gradients. Existing classical and four-qubit hybrid QRL policies are trained only on fresh graph-aware simulator trajectories. Phase 8 still classifies every recommendation and remains the only component that can authorize, execute, verify, or recover a simulated control.

## Governance

The existing QRL `PolicyRegistry` now supports `TRAINED`, `VALIDATION_FAILED`, `PENDING_APPROVAL`, `APPROVED_FOR_SIMULATION`, `ACTIVE_SIMULATION`, `ROLLED_BACK`, and archival states. Reward alone cannot promote a policy: the candidate must meet severe-outcome, disruption, held-out reward, and reproducibility criteria. A server-validated governance token is required by the API approval, activation, and rollback endpoints; client role fields are not trusted.

Activation is simulator-recommendation-only, preserves the previous policy for rollback, and changes neither Phase 8 authority policy nor incidents already in flight.

## Demonstration and results

The Phase 10 demonstration accumulated three complete graph-aware simulator trajectories, validated and persisted them, then ran fresh-on-policy classical and four-qubit hybrid candidate cycles. Both produced `VALIDATION_FAILED`; this is the expected safe result under insufficient evidence of improvement. A separately labelled controlled fixture demonstrated human-governed simulation activation and rollback; it is explicitly not performance promotion. Drift monitoring returned observations for investigation only and never activated a policy.

Focused tests cover trajectory validation/deduplication/censoring, skipped cycles, governance approval/rollback, QRL probabilities, and Phase 8 authority. All actions remain simulated.

## APIs

The existing API now exposes experience history/ingestion, learning-cycle initiation/status, policy metadata, and governance-gated approval/activation/rollback under `/api/shield/learning/*`. The learning-cycle endpoint can create candidates but cannot grant them security authority.

## Limitations

Experience volume and topology diversity are synthetic and small. The policy registry is process-local in the current research workspace; durable model artifact storage and independent final-evaluation rotation are required before any broader simulator study. No online production learning, automated promotion, real CERT-to-response mapping, or quantum advantage is claimed.
