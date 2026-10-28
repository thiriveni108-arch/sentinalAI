# SHIELD Phase 8: policy-governed autonomous defense and self-recovery

## Scope

Phase 8 is a simulator-only control plane around existing Phase 7 proposals. It
does not import a production response adapter and the executor rejects direct
calls without a coordinator-issued private permit. Model source (`classical`,
`qaoa`, or future agent) is recorded but never affects authority.

## Lifecycle and authority

`DefenseCoordinator` persists proposals, decisions, approvals, executions,
feedback and chronological events in a SQLite store. Valid lifecycle transitions
are enforced: `PROPOSED → POLICY_EVALUATED → AUTO_AUTHORIZED | PENDING_ANALYST |
PENDING_HUMAN → AUTHORIZED → READY → EXECUTING → EXECUTED → VERIFYING →
VERIFIED | RECOVERY_PENDING | ESCALATED`. Invalid jumps and duplicate approvals
fail. Idempotency keys return the original proposal rather than duplicate effects.

The deterministic policy engine fails closed if target, recovery, planner or
prediction reliability context is missing. Tier 1 requires an explicit allowlist,
narrow scope, reversibility, recovery plan, strict predicted disruption limit and
`operationally_suitable=true`; an OOD or uncertain prediction can only restrict
autonomy. Tier 2 needs an `analyst`; Tier 3 requires `human_authorizer` and never
executes merely due to model confidence. Approval binds incident/action/targets,
state version, policy version and expiry. The coordinator re-reads the simulator
observation and policy before execution; a changed state blocks execution.

## Execution, verification, recovery, feedback

`SimulatorExecutor` applies only `MultiStepConsequenceEnvironment` actions. It
captures defender-visible pre/post observations and separately retains simulator
ground truth in `evaluation_ground_truth`. An executed action, effective action,
containment and resolution are distinct fields. Recovery needs a pending recovery
state and analyst/human review. Rollback is blocked if visible malicious activity
remains or simulator severe outcome is present; it never follows lease expiry
automatically.

The versioned `FeedbackRecord` is Phase 9 offline-QRL-ready only. It separates
defender observations, belief/prediction metadata, approval and execution facts,
actual simulator outcomes, evidence provenance and evaluation-only ground truth.
No QRL training is performed.

`observe_and_replan` is the bounded Phase 3/Phase 7 integration point. It turns
only visible simulator activity into tracker evidence, recalculates a Phase 7
recommendation, and returns it marked `requires_new_policy_authorization=true`.
It does not recursively execute or reuse an earlier approval.

## Operator API

The existing FastAPI workspace exposes:

- `POST /api/shield/autonomous/proposals`
- `GET /api/shield/autonomous/proposals/{proposal_id}`
- `POST /api/shield/autonomous/proposals/{proposal_id}/approval`
- `POST /api/shield/autonomous/proposals/{proposal_id}/execute`

All endpoints are explicitly simulated; controls invoke coordinator validation,
not frontend-only state. A full UI panel remains future work; the API returns
current state, decision, approval, execution, feedback and audit history for a
SHIELD workspace integration.

## Limitations

The simulator itself remains bounded and synthetic. State is kept in process, so
an interrupted process fails closed rather than reconstructing a live simulator.
Belief updates/replanning remain supported by Phase 7 but are not automatically
re-entered from Phase 8 after an escalation; this prevents uncontrolled recursive
execution. Recovery is deliberately conservative and has no automatic expiry
restore. None of this establishes real-world efficacy or quantum advantage.

Reproduce:

```powershell
$env:PYTHONPATH='src;.'
.\.venv\Scripts\python.exe scripts\demo_phase8_autonomous_defense.py
.\.venv\Scripts\python.exe -m pytest tests/unit/test_phase8_autonomous_defense.py
```
