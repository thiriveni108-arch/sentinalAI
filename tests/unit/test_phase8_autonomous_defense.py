from sentinel_ai.shield.autonomous_defense import Actor, DefenseCoordinator, DefenseStore, Proposal, Status
from sentinel_ai.shield.consequence_simulator import MultiStepConsequenceEnvironment

def proposal(action="REQUIRE_FRESH_MFA", **more):
    base=dict(incident_id="incident-1",action=action,targets=("session-1",),state_version=1,planner_source="classical",
              prediction={"target_cumulative_disruption":.1,"operationally_suitable":True},uncertainty=.1)
    base.update(more); return Proposal(**base)

def coordinator(tmp_path): return DefenseCoordinator(DefenseStore(tmp_path/"phase8.db"))

def test_tier1_executes_once_and_records_feedback(tmp_path):
    c=coordinator(tmp_path); r=c.propose(proposal(),"same",MultiStepConsequenceEnvironment("credential-compromise",1))
    assert r["status"]==Status.AUTO_AUTHORIZED
    done=c.execute(r["proposal_id"]); assert done["status"] in {Status.VERIFIED,Status.RECOVERY_PENDING,Status.ESCALATED}
    assert done["feedback"]["version"]=="shield-qrl-feedback-v1"
    assert c.propose(proposal(),"same",MultiStepConsequenceEnvironment("credential-compromise",1))["proposal_id"]==r["proposal_id"]

def test_tier2_requires_authorized_analyst_and_replay_fails(tmp_path):
    c=coordinator(tmp_path); r=c.propose(proposal(uncertainty=.5),"tier2",MultiStepConsequenceEnvironment("credential-compromise",2))
    assert r["status"]==Status.PENDING_ANALYST
    try:c.approve(r["proposal_id"],Actor("bad","human_authorizer"),"approve")
    except PermissionError: pass
    else: assert False
    approved=c.approve(r["proposal_id"],Actor("analyst-1","analyst"),"approve"); assert approved["status"]==Status.AUTHORIZED
    try:c.approve(r["proposal_id"],Actor("analyst-1","analyst"),"approve")
    except ValueError: pass
    else: assert False

def test_tier3_never_autoexecutes_and_executor_cannot_be_called_directly(tmp_path):
    c=coordinator(tmp_path); r=c.propose(proposal("ISOLATE_DEVICE",reversible=False,target_criticality=5),"tier3",MultiStepConsequenceEnvironment("credential-compromise",3))
    assert r["status"]==Status.PENDING_HUMAN
    try:c.execute(r["proposal_id"])
    except ValueError: pass
    else: assert False
    try:c.executor.execute(MultiStepConsequenceEnvironment("credential-compromise",3),proposal(),object())
    except PermissionError: pass
    else: assert False

def test_changed_simulator_state_invalidates_auto_authorization(tmp_path):
    c=coordinator(tmp_path); env=MultiStepConsequenceEnvironment("credential-compromise",4)
    r=c.propose(proposal(),"stale",env); env.step(__import__("sentinel_ai.shield.consequence_simulator",fromlist=["SimulatedAction"]).SimulatedAction("NO_OP"))
    assert c.execute(r["proposal_id"])["status"]==Status.POLICY_BLOCKED
