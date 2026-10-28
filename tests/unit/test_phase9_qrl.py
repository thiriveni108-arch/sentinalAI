import numpy as np
from sentinel_ai.shield.qrl import (ACTIONS, ClassicalQRLPolicy, HybridQuantumQRLPolicy, ReplayBuffer, ShieldRLEnvironment, masked_softmax, phase8_proposal_from_recommendation)
from sentinel_ai.shield.autonomous_defense import PolicyEngine

def test_environment_is_reproducible_and_hides_oracle():
    a,b=ShieldRLEnvironment(),ShieldRLEnvironment(); oa,ia=a.reset(42,"credential-compromise"); ob,ib=b.reset(42,"credential-compromise")
    assert oa==ob and ia["ground_truth_exposed"] is False and len(oa)==15
    _,ra,_,_,infoa=a.step(ACTIONS.index("REQUIRE_FRESH_MFA")); _,rb,_,_,_=b.step(ACTIONS.index("REQUIRE_FRESH_MFA"))
    assert ra==rb and infoa["oracle_available_to_policy"] is False

def test_high_impact_action_becomes_pending_not_executed():
    env=ShieldRLEnvironment(); env.reset(1); _,_,_,_,info=env.step(ACTIONS.index("ISOLATE_DEVICE"))
    assert info["result"]["approval"]=="pending"
    assert env.action_mask()[ACTIONS.index("NO_OP")]
    _,reward,_,_,resolved=env.step(ACTIONS.index("NO_OP")); assert resolved["result"]["approval"]=="rejected" and reward < -1
    assert not env.action_mask()[ACTIONS.index("REQUEST_HUMAN_REVIEW")]

def test_benign_episode_does_not_reward_unnecessary_restriction():
    env=ShieldRLEnvironment(); env.reset(2,"benign"); _,reward,_,_,_=env.step(ACTIONS.index("DISABLE_BULK_EXPORT"))
    assert reward < 0 and env.env.state.attacker_capability_gt is False

def test_masked_probabilities_and_classical_learning():
    p=masked_softmax([1,3,2],[True,False,True]); assert np.isclose(p.sum(),1) and p[1]==0
    policy=ClassicalQRLPolicy(); report=policy.train(ShieldRLEnvironment(),episodes=4); assert len(report["returns"])==4
    r=policy.recommend_response((0.,)*15,action_constraints=[True]*len(ACTIONS)); assert r.advisory_only

def test_quantum_gradient_and_probability_are_finite():
    policy=HybridQuantumQRLPolicy(); gradient=policy.quantum_gradient((.1,)*15)
    assert gradient.shape==(1,4,3) and np.isfinite(gradient).all()
    result=policy.recommend_response((.1,)*15,action_constraints=[True]*len(ACTIONS)); assert np.isclose(sum(result.probabilities),1)

def test_replay_deduplicates_simulated_only():
    env=ShieldRLEnvironment(); env.reset(9); env.step(0); replay=ReplayBuffer(); replay.extend(env.export_trajectory()); replay.extend(env.export_trajectory())
    assert replay.export()["count"]==1

def test_qrl_proposal_cannot_grant_itself_automatic_authority():
    rec=ClassicalQRLPolicy().recommend_response((.1,)*15,action_constraints=[True]*len(ACTIONS))
    proposal=phase8_proposal_from_recommendation(rec,"incident",("target",),0,{"target_cumulative_disruption":.1})
    assert PolicyEngine().evaluate(proposal).tier.name != "AUTOMATIC"
