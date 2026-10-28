from __future__ import annotations

import pytest

from sentinel_ai.shield.continuous_learning import ExperienceStore, LearningCoordinator, experience_from_environment, experience_from_phase8_record
from sentinel_ai.shield.qrl import ClassicalQRLPolicy, PolicyRegistry, ShieldRLEnvironment


def completed_episode(seed=1):
    env=ShieldRLEnvironment(); observation,_=env.reset(seed)
    done=False
    while not done: observation,_,terminated,truncated,_=env.step(0); done=terminated or truncated
    return experience_from_environment(env,f"episode-{seed}","ESCALATED")


def test_experience_validation_deduplication_and_censoring(tmp_path):
    store=ExperienceStore(tmp_path/"memory.sqlite"); valid=completed_episode()
    assert store.ingest(valid).eligible and store.ingest(valid).fingerprint==store.ingest(valid).fingerprint
    assert len(store.history())==1
    rejected={**completed_episode(2),"status":"REJECTED"}; result=store.ingest(rejected)
    assert not result.eligible and "censored approval outcome" in result.reasons


def test_registry_requires_model_governor_and_rolls_back():
    registry=PolicyRegistry(); registry.register("candidate",ClassicalQRLPolicy(),"PENDING_APPROVAL")
    with pytest.raises(PermissionError): registry.approve_for_simulation("candidate","x","analyst")
    registry.approve_for_simulation("candidate","governor","model_governor"); registry.activate("candidate","governor","model_governor")
    assert registry.get("candidate")["stage"]=="ACTIVE_SIMULATION"
    assert registry.rollback("governor","model_governor")[0]=="candidate"


def test_learning_cycle_skips_without_eligible_experiences_and_drift_is_not_promotion(tmp_path):
    store=ExperienceStore(tmp_path/"memory.sqlite"); coordinator=LearningCoordinator(store)
    skipped=coordinator.run(minimum_episodes=1)
    assert skipped["state"]=="SKIPPED" and store.drift()["status"]=="insufficient_data"


def test_phase8_feedback_conversion_preserves_single_step_limitation(tmp_path):
    record={"proposal_id":"p","status":"VERIFIED","feedback":{"episode_id":"e","incident_id":"i","executed_action":"REVOKE_SESSION","approval_status":"approved","observable_pre_action":{"tick":0,"service_health":1,"observed_compromise":.5,"observed_malicious_activity":True,"evidence_count":1},"observable_post_action":{"tick":1,"service_health":.9,"observed_compromise":.3,"observed_malicious_activity":False,"evidence_count":2},"actual":{"exposure":.2,"disruption":.1,"recovery_cost":.05,"genuinely_contained_gt":False,"severe_outcome_gt":False}}}
    store=ExperienceStore(tmp_path/"memory.sqlite"); episode=experience_from_phase8_record(record)
    assert episode["limitations"] and store.ingest(episode).eligible
