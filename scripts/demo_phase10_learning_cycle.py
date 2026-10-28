"""Simulator-only Phase 10 end-to-end experience, learning, governance demo."""
from __future__ import annotations
import json, tempfile
from pathlib import Path

from sentinel_ai.shield.continuous_learning import ExperienceStore, LearningCoordinator, experience_from_environment
from sentinel_ai.shield.qrl import ClassicalQRLPolicy, ShieldRLEnvironment
from sentinel_ai.shield.topology import grouped_split


def collect(store):
    for index, topology in enumerate(grouped_split()["train"]):
        env=ShieldRLEnvironment(graph_features=True); observation,_=env.reset(40+index,"credential-compromise",topology=topology)
        done=False
        while not done:
            # Explicit simulator-only reference policy generates verified trajectory.
            observation,_,terminated,truncated,_=env.step(0); done=terminated or truncated
        store.ingest(experience_from_environment(env,f"phase10-demo-{index}"))


def main():
    with tempfile.TemporaryDirectory() as directory:
        store=ExperienceStore(Path(directory)/"experience.sqlite"); collect(store); coordinator=LearningCoordinator(store)
        # A real fresh-on-policy candidate cycle. It may fail; no favorable outcome is assumed.
        failed=coordinator.run("classical",episodes=4,seed=501,minimum_episodes=3)
        hybrid=coordinator.run("hybrid",episodes=2,seed=601,minimum_episodes=3)
        failed_name=failed["policy_name"]
        coordinator.registry.register("explicit-rejected-fixture",ClassicalQRLPolicy(features=19),"VALIDATION_FAILED",{"reason":"controlled inferior-policy fixture"})
        # Controlled governance fixture demonstrates approval/activation/rollback without claiming improvement.
        fixture="governance-fixture"; coordinator.registry.register(fixture,ClassicalQRLPolicy(features=19),"PENDING_APPROVAL",{"fixture":True,"not_performance_promotion":True})
        coordinator.registry.approve_for_simulation(fixture,"governor","model_governor"); coordinator.registry.activate(fixture,"governor","model_governor"); rollback=coordinator.registry.rollback("governor","model_governor")
        report={"version":"shield-phase10-demo-v1","experience_history":store.history(),"cycle":failed,"hybrid_cycle":hybrid,"cycle_candidate_stage":coordinator.registry.get(failed_name)["stage"],"rejected_candidate_stage":coordinator.registry.get("explicit-rejected-fixture")["stage"],
                "governance_fixture":{"activated_then_rolled_back":rollback,"stage":coordinator.registry.get(fixture)["stage"]},"drift":store.drift(),"simulator_only":True}
        target=Path("artifacts/reports/shield_phase10_demo_v1.json"); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(report,indent=2),encoding="utf-8"); print(json.dumps(report,indent=2))


if __name__=="__main__": main()
