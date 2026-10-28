"""Reproducible simulator-only Phase 8 authority demonstration."""
from __future__ import annotations
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from sentinel_ai.shield.autonomous_defense import Actor, DefenseCoordinator, DefenseStore, Proposal
from sentinel_ai.shield.consequence_simulator import MultiStepConsequenceEnvironment

def proposal(incident, action, **more):
    value=dict(incident_id=incident,action=action,targets=("simulated-session",),state_version=0,
      planner_source="classical",prediction={"target_cumulative_disruption":.1,"operationally_suitable":True},uncertainty=.1)
    value.update(more); return Proposal(**value)
def main():
    with TemporaryDirectory() as directory:
        c=DefenseCoordinator(DefenseStore(Path(directory)/"phase8.sqlite"))
        one=c.propose(proposal("tier1","REQUIRE_FRESH_MFA"),"tier1",MultiStepConsequenceEnvironment("credential-compromise",7301)); one=c.execute(one["proposal_id"])
        two=c.propose(proposal("tier2","REVOKE_SESSION",uncertainty=.4),"tier2",MultiStepConsequenceEnvironment("credential-compromise",7302)); two=c.approve(two["proposal_id"],Actor("analyst","analyst"),"approve")
        three=c.propose(proposal("tier3","ISOLATE_DEVICE",reversible=False,target_criticality=5),"tier3",MultiStepConsequenceEnvironment("credential-compromise",7303))
        print(json.dumps({"simulator_only":True,"tier1":one["status"],"tier2":two["status"],"tier3":three["status"],"quantum_and_classical_policy_equivalence":"planner_source is not used by PolicyEngine"},indent=2))
if __name__=="__main__":main()
