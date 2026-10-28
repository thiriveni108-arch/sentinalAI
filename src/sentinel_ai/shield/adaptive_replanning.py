"""Belief-conditioned, simulator-only sequential replanning."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .adaptive_planner import ActionSpec, make_problem, solve_exact
from .beliefs import BayesianAttackerBeliefTracker
from .consequence_predictor import ConsequencePredictor
from .consequence_simulator import MultiStepConsequenceEnvironment, SimulatedAction
from .dynamic_models import Evidence


@dataclass(frozen=True)
class ReplanningStep:
    tick: int
    action: str
    continuation_policy: str
    predicted_objective: float
    belief_entropy: float
    visible_observation: dict[str, float]
    actual_exposure: float
    actual_disruption: float
    actual_recovery: float
    severe: bool
    contained: bool


def _visible(observation) -> dict[str, float]:
    return {"state_tick": observation.tick, "service_health": observation.service_health,
            "observed_compromise": observation.observed_compromise,
            "observed_malicious_activity": float(observation.observed_malicious_activity),
            "evidence_count": observation.evidence_count}


def _evidence(observation) -> tuple[Evidence, ...]:
    kind = ("POST_ACTION_MALICIOUS_ACTIVITY" if observation.observed_malicious_activity
            else "POST_ACTION_NO_CONFIRMED_ACTIVITY")
    return (Evidence(f"phase7-{observation.tick}", observation.tick, "phase7-visible-sensor",
                     kind, observation.observed_malicious_activity, .75,
                     available_to_defender=True),)


def run_adaptive_episode(predictor: ConsequencePredictor, family: str, seed: int,
                         actions: tuple[ActionSpec, ...], policies: tuple[str, ...],
                         steps: int = 5, allowed_tier: str = "automatic",
                         approvals: frozenset[str] = frozenset()) -> dict:
    """Plan and act only inside ``MultiStepConsequenceEnvironment``."""
    environment = MultiStepConsequenceEnvironment(family, seed, max_steps=steps)
    tracker = BayesianAttackerBeliefTracker(); tracker.initialize(f"phase7-{seed}")
    records, completed = [], frozenset()
    for _ in range(steps):
        observation = environment.observe()
        posterior = tracker.update_evidence(f"phase7-{seed}", observation.tick, _evidence(observation))
        problem = make_problem(predictor, _visible(observation), actions, policies,
                               allowed_tier=allowed_tier, approvals=approvals,
                               completed_controls=completed, belief_entropy=posterior.normalized_entropy)
        plan = solve_exact(problem)
        if not plan.feasible: break
        transition = environment.step(SimulatedAction(plan.action, approved=plan.action in approvals or
                                                       allowed_tier != "human-approval"))
        records.append(ReplanningStep(observation.tick, plan.action, plan.policy, plan.objective,
                                      posterior.normalized_entropy, _visible(observation), transition.exposure,
                                      transition.disruption, transition.recovery_cost,
                                      transition.severe_outcome_gt, transition.genuinely_contained_gt))
        completed = completed | {plan.action}
        if environment.state.terminal: break
    return {"advisory_only": True, "simulator_only": True,
            "belief_probabilities_empirically_calibrated": False,
            "steps": [asdict(item) for item in records],
            "actual": {"cumulative_exposure": sum(r.actual_exposure for r in records),
                       "cumulative_disruption": sum(r.actual_disruption for r in records),
                       "recovery_cost": sum(r.actual_recovery for r in records),
                       "severe_outcome": any(r.severe for r in records),
                       "contained": any(r.contained for r in records)}}


def run_static_episode(predictor: ConsequencePredictor, family: str, seed: int,
                       actions: tuple[ActionSpec, ...], policies: tuple[str, ...], steps: int = 5) -> dict:
    """One initial plan, held fixed; diagnostic comparator for adaptive planning."""
    environment = MultiStepConsequenceEnvironment(family, seed, max_steps=steps)
    plan = solve_exact(make_problem(predictor, _visible(environment.observe()), actions, policies))
    transitions = []
    for _ in range(steps):
        transitions.append(environment.step(SimulatedAction(plan.action)))
        if environment.state.terminal: break
    return {"action": plan.action, "policy": plan.policy, "predicted_objective": plan.objective,
            "actual": {"cumulative_exposure": sum(x.exposure for x in transitions),
                       "cumulative_disruption": sum(x.disruption for x in transitions),
                       "recovery_cost": sum(x.recovery_cost for x in transitions),
                       "severe_outcome": any(x.severe_outcome_gt for x in transitions),
                       "contained": any(x.genuinely_contained_gt for x in transitions)}}
