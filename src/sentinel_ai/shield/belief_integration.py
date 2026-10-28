"""Composition layer connecting the Bayesian tracker to Phase 2 observations."""

from __future__ import annotations

from dataclasses import dataclass

from .beliefs import BayesianAttackerBeliefTracker, BeliefState
from .dynamic import DynamicShieldEnvironment
from .dynamic_models import DefenderAction, DefenderObservation, EpisodeGroundTruth, TransitionRecord


@dataclass(frozen=True)
class BeliefTrackedTransition:
    transition: TransitionRecord
    posterior: BeliefState


class BeliefTrackedDynamicEnvironment:
    """Updates beliefs from ``observe()`` only; oracle access is never used internally."""

    def __init__(self, environment: DynamicShieldEnvironment | None = None,
                 tracker: BayesianAttackerBeliefTracker | None = None) -> None:
        self.environment = environment or DynamicShieldEnvironment()
        self.tracker = tracker or BayesianAttackerBeliefTracker()

    def reset(self, scenario_family: str, seed: int = 0, episode_id: str | None = None) -> tuple[DefenderObservation, BeliefState]:
        observation = self.environment.reset(scenario_family, seed, episode_id)
        self.tracker.initialize(observation.episode_id)
        posterior = self.tracker.update(observation)
        return observation, posterior

    def step(self, action: DefenderAction) -> BeliefTrackedTransition:
        transition = self.environment.step(action)
        posterior = self.tracker.update(self.environment.observe())
        return BeliefTrackedTransition(transition, posterior)

    def ground_truth_for_evaluation(self) -> EpisodeGroundTruth:
        """Explicit evaluation-only oracle; the tracker never calls this method."""
        return self.environment.ground_truth()
