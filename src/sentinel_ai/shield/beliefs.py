"""Auditable Bayesian attacker-mode filtering for simulated SHIELD episodes.

Probabilities in this module are outputs of an explicitly assumed synthetic
hidden-Markov model. They are not calibrated real-world attack probabilities.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping, Sequence

from .dynamic_models import DefenderObservation, Evidence


MODEL_VERSION = "shield-bayesian-belief-v1.0.0"
CONFIG_VERSION = "shield-bayesian-assumptions-v1.0.0"


class AttackerMode(StrEnum):
    BENIGN = "BENIGN"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    MALICIOUS_INSIDER = "MALICIOUS_INSIDER"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    SENSITIVE_DATA_EXFILTRATION = "SENSITIVE_DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNKNOWN = "UNKNOWN"


MODES = tuple(AttackerMode)


def _default_priors() -> dict[AttackerMode, float]:
    return {
        AttackerMode.BENIGN: 0.45,
        AttackerMode.CREDENTIAL_COMPROMISE: 0.09,
        AttackerMode.MALICIOUS_INSIDER: 0.09,
        AttackerMode.LATERAL_MOVEMENT: 0.09,
        AttackerMode.SENSITIVE_DATA_EXFILTRATION: 0.09,
        AttackerMode.PRIVILEGE_ESCALATION: 0.09,
        AttackerMode.UNKNOWN: 0.10,
    }


def _default_transition() -> dict[AttackerMode, dict[AttackerMode, float]]:
    matrix = {}
    for source in MODES:
        if source == AttackerMode.UNKNOWN:
            matrix[source] = {target: (0.70 if target == source else 0.05) for target in MODES}
        else:
            matrix[source] = {
                target: (0.84 if target == source else (0.06 if target == AttackerMode.UNKNOWN else 0.02))
                for target in MODES
            }
    return matrix


def _row(benign: float, credential: float, insider: float, lateral: float,
         exfiltration: float, privilege: float, unknown: float) -> dict[AttackerMode, float]:
    return dict(zip(MODES, (benign, credential, insider, lateral, exfiltration, privilege, unknown)))


def _default_likelihoods() -> dict[str, dict[AttackerMode, float]]:
    return {
        "ANOMALOUS_SESSION": _row(.12, .86, .30, .38, .28, .42, .35),
        "SENSITIVE_ACCESS_SPIKE": _row(.08, .24, .88, .30, .62, .25, .40),
        "LATERAL_CONNECTION": _row(.05, .30, .22, .90, .35, .55, .45),
        "BULK_EXPORT": _row(.04, .20, .58, .28, .93, .18, .45),
        "PRIVILEGE_CHANGE": _row(.06, .35, .25, .55, .20, .91, .42),
        "POST_ACTION_MALICIOUS_ACTIVITY": _row(.10, .68, .62, .70, .72, .66, .55),
        "POST_ACTION_NO_CONFIRMED_ACTIVITY": _row(.78, .28, .32, .25, .23, .29, .45),
        "CONTAINMENT_ROUTE_SWITCH": _row(.03, .30, .25, .90, .35, .45, .55),
    }


@dataclass(frozen=True)
class BeliefConfig:
    priors: Mapping[AttackerMode, float]
    transitions: Mapping[AttackerMode, Mapping[AttackerMode, float]]
    observation_likelihoods: Mapping[str, Mapping[AttackerMode, float]]
    unsupported_likelihood: float = 0.04
    unsupported_unknown_likelihood: float = 0.72
    likelihood_floor: float = 1e-300
    version: str = CONFIG_VERSION

    @classmethod
    def default(cls) -> "BeliefConfig":
        return cls(_default_priors(), _default_transition(), _default_likelihoods())


@dataclass(frozen=True)
class BeliefState:
    episode_id: str
    time_step: int
    probabilities: dict[AttackerMode, float]
    normalized_entropy: float
    most_likely_mode: AttackerMode
    model_version: str = MODEL_VERSION
    config_version: str = CONFIG_VERSION


@dataclass(frozen=True)
class BeliefUpdate:
    episode_id: str
    time_step: int
    prior: dict[AttackerMode, float]
    predicted: dict[AttackerMode, float]
    observed_evidence: tuple[Evidence, ...]
    transition_model: dict[AttackerMode, dict[AttackerMode, float]]
    observation_likelihoods: dict[AttackerMode, float]
    posterior: dict[AttackerMode, float]
    normalized_entropy: float
    unsupported_evidence: tuple[str, ...]
    explanation: tuple[str, ...]
    model_version: str = MODEL_VERSION
    config_version: str = CONFIG_VERSION

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _normalize(values: Mapping[AttackerMode, float]) -> dict[AttackerMode, float]:
    total = math.fsum(values.values())
    if not math.isfinite(total) or total <= 0:
        raise ValueError("probabilities must have a finite positive sum")
    result = {mode: float(values[mode] / total) for mode in MODES}
    # Put floating-point residual on the largest entry for an exact sum in exports.
    largest = max(result, key=result.get)
    result[largest] += 1.0 - math.fsum(result.values())
    return result


def _entropy(distribution: Mapping[AttackerMode, float]) -> float:
    value = -math.fsum(p * math.log(p) for p in distribution.values() if p > 0)
    return value / math.log(len(MODES))


class BayesianAttackerBeliefTracker:
    """Finite-state Bayesian filter that consumes defender-visible evidence only."""

    def __init__(self, config: BeliefConfig | None = None) -> None:
        self.config = config or BeliefConfig.default()
        self._validate_config()
        self._state: BeliefState | None = None
        self._history: list[BeliefUpdate] = []

    def initialize(self, episode_id: str, time_step: int = -1,
                   priors: Mapping[AttackerMode, float] | None = None) -> BeliefState:
        probabilities = _normalize(priors or self.config.priors)
        self._history = []
        self._state = self._make_state(episode_id, time_step, probabilities)
        return self._state

    @property
    def current(self) -> BeliefState:
        if self._state is None:
            raise RuntimeError("initialize must be called before retrieving beliefs")
        return self._state

    def update(self, observation: DefenderObservation) -> BeliefState:
        """Update from a defender view; no complete CyberState/oracle input is accepted."""
        if self._state is None:
            self.initialize(observation.episode_id)
        if observation.episode_id != self.current.episode_id:
            raise ValueError("observation episode does not match initialized tracker")
        if observation.time_step <= self.current.time_step:
            raise ValueError("belief observations must be strictly chronological")
        return self.update_evidence(observation.episode_id, observation.time_step, observation.evidence)

    def update_evidence(self, episode_id: str, time_step: int,
                        evidence: Sequence[Evidence] | None) -> BeliefState:
        """Bayes predict/update using an explicit evidence sequence; empty is valid."""
        if self._state is None:
            self.initialize(episode_id)
        if episode_id != self.current.episode_id:
            raise ValueError("evidence episode does not match initialized tracker")
        if time_step <= self.current.time_step:
            raise ValueError("belief updates must be strictly chronological")
        prior = dict(self.current.probabilities)
        predicted = {
            target: math.fsum(prior[source] * self.config.transitions[source][target] for source in MODES)
            for target in MODES
        }
        predicted = _normalize(predicted)
        visible = tuple(item for item in (evidence or ()) if item.available_to_defender)
        likelihoods, unsupported = self._combined_likelihoods(visible)
        posterior = self._stable_posterior(predicted, likelihoods)
        explanations = self._explain(prior, posterior, visible, unsupported)
        state = self._make_state(episode_id, time_step, posterior)
        self._history.append(BeliefUpdate(
            episode_id, time_step, prior, predicted, visible,
            {source: dict(row) for source, row in self.config.transitions.items()},
            likelihoods, posterior, state.normalized_entropy, unsupported, explanations,
            MODEL_VERSION, self.config.version,
        ))
        self._state = state
        return state

    def history(self) -> tuple[BeliefUpdate, ...]:
        return tuple(self._history)

    def export_world_model(self) -> dict[str, object]:
        state = self.current
        return {
            "episode_id": state.episode_id, "time_step": state.time_step,
            "mode_order": [mode.value for mode in MODES],
            "posterior": [state.probabilities[mode] for mode in MODES],
            "normalized_entropy": state.normalized_entropy,
            "model_version": state.model_version, "config_version": state.config_version,
            "calibrated_real_world_probability": False,
        }

    def export_planner_uncertainty(self) -> dict[str, object]:
        state = self.current
        return {
            "most_likely_mode": state.most_likely_mode.value,
            "mode_confidence": state.probabilities[state.most_likely_mode],
            "unknown_probability": state.probabilities[AttackerMode.UNKNOWN],
            "normalized_entropy": state.normalized_entropy,
            "posterior": {mode.value: state.probabilities[mode] for mode in MODES},
            "model_version": state.model_version,
        }

    def _combined_likelihoods(self, evidence: tuple[Evidence, ...]) -> tuple[dict[AttackerMode, float], tuple[str, ...]]:
        if not evidence:
            return {mode: 1.0 for mode in MODES}, ()
        logs = {mode: 0.0 for mode in MODES}
        unsupported = []
        for item in evidence:
            table = self.config.observation_likelihoods.get(item.evidence_type)
            if table is None:
                unsupported.append(item.evidence_type)
                table = {mode: (self.config.unsupported_unknown_likelihood if mode == AttackerMode.UNKNOWN
                                else self.config.unsupported_likelihood) for mode in MODES}
            confidence = min(1.0, max(0.0, float(item.confidence)))
            for mode in MODES:
                base = float(table[mode])
                if (isinstance(item.value, bool) and not item.value
                        and item.evidence_type != "POST_ACTION_NO_CONFIRMED_ACTIVITY"):
                    base = 1.0 - base
                # Low-confidence evidence approaches a neutral likelihood of one.
                adjusted = confidence * base + (1.0 - confidence)
                logs[mode] += math.log(max(self.config.likelihood_floor, adjusted))
        maximum = max(logs.values())
        return {mode: math.exp(logs[mode] - maximum) for mode in MODES}, tuple(unsupported)

    def _stable_posterior(self, predicted: Mapping[AttackerMode, float],
                          likelihoods: Mapping[AttackerMode, float]) -> dict[AttackerMode, float]:
        logs = {
            mode: math.log(max(self.config.likelihood_floor, predicted[mode]))
                  + math.log(max(self.config.likelihood_floor, likelihoods[mode]))
            for mode in MODES
        }
        maximum = max(logs.values())
        return _normalize({mode: math.exp(logs[mode] - maximum) for mode in MODES})

    @staticmethod
    def _explain(prior: Mapping[AttackerMode, float], posterior: Mapping[AttackerMode, float],
                 evidence: tuple[Evidence, ...], unsupported: tuple[str, ...]) -> tuple[str, ...]:
        changes = sorted(((posterior[mode] - prior[mode], mode) for mode in MODES), reverse=True)
        positive = changes[0]
        negative = changes[-1]
        result = [
            f"Evidence considered: {', '.join(item.evidence_type for item in evidence) if evidence else 'none; transition prediction only'}.",
            f"Largest increase: {positive[1].value} ({positive[0]:+.4f}).",
            f"Largest decrease: {negative[1].value} ({negative[0]:+.4f}).",
        ]
        if unsupported:
            result.append(f"Unsupported evidence favored UNKNOWN: {', '.join(unsupported)}.")
        return tuple(result)

    def _make_state(self, episode_id: str, time_step: int,
                    probabilities: dict[AttackerMode, float]) -> BeliefState:
        most_likely = max(MODES, key=lambda mode: probabilities[mode])
        return BeliefState(episode_id, time_step, probabilities, _entropy(probabilities), most_likely,
                           MODEL_VERSION, self.config.version)

    def _validate_config(self) -> None:
        if set(self.config.priors) != set(MODES):
            raise ValueError("priors must define every attacker mode")
        _normalize(self.config.priors)
        if set(self.config.transitions) != set(MODES):
            raise ValueError("transition model must define every source mode")
        for source, row in self.config.transitions.items():
            if set(row) != set(MODES) or any(value < 0 for value in row.values()):
                raise ValueError(f"invalid transition row for {source}")
            if not math.isclose(math.fsum(row.values()), 1.0, abs_tol=1e-12):
                raise ValueError(f"transition row for {source} must sum to one")
        for event, row in self.config.observation_likelihoods.items():
            if set(row) != set(MODES) or any(not 0 <= value <= 1 for value in row.values()):
                raise ValueError(f"invalid observation likelihoods for {event}")
        if not 0 < self.config.likelihood_floor < 1:
            raise ValueError("likelihood_floor must be in (0,1)")
