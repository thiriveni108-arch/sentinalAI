"""SHIELD-ACT consequence modeling, applicability, and simulated response state."""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pennylane as qml

from sentinel_ai import config
from .models import Intervention, Scenario, ShieldEdge, ShieldNode
from .paths import enumerate_attack_paths
from .simulator import simulate

FEATURES = ("action_cost", "coverage_ratio", "max_asset_criticality", "dependency_count")
MODEL_VERSION = "shield-act-consequence-v1"
DATASET_VERSION = "shield-act-counterfactual-v1"


@dataclass(frozen=True)
class ScenarioFamily:
    family_id: str
    title: str
    summary: str
    relationships: tuple[str, ...]
    action_templates: tuple[tuple[str, str, float, bool, bool], ...]
    asset_criticality: int
    dependency_count: int
    evidence_requirements: tuple[str, ...]


def default_families() -> dict[str, ScenarioFamily]:
    """Definitions are data; the consequence model and engine are family-agnostic."""
    items = (
        ScenarioFamily("file-collection", "Suspicious file collection", "Modeled collection and export route",
                       ("CAN_ACCESS", "CAN_EXPORT"),
                       (("disable-export", "DISABLE_BULK_EXPORT", 1.5, True, False),
                        ("restrict-resource", "RESTRICT_RESOURCE", 3.0, True, False),
                        ("revoke-session", "REVOKE_SESSION", 4.0, True, False),
                        ("disable-account", "DISABLE_ACCOUNT", 10.0, False, True)), 5, 2,
                       ("file_copy_count", "usb_connect_count")),
        ScenarioFamily("credential-compromise", "Credential compromise", "Modeled session and privilege route",
                       ("HAS_PRIVILEGE", "CAN_ACCESS"),
                       (("require-mfa", "REQUIRE_FRESH_MFA", 1.0, True, False),
                        ("revoke-session", "REVOKE_SESSION", 2.5, True, False),
                        ("remove-privilege", "REMOVE_PRIVILEGE", 4.5, True, True),
                        ("disable-account", "DISABLE_ACCOUNT", 11.0, False, True)), 5, 3,
                       ("credential_signal", "session_signal")),
        ScenarioFamily("lateral-access", "Lateral service access", "Two modeled routes through service dependencies",
                       ("HAS_PRIVILEGE", "CONNECTS_TO", "CAN_ACCESS"),
                       (("segment-service", "RESTRICT_RESOURCE", 1.5, True, False),
                        ("remove-role", "REMOVE_PRIVILEGE", 3.0, True, True),
                        ("revoke-session", "REVOKE_SESSION", 3.5, True, False),
                        ("disable-account", "DISABLE_ACCOUNT", 12.0, False, True)), 5, 4,
                       ("service_signal", "authorization_signal")),
    )
    return {item.family_id: item for item in items}


class AdaptiveScenarioEngine:
    def __init__(self, families: dict[str, ScenarioFamily] | None = None) -> None:
        self.families = families or default_families()

    def build(self, family_id: str, context_id: str, evidence: dict[str, Any], allow_assumptions: bool = True) -> Scenario:
        family = self.families.get(family_id)
        if family is None: raise KeyError(family_id)
        available = {key for key, value in evidence.items() if value is not None}
        missing = [key for key in family.evidence_requirements if key not in available]
        if missing and not allow_assumptions:
            raise ValueError(f"Insufficient evidence for {family_id}: {', '.join(missing)}")
        prefix = context_id.lower()
        session = f"session:{prefix}"; privilege = f"privilege:{prefix}"; service = f"service:{prefix}"
        resource = f"resource:{prefix}"; outcome = f"outcome:{prefix}"
        nodes = (ShieldNode(session, "session", "Modeled active session"), ShieldNode(privilege, "privilege", "Modeled authorization"),
                 ShieldNode(service, "service", "Hypothetical dependent service", 3),
                 ShieldNode(resource, "resource", "Hypothetical protected resource", family.asset_criticality),
                 ShieldNode(outcome, "damaging_action", "Modeled adverse outcome", 5))
        if family.family_id == "lateral-access":
            edges = (ShieldEdge(session, privilege, "HAS_PRIVILEGE", True, True, ("modeled:session",)),
                     ShieldEdge(privilege, service, "CONNECTS_TO", True, False, ("assumption:service-route",)),
                     ShieldEdge(service, outcome, "CAN_ACCESS", True, False, ("assumption:lateral-route",)),
                     ShieldEdge(session, resource, "CAN_ACCESS", True, False, ("assumption:direct-route",)))
        else:
            edges = (ShieldEdge(session, privilege, family.relationships[0], True, True, ("modeled:incident-evidence",)),
                     ShieldEdge(privilege, resource, "CAN_ACCESS", True, False, ("assumption:authorization",)),
                     ShieldEdge(resource, outcome, family.relationships[-1], True, False, ("assumption:progression",)))
        provisional = []
        for slug, action_type, cost, reversible, approval in family.action_templates:
            target = session if action_type in {"REVOKE_SESSION", "DISABLE_ACCOUNT", "REQUIRE_FRESH_MFA"} else (privilege if action_type == "REMOVE_PRIVILEGE" else resource)
            provisional.append(Intervention(f"{slug}-{prefix}", action_type, target, cost, (), reversible=reversible,
                                             approval_required=approval, implementation_impact="high" if approval else "low",
                                             explanation=f"Modeled {family.title.lower()} control: {slug.replace('-', ' ')}."))
        scenario = Scenario(f"act-{family.family_id}-{prefix}", family.title, family.summary, None,
                            "SHIELD-ACT modeled exercise", (session,), nodes, edges, tuple(provisional),
                            tuple(f"{key}: {evidence.get(key, 'assumed')}" for key in family.evidence_requirements))
        paths = enumerate_attack_paths(scenario)
        path_ids = tuple(path.path_id for path in paths)
        actions = []
        for action in provisional:
            if action.action_type in {"REVOKE_SESSION", "DISABLE_ACCOUNT"}: covered = path_ids
            elif action.action_type == "REMOVE_PRIVILEGE": covered = tuple(p.path_id for p in paths if privilege in p.nodes)
            elif action.action_type == "RESTRICT_RESOURCE": covered = tuple(p.path_id for p in paths if resource in p.nodes)
            elif action.action_type == "DISABLE_BULK_EXPORT": covered = tuple(p.path_id for p in paths if resource in p.nodes)
            else: covered = ()
            actions.append(Intervention(**{**action.__dict__, "interrupts": covered}))
        return Scenario(**{**scenario.__dict__, "actions": tuple(actions)})


def consequence_features(scenario: Scenario, action: Intervention) -> np.ndarray:
    paths = enumerate_attack_paths(scenario); covered = len(set(action.interrupts)); total = max(1, len(paths))
    max_criticality = max((node.sensitivity for node in scenario.nodes), default=0)
    dependencies = sum(1 for edge in scenario.edges if not edge.observed)
    return np.asarray([action.cost, covered / total, max_criticality, dependencies], dtype=float)


def exact_consequence(scenario: Scenario, action: Intervention, effectiveness: float = 1.0) -> dict[str, Any]:
    paths = enumerate_attack_paths(scenario)
    effective_interrupts = action.interrupts if effectiveness >= 0.75 else action.interrupts[:max(0, len(action.interrupts) - 1)]
    effective = Intervention(**{**action.__dict__, "interrupts": effective_interrupts})
    result = simulate(paths, (effective,), {effective.action_id}, action.action_id)
    dependency_penalty = sum(1 for edge in scenario.edges if not edge.observed and action.target in (edge.source, edge.target)) * 0.75
    recovery_penalty = 0.0 if action.reversible else 3.0
    disruption = round(float(action.cost) + dependency_penalty + recovery_penalty, 3)
    category = 1 if disruption > 4.0 else 0
    return {**result, "operationalDisruption": disruption, "disruptionCategory": "HIGH" if category else "LOW",
            "target": category, "effectivenessAssumption": effectiveness,
            "affectedResources": sorted({action.target}), "reversible": action.reversible}


class ConsequenceModel:
    def __init__(self, root: Path | None = None) -> None:
        root = Path(root or config.PROJECT_ROOT)
        self.artifact = root / "artifacts" / "models" / "shield_act_consequence_v1.npz"
        self.metadata_path = root / "artifacts" / "reports" / "shield_act_consequence_v1.json"
        self.classical_path = root / "artifacts" / "models" / "shield_act_classical_v1.pkl"

    def predict(self, family_id: str, values: np.ndarray) -> dict[str, Any]:
        if not self.artifact.exists() or not self.metadata_path.exists():
            return {"available": False, "applicable": False, "reason": "Frozen SHIELD-ACT consequence artifact is unavailable."}
        artifact = self._load_npz(str(self.artifact)); meta = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        low, high = artifact["feature_min"], artifact["feature_max"]
        violations = [FEATURES[i] for i, value in enumerate(values) if value < low[i] or value > high[i]]
        family_supported = family_id in meta["validated_families"]
        if violations or not family_supported:
            return {"available": True, "applicable": False, "reason": "Outside validated consequence-model applicability.",
                    "rangeViolations": violations, "familyValidated": family_supported, "modelVersion": MODEL_VERSION}
        scaled = 2 * (values - low) / np.where(high - low == 0, 1, high - low) - 1
        score = float(self._circuit()(scaled, artifact["weights"]))
        prediction = int(score >= float(artifact["threshold"]))
        classical = self._load_classical(str(self.classical_path)); classical_prediction = int(classical.predict(values.reshape(1, -1))[0])
        return {"available": True, "applicable": True, "prediction": "HIGH_DISRUPTION" if prediction else "LOW_DISRUPTION",
                "rawScore": score, "threshold": float(artifact["threshold"]), "scoreIsProbability": False,
                "classicalPrediction": "HIGH_DISRUPTION" if classical_prediction else "LOW_DISRUPTION",
                "modelVersion": MODEL_VERSION, "datasetVersion": DATASET_VERSION, "backend": "PennyLane default.qubit shots=None"}

    @staticmethod
    @lru_cache(maxsize=1)
    def _circuit():
        dev = qml.device("default.qubit", wires=4, shots=None)
        @qml.qnode(dev, interface=None, diff_method=None)
        def circuit(features, weights):
            qml.AngleEmbedding(features, wires=range(4), rotation="Y")
            qml.StronglyEntanglingLayers(weights, wires=range(4), ranges=[1, 1])
            return qml.expval(qml.PauliZ(0))
        return circuit

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_npz(path: str) -> dict[str, np.ndarray]:
        with np.load(path) as data: return {key: np.asarray(data[key]).copy() for key in data.files}

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_classical(path: str):
        with Path(path).open("rb") as handle: return pickle.load(handle)
