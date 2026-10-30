"""Bounded CERT quantum diagnostic integrity checks."""

from __future__ import annotations

import pytest

from sentinel_ai.cert import CertResearchService


def test_incident_quantum_diagnostics_match_real_topologies_and_normalize() -> None:
    service = CertResearchService()
    incident = {
        "incidentId": "INC-DIAGNOSTIC",
        "originalEvidence": {"pca_1": -0.9, "pca_2": 0.8, "pca_3": -0.4, "pca_4": -0.1},
        "injectedEvidence": {"pca_1": 9.8, "pca_2": 1.7, "pca_3": 8.9, "pca_4": 7.7},
    }
    result = service.quantum_diagnostics(incident)
    assert result["qsvc"]["qubits"] == 4
    assert result["qsvc"]["gateCount"] == 20
    assert len(result["qsvc"]["gates"]) == 20
    assert len(result["vqc"]["gates"]) == 20
    assert result["vqc"]["layers"] == 2
    assert sum(result["qsvc"]["stateProbabilities"]) == pytest.approx(1.0)
    assert sum(result["vqc"]["stateProbabilities"]) == pytest.approx(1.0)
    assert result["qsvc"]["kernel"]["similarity"][0][0] == pytest.approx(1.0)
    assert result["qsvc"]["kernel"]["similarity"][1][1] == pytest.approx(1.0)
