# 🛡️ SentinelAI

<p align="center">
  <strong>Explainable AI-Powered Behavioral Threat Detection</strong>
</p>

<p align="center">
  Detect abnormal behavior. Understand why it is suspicious. Respond with confidence.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Streamlit-SOC%20Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" />
  <img src="https://img.shields.io/badge/ML-Isolation%20Forest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" />
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" />
</p>

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-getting-started">Getting Started</a> •
  <a href="#-detection-engine">Detection Engine</a>
</p>

---

## 🚨 Overview

**SentinelAI** is an explainable AI-powered behavioral threat detection platform designed to identify suspicious activity by learning what "normal" behavior looks like and detecting meaningful deviations.

Instead of relying solely on static rules or black-box machine learning, SentinelAI combines:

- 🧠 Behavioral baselines
- 🤖 Machine learning anomaly detection
- 🔍 Explainable rule-based detection
- 🔗 Context and sequence correlation
- 🎯 Hybrid risk scoring
- 🖥️ SOC-style investigation dashboard
- 🛑 Simulated automated containment

The goal is simple:

> **Detect → Explain → Investigate → Respond**

---

## 🎯 Problem Statement

Traditional security systems often depend heavily on predefined signatures and static thresholds.

However, attackers can operate using legitimate credentials and normal system tools, making their activity difficult to distinguish from legitimate behavior.

Examples include:

- Logging in from unusual locations
- Accessing sensitive files outside normal patterns
- Performing privileged operations unexpectedly
- Accessing systems at unusual times
- Moving laterally between resources
- Combining multiple low-risk actions into a suspicious sequence

SentinelAI focuses on **behavioral deviation** rather than relying only on known attack signatures.

---

## 🧠 How SentinelAI Works

SentinelAI builds behavioral profiles from historical activity and compares new events against those profiles.

It considers:

- 👤 Individual user behavior
- 👥 Peer / role behavior
- 🌍 Global behavioral patterns
- 💻 Device activity
- 📁 File access
- 🔐 Privilege usage
- 🌐 Location and network context
- 🔄 Event sequences

These signals are then combined to generate an explainable **0–100 risk score**.

---

## ✨ Key Features

### 🔍 Behavioral Anomaly Detection + Quantum model

SentinelAI establishes behavioral baselines using historical activity.

The system can compare an event against:

```text
Personal Baseline
       +
Peer / Role Baseline
       +
Global Baseline
```

## Quantum AI Architecture

SentinelAI includes a separate experimental quantum-analysis plane for hackathon research. It is read-only with respect to the production detection pipeline: quantum output does not change risk scores, alerts, alert severity, MITRE mappings, graph findings, or simulated containment.

### Four-qubit behavioural encoding

| Qubit | Behavioural feature | Existing SentinelAI source | Normalization |
| --- | --- | --- | --- |
| q0 | Login-time deviation | `login_hour_deviation` | `clamp(hours / 12, 0, 1)` |
| q1 | Failed-login behaviour | `failed_login_count` | `clamp(count / 10, 0, 1)` |
| q2 | Download-volume anomaly | positive maximum of `download_count_deviation` and `download_size_deviation` | `clamp(deviation / 5, 0, 1)` |
| q3 | Device/location anomaly | `unknown_device` and `location_anomaly` | mean of the two binary signals |

Each normalized value `x` is encoded with `RY(πx)` followed by `RZ(πx/2)`. A CX ring (`q0→q1→q2→q3→q0`) adds entanglement. The same reusable circuit is used by the event visualizer, fidelity kernel, threat-profile comparison, and notebook.

### Quantum models and comparison

- **Quantum fidelity kernel:** exact local statevector fidelity, `|⟨φ(x)|φ(y)⟩|²`. Event anomaly is reported as `1 − similarity`; neither value is an attack probability.
- **VQC:** a lightweight four-qubit variational circuit with two RY parameter layers, eight trainable angles, and linear CX entanglement. It trains once per process with deterministic initialization on 12 representative demo rows and is reused for subsequent requests. Its model score is not calibrated confidence.
- **Classical comparison:** displays the persisted Isolation Forest result alongside the two quantum outputs for the same event without changing the classical model or risk calculation.
- **Threat similarity:** computes real fidelity-kernel similarities to encoded Normal Behaviour, Credential Compromise, Suspicious Data Collection, and Account Manipulation reference profiles.

Circuits are constructed with **Qiskit** and request-time analysis uses a local, noiseless, exact Qiskit-compatible 16-amplitude statevector executor. This avoids native simulator thread instability in FastAPI workers while preserving the same four-qubit gate mathematics. It does not use real quantum hardware and does not model hardware noise. The representative dataset is intentionally small, the classical and quantum feature spaces differ, and no production accuracy, quantum advantage, quantum supremacy, or superiority over classical ML is claimed.

### Quantum API

```text
GET /api/quantum/status
GET /api/quantum/models
GET /api/quantum/events/{event_id}/analysis
GET /api/quantum/events/{event_id}/circuit
GET /api/quantum/events/{event_id}/comparison
GET /api/quantum/events/{event_id}/similarity
```

All frontend payloads use camelCase, return structured 404 errors for unknown events, and include `affectsProductionRisk: false` on experimental output.

### Run the hackathon notebook

From the repository root:

```bash
source .venv/bin/activate
pip install -e '.[notebook]'
jupyter notebook notebooks/sentinelai_quantum_demo.ipynb
```

The notebook generates representative SentinelAI data, encodes and visualizes the circuit, runs kernel similarity and VQC inference, compares Isolation Forest output, and explains limitations. If Jupyter is not already available, use any notebook environment with the project dependencies from `pyproject.toml` installed.

## Getting Started

```bash
source .venv/bin/activate
uvicorn sentinel_ai.api.app:create_app --factory --reload
```

In another terminal, start the frontend in live API mode:

```bash
cd frontend
SENTINEL_DATA_SOURCE=http SENTINEL_API_BASE_URL=http://127.0.0.1:8000 npm run dev
```

### Quantum Response Optimization

SentinelAI also provides an experimental **QAOA (Quantum Approximate Optimization Algorithm)** component to advise on response prioritization when multiple alerts are active.

- **QUBO Formulation**: Maps alert severity, risk, business impact, and urgency into a Quadratic Unconstrained Binary Optimization problem.
- **QAOA Circuit**: Implements a depth-1 (or configurable depth) QAOA circuit to optimize the QUBO cost function.
- **Advisory Only**: The optimization is purely advisory (`affectsProductionRisk: false`). It provides a ranked list of alerts and execution probabilities but does not execute automated containment or modify risk scores.
- **Explainable Ranking**: The UI compares the classical deterministic ranking with the QAOA probabilistic ranking, providing contribution factor reasoning for every alert.

## CERT r4.2 primary research workflow

SentinelAI-Q's primary behavioural research source is the prepared **CERT r4.2 employee user-day dataset**. The runtime reads the existing chronological splits and saved preprocessing artifacts; it does not parse the raw CERT logs. PennyLane's four-qubit fidelity-kernel QSVC is the main experimental classifier and remains advisory. Its threshold was selected on a small artificially balanced benchmark, so it does not alter production risk or trigger containment until alert burden is validated on naturally imbalanced data.

Materialize the selected benchmark once (no hyperparameter search or test-label use), then inspect a prepared user-day:

```powershell
python scripts/materialize_cert_qsvc.py
curl "http://127.0.0.1:8000/api/cert/status"
curl "http://127.0.0.1:8000/api/cert/user-days/AAF0535/2011-03-01?split=test"
curl "http://127.0.0.1:8000/api/cert/replay/AAF0535?split=test&malicious_only=true"
```

The investigation response separates recorded daily aggregates, inferred QSVC evidence, and research labels. The replay endpoint is a chronological user-day aggregate timeline—not a raw within-day event replay. CERT r4.2 user-day rows do not contain sufficient access-control or attack-graph relationships for an automatic SHIELD handoff, so the API explicitly returns `shieldEligible: false` / `shieldHandoff: null`. SHIELD continues to operate on its explicit synthetic graphs with deterministic constraints and the exact classical optimizer as authority.

The old deterministic event demo, Attack Lab, and SQLite records are retained temporarily as working legacy functionality. They are no longer described as the primary behavioural dataset and are not silently mixed with CERT user-day inputs.

### Unified SOC console

The frontend now presents exactly six primary workspaces: Command Center (`/`), Threat Monitor (`/threats`), Identities & Activity (`/users`), Investigation (`/investigation`), SHIELD Response (`/shield`), and Simulation & Evaluation (`/simulation`). Legacy routes remain available for compatible deep links and controlled simulation workflows, but are no longer duplicated in primary navigation.

Threat Monitor identifies the source and model for each finding. CERT QSVC entries come only from the persisted 100-row balanced test benchmark; legacy SQLite alerts remain separately labelled synthetic event detections. Investigation preserves recorded, inferred, and hypothetical provenance and blocks CERT-to-SHIELD handoff where access relationships are unavailable.

## SHIELD Decision Engine

SHIELD is a separate, advisory containment planner. It enumerates bounded, directed attack paths only across explicitly exploitable relationships; models reversible session, privilege, resource, export, device, and account interventions; and selects the least-disruptive combination that covers every enumerated critical path. The authoritative recommendation is always checked by the exact classical solver. Counterfactuals clone the modeled state and never invoke the existing response adapter.

The containment QUBO uses an upper-triangular coefficient convention and binary slack variables for each hard path-coverage constraint. A depth-1 QAOA circuit runs on Qiskit Aer with deterministic simulator seeding. Measured candidates are decoded using Qiskit's little-endian convention and independently checked for prerequisites, compatibility, and complete path coverage. Invalid or unavailable quantum results fall back to the exact plan. No quantum advantage is claimed.

```text
GET /api/shield/scenarios
GET /api/shield/scenarios/{credential-compromise|malicious-insider|multiple-routes}
GET /api/shield/benchmark
GET /api/shield/scenarios/{scenario_id}/quantum-experiment
```

Open `http://localhost:3000/shield` for the Decision Lab. The flagship `multiple-routes` scenario demonstrates why the individually cheapest action is rejected: two targeted controls (modeled cost 3) cover both independent routes, compared with broad account containment (cost 12).

Run verification and the synthetic benchmark:

```bash
python -m pytest
curl http://127.0.0.1:8000/api/shield/benchmark
```

Benchmark values are deterministic synthetic results, not deployment-performance claims. Path enumeration is bounded to depth 6 and 32 paths, and intervention effectiveness depends on the token and enforcement assumptions returned in each action.

### Verified QAOA comparison

Run the bounded six-trial matrix with `python scripts/benchmark_shield_qaoa.py multiple-routes`. It compares COBYLA and Powell, depth 1 and 2, 512 and 1,024 shots, three deterministic seeds, and fixed/ramp/random initializations. Parameter optimization uses exact statevector expectation; shots are reserved for final sampling. The reported quantum candidate is the lowest-cost classically feasible measured sample, not merely the most frequent sample.

On the verified flagship run, all 256 eight-qubit bitstrings matched the independent semantic objective with zero energy mismatches. The six-trial matrix produced 100% trial-level feasibility, best and median feasible cost 3, approximation ratio 1.0, zero absolute and relative gap, and median runtime about 384 ms on the validation machine. Circuit depth was 16 for p=1 and 28 for p=2. These small simulated results demonstrate formulation correctness, not scaling or quantum advantage.

## Phase 5 hybrid quantum world model

The experimental four-qubit PennyLane consequence predictor is implemented as a separately versioned, read-only service. It retains the Phase 4 feature and target contracts and is not promoted over the classical model. Architecture, reproducible benchmarks, calibration findings, uncertainty semantics, and limitations are documented in `docs/research/shield-phase5-hybrid-quantum-world-model.md`.

## Phase 5B trainable quantum kernel

The bounded containment experiment compares fixed fidelity, projected, and trainable projected four-qubit kernels against subset-matched classical baselines. The learned kernel underperformed, and no model was integrated or promoted. Full results and the stop recommendation are documented in `docs/research/shield-phase5b-trainable-quantum-kernel.md`.

## Phase 6 downstream consequence modeling

Phase 6 adds isolated matched-seed counterfactual rollouts and a read-only classical consequence scorer. Target validation found constant severe-damage and recovery-burden labels plus substantial redundancy with one-step outcomes, so no new VQC was trained and adaptive QAOA remains deferred. See `docs/research/shield-phase6-downstream-consequence-modeling.md`.

## Phase 6.5 multi-step consequence realism

Phase 6.5 introduces a separately versioned causal simulator with recovery operations, rollback tradeoffs, delayed attacker adaptation, genuine versus temporary containment, explicit severe outcomes, and six defender continuation policies. The pilot and full release pass all target-diversity checks. Phase 7 is conditionally ready for classical planning research, but QAOA changes remain deferred pending predictive and uncertainty validation. See `docs/research/shield-phase6-5-multistep-consequence-realism.md`.
