# Architecture documentation

Record durable architecture decisions, typed contracts, data schemas, and scoring-version rules here. Research evidence belongs in `../research/`; generated evaluation reports belong in `../../artifacts/reports/`.

## Runtime boundaries

The canonical detection path remains event ingestion → feature construction → deterministic rules and Isolation Forest scoring → bounded risk calculation → SQLite persistence. Behavioural baselines, ordered Attack Lab sequence findings, Graph Analysis, MITRE ATT&CK mapping, model evaluation, and quantum-kernel evaluation are parallel evidence or evaluation layers; none silently alter the canonical risk score.

## MITRE ATT&CK intelligence

The MITRE layer lives in `src/sentinel_ai/mitre` and uses a deliberately small local catalog sourced from Enterprise ATT&CK v19.2. Runtime operation never depends on an external ATT&CK API. The mapper can originate a technique only from explicit detection-rule evidence or an ordered sequence finding. Related medium-or-higher graph findings may strengthen confidence when they share supporting events, but graph context cannot create a technique by itself. Final risk, Isolation Forest output, scenario names, and quantum-kernel output are excluded as mapping origins. `ENABLE_MITRE_RISK_CONTRIBUTION` remains `False`.

```text
Classical + Quantum Detection
            ↓
Sequence + Graph Analysis
            ↓
Risk Engine
            ↓
Threat Story Engine
            ↓
MITRE ATT&CK Mapping
            ↓
Analyst Investigation
```

The supported catalog is intentionally limited to T1110 Brute Force, T1078 Valid Accounts, T1098 Account Manipulation, and T1005 Data from Local System. Rule mappings cover repeated authentication failures, anomalous successful account use, privilege changes, and sensitive-data access. Ordered Attack Lab findings can correlate those behaviours across a run. Confidence is deterministic: one direct observation is low; ordered sequence or multiple direct observations are medium; high requires direct rules, sequence evidence, related medium-or-higher graph corroboration, and multiple events.

Threat stories are generated from persisted events ordered by timestamp and event ID. They retain supporting event IDs, rules, sequence findings, graph findings, confidence, and investigation prompts so every narrative statement remains traceable. FastAPI exposes the local catalog and event, attack-run, alert, and overview reports as camelCase DTOs. The Next.js data-source interface consumes those reports for the Threat Intelligence workspace and small contextual additions to Activity, Attack Lab, and Alert Investigation.

Public endpoints are `GET /api/mitre/catalog`, `GET /api/mitre/overview`, `GET /api/mitre/events/{event_id}`, `GET /api/mitre/attack-runs/{run_id}`, and `GET /api/mitre/alerts/{alert_id}`. The UI entry point is `/threat-intelligence`; event IDs link to `/activity/{event_id}`, completed Attack Lab runs embed their report, and a focused alert conditionally renders its report above the existing investigation queue.

## Graph Analysis

Graph Analysis builds an in-memory typed graph from persisted employees, events, detections, and simulation runs, applies conservative correlation safeguards, and exposes summary, scoped subgraph, finding, entity, event, and run views without duplicating transactional data. Its page and production-risk boundary remain unchanged.

## SHIELD advisory boundary

`sentinel_ai.shield` is deliberately separate from the canonical risk pipeline and existing response service. Its deterministic demo graphs carry directed edge semantics, observed-versus-hypothetical evidence, asset sensitivity, and bounded traversal limits. Intervention coverage is derived from nodes and capabilities present on each enumerated path. Exact enumeration is the correctness oracle; greedy selection is the scalable baseline; QAOA is experimental and can only supply a recommendation after classical feasibility validation. Counterfactual simulation is pure and does not persist state or call containment adapters. Every high-impact recommendation requires analyst approval.

SHIELD's QUBO uses an upper-triangular convention, `E(x)=sum(i<=j) Q[i,j] x_i x_j`. Each coverage constraint uses binary slack in `P(sum(cover)-1-slack)^2`; prerequisites use `P*x_i*(1-x_required)` and incompatibilities use `P*x_i*x_j`. The penalty exceeds the sum of all non-negative action costs. Conversion uses `x=(1-Z)/2`, including the accumulated linear fields from every quadratic coefficient. Qiskit's displayed measurement strings are reversed before action-variable decoding. An exhaustive independent semantic evaluator checks every bitstring for small demo instances and reports feasible versus penalty-violating encodings separately.
