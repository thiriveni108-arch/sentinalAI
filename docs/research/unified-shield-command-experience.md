# Unified SHIELD Command Experience

The SHIELD Defense workspace now contains a server-derived simulator-session panel. It creates one correlated graph-aware incident, shows defender-visible evidence, Bayesian beliefs, declared topology/workflow context, learned graph-consequence estimates, the exact Phase 7 plan, and the persisted Phase 8 timeline.

Browser actions carry only the session version and a server-established simulated identity name for approval. The server derives predictor outputs, targets, criticality, authorization tier, execution effects, and experience ingestion. Sessions are intentionally in-memory: after a backend restart the API fails closed with `session_unavailable`, requiring a new simulator session rather than reconstructing state without proof.

The existing five navigation labels are unchanged. The central integration is currently implemented in SHIELD Defense; the pre-existing Threat Investigation, Adversary Lab, Command Center, and Model Observatory retain their routes and backend data sources. A fully shared incident-context presentation across every legacy screen remains follow-up UI work.

Validation: unified session integration test, Phase 8–10 regression subset, and frontend TypeScript typecheck pass. All execution remains simulator-only. QAOA and QRL are not portrayed as authoritative or automatically promoted.
