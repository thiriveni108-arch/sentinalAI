"""Thin FastAPI layer over SentinelAI domain and application services."""

from __future__ import annotations

from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime
import logging
import os
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Header
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from sentinel_ai import config
from sentinel_ai.api.schemas import (
    AttackLabRunDto,
    AttackLabRunRequest,
    AttackLabScenarioDto,
    ActivityPageDto,
    ModelMetadataDto,
    OverviewDto,
    PageMeta,
    SystemCountsDto,
    SystemPartDto,
    SystemStatusDto,
    OperatorDto,
    ThreatPageDto,
    ThreatSummaryDto,
    UserDetailDto,
    UserPageDto,
    UserSummaryDto,
    SequenceFindingDto,
    GraphOverviewDto,
    GraphEntityDetailDto,
    GraphEventContextDto,
    GraphAttackRunContextDto,
    GraphFindingsPageDto,
    GraphDataDto,
    MitreCatalogDto,
    MitreOverviewDto,
    MitreReportDto,
    MitreTechniqueDto,
    ContainmentStateDto,
    ResponseActionRequest,
    ResponseActionResultDto,
    ResponseAuditDto,
    ResponseHistoryDto,
)

from sentinel_ai.api.serializers import (
    activity,
    behavioural_assessment,
    detection_history,
    overview,
    peer_baseline,
    peer_group,
    personal_baseline,
    threat,
    graph_node,
    graph_edge,
    graph_finding,
    mitre_report,
)
from sentinel_ai.baselines import build_peer_profile, build_profiles, peer_group_key
from sentinel_ai.demo import ATTACK_LAB_SCENARIOS
from sentinel_ai.services import SentinelService
from sentinel_ai.models import evaluate_existing_models, evaluate_quantum_kernel
from sentinel_ai.mitre import ATTACK_SOURCE_URL, ATTACK_VERSION, catalog
from sentinel_ai.response.models import ContainmentState, ResponseAction, ResponseAudit
from sentinel_ai.response.service import ResponseActionFailed
from sentinel_ai.quantum import QuantumAnalyzer
from sentinel_ai.cert import CertResearchService
from sentinel_ai.incidents import IncidentService


logger = logging.getLogger(__name__)


def _demo_bootstrap_enabled(override: bool | None = None) -> bool:
    if override is not None:
        return override
    return os.environ.get("SENTINEL_BOOTSTRAP_DEMO_DATA", "false").strip().lower() in {"1", "true", "yes", "on"}


def _page_meta(page: int, page_size: int, total: int) -> PageMeta:
    return PageMeta(page=page, page_size=page_size, total=total, total_pages=max(1, (total + page_size - 1) // page_size))


def _containment_state(item: ContainmentState) -> ContainmentStateDto:
    return ContainmentStateDto(
        employee_id=item.employee_id,
        account_status=item.account_status.value,
        session_status=item.session_status.value,
        containment_status=item.containment_status.value,
        containment_mode=item.containment_mode.value if item.containment_mode else None,
        contained_at=item.contained_at,
        contained_by=item.contained_by,
        reason=item.reason,
        source_alert_id=item.source_alert_id,
        risk_score_at_action=item.risk_score_at_action,
        last_action=item.last_action.value if item.last_action else None,
        updated_at=item.updated_at,
    )


def _response_audit(item: ResponseAudit) -> ResponseAuditDto:
    return ResponseAuditDto(
        action_id=item.action_id,
        employee_id=item.employee_id,
        action=item.action.value,
        mode=item.mode.value,
        actor=item.actor,
        alert_id=item.alert_id,
        risk_score_at_action=item.risk_score_at_action,
        reason=item.reason,
        result=item.result.value,
        detail=item.detail,
        created_at=item.created_at,
    )


def _service(request: Request) -> SentinelService:
    return request.app.state.service


Service = Annotated[SentinelService, Depends(_service)]


def create_app(database_path: str | Path | None = None, bootstrap_demo_data: bool | None = None) -> FastAPI:
    resolved_database_path = Path(database_path or os.environ.get("SENTINEL_DATABASE_PATH", config.DEFAULT_DATABASE_PATH))
    bootstrap_enabled = _demo_bootstrap_enabled(bootstrap_demo_data)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        service = SentinelService(resolved_database_path)
        bootstrapped = service.initialize(bootstrap_demo_data=bootstrap_enabled)
        logger.info(
            "SentinelAI database ready path=%s demo_bootstrap_enabled=%s demo_data_initialized=%s",
            resolved_database_path,
            bootstrap_enabled,
            bootstrapped,
        )
        app.state.service = service
        yield

    app = FastAPI(title="SentinelAI API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
        allow_methods=["GET", "POST"],
        allow_headers=["content-type", "x-model-governance-token"],
    )

    from sentinel_ai.shield import ShieldService
    from sentinel_ai.shield.autonomous_defense import (Actor, DefenseCoordinator, DefenseStore,
        MultiStepConsequenceEnvironment, Proposal)
    from sentinel_ai.shield.continuous_learning import ExperienceStore, LearningCoordinator
    from sentinel_ai.shield.unified_session import UnifiedSessionService
    shield = ShieldService()
    autonomous_defense = DefenseCoordinator(DefenseStore(resolved_database_path.with_name("shield_phase8.db")))
    learning = LearningCoordinator(ExperienceStore(resolved_database_path.with_name("shield_phase10_learning.db")))
    unified_shield = UnifiedSessionService(autonomous_defense, learning.store)
    cert = CertResearchService()
    incidents = IncidentService(resolved_database_path, cert, shield)

    @app.post("/api/incidents", response_model=dict[str, object], status_code=201)
    def create_incident(payload: Annotated[dict[str, object], Body()]) -> dict[str, object]:
        try:
            return incidents.create(str(payload.get("user", "")), str(payload.get("date", "")),
                                    str(payload.get("split", "test")), str(payload.get("scenario", IncidentService.SCENARIO)))
        except KeyError as error:
            raise HTTPException(404, {"code": "cert_user_day_not_found", "message": str(error).strip("'")}) from error
        except ValueError as error:
            raise HTTPException(422, {"code": "invalid_incident", "message": str(error)}) from error

    @app.get("/api/incidents", response_model=dict[str, object])
    def list_incidents(detected: bool | None = None, limit: Annotated[int, Query(ge=1, le=100)] = 50) -> dict[str, object]:
        return {"items": incidents.list(detected, limit), "summary": incidents.summary()}

    @app.get("/api/incidents/{incident_id}", response_model=dict[str, object])
    def get_incident(incident_id: str) -> dict[str, object]:
        try: return incidents.get(incident_id)
        except KeyError as error: raise HTTPException(404, {"code": "incident_not_found", "message": incident_id}) from error

    @app.post("/api/incidents/{incident_id}/shield", response_model=dict[str, object])
    def plan_incident_response(incident_id: str) -> dict[str, object]:
        try: return incidents.plan_response(incident_id)
        except KeyError as error: raise HTTPException(404, {"code": "incident_not_found", "message": incident_id}) from error

    @app.post("/api/incidents/{incident_id}/shield-act/plan", response_model=dict[str, object])
    def plan_adaptive_response(incident_id: str, payload: Annotated[dict[str, object], Body()] = {}) -> dict[str, object]:
        try:
            return incidents.plan_adaptive_response(incident_id, str(payload.get("familyId", "file-collection")))
        except KeyError as error:
            raise HTTPException(404, {"code": "incident_or_family_not_found", "message": str(error).strip("'")}) from error
        except ValueError as error:
            raise HTTPException(422, {"code": "invalid_shield_act_plan", "message": str(error)}) from error

    @app.post("/api/incidents/{incident_id}/shield-act/actions/{action_id}/execute", response_model=dict[str, object])
    def execute_adaptive_action(incident_id: str, action_id: str) -> dict[str, object]:
        try:
            return incidents.execute_adaptive_action(incident_id, action_id)
        except KeyError as error:
            raise HTTPException(404, {"code": "incident_or_action_not_found", "message": str(error).strip("'")}) from error
        except ValueError as error:
            raise HTTPException(422, {"code": "invalid_shield_act_state", "message": str(error)}) from error
        except PermissionError as error:
            raise HTTPException(409, {"code": "action_requires_escalation", "message": str(error)}) from error

    @app.post("/api/incidents/{incident_id}/shield-act/actions/{action_id}/rollback", response_model=dict[str, object])
    def rollback_adaptive_action(incident_id: str, action_id: str) -> dict[str, object]:
        try:
            return incidents.rollback_adaptive_action(incident_id, action_id)
        except KeyError as error:
            raise HTTPException(404, {"code": "incident_or_action_not_found", "message": str(error).strip("'")}) from error
        except ValueError as error:
            raise HTTPException(422, {"code": "rollback_unavailable", "message": str(error)}) from error

    @app.get("/api/cert/status", response_model=dict[str, object])
    def cert_status() -> dict[str, object]:
        """Describe the primary CERT research dataset and frozen QSVC boundary."""
        return cert.status()

    @app.get("/api/cert/user-days/{user}/{date}", response_model=dict[str, object])
    def cert_user_day(user: str, date: str, split: Literal["train", "validation", "test"] = "test") -> dict[str, object]:
        try:
            return cert.investigate(user, date, split)
        except KeyError as error:
            raise HTTPException(404, {"code": "cert_user_day_not_found", "message": str(error).strip("'")}) from error
        except FileNotFoundError as error:
            raise HTTPException(503, {"code": "cert_qsvc_artifact_missing", "message": str(error)}) from error
        except RuntimeError as error:
            raise HTTPException(503, {"code": "cert_qsvc_unavailable", "message": str(error)}) from error

    @app.get("/api/cert/replay/{user}", response_model=dict[str, object])
    def cert_replay(user: str, split: Literal["train", "validation", "test"] = "test",
                    malicious_only: bool = True, limit: Annotated[int, Query(ge=1, le=100)] = 30) -> dict[str, object]:
        try:
            return cert.replay(user, split, malicious_only, limit)
        except KeyError as error:
            raise HTTPException(404, {"code": "cert_replay_not_found", "message": str(error).strip("'")}) from error

    @app.get("/api/cert/users", response_model=dict[str, object])
    def cert_users(q: str = "", page: Annotated[int, Query(ge=1)] = 1,
                   page_size: Annotated[int, Query(ge=1, le=100)] = 50) -> dict[str, object]:
        return cert.list_users(q, page, page_size)

    @app.get("/api/cert/users/{user}/days", response_model=dict[str, object])
    def cert_user_days(user: str, start: str | None = None, end: str | None = None,
                       page: Annotated[int, Query(ge=1)] = 1,
                       page_size: Annotated[int, Query(ge=1, le=100)] = 50) -> dict[str, object]:
        return cert.list_user_days(user, start, end, page, page_size)

    @app.get("/api/cert/findings", response_model=dict[str, object])
    def cert_findings(q: str = "", prediction: Annotated[int | None, Query(ge=0, le=1)] = 1,
                      page: Annotated[int, Query(ge=1)] = 1,
                      page_size: Annotated[int, Query(ge=1, le=100)] = 50) -> dict[str, object]:
        return cert.list_findings(q, prediction, page, page_size)

    @app.get("/api/cert/benchmarks", response_model=dict[str, object])
    def cert_benchmarks() -> dict[str, object]:
        return cert.benchmark_results()

    @app.get("/api/shield/scenarios", response_model=list[dict[str, object]])
    def shield_scenarios() -> list[dict[str, object]]:
        return shield.list_scenarios()

    @app.get("/api/shield/scenarios/{scenario_id}", response_model=dict[str, object])
    def shield_scenario(scenario_id: str, quantum: bool = True) -> dict[str, object]:
        try:
            return shield.analyze(scenario_id, include_quantum=quantum)
        except KeyError:
            raise HTTPException(404, {"code": "shield_scenario_not_found", "message": f"Unknown SHIELD scenario: {scenario_id}"})

    @app.get("/api/shield/benchmark", response_model=dict[str, object])
    def shield_benchmark(quantum: bool = False) -> dict[str, object]:
        return shield.benchmark(include_quantum=quantum)

    @app.get("/api/shield/scenarios/{scenario_id}/quantum-experiment", response_model=dict[str, object])
    def shield_quantum_experiment(scenario_id: str) -> dict[str, object]:
        try:
            return shield.quantum_experiment(scenario_id)
        except KeyError:
            raise HTTPException(404, {"code": "shield_scenario_not_found", "message": f"Unknown SHIELD scenario: {scenario_id}"})

    @app.post("/api/shield/autonomous/proposals", response_model=dict[str, object], status_code=201)
    def create_autonomous_proposal(payload: Annotated[dict[str, object], Body()]) -> dict[str, object]:
        """Create a simulated-only Phase 8 proposal; no production action is possible."""
        try:
            proposal = Proposal(incident_id=str(payload["incidentId"]), action=str(payload["action"]),
                targets=tuple(str(x) for x in payload.get("targets", ())), state_version=int(payload.get("stateVersion", 0)),
                planner_source=str(payload.get("plannerSource", "classical")), prediction=dict(payload.get("prediction", {})),
                uncertainty=float(payload.get("uncertainty", 1.0)), target_criticality=int(payload.get("targetCriticality", 1)),
                blast_radius=int(payload.get("blastRadius", 1)), reversible=bool(payload.get("reversible", True)),
                recovery_plan=bool(payload.get("recoveryPlan", True)), incident_severity=int(payload.get("incidentSeverity", 1)))
            env = MultiStepConsequenceEnvironment(str(payload.get("family", "credential-compromise")), int(payload.get("seed", 7301)))
            return autonomous_defense.propose(proposal, str(payload["idempotencyKey"]), env)
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(422, {"code":"invalid_phase8_proposal","message":str(error)}) from error

    @app.get("/api/shield/autonomous/proposals/{proposal_id}", response_model=dict[str, object])
    def get_autonomous_proposal(proposal_id: str) -> dict[str, object]:
        try:
            result=autonomous_defense.store.get(proposal_id); result["history"]=autonomous_defense.store.events(proposal_id); return result
        except KeyError as error: raise HTTPException(404,{"code":"phase8_proposal_not_found","message":proposal_id}) from error

    @app.post("/api/shield/autonomous/proposals/{proposal_id}/approval", response_model=dict[str, object])
    def approve_autonomous_proposal(proposal_id: str, payload: Annotated[dict[str, object], Body()]) -> dict[str, object]:
        try:return autonomous_defense.approve(proposal_id,Actor(str(payload["actorId"]),str(payload["role"])),str(payload["decision"]))
        except KeyError as error: raise HTTPException(404,{"code":"phase8_proposal_not_found","message":proposal_id}) from error
        except PermissionError as error: raise HTTPException(403,{"code":"phase8_approval_denied","message":str(error)}) from error
        except ValueError as error: raise HTTPException(409,{"code":"phase8_approval_invalid","message":str(error)}) from error

    @app.post("/api/shield/autonomous/proposals/{proposal_id}/execute", response_model=dict[str, object])
    def execute_autonomous_proposal(proposal_id: str, payload: Annotated[dict[str, object], Body()] = {}) -> dict[str, object]:
        try:return autonomous_defense.execute(proposal_id,Actor(str(payload.get("actorId","system")),str(payload.get("role","system"))))
        except KeyError as error: raise HTTPException(404,{"code":"phase8_proposal_not_found","message":proposal_id}) from error
        except PermissionError as error: raise HTTPException(403,{"code":"phase8_execution_denied","message":str(error)}) from error
        except ValueError as error: raise HTTPException(409,{"code":"phase8_execution_invalid","message":str(error)}) from error

    @app.post("/api/shield/sessions", response_model=dict[str, object], status_code=201)
    def create_shield_session(payload: Annotated[dict[str, object], Body()] = {}) -> dict[str, object]:
        try:return unified_shield.create(str(payload.get("scenario","credential-compromise")),str(payload.get("topology","small-office")),int(payload.get("seed",96001)))
        except ValueError as error: raise HTTPException(422,{"code":"invalid_simulator_session","message":str(error)}) from error

    @app.get("/api/shield/sessions/{incident_id}", response_model=dict[str, object])
    def shield_session(incident_id:str) -> dict[str, object]:
        try:return unified_shield.snapshot(incident_id)
        except KeyError as error: raise HTTPException(409,{"code":"session_unavailable","message":str(error)}) from error

    @app.post("/api/shield/sessions/{incident_id}/plan", response_model=dict[str, object])
    def plan_shield_session(incident_id:str,payload:Annotated[dict[str,object],Body()]) -> dict[str,object]:
        try:return unified_shield.plan(incident_id,int(payload["version"]))
        except KeyError as error: raise HTTPException(409,{"code":"session_unavailable","message":str(error)}) from error
        except RuntimeError as error: raise HTTPException(409,{"code":"shield_plan_conflict","message":str(error)}) from error

    @app.post("/api/shield/sessions/{incident_id}/submit", response_model=dict[str, object])
    def submit_shield_session(incident_id:str,payload:Annotated[dict[str,object],Body()]) -> dict[str,object]:
        try:return unified_shield.submit(incident_id,int(payload["version"]))
        except (KeyError,RuntimeError) as error: raise HTTPException(409,{"code":"shield_submit_conflict","message":str(error)}) from error

    @app.post("/api/shield/sessions/{incident_id}/approval", response_model=dict[str, object])
    def approve_shield_session(incident_id:str,payload:Annotated[dict[str,object],Body()]) -> dict[str,object]:
        try:return unified_shield.approve(incident_id,str(payload["identity"]),str(payload["decision"]),int(payload["version"]))
        except PermissionError as error: raise HTTPException(403,{"code":"simulated_identity_denied","message":str(error)}) from error
        except (KeyError,RuntimeError,ValueError) as error: raise HTTPException(409,{"code":"shield_approval_conflict","message":str(error)}) from error

    @app.post("/api/shield/sessions/{incident_id}/execute", response_model=dict[str, object])
    def execute_shield_session(incident_id:str,payload:Annotated[dict[str,object],Body()]) -> dict[str,object]:
        try:return unified_shield.execute(incident_id,int(payload["version"]))
        except (KeyError,RuntimeError,ValueError,PermissionError) as error: raise HTTPException(409,{"code":"shield_execution_conflict","message":str(error)}) from error

    @app.post("/api/shield/sessions/{incident_id}/recovery", response_model=dict[str, object])
    def recover_shield_session(incident_id:str,payload:Annotated[dict[str,object],Body()]) -> dict[str,object]:
        try:return unified_shield.recover(incident_id,str(payload["identity"]),int(payload["version"]))
        except PermissionError as error: raise HTTPException(403,{"code":"shield_recovery_denied","message":str(error)}) from error
        except (KeyError,RuntimeError,ValueError) as error: raise HTTPException(409,{"code":"shield_recovery_conflict","message":str(error)}) from error

    @app.post("/api/shield/sessions/{incident_id}/replan", response_model=dict[str, object])
    def replan_shield_session(incident_id:str,payload:Annotated[dict[str,object],Body()]) -> dict[str,object]:
        try:return unified_shield.replan(incident_id,int(payload["version"]))
        except (KeyError,RuntimeError,ValueError) as error: raise HTTPException(409,{"code":"shield_replan_conflict","message":str(error)}) from error

    def require_model_governance(token: Annotated[str | None, Header(alias="X-Model-Governance-Token")] = None) -> str:
        expected=os.environ.get("SENTINEL_MODEL_GOVERNANCE_TOKEN")
        if not expected or token != expected: raise HTTPException(403,{"code":"model_governance_denied","message":"Server-validated model-governance token required."})
        return "server-validated-model-governor"

    @app.get("/api/shield/learning/experiences", response_model=dict[str, object])
    def learning_experiences() -> dict[str, object]: return {"version":"shield-experience-v1","items":learning.store.history(),"drift":learning.store.drift()}

    @app.post("/api/shield/learning/experiences", response_model=dict[str, object], status_code=201)
    def ingest_learning_experience(payload: Annotated[dict[str, object], Body()]) -> dict[str, object]:
        result=learning.store.ingest(payload); return {"eligible":result.eligible,"reasons":result.reasons,"fingerprint":result.fingerprint}

    @app.post("/api/shield/learning/cycles", response_model=dict[str, object], status_code=201)
    def start_learning_cycle(payload: Annotated[dict[str, object], Body()] = {}) -> dict[str, object]:
        try:return learning.run(str(payload.get("algorithm","classical")),int(payload.get("episodes",8)),int(payload.get("seed",100)),int(payload.get("minimumEpisodes",3)))
        except RuntimeError as error: raise HTTPException(409,{"code":"learning_cycle_conflict","message":str(error)}) from error

    @app.get("/api/shield/learning/cycles", response_model=dict[str, object])
    def learning_cycles() -> dict[str, object]: return {"items":learning.cycles()}

    @app.get("/api/shield/learning/policies", response_model=dict[str, object])
    def learning_policies() -> dict[str, object]: return {"active":learning.registry.active_name,"policies":{name:{k:v for k,v in entry.items() if k!="policy"} for name,entry in learning.registry.entries.items()}}

    @app.post("/api/shield/learning/policies/{name}/approve", response_model=dict[str, object])
    def approve_learning_policy(name:str, _actor:Annotated[str,Depends(require_model_governance)]) -> dict[str, object]:
        learning.registry.approve_for_simulation(name,_actor,"model_governor"); return learning.registry.get(name)

    @app.post("/api/shield/learning/policies/{name}/activate", response_model=dict[str, object])
    def activate_learning_policy(name:str, _actor:Annotated[str,Depends(require_model_governance)]) -> dict[str, object]:
        learning.registry.activate(name,_actor,"model_governor"); return {"active":learning.registry.active_name,"policy":learning.registry.get(name)}

    @app.post("/api/shield/learning/policies/rollback", response_model=dict[str, object])
    def rollback_learning_policy(_actor:Annotated[str,Depends(require_model_governance)]) -> dict[str, object]:
        active,previous=learning.registry.rollback(_actor,"model_governor"); return {"rolled_back":active,"active":previous}

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, error: HTTPException) -> JSONResponse:
        detail = error.detail if isinstance(error.detail, dict) else {"code": "request_error", "message": str(error.detail)}
        return JSONResponse(status_code=error.status_code, content={"error": detail})

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, error: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "validation_error", "message": "Request validation failed.", "details": error.errors()}},
        )

    @app.get("/api/system/status", response_model=SystemStatusDto)
    def system_status(service: Service) -> SystemStatusDto:
        return SystemStatusDto(
            mode="LIVE",
            data=SystemPartDto(label="LIVE SQLITE", status="ready"),
            database=SystemPartDto(label="SQLite", status="ready"),
            model=SystemPartDto(label="Isolation Forest", status=service.model_status),
            operator=OperatorDto(label="LOCAL ANALYST", session="API"),
            counts=SystemCountsDto(
                employees=len(service.employees()),
                activity_events=len(service.event_rows()),
                detections=len(service.detection_rows()),
                alerts=len(service.alert_rows()),
            ),
        )

    @app.get("/api/overview", response_model=OverviewDto)
    def operations_overview(service: Service) -> OverviewDto:
        return overview(service.detection_rows(), service.alert_rows())

    @app.get("/api/activity", response_model=ActivityPageDto)
    def list_activity(
        service: Service,
        start: datetime | None = None,
        end: datetime | None = None,
        employee_id: str | None = None,
        department: str | None = None,
        activity_type: str | None = None,
        scenario: str | None = None,
        risk_level: str | None = None,
        anomalous_only: bool = False,
        q: str | None = None,
        sort: Literal["timestamp", "risk_score", "employee", "activity_type"] = "timestamp",
        direction: Literal["asc", "desc"] = "desc",
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> ActivityPageDto:
        rows = service.event_rows()
        query = q.strip().lower() if q else None

        def matches(row: dict[str, object]) -> bool:
            timestamp = datetime.fromisoformat(str(row["timestamp"]))
            if start and timestamp < start:
                return False
            if end and timestamp > end:
                return False
            if employee_id and row["employee_id"] != employee_id:
                return False
            if department and row["department"] != department:
                return False
            if activity_type and row["activity_type"] != activity_type:
                return False
            if scenario and row["scenario"] != scenario:
                return False
            if risk_level and row.get("risk_level") != risk_level:
                return False
            percentile = row.get("anomaly_percentile")
            if anomalous_only and (percentile is None or float(percentile) < 95.0):
                return False
            if query:
                searchable = (
                    row["event_id"], row["employee_id"], row["employee_name"], row["department"],
                    row["activity_type"], row["scenario"], row["device_id"], row["ip_address"],
                    row["city"], row["country"], row["file_name"],
                )
                if not any(query in str(value).lower() for value in searchable):
                    return False
            return True

        filtered = [row for row in rows if matches(row)]
        sorters = {
            "timestamp": lambda row: str(row["timestamp"]),
            "risk_score": lambda row: float(row.get("final_risk_score") or -1),
            "employee": lambda row: str(row["employee_name"]).lower(),
            "activity_type": lambda row: str(row["activity_type"]),
        }
        filtered.sort(key=sorters[sort], reverse=direction == "desc")
        total = len(filtered)
        offset = (page - 1) * page_size
        return ActivityPageDto(items=[activity(row) for row in filtered[offset:offset + page_size]], page=_page_meta(page, page_size, total))

    @app.get("/api/threats", response_model=ThreatPageDto)
    def list_threats(
        service: Service,
        q: str | None = None,
        risk: str | None = None,
        status: str | None = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=250)] = 100,
    ) -> ThreatPageDto:
        query = q.strip().lower() if q else None
        items = [threat(row) for row in service.alert_rows()]
        items = [
            item for item in items
            if (not risk or risk == "All" or item.risk_level == risk)
            and (not status or status == "All" or item.status == status)
            and (
                not query
                or any(query in value.lower() for value in (
                    item.alert_id, item.employee_id, item.employee_name, item.department,
                    item.title, item.story, item.primary_evidence.code if item.primary_evidence else "",
                ))
            )
        ]
        items.sort(key=lambda item: (item.risk_score, item.occurred_at, item.alert_id), reverse=True)
        total = len(items)
        offset = (page - 1) * page_size
        return ThreatPageDto(items=items[offset:offset + page_size], page=_page_meta(page, page_size, total))

    @app.get("/api/threats/{alert_id}", response_model=ThreatSummaryDto)
    def threat_detail(alert_id: str, service: Service) -> ThreatSummaryDto:
        row = service.database.get_alert_row(alert_id)
        if row is None:
            raise HTTPException(404, {"code": "alert_not_found", "message": f"Unknown alert: {alert_id}"})
        return threat(row)

    @app.get("/api/response/users/{employee_id}", response_model=ContainmentStateDto)
    def response_state(employee_id: str, service: Service) -> ContainmentStateDto:
        try:
            return _containment_state(service.containment_state(employee_id))
        except KeyError as error:
            raise HTTPException(404, {"code": "employee_not_found", "message": str(error.args[0])}) from error

    @app.get("/api/response/users/{employee_id}/history", response_model=ResponseHistoryDto)
    def response_history(employee_id: str, service: Service) -> ResponseHistoryDto:
        try:
            return ResponseHistoryDto(items=[_response_audit(item) for item in service.response_history(employee_id)])
        except KeyError as error:
            raise HTTPException(404, {"code": "employee_not_found", "message": str(error.args[0])}) from error

    def perform_response_action(
        employee_id: str,
        action: ResponseAction,
        payload: ResponseActionRequest,
        service: SentinelService,
    ) -> ResponseActionResultDto:
        try:
            state, recorded = service.perform_response_action(
                employee_id,
                action,
                payload.reason,
                payload.actor,
                payload.alert_id,
            )
            return ResponseActionResultDto(state=_containment_state(state), action_recorded=recorded)
        except KeyError as error:
            message = str(error.args[0])
            code = "alert_not_found" if "alert" in message.lower() else "employee_not_found"
            raise HTTPException(404, {"code": code, "message": message}) from error
        except ValueError as error:
            raise HTTPException(422, {"code": "invalid_response_action", "message": str(error)}) from error
        except ResponseActionFailed as error:
            raise HTTPException(503, {"code": "containment_failed", "message": str(error)}) from error

    @app.post("/api/response/users/{employee_id}/block", response_model=ResponseActionResultDto)
    def block_user(employee_id: str, payload: ResponseActionRequest, service: Service) -> ResponseActionResultDto:
        return perform_response_action(employee_id, ResponseAction.BLOCK_USER, payload, service)

    @app.post("/api/response/users/{employee_id}/unblock", response_model=ResponseActionResultDto)
    def unblock_user(employee_id: str, payload: ResponseActionRequest, service: Service) -> ResponseActionResultDto:
        return perform_response_action(employee_id, ResponseAction.UNBLOCK_USER, payload, service)

    @app.post("/api/response/users/{employee_id}/revoke-sessions", response_model=ResponseActionResultDto)
    def revoke_sessions(employee_id: str, payload: ResponseActionRequest, service: Service) -> ResponseActionResultDto:
        return perform_response_action(employee_id, ResponseAction.REVOKE_SESSIONS, payload, service)

    @app.post("/api/response/users/{employee_id}/restore-sessions", response_model=ResponseActionResultDto)
    def restore_sessions(employee_id: str, payload: ResponseActionRequest, service: Service) -> ResponseActionResultDto:
        return perform_response_action(employee_id, ResponseAction.RESTORE_SESSIONS, payload, service)

    @app.post("/api/response/users/{employee_id}/contain", response_model=ResponseActionResultDto)
    def contain_user(employee_id: str, payload: ResponseActionRequest, service: Service) -> ResponseActionResultDto:
        return perform_response_action(employee_id, ResponseAction.BLOCK_AND_REVOKE, payload, service)

    @app.get("/api/users", response_model=UserPageDto)
    def list_users(
        service: Service,
        q: str | None = None,
        department: str | None = None,
        role: str | None = None,
        sort: Literal["name", "department", "risk", "activity"] = "name",
        direction: Literal["asc", "desc"] = "asc",
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> UserPageDto:
        employees = service.employees()
        profiles = service.database.list_profiles()
        events = service.event_rows()
        alerts = service.alert_rows()
        detections = service.detection_rows()
        event_counts = Counter(str(row["employee_id"]) for row in events)
        alert_counts = Counter(str(row["employee_id"]) for row in alerts)
        latest_detection: dict[str, dict[str, object]] = {}
        for row in detections:
            latest_detection.setdefault(str(row["employee_id"]), row)
        query = q.strip().lower() if q else None
        items: list[UserSummaryDto] = []
        for employee in employees:
            if department and employee.department != department:
                continue
            if role and employee.normal_privilege != role:
                continue
            if query and not any(query in value.lower() for value in (employee.employee_id, employee.employee_name, employee.department, employee.normal_privilege)):
                continue
            profile = profiles.get(employee.employee_id) or build_profiles([employee], [])[employee.employee_id]
            latest = latest_detection.get(employee.employee_id)
            key = peer_group_key(employee)
            items.append(UserSummaryDto(
                employee_id=employee.employee_id,
                employee_name=employee.employee_name,
                department=employee.department,
                role=employee.normal_privilege,
                peer_group=peer_group(key.department, key.role),
                profile_confidence=profile.confidence,
                history_event_count=profile.history_event_count,
                activity_count=event_counts[employee.employee_id],
                alert_count=alert_counts[employee.employee_id],
                latest_risk_score=float(latest["final_risk_score"]) if latest else None,
                latest_risk_level=str(latest["risk_level"]) if latest else None,
            ))
        sorters = {
            "name": lambda item: item.employee_name.lower(),
            "department": lambda item: (item.department, item.employee_name),
            "risk": lambda item: item.latest_risk_score if item.latest_risk_score is not None else -1,
            "activity": lambda item: item.activity_count,
        }
        items.sort(key=sorters[sort], reverse=direction == "desc")
        total = len(items)
        offset = (page - 1) * page_size
        return UserPageDto(items=items[offset:offset + page_size], page=_page_meta(page, page_size, total))

    @app.get("/api/users/{employee_id}", response_model=UserDetailDto)
    def user_detail(employee_id: str, service: Service) -> UserDetailDto:
        employee = service.database.get_employee(employee_id)
        if employee is None:
            raise HTTPException(404, {"code": "employee_not_found", "message": f"Unknown employee: {employee_id}"})
        profile = service.database.get_profile(employee_id) or build_profiles([employee], [])[employee_id]
        employees = service.employees()
        events = service.database.list_activity_events()
        key = peer_group_key(employee)
        peers = [item for item in employees if item.employee_id != employee_id and peer_group_key(item) == key]
        peer_profile = build_peer_profile(key, peers, events)
        employee_events = [event for event in events if event.employee_id == employee_id]
        latest_event = max(employee_events, key=lambda item: (item.timestamp, item.event_id)) if employee_events else None
        assessment = service.behavioural_assessment(latest_event.event_id) if latest_event else None
        detection_rows = service.detection_rows(employee_id)[:50]
        activity_rows = [row for row in service.event_rows() if row["employee_id"] == employee_id][:50]
        alert_rows = [row for row in service.alert_rows() if row["employee_id"] == employee_id][:50]
        return UserDetailDto(
            employee_id=employee.employee_id,
            employee_name=employee.employee_name,
            department=employee.department,
            role=employee.normal_privilege,
            home_city=employee.home_city,
            home_country=employee.home_country,
            peer_group=peer_group(key.department, key.role),
            personal_baseline=personal_baseline(profile),
            peer_baseline=peer_baseline(peer_profile),
            current_assessment=behavioural_assessment(assessment) if assessment else None,
            risk_history=[detection_history(row) for row in detection_rows],
            activity_history=[activity(row) for row in activity_rows],
            related_alerts=[threat(row) for row in alert_rows],
        )

    @app.get("/api/models", response_model=list[ModelMetadataDto])
    def models(service: Service) -> list[ModelMetadataDto]:
        return [ModelMetadataDto(
            name="Isolation Forest",
            implementation="sklearn.ensemble.IsolationForest",
            version=config.MODEL_VERSION,
            status=service.model_status,
            feature_schema_version=config.FEATURE_SCHEMA_VERSION,
            feature_order=list(config.FEATURE_ORDER),
            training_rows=service.detector.training_row_count,
            training_scope="Normal history only; final 30% per employee after the persisted baseline split.",
            estimator_configuration={"n_estimators": 200, "contamination": "auto", "max_samples": "auto", "random_state": config.RANDOM_SEED, "n_jobs": 1},
            anomaly_definition="Empirical nonconformity percentile against normal training history; not an attack probability.",
        ), ModelMetadataDto(
            name="CERT r4.2 PennyLane QSVC (advisory)",
            implementation="PennyLane fidelity kernel + sklearn.svm.SVC(precomputed)",
            version="cert-r4.2-qsvc-v1",
            status="ready" if cert.artifact_path.exists() else "artifact-missing",
            feature_schema_version="cert-r4.2-user-day-pca4-v1",
            feature_order=["pca_1", "pca_2", "pca_3", "pca_4"],
            training_rows=250,
            training_scope="Fixed balanced chronological benchmark cohort; runtime accepts prepared CERT user-days only.",
            estimator_configuration={"qubits": 4, "C": 1.0, "kernel": "PennyLane exact fidelity", "advisory": True},
            anomaly_definition="Validation-thresholded QSVC decision score; not a calibrated probability and not validated for natural alert burden.",
        ), ModelMetadataDto(
            name="CERT r4.2 PennyLane VQC (advisory)",
            implementation="PennyLane AngleEmbedding + StronglyEntanglingLayers",
            version="cert-r4.2-vqc-v1",
            status="ready" if cert.vqc_artifact_path.exists() else "artifact-missing",
            feature_schema_version="cert-r4.2-user-day-pca4-v1",
            feature_order=["pca_1", "pca_2", "pca_3", "pca_4"],
            training_rows=250,
            training_scope="Fixed balanced chronological benchmark; frozen checkpoint and train-only MinMax scaling.",
            estimator_configuration={"qubits": 4, "layers": 2, "measurement": "mean Pauli-Z", "advisory": True},
            anomaly_definition="Validation-thresholded mean Pauli-Z score; not a calibrated probability.",
        ), ModelMetadataDto(
            name="CERT r4.2 RBF-SVM comparator",
            implementation="sklearn.svm.SVC(kernel='rbf')",
            version="cert-r4.2-rbf-svm-v1",
            status="ready" if cert.artifact_path.exists() else "artifact-missing",
            feature_schema_version="cert-r4.2-user-day-pca4-v1",
            feature_order=["pca_1", "pca_2", "pca_3", "pca_4"],
            training_rows=250,
            training_scope="Same fixed benchmark cohort; independent classical verification baseline.",
            estimator_configuration={"kernel": "RBF", "advisory": True},
            anomaly_definition="Validation-thresholded SVM decision score; not a calibrated probability.",
        )]

    @app.get("/api/models/evaluation", response_model=dict[str, object])
    def model_evaluation() -> dict[str, object]:
        return evaluate_existing_models()

    @app.get("/api/models/quantum", response_model=dict[str, object])
    def quantum_evaluation() -> dict[str, object]:
        return evaluate_quantum_kernel()

    def quantum_event_document(event_id: str, service: SentinelService) -> dict[str, object]:
        try:
            return service.quantum_event_analysis(event_id)
        except KeyError as error:
            raise HTTPException(404, {"code": "event_not_found", "message": str(error.args[0])}) from error

    @app.get("/api/quantum/status", response_model=dict[str, object])
    def quantum_status() -> dict[str, object]:
        return QuantumAnalyzer.status()

    @app.get("/api/quantum/models", response_model=dict[str, object])
    def quantum_models() -> dict[str, object]:
        return QuantumAnalyzer.models()

    @app.get("/api/quantum/events/{event_id}/analysis", response_model=dict[str, object])
    def quantum_event_analysis(event_id: str, service: Service) -> dict[str, object]:
        return quantum_event_document(event_id, service)

    @app.get("/api/quantum/events/{event_id}/circuit", response_model=dict[str, object])
    def quantum_event_circuit(event_id: str, service: Service) -> dict[str, object]:
        return dict(quantum_event_document(event_id, service)["circuit"])

    @app.get("/api/quantum/events/{event_id}/comparison", response_model=dict[str, object])
    def quantum_event_comparison(event_id: str, service: Service) -> dict[str, object]:
        return dict(quantum_event_document(event_id, service)["comparison"])

    @app.get("/api/quantum/events/{event_id}/similarity", response_model=dict[str, object])
    def quantum_event_similarity(event_id: str, service: Service) -> dict[str, object]:
        document = dict(quantum_event_document(event_id, service)["threatSimilarity"])
        document["eventId"] = event_id
        return document
    @app.get("/api/quantum/optimization/status", response_model=dict[str, object])
    def qaoa_status(service: Service) -> dict[str, object]:
        """Return status and config for QAOA optimizer (experimental, advisory only)."""
        return {
            "experimental": True,
            "affectsProductionRisk": False,
            "executesContainment": False,
            "maxAlerts": config.QAOA_MAX_ALERTS,
            "depth": config.QAOA_DEPTH,
            "shots": config.QAOA_SHOTS,
        }

    @app.post("/api/quantum/optimization/prioritize", response_model=dict[str, object])
    def qaoa_prioritize(service: Service) -> dict[str, object]:
        """Run the read‑only QAOA response prioritization and cache the result."""
        result = service.qaoa_response_prioritization()
        # cache result for later retrieval
        if not hasattr(app.state, "qaoa_latest"):
            app.state.qaoa_latest = result
        else:
            app.state.qaoa_latest = result
        return result

    @app.get("/api/quantum/optimization/latest", response_model=dict[str, object])
    def qaoa_latest(service: Service) -> dict[str, object]:
        """Return the most recent cached QAOA result, or 404 if not run yet."""
        if not hasattr(app.state, "qaoa_latest"):
            raise HTTPException(404, {"code": "no_qaoa_result", "message": "QAOA optimization has not been run yet."})
        return app.state.qaoa_latest
    @app.get("/api/attack-lab/scenarios", response_model=list[AttackLabScenarioDto])
    def attack_lab_scenarios() -> list[AttackLabScenarioDto]:
        descriptions = {
            "account_compromise": "Authentication anomaly, unknown-device login, then sensitive access.",
            "credential_attack": "Failed authentication burst followed by a successful login.",
            "privilege_abuse": "Successful login, privilege escalation, then sensitive access.",
            "data_exfiltration": "Sensitive access followed by a bulk or large download.",
        }
        counts = {"account_compromise": 3, "credential_attack": 2, "privilege_abuse": 3, "data_exfiltration": 2}
        return [AttackLabScenarioDto(scenario=key, label=label, event_count=counts[key], description=descriptions[key]) for key, label in ATTACK_LAB_SCENARIOS.items()]

    def run_document(simulation_id: str, service: SentinelService) -> AttackLabRunDto:
        try:
            run = service.simulation_run(simulation_id)
        except KeyError as error:
            raise HTTPException(404, {"code": "simulation_not_found", "message": str(error).strip("'")}) from error
        event_rows = {str(row["event_id"]): row for row in service.event_rows()}
        return AttackLabRunDto(
            simulation_id=run.simulation_id,
            employee_id=run.employee_id,
            scenario=run.scenario,
            start_time=run.start_time,
            intensity=run.intensity,
            status=run.status,
            created_at=run.created_at,
            event_ids=list(run.event_ids),
            findings=[SequenceFindingDto(
                code=item.code, title=item.title, severity=item.severity, status=item.status,
                event_ids=list(item.event_ids), window_minutes=item.window_minutes, evidence=list(item.evidence),
            ) for item in run.findings],
            events=[activity(event_rows[event_id]) for event_id in run.event_ids if event_id in event_rows],
        )

    @app.post("/api/attack-lab/runs", response_model=AttackLabRunDto, status_code=201)
    def create_attack_lab_run(payload: AttackLabRunRequest, service: Service) -> AttackLabRunDto:
        if payload.scenario not in ATTACK_LAB_SCENARIOS:
            raise HTTPException(422, {"code": "unknown_scenario", "message": f"Unknown Attack Lab scenario: {payload.scenario}"})
        try:
            run = service.run_attack_lab(payload.scenario, payload.employee_id, payload.start_time, payload.intensity)
        except KeyError as error:
            raise HTTPException(404, {"code": "employee_not_found", "message": str(error).strip("'")}) from error
        return run_document(run.simulation_id, service)

    @app.get("/api/attack-lab/runs/{simulation_id}", response_model=AttackLabRunDto)
    def get_attack_lab_run(simulation_id: str, service: Service) -> AttackLabRunDto:
        return run_document(simulation_id, service)

    def mitre_document(report, service: SentinelService) -> MitreReportDto:
        event_rows = {str(row["event_id"]): row for row in service.event_rows()}
        return mitre_report(report, event_rows)

    @app.get("/api/mitre/catalog", response_model=MitreCatalogDto)
    def mitre_catalog() -> MitreCatalogDto:
        return MitreCatalogDto(
            source_version=ATTACK_VERSION,
            source_url=ATTACK_SOURCE_URL,
            techniques=[MitreTechniqueDto(
                technique_id=item.technique_id,
                name=item.name,
                tactics=list(item.tactics),
                description=item.description,
                source_version=item.source_version,
                source_url=item.source_url,
            ) for item in catalog()],
        )

    @app.get("/api/mitre/overview", response_model=MitreOverviewDto)
    def mitre_overview(service: Service) -> MitreOverviewDto:
        data = service.mitre_overview()
        event_rows = {str(row["event_id"]): row for row in service.event_rows()}
        return MitreOverviewDto(
            source_version=str(data["source_version"]),
            source_url=str(data["source_url"]),
            catalog_technique_count=int(data["catalog_technique_count"]),
            mapped_technique_count=int(data["mapped_technique_count"]),
            story_count=int(data["story_count"]),
            correlated_case_count=int(data["correlated_case_count"]),
            technique_counts=dict(data["technique_counts"]),
            recent_reports=[mitre_report(report, event_rows) for report in data["recent_reports"]],
            affects_production_risk=bool(data["affects_production_risk"]),
        )

    @app.get("/api/mitre/events/{event_id}", response_model=MitreReportDto)
    def mitre_event(event_id: str, service: Service) -> MitreReportDto:
        report = service.mitre_event_report(event_id)
        if report is None:
            raise HTTPException(404, {"code": "event_not_found", "message": f"Unknown event: {event_id}"})
        return mitre_document(report, service)

    @app.get("/api/mitre/attack-runs/{run_id}", response_model=MitreReportDto)
    def mitre_attack_run(run_id: str, service: Service) -> MitreReportDto:
        report = service.mitre_attack_run_report(run_id)
        if report is None:
            raise HTTPException(404, {"code": "simulation_not_found", "message": f"Unknown simulation: {run_id}"})
        return mitre_document(report, service)

    @app.get("/api/mitre/alerts/{alert_id}", response_model=MitreReportDto)
    def mitre_alert(alert_id: str, service: Service) -> MitreReportDto:
        report = service.mitre_alert_report(alert_id)
        if report is None:
            raise HTTPException(404, {"code": "alert_not_found", "message": f"Unknown alert: {alert_id}"})
        return mitre_document(report, service)

    @app.get("/api/graph/overview")
    def graph_overview(service: Service) -> GraphOverviewDto:
        data = service.graph_overview()
        return GraphOverviewDto(
            node_count=data["node_count"],
            edge_count=data["edge_count"],
            entity_counts=data["entity_counts"],
            finding_count=data["finding_count"],
            high_severity_finding_count=data["high_severity_finding_count"],
        )


    @app.get("/api/graph/entities/{entity_type}/{entity_id:path}")
    def graph_entity_detail(entity_type: str, entity_id: str, service: Service) -> GraphEntityDetailDto:
        data = service.graph_entity_detail(entity_type, entity_id)
        if data is None:
            raise HTTPException(404, {"code": "entity_not_found", "message": f"Unknown entity: {entity_type}:{entity_id}"})
        return GraphEntityDetailDto(
            entity=graph_node(data["entity"]),
            connected_entities=[graph_node(n) for n in data["connected_entities"]],
            edges=[graph_edge(e) for e in data["edges"]],
            findings=[graph_finding(f) for f in data["findings"]],
            event_ids=data["event_ids"],
        )

    @app.get("/api/graph/events/{event_id}")
    def graph_event_context(event_id: str, service: Service) -> GraphEventContextDto:
        data = service.graph_event_context(event_id)
        if data is None:
            raise HTTPException(404, {"code": "event_not_found", "message": f"Unknown event: {event_id}"})
        return GraphEventContextDto(
            event_id=data["event_id"],
            entities=[graph_node(n) for n in data["entities"]],
            findings=[graph_finding(f) for f in data["findings"]],
        )

    @app.get("/api/graph/attack-runs/{simulation_id}")
    def graph_attack_run_context(simulation_id: str, service: Service) -> GraphAttackRunContextDto:
        data = service.graph_attack_run_context(simulation_id)
        if data is None:
            raise HTTPException(404, {"code": "simulation_not_found", "message": f"Unknown simulation: {simulation_id}"})
        return GraphAttackRunContextDto(
            simulation_id=data["simulation_id"],
            employees=[graph_node(n) for n in data["employees"]],
            devices=[graph_node(n) for n in data["devices"]],
            ip_addresses=[graph_node(n) for n in data["ip_addresses"]],
            locations=[graph_node(n) for n in data["locations"]],
            files=[graph_node(n) for n in data["files"]],
            findings=[graph_finding(f) for f in data["findings"]],
            event_ids=data["event_ids"],
        )

    @app.get("/api/graph/findings")
    def list_graph_findings(
        service: Service,
        severity: str | None = None,
        finding_type: str | None = None,
        entity_type: str | None = None,
        employee_id: str | None = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> GraphFindingsPageDto:
        findings = service.graph_findings(severity=severity, finding_type=finding_type, entity_type=entity_type, employee_id=employee_id)
        total = len(findings)
        offset = (page - 1) * page_size
        items = [graph_finding(f) for f in findings[offset:offset + page_size]]
        return GraphFindingsPageDto(items=items, page=_page_meta(page, page_size, total))

    @app.get("/api/graph/data")
    def graph_data(
        service: Service,
        node_type: Annotated[str | None, Query(alias="nodeType")] = None,
        severity: str | None = None,
        employee_id: Annotated[str | None, Query(alias="employeeId")] = None,
        attack_run_id: Annotated[str | None, Query(alias="attackRunId")] = None,
        max_nodes: Annotated[int | None, Query(alias="maxNodes")] = None,
    ) -> GraphDataDto:
        data = service.graph_data(
            node_type=node_type,
            severity=severity,
            employee_id=employee_id,
            attack_run_id=attack_run_id,
            max_nodes=max_nodes,
        )
        return GraphDataDto(
            nodes=[graph_node(n) for n in data["nodes"]],
            edges=[graph_edge(e) for e in data["edges"]],
            findings=[graph_finding(f) for f in data["findings"]],
        )



    return app


app = create_app()
