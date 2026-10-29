import "server-only";
import type { ActivityFilters, ActivityRecord, AttackLabRun, AttackLabScenario, CreateAttackLabRun, ModelEvaluationReport, ModelMetadata, OperationsOverview, PageResult, QuantumEvaluationReport, QuantumStatus, QuantumEventAnalysis, SystemCounts, SystemStatusSnapshot, ThreatFilters, ThreatSummary, UserDetail, UserFilters, UserSummary, GraphOverview, GraphEntityDetail, GraphEventContext, GraphAttackRunContext, GraphFinding, GraphData, GraphFilters, MitreCatalog, MitreOverview, MitreReport, ContainmentState, ResponseHistory, QaoaOptimizationStatus, QaoaOptimizationResult, CertStatus, CertUserSummary, CertUserDay, CertFinding, CertInvestigation, CertReplay, CertBenchmarks, CertIncident, IncidentList } from "@/domain/sentinel";

import type { SentinelDataSource } from "@/data/sentinel-data-source";

interface ApiErrorDocument { error?: { code?: string; message?: string } }

export class SentinelApiError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
    this.name = "SentinelApiError";
  }
}

function queryString(values: Record<string, string | number | boolean | undefined>) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "" && value !== "All") query.set(key, String(value));
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export class HttpDataSource implements SentinelDataSource {
  readonly mode = "http" as const;
  constructor(private readonly baseUrl: string) {}

  private async get<T>(path: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, { cache: "no-store", headers: { accept: "application/json" } });
    if (!response.ok) {
      const document = await response.json().catch(() => ({})) as ApiErrorDocument;
      throw new SentinelApiError(response.status, document.error?.code ?? "api_error", document.error?.message ?? `SentinelAI API returned ${response.status}.`);
    }
    return response.json() as Promise<T>;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, { method: "POST", cache: "no-store", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) {
      const document = await response.json().catch(() => ({})) as ApiErrorDocument;
      throw new SentinelApiError(response.status, document.error?.code ?? "api_error", document.error?.message ?? `SentinelAI API returned ${response.status}.`);
    }
    return response.json() as Promise<T>;
  }

  getSystemStatus() { return this.get<SystemStatusSnapshot>("/api/system/status"); }
  async getCounts(): Promise<SystemCounts> {
    const status = await this.getSystemStatus();
    if (!status.counts) throw new SentinelApiError(502, "missing_counts", "SentinelAI API status did not include dataset counts.");
    return status.counts;
  }
  getOverview() { return this.get<OperationsOverview>("/api/overview"); }
  async listThreats(filters: ThreatFilters = {}) {
    const result = await this.get<PageResult<ThreatSummary>>(`/api/threats${queryString({ q: filters.q, risk: filters.risk, status: filters.status, page_size: 100 })}`);
    return result.items;
  }
  async getThreat(alertId: string) {
    try {
      return await this.get<ThreatSummary>(`/api/threats/${encodeURIComponent(alertId)}`);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  listActivity(filters: ActivityFilters = {}) {
    return this.get<PageResult<ActivityRecord>>(`/api/activity${queryString({
      q: filters.q, start: filters.start, end: filters.end, employee_id: filters.employeeId,
      department: filters.department, activity_type: filters.activityType, scenario: filters.scenario,
      risk_level: filters.riskLevel, anomalous_only: filters.anomalousOnly || undefined,
      sort: filters.sort, direction: filters.direction, page: filters.page, page_size: filters.pageSize,
    })}`);
  }
  listUsers(filters: UserFilters = {}) {
    return this.get<PageResult<UserSummary>>(`/api/users${queryString({
      q: filters.q, department: filters.department, role: filters.role, sort: filters.sort,
      direction: filters.direction, page: filters.page, page_size: filters.pageSize,
    })}`);
  }
  async getUser(employeeId: string) {
    try {
      return await this.get<UserDetail>(`/api/users/${encodeURIComponent(employeeId)}`);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  listAttackLabScenarios() { return this.get<AttackLabScenario[]>("/api/attack-lab/scenarios"); }
  createAttackLabRun(input: CreateAttackLabRun) { return this.post<AttackLabRun>("/api/attack-lab/runs", input); }
  async getAttackLabRun(simulationId: string) {
    try {
      return await this.get<AttackLabRun>(`/api/attack-lab/runs/${encodeURIComponent(simulationId)}`);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  listModels() { return this.get<ModelMetadata[]>("/api/models"); }
  getModelEvaluation() { return this.get<ModelEvaluationReport>("/api/models/evaluation"); }
  getQuantumEvaluation() { return this.get<QuantumEvaluationReport>("/api/models/quantum"); }
  getQuantumStatus() { return this.get<QuantumStatus>("/api/quantum/status"); }
  async getQuantumEventAnalysis(eventId: string) {
    try {
      return await this.get<QuantumEventAnalysis>(`/api/quantum/events/${encodeURIComponent(eventId)}/analysis`);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }

  async getGraphOverview(): Promise<GraphOverview> {
    return this.get<GraphOverview>("/api/graph/overview");
  }

  async getGraphData(filters?: GraphFilters): Promise<GraphData> {
    return this.get<GraphData>("/api/graph/data" + queryString((filters ?? {}) as Record<string, string | number | boolean | undefined>));
  }


  async getGraphEntityDetail(entityType: string, entityId: string): Promise<GraphEntityDetail | null> {

    try {
      return await this.get<GraphEntityDetail>(`/api/graph/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`);
    } catch (err) {
      if (err instanceof SentinelApiError && err.status === 404) return null;
      throw err;
    }
  }

  async getGraphEventContext(eventId: string): Promise<GraphEventContext | null> {
    try {
      return await this.get<GraphEventContext>(`/api/graph/events/${encodeURIComponent(eventId)}`);
    } catch (err) {
      if (err instanceof SentinelApiError && err.status === 404) return null;
      throw err;
    }
  }

  async getGraphAttackRunContext(simulationId: string): Promise<GraphAttackRunContext | null> {
    try {
      return await this.get<GraphAttackRunContext>(`/api/graph/attack-runs/${encodeURIComponent(simulationId)}`);
    } catch (err) {
      if (err instanceof SentinelApiError && err.status === 404) return null;
      throw err;
    }
  }

  async getGraphFindings(filters?: { severity?: string; findingType?: string; entityType?: string; employeeId?: string }): Promise<PageResult<GraphFinding>> {
    return this.get<PageResult<GraphFinding>>("/api/graph/findings" + queryString(filters ?? {}));
  }

  getMitreCatalog() { return this.get<MitreCatalog>("/api/mitre/catalog"); }
  getMitreOverview() { return this.get<MitreOverview>("/api/mitre/overview"); }
  private async getMitreReport(path: string): Promise<MitreReport | null> {
    try {
      return await this.get<MitreReport>(path);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  getMitreEvent(eventId: string) { return this.getMitreReport(`/api/mitre/events/${encodeURIComponent(eventId)}`); }
  getMitreAttackRun(simulationId: string) { return this.getMitreReport(`/api/mitre/attack-runs/${encodeURIComponent(simulationId)}`); }
  getMitreAlert(alertId: string) { return this.getMitreReport(`/api/mitre/alerts/${encodeURIComponent(alertId)}`); }
  async getContainmentState(employeeId: string) {
    try {
      return await this.get<ContainmentState>(`/api/response/users/${encodeURIComponent(employeeId)}`);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  getResponseHistory(employeeId: string) {
    return this.get<ResponseHistory>(`/api/response/users/${encodeURIComponent(employeeId)}/history`);
  }

  getQuantumOptimizationStatus() {
    return this.get<QaoaOptimizationStatus>("/api/quantum/optimization/status");
  }

  runQuantumOptimization() {
    return this.post<QaoaOptimizationResult>("/api/quantum/optimization/prioritize", {});
  }

  async getQuantumOptimizationLatest() {
    try {
      return await this.get<QaoaOptimizationResult>("/api/quantum/optimization/latest");
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  getCertStatus() { return this.get<CertStatus>("/api/cert/status"); }
  listCertUsers(filters: { q?: string; page?: number; pageSize?: number } = {}) {
    return this.get<PageResult<CertUserSummary>>(`/api/cert/users${queryString({ q: filters.q, page: filters.page, page_size: filters.pageSize })}`);
  }
  listCertUserDays(user: string, filters: { start?: string; end?: string; page?: number; pageSize?: number } = {}) {
    return this.get<PageResult<CertUserDay>>(`/api/cert/users/${encodeURIComponent(user)}/days${queryString({ start: filters.start, end: filters.end, page: filters.page, page_size: filters.pageSize })}`);
  }
  listCertFindings(filters: { q?: string; prediction?: number; page?: number; pageSize?: number } = {}) {
    return this.get<PageResult<CertFinding> & { scoringCoverage: number; coverageBasis: string; advisory: boolean }>(`/api/cert/findings${queryString({ q: filters.q, prediction: filters.prediction, page: filters.page, page_size: filters.pageSize })}`);
  }
  async getCertInvestigation(user: string, date: string, split = "test") { try { return await this.get<CertInvestigation>(`/api/cert/user-days/${encodeURIComponent(user)}/${encodeURIComponent(date)}?split=${encodeURIComponent(split)}`); } catch (error) { if (error instanceof SentinelApiError && error.status === 404) return null; throw error; } }
  async getCertReplay(user: string, split = "test") { try { return await this.get<CertReplay>(`/api/cert/replay/${encodeURIComponent(user)}?split=${encodeURIComponent(split)}`); } catch (error) { if (error instanceof SentinelApiError && error.status === 404) return null; throw error; } }
  getCertBenchmarks() { return this.get<CertBenchmarks>("/api/cert/benchmarks"); }
  listIncidents(detected?: boolean) { return this.get<IncidentList>(`/api/incidents${queryString({ detected })}`); }
  async getIncident(incidentId: string) { try { return await this.get<CertIncident>(`/api/incidents/${encodeURIComponent(incidentId)}`); } catch (error) { if (error instanceof SentinelApiError && error.status === 404) return null; throw error; } }
  createIncident(input: { user: string; date: string; split: string; scenario: string }) { return this.post<CertIncident>("/api/incidents", input); }
  planIncidentResponse(incidentId: string) { return this.post<CertIncident>(`/api/incidents/${encodeURIComponent(incidentId)}/shield`, {}); }
  createLinkedShieldSession(incidentId: string, topology: string) { return this.post<{incident_id:string;session_id:string}>(`/api/incidents/${encodeURIComponent(incidentId)}/shield/session`, { topology, seed: 96001 }); }
  planAdaptiveResponse(incidentId: string, familyId: string) { return this.post<CertIncident>(`/api/incidents/${encodeURIComponent(incidentId)}/shield-act/plan`, { familyId }); }
  executeAdaptiveAction(incidentId: string, actionId: string) { return this.post<CertIncident>(`/api/incidents/${encodeURIComponent(incidentId)}/shield-act/actions/${encodeURIComponent(actionId)}/execute`, {}); }
  rollbackAdaptiveAction(incidentId: string, actionId: string) { return this.post<CertIncident>(`/api/incidents/${encodeURIComponent(incidentId)}/shield-act/actions/${encodeURIComponent(actionId)}/rollback`, {}); }
}
