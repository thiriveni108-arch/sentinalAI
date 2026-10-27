import type {
  ActivityFilters,
  ActivityRecord,
  AttackLabRun,
  AttackLabScenario,
  CreateAttackLabRun,
  OperationsOverview,
  ModelEvaluationReport,
  ModelMetadata,
  QuantumEvaluationReport,
  PageResult,
  SystemCounts,
  SystemStatusSnapshot,
  ThreatFilters,
  ThreatSummary,
  UserDetail,
  UserFilters,
  UserSummary,
  GraphOverview,
  GraphEntityDetail,
  GraphEventContext,
  GraphAttackRunContext,
  GraphFinding,
  GraphData,
  GraphFilters,
  MitreCatalog,
  MitreOverview,
  MitreReport,
  ContainmentState,
  ResponseHistory,
  QuantumStatus,
  QuantumEventAnalysis,
  QaoaOptimizationStatus,
  QaoaOptimizationResult,
  CertStatus, CertUserSummary, CertUserDay, CertFinding, CertInvestigation, CertReplay, CertBenchmarks, CertIncident, IncidentList,
} from "@/domain/sentinel";

export interface SentinelDataSource {
  readonly mode: "fixture" | "http";
  getSystemStatus(): Promise<SystemStatusSnapshot>;
  getCounts(): Promise<SystemCounts>;
  getOverview(): Promise<OperationsOverview>;
  listThreats(filters?: ThreatFilters): Promise<ThreatSummary[]>;
  getThreat(alertId: string): Promise<ThreatSummary | null>;
  listActivity(filters?: ActivityFilters): Promise<PageResult<ActivityRecord>>;
  listUsers(filters?: UserFilters): Promise<PageResult<UserSummary>>;
  getUser(employeeId: string): Promise<UserDetail | null>;
  listAttackLabScenarios(): Promise<AttackLabScenario[]>;
  createAttackLabRun(input: CreateAttackLabRun): Promise<AttackLabRun>;
  getAttackLabRun(simulationId: string): Promise<AttackLabRun | null>;
  listModels(): Promise<ModelMetadata[]>;
  getModelEvaluation(): Promise<ModelEvaluationReport | null>;
  getQuantumEvaluation(): Promise<QuantumEvaluationReport>;
  getQuantumStatus(): Promise<QuantumStatus>;
  getQuantumEventAnalysis(eventId: string): Promise<QuantumEventAnalysis | null>;
  getGraphOverview(): Promise<GraphOverview>;
  getGraphData(filters?: GraphFilters): Promise<GraphData>;
  getGraphEntityDetail(entityType: string, entityId: string): Promise<GraphEntityDetail | null>;
  getGraphEventContext(eventId: string): Promise<GraphEventContext | null>;
  getGraphAttackRunContext(simulationId: string): Promise<GraphAttackRunContext | null>;
  getGraphFindings(filters?: { severity?: string; findingType?: string; entityType?: string; employeeId?: string }): Promise<PageResult<GraphFinding>>;
  getMitreCatalog(): Promise<MitreCatalog>;
  getMitreOverview(): Promise<MitreOverview>;
  getMitreEvent(eventId: string): Promise<MitreReport | null>;
  getMitreAttackRun(simulationId: string): Promise<MitreReport | null>;
  getMitreAlert(alertId: string): Promise<MitreReport | null>;
  getContainmentState(employeeId: string): Promise<ContainmentState | null>;
  getResponseHistory(employeeId: string): Promise<ResponseHistory>;
  getQuantumOptimizationStatus(): Promise<QaoaOptimizationStatus>;
  runQuantumOptimization(): Promise<QaoaOptimizationResult>;
  getQuantumOptimizationLatest(): Promise<QaoaOptimizationResult | null>;
  getCertStatus(): Promise<CertStatus>;
  listCertUsers(filters?: { q?: string; page?: number; pageSize?: number }): Promise<PageResult<CertUserSummary>>;
  listCertUserDays(user: string, filters?: { start?: string; end?: string; page?: number; pageSize?: number }): Promise<PageResult<CertUserDay>>;
  listCertFindings(filters?: { q?: string; prediction?: number; page?: number; pageSize?: number }): Promise<PageResult<CertFinding> & { scoringCoverage: number; coverageBasis: string; advisory: boolean }>;
  getCertInvestigation(user: string, date: string, split?: string): Promise<CertInvestigation | null>;
  getCertReplay(user: string, split?: string): Promise<CertReplay | null>;
  getCertBenchmarks(): Promise<CertBenchmarks>;
  listIncidents(detected?: boolean): Promise<IncidentList>;
  getIncident(incidentId: string): Promise<CertIncident | null>;
  createIncident(input: { user: string; date: string; split: string; scenario: string }): Promise<CertIncident>;
  planIncidentResponse(incidentId: string): Promise<CertIncident>;
  planAdaptiveResponse(incidentId: string, familyId: string): Promise<CertIncident>;
  executeAdaptiveAction(incidentId: string, actionId: string): Promise<CertIncident>;
  rollbackAdaptiveAction(incidentId: string, actionId: string): Promise<CertIncident>;
}
