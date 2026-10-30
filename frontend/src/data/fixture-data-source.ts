import "server-only";
import fixture from "@/data/fixtures/sentinel-demo.v1.json";
import type { ActivityFilters, ActivityRecord, AlertStatus, RiskLevel, SentinelFixture, ThreatFilters, UserFilters, UserSummary, GraphOverview, GraphNode, GraphEdge, GraphEntityDetail, GraphEventContext, GraphAttackRunContext, GraphFinding, GraphData, PageResult, MitreCatalog, MitreOverview, ContainmentState, ResponseHistory } from "@/domain/sentinel";

import { SentinelApiError } from "@/data/http-data-source";
import type { SentinelDataSource } from "@/data/sentinel-data-source";

const riskLevels = new Set<RiskLevel>(["Low", "Medium", "High", "Critical"]);
const alertStatuses = new Set<AlertStatus>(["New", "Investigating", "Resolved", "False Positive"]);

function validateFixture(value: unknown): asserts value is SentinelFixture {
  if (!value || typeof value !== "object") throw new Error("Sentinel fixture is not an object.");
  const candidate = value as Partial<SentinelFixture>;
  if (candidate.fixture?.schemaVersion !== "sentinel-demo.v1") throw new Error("Unsupported Sentinel fixture schema.");
  if (!candidate.system || !candidate.overview || !Array.isArray(candidate.threats) || !Array.isArray(candidate.activity) || !Array.isArray(candidate.employees) || !Array.isArray(candidate.profiles)) throw new Error("Sentinel fixture is missing required sections.");
  if (candidate.threats.length !== candidate.fixture.counts.alerts) throw new Error("Sentinel fixture alert count does not match the threat collection.");
  for (const threat of candidate.threats) {
    if (!riskLevels.has(threat.riskLevel) || !alertStatuses.has(threat.status)) throw new Error(`Invalid enum value in ${threat.alertId}.`);
    if (!Number.isFinite(threat.riskScore) || threat.riskScore < 0 || threat.riskScore > 100) throw new Error(`Invalid persisted risk score in ${threat.alertId}.`);
    if (threat.primaryEvidence && !threat.primaryEvidence.code) throw new Error(`Invalid primary evidence in ${threat.alertId}.`);
  }
}

const fixtureDocument: unknown = fixture;
validateFixture(fixtureDocument);
const data = fixtureDocument;

export const fixtureDataSource: SentinelDataSource = {
  mode: "fixture",
  getSystemStatus: async () => data.system,
  getCounts: async () => data.fixture.counts,
  getOverview: async () => data.overview,
  listThreats: async (filters: ThreatFilters = {}) => {
    const query = filters.q?.trim().toLowerCase();
    return data.threats.filter((threat) => {
      const matchesQuery = !query || [threat.alertId, threat.employeeId, threat.employeeName, threat.department, threat.title, threat.story, threat.primaryEvidence?.code ?? "", threat.primaryEvidence?.reason ?? ""]
        .some((value) => value.toLowerCase().includes(query));
      const matchesRisk = !filters.risk || filters.risk === "All" || threat.riskLevel === filters.risk;
      const matchesStatus = !filters.status || filters.status === "All" || threat.status === filters.status;
      return matchesQuery && matchesRisk && matchesStatus;
    });
  },
  getThreat: async (alertId: string) => data.threats.find((item) => item.alertId === alertId) ?? null,
  listActivity: async (filters: ActivityFilters = {}) => {
    const query = filters.q?.trim().toLowerCase();
    const items: ActivityRecord[] = data.activity.map((item) => ({
      ...item,
      anomalyPercentile: null,
      isAnomalous: false,
      simulationId: null,
    })).filter((item) => {
      const timestamp = new Date(item.occurredAt).getTime();
      const matchesQuery = !query || [item.eventId, item.employeeId, item.employeeName, item.department, item.activityType, item.scenario, item.deviceId, item.ipAddress, item.city, item.country, item.resourceName ?? ""]
        .some((value) => value.toLowerCase().includes(query));
      return matchesQuery
        && (!filters.start || timestamp >= new Date(filters.start).getTime())
        && (!filters.end || timestamp <= new Date(filters.end).getTime())
        && (!filters.employeeId || item.employeeId === filters.employeeId)
        && (!filters.department || item.department === filters.department)
        && (!filters.activityType || item.activityType === filters.activityType)
        && (!filters.scenario || item.scenario === filters.scenario)
        && (!filters.riskLevel || filters.riskLevel === "All" || item.riskLevel === filters.riskLevel)
        && !filters.anomalousOnly;
    });
    const direction = filters.direction === "asc" ? 1 : -1;
    const sort = filters.sort ?? "timestamp";
    items.sort((left, right) => {
      const values = sort === "risk_score"
        ? [(left.riskScore ?? -1), (right.riskScore ?? -1)]
        : sort === "employee"
          ? [left.employeeName, right.employeeName]
          : sort === "activity_type"
            ? [left.activityType, right.activityType]
            : [left.occurredAt, right.occurredAt];
      return (values[0] < values[1] ? -1 : values[0] > values[1] ? 1 : 0) * direction;
    });
    const page = filters.page ?? 1;
    const pageSize = filters.pageSize ?? 50;
    const total = items.length;
    return { items: items.slice((page - 1) * pageSize, page * pageSize), page: { page, pageSize, total, totalPages: Math.max(1, Math.ceil(total / pageSize)) } };
  },
  listUsers: async (filters: UserFilters = {}) => {
    const query = filters.q?.trim().toLowerCase();
    const alerts = new Map<string, number>();
    const activities = new Map<string, number>();
    const latest = new Map<string, { score: number | null; level: RiskLevel | null; occurredAt: string }>();
    for (const item of data.activity) {
      activities.set(item.employeeId, (activities.get(item.employeeId) ?? 0) + 1);
      if (item.alertId) alerts.set(item.employeeId, (alerts.get(item.employeeId) ?? 0) + 1);
      const current = latest.get(item.employeeId);
      if (!current || item.occurredAt > current.occurredAt) latest.set(item.employeeId, { score: item.riskScore, level: item.riskLevel, occurredAt: item.occurredAt });
    }
    const profiles = new Map(data.profiles.map((profile) => [profile.employeeId, profile]));
    const items: UserSummary[] = data.employees.map((employee) => {
      const profile = profiles.get(employee.employeeId);
      const risk = latest.get(employee.employeeId);
      return {
        employeeId: employee.employeeId,
        employeeName: employee.employeeName,
        department: employee.department,
        role: employee.normalPrivilege,
        peerGroup: { department: employee.department, role: employee.normalPrivilege },
        profileConfidence: profile?.confidence ?? 0,
        historyEventCount: profile?.historyEventCount ?? 0,
        activityCount: activities.get(employee.employeeId) ?? 0,
        alertCount: alerts.get(employee.employeeId) ?? 0,
        latestRiskScore: risk?.score ?? null,
        latestRiskLevel: risk?.level ?? null,
      };
    }).filter((item) => (!query || [item.employeeId, item.employeeName, item.department, item.role].some((value) => value.toLowerCase().includes(query)))
      && (!filters.department || item.department === filters.department)
      && (!filters.role || item.role === filters.role));
    const direction = filters.direction === "desc" ? -1 : 1;
    const sort = filters.sort ?? "name";
    items.sort((left, right) => {
      const values = sort === "risk" ? [left.latestRiskScore ?? -1, right.latestRiskScore ?? -1]
        : sort === "activity" ? [left.activityCount, right.activityCount]
          : sort === "department" ? [`${left.department}:${left.employeeName}`, `${right.department}:${right.employeeName}`]
            : [left.employeeName, right.employeeName];
      return (values[0] < values[1] ? -1 : values[0] > values[1] ? 1 : 0) * direction;
    });
    const page = filters.page ?? 1;
    const pageSize = filters.pageSize ?? 50;
    const total = items.length;
    return { items: items.slice((page - 1) * pageSize, page * pageSize), page: { page, pageSize, total, totalPages: Math.max(1, Math.ceil(total / pageSize)) } };
  },
  getUser: async (employeeId: string) => {
    const employee = data.employees.find((item) => item.employeeId === employeeId);
    const personalBaseline = data.profiles.find((item) => item.employeeId === employeeId);
    if (!employee || !personalBaseline) return null;
    const activityHistory = data.activity.filter((item) => item.employeeId === employeeId).slice(0, 50).map((item) => ({ ...item, anomalyPercentile: null, isAnomalous: false, simulationId: null }));
    return {
      employeeId,
      employeeName: employee.employeeName,
      department: employee.department,
      role: employee.normalPrivilege,
      homeCity: employee.homeCity,
      homeCountry: employee.homeCountry,
      peerGroup: { department: employee.department, role: employee.normalPrivilege },
      personalBaseline,
      peerBaseline: null,
      currentAssessment: null,
      riskHistory: [],
      activityHistory,
      relatedAlerts: data.threats.filter((item) => item.employeeId === employeeId).slice(0, 50),
    };
  },
  listAttackLabScenarios: async () => [
    { scenario: "account_compromise", label: "Account compromise", eventCount: 3, description: "Authentication anomaly, unknown-device login, then sensitive access." },
    { scenario: "credential_attack", label: "Credential attack", eventCount: 2, description: "Failed authentication burst followed by a successful login." },
    { scenario: "privilege_abuse", label: "Privilege abuse", eventCount: 3, description: "Successful login, privilege escalation, then sensitive access." },
    { scenario: "data_exfiltration", label: "Data exfiltration", eventCount: 2, description: "Sensitive access followed by a bulk or large download." },
  ],
  createAttackLabRun: async () => { throw new SentinelApiError(409, "live_api_required", "Attack Lab runs require SENTINEL_DATA_SOURCE=http."); },
  getAttackLabRun: async () => null,
  listModels: async () => data.models,
  getModelEvaluation: async () => null,
  getQuantumEvaluation: async () => ({ status: "unavailable", reason: "Evaluation execution requires SENTINEL_DATA_SOURCE=http.", affectsProductionRisk: false }),
  getQuantumStatus: async () => ({ status: "unavailable", backend: "Live API required", simulation: true, realQuantumHardware: false, qubits: 4, quantumKernelStatus: "unavailable", vqcStatus: "unavailable", affectsProductionRisk: false, reason: "Set SENTINEL_DATA_SOURCE=http to run Qiskit analysis." }),
  getQuantumEventAnalysis: async () => null,
  getGraphOverview: async (): Promise<GraphOverview> => {
    const employeesCount = data.employees.length;
    const activityCount = data.activity.length;
    const devicesSet = new Set(data.activity.map(a => a.deviceId).filter(Boolean));
    const ipSet = new Set(data.activity.map(a => a.ipAddress).filter(Boolean));
    const deptSet = new Set(data.employees.map(e => e.department).filter(Boolean));

    const totalNodes = employeesCount + activityCount + devicesSet.size + ipSet.size + deptSet.size;

    return {
      nodeCount: totalNodes,
      edgeCount: activityCount * 2 + employeesCount,
      entityCounts: {
        employee: employeesCount,
        event: activityCount,
        device: devicesSet.size,
        ip_address: ipSet.size,
        location: 0,
        file: 0,
        department: deptSet.size,
        attack_run: 0,
      },
      findingCount: 0,
      highSeverityFindingCount: 0,
    };
  },
  getGraphData: async (): Promise<GraphData> => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const nodeSet = new Set<string>();

    for (const user of data.employees) {
      const nodeId = `employee:${user.employeeId}`;
      if (!nodeSet.has(nodeId)) {
        nodeSet.add(nodeId);
        nodes.push({ nodeId, nodeType: "employee", label: user.employeeName, metadata: { department: user.department } });
      }
    }

    for (const event of data.activity) {
      if (event.deviceId) {
        const nodeId = `device:${event.deviceId}`;
        if (!nodeSet.has(nodeId)) {
          nodeSet.add(nodeId);
          nodes.push({ nodeId, nodeType: "device", label: event.deviceId, metadata: {} });
        }
        edges.push({ sourceId: `employee:${event.employeeId}`, targetId: nodeId, edgeType: "USES_DEVICE", metadata: {} });
      }
      if (event.ipAddress) {
        const nodeId = `ip_address:${event.ipAddress}`;
        if (!nodeSet.has(nodeId)) {
          nodeSet.add(nodeId);
          nodes.push({ nodeId, nodeType: "ip_address", label: event.ipAddress, metadata: {} });
        }
        edges.push({ sourceId: `employee:${event.employeeId}`, targetId: nodeId, edgeType: "CONNECTS_FROM", metadata: {} });
      }
    }

    return { nodes, edges, findings: [] };
  },

  getGraphEntityDetail: async (): Promise<GraphEntityDetail | null> => null,
  getGraphEventContext: async (): Promise<GraphEventContext | null> => null,
  getGraphAttackRunContext: async (): Promise<GraphAttackRunContext | null> => null,
  getGraphFindings: async (): Promise<PageResult<GraphFinding>> => {
    return { items: [], page: { page: 1, pageSize: 50, total: 0, totalPages: 1 } };
  },
  getMitreCatalog: async (): Promise<MitreCatalog> => ({
    sourceVersion: "Enterprise ATT&CK v19.2",
    sourceUrl: "https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2",
    techniques: [],
  }),
  getMitreOverview: async (): Promise<MitreOverview> => ({
    sourceVersion: "Enterprise ATT&CK v19.2",
    sourceUrl: "https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2",
    catalogTechniqueCount: 0,
    mappedTechniqueCount: 0,
    storyCount: 0,
    correlatedCaseCount: 0,
    techniqueCounts: {},
    recentReports: [],
    affectsProductionRisk: false,
  }),
  getMitreEvent: async () => null,
  getMitreAttackRun: async () => null,
  getMitreAlert: async () => null,
  getContainmentState: async (employeeId: string): Promise<ContainmentState | null> => {
    if (!data.employees.some((item) => item.employeeId === employeeId)) return null;
    return {
      employeeId,
      accountStatus: "ACTIVE",
      sessionStatus: "ACTIVE",
      containmentStatus: "NONE",
      containmentMode: null,
      containedAt: null,
      containedBy: null,
      reason: null,
      sourceAlertId: null,
      riskScoreAtAction: null,
      lastAction: null,
      updatedAt: null,
      adapter: "SentinelAI Simulation",
      simulated: true,
    };
  },
  getResponseHistory: async (): Promise<ResponseHistory> => ({ items: [] }),

  getQuantumOptimizationStatus: async () => ({
    experimental: true,
    affectsProductionRisk: false,
    executesContainment: false,
    maxAlerts: 8,
    depth: 2,
    shots: 1024,
  }),
  runQuantumOptimization: async () => {
    throw new Error("Cannot run optimization in fixture mode.");
  },
  getQuantumOptimizationLatest: async () => null,
  getCertStatus: async () => ({ primaryDataset: "CERT r4.2 (live API required)", entitySchema: "employee user-day", featureSchema: ["pca_1", "pca_2", "pca_3", "pca_4"], processedDataReady: false, savedPreprocessingReady: false, qsvcArtifactReady: false, vqcArtifactReady: false, rbfSvmArtifactReady: false, assessmentPolicy: null, qsvcRole: "advisory", affectsProductionRisk: false, naturalPositiveRate: 0.002923, availableEmployees: 0, processedUserDays: 0, dateCoverage: { start: "unavailable", end: "unavailable" }, benchmark: {}, runtimeBoundary: "Fixture mode does not include CERT records.", legacyDemo: "Current fixture is retained for simulation only." }),
  getCertMonthlyActivity: async () => ({ dataset: "CERT r4.2", unit: "raw telemetry events per calendar month", reportingPeriod: { start: null, end: null, months: 0 }, categories: [], points: [], totals: {}, provenance: { available: false, reason: "Live API required." } }),
  listCertUsers: async () => ({ items: [], page: { page: 1, pageSize: 50, total: 0, totalPages: 1 } }),
  listCertUserDays: async () => ({ items: [], page: { page: 1, pageSize: 50, total: 0, totalPages: 1 } }),
  listCertFindings: async () => ({ items: [], page: { page: 1, pageSize: 50, total: 0, totalPages: 1 }, scoringCoverage: 0, coverageBasis: "Live API required.", advisory: true }),
  getCertInvestigation: async () => null,
  getCertReplay: async () => null,
  getCertBenchmarks: async () => ({ dataset: "CERT r4.2", cohort: { train: 250, validation: 100, test: 100, balanced: true, naturalPrevalenceValidated: false }, models: {}, circuits: {}, fusionPolicy: { selectedPolicy: "UNAVAILABLE", objective: "Live API required", validationRows: 0, evidence: {}, testLabelsUsedForSelection: false }, limitations: ["Live API required to read persisted experiment metrics."], claim: "No established quantum advantage." }),
  listIncidents: async () => ({ items: [], summary: { total: 0, detected: 0, responsePlanned: 0 } }),
  getIncident: async () => null,
  createIncident: async () => { throw new Error("Live API required"); },
  planIncidentResponse: async () => { throw new Error("Live API required"); },
  createLinkedShieldSession: async () => { throw new Error("Live API required"); },
  planAdaptiveResponse: async () => { throw new Error("Live API required"); },
  executeAdaptiveAction: async () => { throw new Error("Live API required"); },
  rollbackAdaptiveAction: async () => { throw new Error("Live API required"); },
};
