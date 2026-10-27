export type RiskLevel = "Low" | "Medium" | "High" | "Critical";
export type AlertStatus = "New" | "Investigating" | "Resolved" | "False Positive";

export interface EvidenceSummary {
  code: string;
  contribution: number;
  expected: string;
  observed: string;
  reason: string;
}

export interface ThreatSummary {
  activity: string;
  alertId: string;
  createdAt: string;
  department: string;
  employeeId: string;
  employeeName: string;
  eventId: string;
  evidenceCount: number;
  occurredAt: string;
  primaryEvidence: EvidenceSummary | null;
  riskLevel: RiskLevel;
  riskScore: number;
  status: AlertStatus;
  story: string;
  title: string;
}

export type AccountStatus = "ACTIVE" | "BLOCKED";
export type SessionStatus = "ACTIVE" | "REVOKED";
export type ContainmentStatus = "NONE" | "PARTIAL" | "CONTAINED";
export type ContainmentMode = "AUTO" | "MANUAL";
export type ResponseAction = "BLOCK_USER" | "UNBLOCK_USER" | "REVOKE_SESSIONS" | "RESTORE_SESSIONS" | "BLOCK_AND_REVOKE";

export interface ContainmentState {
  employeeId: string;
  accountStatus: AccountStatus;
  sessionStatus: SessionStatus;
  containmentStatus: ContainmentStatus;
  containmentMode: ContainmentMode | null;
  containedAt: string | null;
  containedBy: string | null;
  reason: string | null;
  sourceAlertId: string | null;
  riskScoreAtAction: number | null;
  lastAction: ResponseAction | null;
  updatedAt: string | null;
  adapter: "SentinelAI Simulation";
  simulated: true;
}

export interface ResponseAudit {
  actionId: string;
  employeeId: string;
  action: ResponseAction;
  mode: ContainmentMode;
  actor: string;
  alertId: string | null;
  riskScoreAtAction: number | null;
  reason: string;
  result: "SUCCESS" | "FAILED";
  detail: string | null;
  createdAt: string;
}

export interface ResponseHistory { items: ResponseAudit[] }

export interface RiskPoint { date: string; alertCount: number; averageRisk: number }
export interface AnomalyPoint { date: string; medianPercentile: number; p95Percentile: number }
export interface ThreatTrendPoint { date: string; medium: number; high: number; critical: number }
export interface NamedMetric { name: string; count: number; averageRisk: number | null; highCriticalCount: number | null }
export interface DetectionContribution { ruleBased: number; aiAnomaly: number; contextual: number }
export interface EmployeeAttention {
  employeeId: string;
  employeeName: string;
  department: string;
  maximumRisk: number;
  averageRisk: number;
  eventCount: number;
  activeAlertCount: number;
}

export interface SystemStatusSnapshot {
  mode: string;
  data: { label: string; status: string };
  database: { label: string; status: string };
  model: { label: string; status: string };
  operator: { label: string; session: string };
  counts?: SystemCounts;
}

export interface SystemCounts {
  employees: number;
  activityEvents: number;
  detections: number;
  alerts: number;
}

export interface OperationsOverview {
  activeThreats: Record<Exclude<RiskLevel, "Low">, number>;
  riskDistribution: Record<RiskLevel, number>;
  riskActivity: RiskPoint[];
  anomalyActivity: AnomalyPoint[];
  totalEvents?: number;
  activeAlerts?: number;
  highRiskEvents?: number;
  criticalThreats?: number;
  averageRiskScore?: number;
  threatTrend?: ThreatTrendPoint[];
  threatTypes?: NamedMetric[];
  detectionContribution?: DetectionContribution;
  employeesRequiringAttention?: EmployeeAttention[];
  departmentRisk?: NamedMetric[];
}

export interface SentinelFixture {
  fixture: {
    schemaVersion: "sentinel-demo.v1";
    source: "sentinelai-python-reference";
    classification: "development_demo_data";
    randomSeed: number;
    timestampPolicy: string;
    counts: SystemCounts;
  };
  system: SystemStatusSnapshot;
  overview: OperationsOverview;
  employees: FixtureEmployee[];
  profiles: PersonalBaseline[];
  activity: FixtureActivityRecord[];
  threats: ThreatSummary[];
  models: ModelMetadata[];
}

export interface ThreatFilters {
  q?: string;
  risk?: RiskLevel | "All";
  status?: AlertStatus | "All";
}

export interface PageMeta {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface PageResult<T> {
  items: T[];
  page: PageMeta;
}

export interface CertStatus {
  primaryDataset: string; entitySchema: string; featureSchema: string[]; processedDataReady: boolean;
  savedPreprocessingReady: boolean; qsvcArtifactReady: boolean; vqcArtifactReady: boolean; rbfSvmArtifactReady: boolean;
  assessmentPolicy: { selectedPolicy: string } | null; qsvcRole: string; affectsProductionRisk: boolean;
  naturalPositiveRate: number; benchmark: Record<string, unknown>; runtimeBoundary: string; legacyDemo: string;
  availableEmployees: number; processedUserDays: number; dateCoverage: { start: string; end: string };
}
export interface CertIdentity { displayLabel: string; sourceId: string; monogram: string; source: string }
export interface CertUserSummary { user: string; identity: CertIdentity; userDays: number; firstDate: string; lastDate: string; labelledMaliciousDays: number; activityTotals: { afterHoursLogons: number; usbConnections: number; filesCopied: number; emailsSent: number } }
export interface CertUserDay { user: string; identity: CertIdentity; date: string; split: string; label: number; scenario: number; activity: { logons: number; afterHoursLogons: number; usbConnections: number; filesCopied: number; emailsSent: number; externalEmails: number } }
export interface CertFinding { findingId: string; user: string; identity: CertIdentity; date: string; source: string; model: string; prediction: number; decisionScore: number; decisionThreshold: number; scoreIsProbability: false; qsvcPrediction: number; vqcPrediction: number; quantumAgreement: boolean; policy: string; recordedLabel: number; observedSignals: string[] }
export interface CertModelResult { model: string; method?: string; available?: boolean; prediction: number; decisionScore: number; decisionThreshold: number; scoreIsProbability?: boolean; advisory?: boolean }
export interface CertInvestigation { identity: CertIdentity; record: { user: string; date: string; split: string; label: number; scenario: number; features: Record<string, number> }; behaviouralEvidence: { feature: string; value: number; evidenceType: string }[]; models: { qsvc: CertModelResult & { featureInfluences: { feature: string; value: number; scoreInfluence: number }[]; validationCaveat: string }; vqc: CertModelResult; rbfSvm: CertModelResult | null }; assessment: { verdict: string; prediction: number; policy: string; reason: string; quantumAgreement: boolean; agreementLabel: string; limitations: string }; classicalEvidence: { transparentUserDayRules: string[]; rbfSvm: CertModelResult | null; agreementWithQsvc: boolean; note: string }; classification: CertModelResult & { featureInfluences: { feature: string; value: number; scoreInfluence: number }[]; validationCaveat: string }; alert: { raised: boolean; advisory: boolean; title: string }; threatContext: { recorded: string; inferred: string; shieldEligible: boolean; shieldHandoff: null; reason: string } }
export interface CertReplay { user: string; split: string; replayType: string; timeline: { date: string; label: number; scenario: number; recordedAggregates: Record<string, number> }[]; eventSequenceAvailable: false; simulatedContainment: false; shieldHandoff: null; disclosure: string }
export interface CertBenchmarks { dataset: string; cohort: { train: number; validation: number; test: number; balanced: boolean; naturalPrevalenceValidated: boolean }; models: Record<string, Record<string, unknown>>; circuits: Record<string, Record<string, unknown>>; fusionPolicy: { selectedPolicy: string; objective: string; validationRows: number; evidence: Record<string, { falsePositives: number; falseNegatives: number; securityCost: number }>; testLabelsUsedForSelection: false }; limitations: string[]; claim: string }
export interface IncidentModelResult { model: string; prediction: number; decisionScore: number; decisionThreshold: number; executionTimeMs: number }
export interface IncidentDetection { models: { qsvc: IncidentModelResult; vqc: IncidentModelResult; rbfSvm: IncidentModelResult }; rules: string[]; assessment: { prediction: number; verdict: string; policy: string; quantumAgreement: boolean; reason: string } }
export interface CertIncident { incidentId: string; createdAt: string; updatedAt: string; status: string; sourceType: string; scenario: string; scenarioLabel: string; canonicalRecord: { user: string; date: string; split: string; researchLabel: number; researchScenario: number; identity: CertIdentity }; provenance: Record<string, string | boolean>; originalEvidence: Record<string, number>; injectedEvidence: Record<string, number>; featureChanges: { feature: string; before: number; after: number; delta: number; provenance: string }[]; baselineContext: { original: Record<string, unknown>[]; injected: Record<string, unknown>[]; peerGroupAvailable: false; label: string }; detection: { original: IncidentDetection; injected: IncidentDetection; findingCreated: boolean; outcome: string }; shield: { status: string; eligible: boolean; boundary?: string; result?: Record<string, unknown>; executionTimeMs?: number }; history: { at: string; stage: string; detail: string }[] }
export interface IncidentList { items: CertIncident[]; summary: { total: number; detected: number; responsePlanned: number } }

export interface ActivityRecord {
  eventId: string;
  occurredAt: string;
  employeeId: string;
  employeeName: string;
  department: string;
  activityType: string;
  scenario: string;
  deviceId: string;
  isKnownDevice: boolean;
  ipAddress: string;
  city: string;
  country: string;
  resourceName: string | null;
  resourceSensitivity: string;
  previousPrivilege: string;
  currentPrivilege: string;
  failedLoginCount: number;
  downloadCount: number;
  downloadSizeMb: number;
  riskScore: number | null;
  riskLevel: RiskLevel | null;
  anomalyPercentile: number | null;
  isAnomalous: boolean;
  alertId: string | null;
  alertStatus: AlertStatus | null;
  simulationId: string | null;
}

export interface FixtureActivityRecord extends Omit<ActivityRecord, "anomalyPercentile" | "isAnomalous" | "simulationId"> {
  isApprovedTravel: boolean;
  isSuspicious: boolean;
  loginSuccess: boolean;
}

export interface ActivityFilters {
  q?: string;
  start?: string;
  end?: string;
  employeeId?: string;
  department?: string;
  activityType?: string;
  scenario?: string;
  riskLevel?: RiskLevel | "All";
  anomalousOnly?: boolean;
  sort?: "timestamp" | "risk_score" | "employee" | "activity_type";
  direction?: "asc" | "desc";
  page?: number;
  pageSize?: number;
}

export interface PeerGroup {
  department: string;
  role: string;
}

export interface UserSummary {
  employeeId: string;
  employeeName: string;
  department: string;
  role: string;
  peerGroup: PeerGroup;
  profileConfidence: number;
  historyEventCount: number;
  activityCount: number;
  alertCount: number;
  latestRiskScore: number | null;
  latestRiskLevel: RiskLevel | null;
}

export interface UserFilters {
  q?: string;
  department?: string;
  role?: string;
  sort?: "name" | "department" | "risk" | "activity";
  direction?: "asc" | "desc";
  page?: number;
  pageSize?: number;
}

export interface PersonalBaseline {
  employeeId?: string;
  normalLoginStart: number;
  normalLoginEnd: number;
  usualCountries: string[];
  usualCities: string[];
  knownDevices: string[];
  averageDownloadCount: number;
  averageDownloadSizeMb: number;
  typicalFileSensitivity: string[];
  normalPrivilege: string;
  averageFailedLoginCount: number;
  historyEventCount: number;
  confidence: number;
}

export interface PeerBaseline {
  peerGroup: PeerGroup;
  memberCount: number;
  contributingMemberCount: number;
  normalLoginStart: number | null;
  normalLoginEnd: number | null;
  usualCountries: string[];
  usualCities: string[];
  knownDevices: string[];
  averageDownloadCount: number | null;
  averageDownloadSizeMb: number | null;
  typicalFileSensitivity: string[];
  normalPrivilege: string;
  averageFailedLoginCount: number | null;
  historyEventCount: number;
  confidence: number;
  status: string;
}

export interface BehaviouralSignal {
  signalName: string;
  isUnusual: boolean;
  observedValue: string;
  expectedValue: string;
}

export interface BehaviouralAssessment {
  eventId: string;
  employeeId: string;
  peerGroup: PeerGroup;
  personalDeviation: number | null;
  peerDeviation: number | null;
  personalConfidence: number;
  peerConfidence: number;
  personalStatus: string;
  peerStatus: string;
  comparisonCase: string;
  personalSignals: BehaviouralSignal[];
  peerSignals: BehaviouralSignal[];
}

export interface DetectionHistory {
  detectionId: string;
  eventId: string;
  occurredAt: string;
  riskScore: number;
  riskLevel: RiskLevel;
  anomalyPercentile: number | null;
  modelStatus: string;
}

export interface UserDetail {
  employeeId: string;
  employeeName: string;
  department: string;
  role: string;
  homeCity: string;
  homeCountry: string;
  peerGroup: PeerGroup;
  personalBaseline: PersonalBaseline;
  peerBaseline: PeerBaseline | null;
  currentAssessment: BehaviouralAssessment | null;
  riskHistory: DetectionHistory[];
  activityHistory: ActivityRecord[];
  relatedAlerts: ThreatSummary[];
}

export interface FixtureEmployee {
  employeeId: string;
  employeeName: string;
  department: string;
  homeCountry: string;
  homeCity: string;
  knownDevices: string[];
  normalPrivilege: string;
}

export interface AttackLabScenario {
  scenario: string;
  label: string;
  eventCount: number;
  description: string;
}

export interface SequenceFinding {
  code: string;
  title: string;
  severity: RiskLevel;
  status: string;
  eventIds: string[];
  windowMinutes: number;
  evidence: string[];
}

export interface AttackLabRun {
  simulationId: string;
  employeeId: string;
  scenario: string;
  startTime: string;
  intensity: "standard" | "elevated";
  status: string;
  createdAt: string;
  eventIds: string[];
  findings: SequenceFinding[];
  events: ActivityRecord[];
}

export interface CreateAttackLabRun {
  employeeId: string;
  scenario: string;
  startTime: string;
  intensity: "standard" | "elevated";
}

export interface ModelMetadata {
  name: string;
  implementation?: string;
  status: string;
  version: string | null;
  featureSchemaVersion: string | null;
  featureOrder: string[];
  trainingRows: number | null;
  trainingScope: string | null;
  estimatorConfiguration?: Record<string, string | number>;
  anomalyDefinition: string | null;
}

export interface EvaluationMetrics {
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
}

export interface EvaluationChannel {
  name: string;
  status: string;
  metrics: EvaluationMetrics;
  scenarioCoverage: Record<string, { detected: number; total: number; recall: number }>;
}

export interface ModelEvaluationReport {
  dataset: { strategy: string; baselineRows: number; trainingRows: number; normalTestRows: number; anomalyTestRows: number; futureDataUsed: boolean };
  thresholds: { classical: string; rules: string };
  classical: EvaluationChannel;
  rules: EvaluationChannel;
  limitations: string[];
}

export interface ModelAnomalyAssessment {
  eventId: string;
  scenario: string;
  expectedAnomaly: boolean;
  classicalScore: number | null;
  quantumScore: number | null;
  personalDeviation: number | null;
  peerDeviation: number | null;
  classicalStatus: string;
  quantumStatus: string;
  agreement: boolean | null;
  confidence: number | null;
  novelty: Record<string, number>;
}

export interface QuantumEvaluationReport {
  status: string;
  reason?: string;
  label?: string;
  implementation?: string;
  versions?: Record<string, string>;
  configuration?: { randomSeed: number; shots: number; qubits: number; features: string[]; featureMap: string; repetitions: number; entanglement: string; trainingRows: number; normalTestRows: number; anomalyTestRows: number; oneClassNu: number };
  metrics?: EvaluationMetrics;
  runtimeSeconds?: number;
  assessments?: ModelAnomalyAssessment[];
  affectsProductionRisk: boolean;
  limitations?: string[];
}

export interface QuantumStatus {
  status: string;
  backend: string;
  simulation: boolean;
  realQuantumHardware: boolean;
  qubits: number;
  quantumKernelStatus: string;
  vqcStatus: string;
  affectsProductionRisk: false;
  reason?: string;
}

export interface QuantumFeatureMapping {
  feature: string;
  label: string;
  qubit: number;
  sourceFeature: string;
  normalization: string;
}

export interface QuantumCircuitAnalysis {
  eventId: string;
  employee: string;
  originalFeatureValues: Record<string, number>;
  normalizedFeatureValues: Record<string, number>;
  featureQubitMapping: QuantumFeatureMapping[];
  qubits: number;
  rotationParameters: { feature: string; qubit: number; ryRadians: number; rzRadians: number }[];
  gateSequence: string[];
  entanglementStructure: string;
  circuitDiagram: string;
  backend: string;
  simulation: true;
  affectsProductionRisk: false;
}

export interface QuantumKernelResult {
  similarityToNormalBaseline: number;
  anomalyScore: number;
  scoreMeaning: string;
  interpretation: string;
  normalBaselineRows: number;
  normalBaselineVector: Record<string, number>;
  featureDimensions: number;
  executionBackend: string;
  executionTimeMs: number;
  experimental: true;
  affectsProductionRisk: false;
}

export interface VqcResult {
  prediction: "NORMAL" | "SUSPICIOUS";
  modelScore: number;
  scoreMeaning: string;
  modelType: "VQC";
  qubits: number;
  ansatz: string;
  trainingRows: number;
  optimizer: string;
  executionBackend: string;
  executionTimeMs: number;
  experimental: true;
  affectsProductionRisk: false;
}

export interface QuantumComparison {
  eventId: string;
  classicalModel: { model: string; prediction: string; anomalyScore: number | null; scoreMeaning: string; featuresUsed: string[]; featureDimensions: number; executionBackend: string; simulation: false };
  quantumKernel: QuantumKernelResult & { model: string; featuresUsed: string[]; simulation: true };
  vqc: VqcResult & { featuresUsed: string[]; featureDimensions: number; simulation: true };
  disclosure: string;
  affectsProductionRisk: false;
}

export interface QuantumThreatSimilarity {
  items: { profile: string; similarity: number; referenceVector: Record<string, number> }[];
  scoreMeaning: string;
  executionBackend: string;
  executionTimeMs: number;
  experimental: true;
  affectsProductionRisk: false;
}

export interface QuantumEventAnalysis {
  eventId: string;
  employee: { employeeId: string; employeeName: string; department: string };
  occurredAt: string;
  activityType: string;
  scenario: string;
  circuit: QuantumCircuitAnalysis;
  quantumKernel: QuantumKernelResult;
  vqc: VqcResult;
  comparison: QuantumComparison;
  threatSimilarity: QuantumThreatSimilarity;
  experimental: true;
  affectsProductionRisk: false;
  limitations: string[];
}

// Graph Analysis types
export type GraphNodeType = "employee" | "event" | "device" | "ip_address" | "location" | "file" | "department" | "attack_run";
export type GraphEdgeType = "USES_DEVICE" | "USED_DEVICE" | "CONNECTS_FROM" | "CONNECTED_FROM" | "LOGS_IN_FROM" | "OCCURRED_AT" | "ACCESSES_FILE" | "ACCESSED_FILE" | "GENERATED" | "BELONGS_TO" | "PART_OF_ATTACK_RUN" | "ASSOCIATED_WITH_ATTACK";
export type GraphFindingSeverity = "informational" | "low" | "medium" | "high" | "critical";

export interface GraphNode {
  nodeId: string;
  nodeType: GraphNodeType;
  label: string;
  metadata: Record<string, string | number>;
}

export interface GraphEdge {
  sourceId: string;
  targetId: string;
  edgeType: GraphEdgeType;
  metadata: Record<string, string | number>;
}

export interface GraphFinding {
  findingType: string;
  severity: GraphFindingSeverity;
  entities: string[];
  supportingEvents: string[];
  supportingAttackRuns: string[];
  observedRelationship: string;
  explanation: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: GraphFinding[];
}

export interface GraphFilters {
  nodeType?: string;
  severity?: string;
  employeeId?: string;
  attackRunId?: string;
  maxNodes?: number;
}

export interface GraphOverview {
  nodeCount: number;
  edgeCount: number;
  entityCounts: Record<string, number>;
  findingCount: number;
  highSeverityFindingCount: number;
}


export interface GraphEntityDetail {
  entity: GraphNode;
  connectedEntities: GraphNode[];
  edges: GraphEdge[];
  findings: GraphFinding[];
  eventIds: string[];
}

export interface GraphEventContext {
  eventId: string;
  entities: GraphNode[];
  findings: GraphFinding[];
}

export interface GraphAttackRunContext {
  simulationId: string;
  employees: GraphNode[];
  devices: GraphNode[];
  ipAddresses: GraphNode[];
  locations: GraphNode[];
  files: GraphNode[];
  findings: GraphFinding[];
  eventIds: string[];
}

export type MitreConfidence = "none" | "low" | "medium" | "high";

export interface MitreTechnique {
  techniqueId: string;
  name: string;
  tactics: string[];
  description: string;
  sourceVersion: string;
  sourceUrl: string;
}

export interface MitreCatalog {
  sourceVersion: string;
  sourceUrl: string;
  techniques: MitreTechnique[];
}

export interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  confidence: Exclude<MitreConfidence, "none">;
  observedBehaviour: string;
  explanation: string;
  supportingEventIds: string[];
  supportingRuleNames: string[];
  supportingSequenceFindings: string[];
  supportingGraphFindings: string[];
  evidenceCount: number;
}

export interface ThreatTimelineEntry {
  timestamp: string;
  eventId: string;
  activity: string;
  observation: string;
  riskLevel: RiskLevel | null;
}

export interface ThreatStory {
  title: string;
  summary: string;
  employeeId: string;
  employeeName: string;
  riskLevel: RiskLevel;
  timeline: ThreatTimelineEntry[];
  keyEvidence: string[];
  sequenceContext: string[];
  graphContext: string[];
  mappedTechniqueIds: string[];
  investigationFocus: string[];
}

export interface MitreReport {
  subjectType: "event" | "attack_run" | "alert";
  subjectId: string;
  confidence: MitreConfidence;
  threatStory: ThreatStory;
  timeline: ThreatTimelineEntry[];
  mappings: MitreMapping[];
  supportingEvents: ActivityRecord[];
  sequenceEvidence: SequenceFinding[];
  graphEvidence: GraphFinding[];
}

export interface MitreOverview {
  sourceVersion: string;
  sourceUrl: string;
  catalogTechniqueCount: number;
  mappedTechniqueCount: number;
  storyCount: number;
  correlatedCaseCount: number;
  techniqueCounts: Record<string, number>;
  recentReports: MitreReport[];
  affectsProductionRisk: boolean;
}

// Quantum QAOA Optimization types
export interface QaoaOptimizationStatus {
  experimental: boolean;
  affectsProductionRisk: boolean;
  executesContainment: boolean;
  maxAlerts: number;
  depth: number;
  shots: number;
}

export interface QaoaExplanation {
  alertId: string;
  priorityScore: number;
  probability?: number;
  reasoning: string[];
}

export interface QaoaOptimizationMetadata {
  alertsConsidered: number;
  qaoaDepth: number;
  shots: number;
  optimizerSuccess: boolean;
  objectiveValue: number;
}

export interface QaoaOptimizationResult {
  experimental: boolean;
  affectsProductionRisk: boolean;
  executesContainment: boolean;
  classicalRanking: QaoaExplanation[];
  qaoaRanking: QaoaExplanation[];
  metadata: QaoaOptimizationMetadata;
}
