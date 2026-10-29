export type ShieldLifecycleStatus =
  | "INVESTIGATING" | "PENDING_ANALYST" | "PENDING_HUMAN" | "AUTO_AUTHORIZED"
  | "AUTHORIZED" | "READY" | "EXECUTING" | "VERIFYING" | "VERIFIED"
  | "RECOVERY_PENDING" | "RECOVERING" | "RECOVERED" | "ESCALATED"
  | "REJECTED" | "POLICY_BLOCKED" | "EXECUTION_FAILED";

export interface UnifiedTopologyNode { identifier: string; kind: string; criticality: number; compromised?: boolean }
export interface UnifiedTopologyConnection { source: string; target: string; kind: string }
export interface UnifiedWorkflow { identifier: string; critical: boolean; dependencies: string[] }
export interface ExperienceIngestionStatus { attempted: boolean; created: boolean; eligible: boolean; reasons: string[]; fingerprint: string | null; coverage_available: boolean }
export interface ShieldTimelineEvent { state: string; actor: string; detail: string; created_at: string }
export interface UnifiedShieldSession {
  incident_id: string; session_id: string; correlation_id: string; version: number;
  lifecycle_status: ShieldLifecycleStatus; origin: "simulated-evidence-bridge"|"cert-linked-incident"; mode:"CERT_LINKED_INCIDENT"|"STANDALONE_GRAPH_EXERCISE"; simulation_only: true;
  scenario: string; topology: string; seed:number; predictor_available: boolean; adapter:{version:string;assumptions:string[];mappings?:unknown[];unknownFields?:string[]};
  observation: { tick: number; service_health: number; observed_compromise: number; observed_malicious_activity: boolean; evidence_count: number; recovery_active: boolean; terminal: boolean };
  topology_state: { nodes: UnifiedTopologyNode[]; connections: UnifiedTopologyConnection[]; workflows: UnifiedWorkflow[]; posture: unknown };
  belief: Record<string, number>; proposal: Record<string, unknown> | null; timeline: ShieldTimelineEvent[];
  pending_authorization: { tier?: string; reasons?: string[] } | null; available_actions: string[];
  experience_ingestion: ExperienceIngestionStatus;
  context: {
    identity: { established: boolean; display_label: string; identifier: string | null; role: string | null; department: string | null };
    trigger: { event: string; summary: string; source_event_ids: string[] };
    evidence_summary: string; affected_resources: string[]; detection_outcome: string;
    network_context: string; approval_scope: "simulation-only";
  };
  provenance: { evidence: string; prediction: string; execution: string; learning: string };
}

export interface ShieldPlan {
  version: number; plan: { action: string; policy: string; solver: string; objective: number };
  prediction: Record<string, number>; uncertainty: number; diagnostic: { reason: string; operationally_suitable: boolean };
  alternatives: Array<{action:string;policy:string;objective:number;feasible:boolean;reason:string;reversible:boolean;tier:string;prediction:Record<string,number>;uncertainty:number}>;
}
