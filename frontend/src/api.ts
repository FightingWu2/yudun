export type Role = "ANALYST" | "APPROVER" | "AUDITOR" | "ADMIN";
export type RunMode = "PRODUCTION_GUARDED" | "COMPETITION_AUTONOMOUS";

export interface RuntimeStatus {
  run_id: string | null;
  incident_id: string | null;
  stage: string;
  run_mode: string;
  model_provider: string;
  competition_autonomous: string;
  autonomous_enabled: boolean;
  node_timings_ms: Record<string, number[]>;
  stop_reason: string | null;
}

export interface ReplaySource {
  capture_id?: string;
  scenario_id?: string;
  display_name: string;
  source_type: "OFFICIAL" | "SYNTHETIC";
  format?: string;
  packet_count?: number;
}

export interface ReplaySources {
  official: ReplaySource[];
  synthetic: ReplaySource[];
  run_modes: Array<{
    run_mode: RunMode;
    enabled: boolean;
    safety_label: string;
  }>;
}

export interface Incident {
  incident_id: string;
  title: string;
  status: string;
  automation_state: string;
  severity: string;
  summary: string;
  signal_refs: string[];
  fact_refs: string[];
  task_refs: string[];
  pending_action_refs: string[];
  version: number;
  opened_at: string;
  updated_at: string;
  current_blocker?: string | null;
  next_expected_stage?: string | null;
}

export interface Evidence {
  evidence_id: string;
  source_type: "OFFICIAL" | "SYNTHETIC" | "MOCK" | "SYSTEM";
  source_badge: string;
  source_dataset: string;
  source_record_id: string;
  evidence_type: string;
  locator: Record<string, unknown>;
  summary: string;
  redacted_snapshot?: Record<string, unknown> | null;
  content_sha256: string;
  sensitivity: string;
  created_at: string;
}

export interface Signal {
  signal_id: string;
  signal_type: string;
  severity: string;
  trigger_reason: string;
  detector: {
    detector_type: string;
    detector_id: string;
    detector_version: string;
  };
  evidence_refs: string[];
  source_types: string[];
}

export interface AgentTask {
  task_id: string;
  task_type: string;
  task_goal: string;
  assigned_agent_type: string;
  allowed_context: Record<string, unknown>;
  allowed_tools: string[];
  evidence_refs: string[];
  status: string;
}

export interface AgentResult {
  result_id: string;
  task_id: string;
  task_status: string;
  findings: string[];
  evidence_refs: string[];
  unresolved_questions: string[];
  next_step?: string;
}

export interface Finding {
  finding_id: string;
  task_id: string;
  finding_type: string;
  statement: string;
  evidence_refs: string[];
  confidence_level: string;
  limitations: string[];
  knowledge_refs?: string[];
  metadata?: {
    timeline?: { nodes?: TimelineNode[]; missing_links?: string[] };
  };
}

export interface Fact {
  fact_id: string;
  fact_type: string;
  statement: string;
  evidence_refs: string[];
  validated_by: string;
}

export interface TimelineNode {
  timestamp: string;
  event_type: string;
  source_type: string;
  object_ref: string;
  evidence_refs: string[];
  association_basis: string;
  summary: string;
}

export interface ActionRequest {
  action_request_id: string;
  action_type: string;
  target_ref: string;
  operations: Array<{
    operation_type: string;
    operation_id: string;
    parameters: Record<string, unknown>;
  }>;
  risk_level: string;
  requested_by: string;
  idempotency_key: string;
  status: string;
}

export interface PolicyDecision {
  policy_decision_id: string;
  decision: string;
  approval_requirement: string;
  checks: Array<{ check_id: string; passed: boolean; reason: string }>;
}

export interface PolicyPreAuthorization {
  preauthorization_id: string;
  decision: "AUTO_PREAUTHORIZED" | "DENY";
  run_mode: "COMPETITION_AUTONOMOUS";
  environment: "SANDBOX";
  guard_checks: Array<{ check_id: string; passed: boolean; reason: string }>;
}

export interface Execution {
  execution_id: string;
  overall_status: string;
  operation_results: Array<{
    operation_id: string;
    status: string;
    state_snapshot_before: string;
    state_snapshot_after: string;
    receipt_ref: string;
  }>;
}

export interface Verification {
  verification_id: string;
  overall_status: string;
  next_step: string;
  assertions: Array<{
    assertion_type: string;
    passed: boolean;
    observed_value: { actual: unknown; expected: unknown };
    evidence_refs: string[];
  }>;
}

export interface AuditRecord {
  audit_id: string;
  actor_id: string;
  event_type: string;
  object_type: string;
  object_id: string;
  summary: string;
  occurred_at: string;
}

export interface TraceNode {
  timestamp: string;
  stage: string;
  actor: string;
  object_type: string;
  object_id: string;
  summary: string;
  input_refs: string[];
  output_refs: string[];
  source_type: string;
  result: string;
}

export type KnowledgeCategory =
  | "ATTACK_TECHNIQUE"
  | "CLOUD_CREDENTIAL"
  | "CI_SUPPLY_CHAIN"
  | "DETECTION_RULE"
  | "RESPONSE_PLAYBOOK"
  | "CLOUD_ABUSE"
  | "REFERENCE";

export interface KnowledgeDocument {
  doc_id: string;
  category: KnowledgeCategory;
  doc_type: string;
  title: string;
  tags: string[];
  content: string;
  source: string;
  version: string;
}

export interface KnowledgeHit {
  doc_id: string;
  title: string;
  category: KnowledgeCategory;
  doc_type: string;
  score: number;
  matched_terms: string[];
  snippet: string;
  source: string;
  version: string;
}

export interface KnowledgeSearchResult {
  query: string;
  limit: number;
  total: number;
  elapsed_ms: number;
  mode: string;
  hits: KnowledgeHit[];
}

export interface KnowledgeIndexStatus {
  mode: string;
  fts_available: boolean;
  document_count: number;
  imported_count: number;
  categories: Record<string, number>;
  knowledge_dir: string;
}

export interface IncidentBundle {
  runtime: RuntimeStatus;
  incident: Incident;
  signals: Signal[];
  evidence: Evidence[];
  official_evidence: Evidence[];
  tasks: AgentTask[];
  results: AgentResult[];
  findings: Finding[];
  facts: Fact[];
  associations: Array<Record<string, unknown>>;
  actions: {
    recommendations: Array<Record<string, unknown>>;
    requests: ActionRequest[];
    policies: PolicyDecision[];
    approvals: Array<Record<string, unknown>>;
    preauthorizations: PolicyPreAuthorization[];
    executions: Execution[];
    request_digest: string | null;
  };
  verification: Verification[];
  audit: { chain_valid: boolean; records: AuditRecord[] };
  reasoning_trace: TraceNode[];
  mock_state: {
    source_type: "MOCK";
    resource_environment: "SANDBOX";
    credential: Record<string, unknown>;
    attack: Record<string, unknown>;
    ci: Record<string, unknown>;
    resource: Record<string, unknown>;
  } | null;
}

const API = "/api/v1";

export async function api<T>(
  path: string,
  role: Role,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-Demo-Role": role,
      ...init?.headers,
    },
  });
  const body = (await response.json()) as T & {
    code?: string;
    message?: string;
  };
  if (!response.ok) {
    throw new Error(
      `${body.code ?? "ERROR"}: ${body.message ?? response.statusText}`,
    );
  }
  return body;
}
