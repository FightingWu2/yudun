import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  api,
  type Evidence,
  type IncidentBundle,
  type KnowledgeDocument,
  type KnowledgeHit,
  type KnowledgeIndexStatus,
  type KnowledgeSearchResult,
  type ReplaySources,
  type Role,
  type RunMode,
  type RuntimeStatus,
  type TimelineNode,
} from "./api";
import "./styles.css";

type Workspace =
  | "detection"
  | "investigation"
  | "response"
  | "audit"
  | "knowledge";

const roles: Role[] = ["ANALYST", "APPROVER", "AUDITOR", "ADMIN"];
const workspaces: Array<{ id: Workspace; label: string; index: string }> = [
  { id: "detection", label: "Detection & Incident", index: "01" },
  { id: "investigation", label: "Evidence & Investigation", index: "02" },
  { id: "response", label: "Response & Verification", index: "03" },
  { id: "audit", label: "Audit & Trace", index: "04" },
  { id: "knowledge", label: "Security Knowledge", index: "05" },
];

function SourceBadge({ source }: { source: string }) {
  return (
    <span className={`badge source ${source.toLowerCase()}`}>{source}</span>
  );
}

function StatusBadge({ value }: { value: string }) {
  return <span className={`badge status ${value.toLowerCase()}`}>{value}</span>;
}

function Empty({ children }: { children: string }) {
  return <div className="empty">{children}</div>;
}

function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}

export default function App() {
  const [role, setRole] = useState<Role>("ADMIN");
  const [workspace, setWorkspace] = useState<Workspace>("detection");
  const [sources, setSources] = useState<ReplaySources | null>(null);
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
  const [bundle, setBundle] = useState<IncidentBundle | null>(null);
  const [captureId, setCaptureId] = useState("");
  const [scenarioId, setScenarioId] = useState("");
  const [runMode, setRunMode] = useState<RunMode>("PRODUCTION_GUARDED");
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const refreshSequence = useRef(0);

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    try {
      const status = await api<RuntimeStatus>("/runtime/status", role);
      const nextBundle = status.incident_id
        ? await api<IncidentBundle>(
            `/incidents/${status.incident_id}/bundle`,
            role,
          )
        : null;
      if (sequence === refreshSequence.current) {
        setRuntime(status);
        setBundle(nextBundle);
        setError(null);
      }
    } catch (caught) {
      if (sequence === refreshSequence.current) throw caught;
    }
  }, [role]);

  useEffect(() => {
    void Promise.all([
      api<ReplaySources>("/replay/sources", role),
      api<RuntimeStatus>("/runtime/status", role),
    ])
      .then(([loadedSources, status]) => {
        setSources(loadedSources);
        setRuntime(status);
        setCaptureId(
          (current) => current || loadedSources.official[0]?.capture_id || "",
        );
        setScenarioId(
          (current) => current || loadedSources.synthetic[0]?.scenario_id || "",
        );
        if (status.incident_id) {
          return api<IncidentBundle>(
            `/incidents/${status.incident_id}/bundle`,
            role,
          );
        }
        return null;
      })
      .then(setBundle)
      .catch((caught: unknown) => setError(String(caught)));
  }, [role]);

  useEffect(() => {
    const eventSource = new EventSource("/api/v1/events");
    const eventTypes = [
      "incident.updated",
      "approval.required",
      "approval.decided",
      "execution.step.updated",
      "verification.updated",
      "incident.closed",
      "replan.created",
    ];
    const update = () =>
      void refresh().catch((caught: unknown) => setError(String(caught)));
    eventTypes.forEach((type) => eventSource.addEventListener(type, update));
    return () => eventSource.close();
  }, [refresh]);

  const reset = async () => {
    setBusy(true);
    setError(null);
    try {
      setRuntime(
        await api<RuntimeStatus>("/replay/reset", "ADMIN", { method: "POST" }),
      );
      setBundle(null);
      setSelectedEvidence(null);
    } catch (caught) {
      setError(String(caught));
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const status = await api<RuntimeStatus>("/replay/start", "ADMIN", {
        method: "POST",
        body: JSON.stringify({
          official_capture_id: captureId,
          synthetic_scenario_id: scenarioId,
          run_mode: runMode,
        }),
      });
      setRuntime(status);
      await refresh();
    } catch (caught) {
      setError(String(caught));
    } finally {
      setBusy(false);
    }
  };

  const decide = async (decision: "APPROVED" | "REJECTED") => {
    const request = bundle?.actions.requests.at(-1);
    const digest = bundle?.actions.request_digest;
    if (!request || !digest) return;
    setBusy(true);
    setError(null);
    try {
      setRuntime(
        await api<RuntimeStatus>("/approvals", role, {
          method: "POST",
          body: JSON.stringify({
            action_request_id: request.action_request_id,
            decision,
            comment: `${decision} through guarded demo console`,
            expected_digest: digest,
            request_id: `ui-${decision.toLowerCase()}-${request.action_request_id}`,
          }),
        }),
      );
      await refresh();
    } catch (caught) {
      setError(String(caught));
    } finally {
      setBusy(false);
    }
  };

  const timeline = useMemo<TimelineNode[]>(() => {
    return (
      bundle?.findings.find(
        (finding) => finding.finding_type === "ATTACK_TIMELINE",
      )?.metadata?.timeline?.nodes ?? []
    );
  }, [bundle]);

  const openEvidence = async (item: Evidence) => {
    try {
      setSelectedEvidence(
        await api<Evidence>(`/evidence/${item.evidence_id}`, role),
      );
    } catch (caught) {
      setError(String(caught));
    }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">御</div>
          <div>
            <strong>御盾智核</strong>
            <span>API Credential Incident Response</span>
          </div>
        </div>
        <div className="global-state" data-testid="global-state">
          <div>
            <label>INCIDENT</label>
            <b>{bundle?.incident.incident_id ?? "—"}</b>
          </div>
          <div>
            <label>STATUS</label>
            <StatusBadge value={bundle?.incident.status ?? "IDLE"} />
          </div>
          <div>
            <label>AUTOMATION</label>
            <b>{bundle?.incident.automation_state ?? "—"}</b>
          </div>
          <div>
            <label>SEVERITY</label>
            <b className="critical">{bundle?.incident.severity ?? "—"}</b>
          </div>
          <div>
            <label>RUN MODE</label>
            <b>{runtime?.run_mode ?? "PRODUCTION_GUARDED"}</b>
          </div>
          <div>
            <label>MODEL</label>
            <b data-testid="model-provider">
              {runtime?.model_provider ?? "DETERMINISTIC_TEST"}
            </b>
          </div>
          <div>
            <label>STAGE</label>
            <b>{runtime?.stage ?? "IDLE"}</b>
          </div>
        </div>
        <label className="role-control">
          Local Role
          <select
            value={role}
            onChange={(event) => setRole(event.target.value as Role)}
          >
            {roles.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        </label>
      </header>

      <aside className="sidebar">
        <div className="nav-label">WORKSPACES</div>
        {workspaces.map((item) => (
          <button
            className={workspace === item.id ? "nav-item active" : "nav-item"}
            key={item.id}
            onClick={() => setWorkspace(item.id)}
          >
            <span>{item.index}</span>
            {item.label}
          </button>
        ))}
        <div className="boundary-card">
          <span>TRUST BOUNDARY</span>
          <b>Guarded execution</b>
          <p>模型负责分析，Policy、审批、执行与验证保持确定性。</p>
        </div>
      </aside>

      <main className="workspace">
        {error && (
          <div className="error-banner" role="alert">
            {error}
          </div>
        )}
        {workspace === "detection" && (
          <DetectionWorkspace
            sources={sources}
            captureId={captureId}
            scenarioId={scenarioId}
            runMode={runMode}
            setCaptureId={setCaptureId}
            setScenarioId={setScenarioId}
            setRunMode={setRunMode}
            reset={reset}
            start={start}
            busy={busy}
            bundle={bundle}
            openEvidence={openEvidence}
          />
        )}
        {workspace === "investigation" && (
          <InvestigationWorkspace
            bundle={bundle}
            timeline={timeline}
            openEvidence={openEvidence}
          />
        )}
        {workspace === "response" && (
          <ResponseWorkspace
            bundle={bundle}
            role={role}
            busy={busy}
            decide={decide}
          />
        )}
        {workspace === "audit" && <AuditWorkspace bundle={bundle} />}
        {workspace === "knowledge" && <KnowledgeWorkspace role={role} />}
      </main>

      {selectedEvidence && (
        <div
          className="drawer-backdrop"
          onClick={() => setSelectedEvidence(null)}
        >
          <aside
            className="drawer"
            data-testid="evidence-drawer"
            onClick={(event) => event.stopPropagation()}
          >
            <button className="close" onClick={() => setSelectedEvidence(null)}>
              ×
            </button>
            <SourceBadge source={selectedEvidence.source_type} />
            <h2>Evidence Detail</h2>
            <p className="mono">{selectedEvidence.evidence_id}</p>
            <dl className="detail-list">
              <dt>Summary</dt>
              <dd>{selectedEvidence.summary}</dd>
              <dt>Type</dt>
              <dd>{selectedEvidence.evidence_type}</dd>
              <dt>Sensitivity</dt>
              <dd>{selectedEvidence.sensitivity}</dd>
              <dt>Content hash</dt>
              <dd className="mono wrap">{selectedEvidence.content_sha256}</dd>
            </dl>
            <h3>Safe locator</h3>
            <JsonView value={selectedEvidence.locator} />
            <h3>Redacted snapshot</h3>
            <JsonView value={selectedEvidence.redacted_snapshot} />
          </aside>
        </div>
      )}
    </div>
  );
}

interface DetectionProps {
  sources: ReplaySources | null;
  captureId: string;
  scenarioId: string;
  runMode: RunMode;
  setCaptureId: (value: string) => void;
  setScenarioId: (value: string) => void;
  setRunMode: (value: RunMode) => void;
  reset: () => Promise<void>;
  start: () => Promise<void>;
  busy: boolean;
  bundle: IncidentBundle | null;
  openEvidence: (item: Evidence) => Promise<void>;
}

function DetectionWorkspace(props: DetectionProps) {
  const { bundle } = props;
  return (
    <>
      <section className="page-heading">
        <div>
          <span>01 / INGEST & DETECT</span>
          <h1>安全事件从证据开始</h1>
        </div>
        <p>Official NTA 样本与 Synthetic 凭据场景分别标识，不伪造跨源因果。</p>
      </section>
      <section className="replay-console card" data-testid="replay-console">
        <div className="card-title">
          <div>
            <span>DATA REPLAY</span>
            <h2>数据重放台</h2>
          </div>
          <StatusBadge value={bundle ? "PAUSED" : "READY"} />
        </div>
        <div className="source-grid">
          <label>
            <SourceBadge source="OFFICIAL" /> Official NTA Sample
            <select
              value={props.captureId}
              onChange={(e) => props.setCaptureId(e.target.value)}
            >
              {props.sources?.official.map((item) => (
                <option value={item.capture_id} key={item.capture_id}>
                  {item.display_name} · {item.packet_count} packets
                </option>
              ))}
            </select>
          </label>
          <div className="not-equal">≠</div>
          <label>
            <SourceBadge source="SYNTHETIC" /> Credential Incident Scenario
            <select
              value={props.scenarioId}
              onChange={(e) => props.setScenarioId(e.target.value)}
            >
              {props.sources?.synthetic.map((item) => (
                <option value={item.scenario_id} key={item.scenario_id}>
                  {item.display_name}
                </option>
              ))}
            </select>
          </label>
          <div className="replay-actions">
            <button
              className="secondary"
              onClick={() => void props.reset()}
              disabled={props.busy}
            >
              Reset
            </button>
            <button
              className="primary"
              data-testid="start-replay"
              onClick={() => void props.start()}
              disabled={props.busy || Boolean(bundle)}
            >
              Start Replay
            </button>
          </div>
        </div>
        <div className="mode-selector" data-testid="run-mode-selector">
          <label>
            Execution mode
            <select
              aria-label="Execution mode"
              value={props.runMode}
              onChange={(event) =>
                props.setRunMode(event.target.value as RunMode)
              }
              disabled={Boolean(bundle)}
            >
              {props.sources?.run_modes.map((mode) => (
                <option
                  value={mode.run_mode}
                  key={mode.run_mode}
                  disabled={!mode.enabled}
                >
                  {mode.run_mode} · {mode.safety_label}
                </option>
              ))}
            </select>
          </label>
          {props.runMode === "COMPETITION_AUTONOMOUS" ? (
            <div className="sandbox-banner" data-testid="sandbox-only-banner">
              COMPETITION AUTONOMOUS · SANDBOX ONLY · 0 HUMAN APPROVALS · NO
              PRODUCTION SIDE EFFECT
            </div>
          ) : (
            <div className="guarded-banner">
              PRODUCTION GUARDED · POLICY + HUMAN APPROVAL REQUIRED
            </div>
          )}
        </div>
      </section>
      {bundle ? (
        <>
          <section className="metric-grid" data-testid="incident-overview">
            <Metric
              label="Signals"
              value={bundle.signals.length}
              note="Signal ≠ ConfirmedFact"
            />
            <Metric
              label="Confirmed Facts"
              value={bundle.facts.length}
              note="Deterministic validation"
            />
            <Metric
              label="Agent Tasks"
              value={bundle.tasks.length}
              note="Bounded contracts"
            />
            <Metric
              label="Next Stage"
              value={bundle.incident.next_expected_stage ?? "—"}
              note={bundle.incident.current_blocker ?? "No blocker"}
            />
          </section>
          <div className="two-column">
            <section className="card" data-testid="detection-signals">
              <div className="card-title">
                <div>
                  <span>DETECTION</span>
                  <h2>Security Signals</h2>
                </div>
                <small>Signal ≠ ConfirmedFact</small>
              </div>
              {bundle.signals.map((signal) => (
                <article className="record" key={signal.signal_id}>
                  <div>
                    <StatusBadge value={signal.severity} />
                    <b>{signal.signal_type}</b>
                  </div>
                  <p>{signal.trigger_reason}</p>
                  <small>
                    {signal.detector.detector_type} ·{" "}
                    {signal.detector.detector_id} v
                    {signal.detector.detector_version}
                  </small>
                </article>
              ))}
            </section>
            <section className="card" data-testid="evidence-index">
              <div className="card-title">
                <div>
                  <span>EVIDENCE</span>
                  <h2>Evidence Index</h2>
                </div>
                <small>
                  {bundle.evidence.length + bundle.official_evidence.length}{" "}
                  refs
                </small>
              </div>
              <div className="evidence-list">
                {[
                  ...bundle.official_evidence.slice(0, 2),
                  ...bundle.evidence.slice(0, 5),
                ].map((item) => (
                  <button
                    className="evidence-row"
                    key={item.evidence_id}
                    onClick={() => void props.openEvidence(item)}
                  >
                    <SourceBadge source={item.source_type} />
                    <span>
                      <b>{item.summary}</b>
                      <small>{item.evidence_id}</small>
                    </span>
                    <i>↗</i>
                  </button>
                ))}
              </div>
            </section>
          </div>
        </>
      ) : (
        <Empty>Reset 后选择两个明确来源并开始重放。</Empty>
      )}
    </>
  );
}

function Metric({
  label,
  value,
  note,
}: {
  label: string;
  value: string | number;
  note: string;
}) {
  return (
    <article className="metric">
      <span>{label}</span>
      <b>{value}</b>
      <small>{note}</small>
    </article>
  );
}

function KnowledgeWorkspace({ role }: { role: Role }) {
  const [status, setStatus] = useState<KnowledgeIndexStatus | null>(null);
  const [documents, setDocuments] = useState<KnowledgeDocument[]>([]);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<KnowledgeSearchResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void Promise.all([
      api<KnowledgeIndexStatus>("/knowledge/status", role),
      api<{ documents: KnowledgeDocument[]; total: number }>(
        "/knowledge/documents",
        role,
      ),
    ])
      .then(([loadedStatus, loadedDocuments]) => {
        setStatus(loadedStatus);
        setDocuments(loadedDocuments.documents);
      })
      .catch((caught: unknown) => setError(String(caught)));
  }, [role]);

  const search = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api<KnowledgeSearchResult>(
        `/knowledge/search?q=${encodeURIComponent(query)}&limit=8`,
        role,
      );
      setResults(result);
    } catch (caught) {
      setError(String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <section className="page-heading">
        <div>
          <span>05 / SECURITY KNOWLEDGE RAG</span>
          <h1>安全知识检索</h1>
        </div>
        <p>
          检索结果仅作为参考材料，不能直接成为攻击事实或授权依据。
          {status
            ? ` 索引 ${status.mode} · ${status.document_count} 条（导入 ${status.imported_count}）`
            : ""}
        </p>
      </section>

      <div className="knowledge-search card">
        <input
          type="search"
          value={query}
          placeholder="检索规则说明、处置手册、ATT&CK 技战术…"
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void search();
          }}
        />
        <button onClick={() => void search()} disabled={busy || !query.trim()}>
          {busy ? "检索中…" : "检索"}
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {results ? (
        <section className="card" data-testid="knowledge-results">
          <div className="card-title">
            <div>
              <span>RESULTS</span>
              <h2>{results.query}</h2>
            </div>
            <small>
              {results.total} hits · {results.elapsed_ms}ms · {results.mode}
            </small>
          </div>
          {results.hits.length === 0 ? (
            <Empty>未检索到相关知识条目。</Empty>
          ) : (
            results.hits.map((hit) => (
              <article className="knowledge-hit" key={hit.doc_id}>
                <div className="knowledge-hit-head">
                  <SourceBadge source={hit.category} />
                  <b>{hit.title}</b>
                  <small>score {hit.score.toFixed(3)}</small>
                </div>
                <p>{hit.snippet}</p>
                <small className="muted">
                  {hit.doc_id} · {hit.source}@{hit.version} · 命中{" "}
                  {hit.matched_terms.join(" · ") || "—"}
                </small>
              </article>
            ))
          )}
        </section>
      ) : null}

      <section className="card" data-testid="knowledge-documents">
        <div className="card-title">
          <div>
            <span>KNOWLEDGE BASE</span>
            <h2>知识库目录</h2>
          </div>
          <small>{documents.length} documents</small>
        </div>
        <div className="knowledge-grid">
          {documents.map((document) => (
            <details className="knowledge-doc" key={document.doc_id}>
              <summary>
                <SourceBadge source={document.category} />
                <span>{document.title}</span>
                <small>{document.doc_id}</small>
              </summary>
              <div>
                <p>{document.content}</p>
                <small className="muted">
                  {document.source}@{document.version} ·{" "}
                  {document.tags.join(" · ")}
                </small>
              </div>
            </details>
          ))}
        </div>
      </section>
    </>
  );
}

function InvestigationWorkspace({
  bundle,
  timeline,
  openEvidence,
}: {
  bundle: IncidentBundle | null;
  timeline: TimelineNode[];
  openEvidence: (item: Evidence) => Promise<void>;
}) {
  if (!bundle) return <Empty>请先在 Detection 工作区启动重放。</Empty>;
  const toolCalls = bundle.audit.records.filter(
    (item) => item.event_type === "TOOL_ACCESS_GRANTED",
  );
  return (
    <>
      <section className="page-heading">
        <div>
          <span>02 / INVESTIGATE & TRACE</span>
          <h1>受限智能体协作轨迹</h1>
        </div>
        <p>每个结论都能回到 Evidence；Finding 必须经过验证才能成为 Fact。</p>
      </section>
      <div className="two-column wide-left">
        <section className="card" data-testid="agent-tasks">
          <div className="card-title">
            <div>
              <span>AGENT TASKS</span>
              <h2>任务、工具与权限</h2>
            </div>
            <small>{bundle.tasks.length} tasks</small>
          </div>
          {bundle.tasks.map((task) => {
            const result = bundle.results.find(
              (item) => item.task_id === task.task_id,
            );
            const findings = bundle.findings.filter(
              (item) => item.task_id === task.task_id,
            );
            const calls = toolCalls.filter(
              (item) => item.actor_id === task.assigned_agent_type,
            );
            return (
              <details className="agent-card" key={task.task_id} open>
                <summary>
                  <span className="agent-icon">
                    {task.assigned_agent_type.slice(0, 2)}
                  </span>
                  <span>
                    <b>{task.assigned_agent_type}</b>
                    <small>{task.task_goal}</small>
                  </span>
                  <StatusBadge value={result?.task_status ?? task.status} />
                </summary>
                <div className="agent-body">
                  <div>
                    <label>Allowed tools</label>
                    <div className="chips">
                      {task.allowed_tools.map((tool) => (
                        <span key={tool}>{tool}</span>
                      ))}
                    </div>
                    <label>Explicitly denied</label>
                    <div className="chips denied">
                      <span>execute_mock_action_plan</span>
                    </div>
                  </div>
                  <div>
                    <label>Actual calls</label>
                    {calls.length ? (
                      calls.map((call) => (
                        <p className="mono compact" key={call.audit_id}>
                          {call.object_id} · {call.audit_id}
                        </p>
                      ))
                    ) : (
                      <p className="muted">No tool call</p>
                    )}
                  </div>
                  <div className="full">
                    <label>Findings</label>
                    {findings.map((finding) => (
                      <div className="finding" key={finding.finding_id}>
                        <b>{finding.finding_type}</b>
                        <p>{finding.statement}</p>
                        <small>
                          Confidence {finding.confidence_level} ·{" "}
                          {finding.evidence_refs.length} evidence refs
                        </small>
                        {finding.knowledge_refs?.length ? (
                          <small className="knowledge-refs">
                            Knowledge · {finding.knowledge_refs.join(" · ")}
                          </small>
                        ) : null}
                      </div>
                    ))}
                  </div>
                  {result?.unresolved_questions.length ? (
                    <div className="full warning">
                      <label>Unresolved</label>
                      {result.unresolved_questions.join(" · ")}
                    </div>
                  ) : null}
                </div>
              </details>
            );
          })}
        </section>
        <section className="card">
          <div className="card-title">
            <div>
              <span>CONFIRMED FACTS</span>
              <h2>Finding → Fact</h2>
            </div>
            <small>{bundle.facts.length}/6</small>
          </div>
          {bundle.facts.map((fact) => (
            <article className="fact" key={fact.fact_id}>
              <span>✓</span>
              <div>
                <b>{fact.fact_type}</b>
                <p>{fact.statement}</p>
                <small>
                  {fact.validated_by} · {fact.evidence_refs[0]}
                </small>
              </div>
            </article>
          ))}
        </section>
      </div>
      <section className="card timeline-card" data-testid="attack-timeline">
        <div className="card-title">
          <div>
            <span>ATTACK TIMELINE</span>
            <h2>确定性证据时间线</h2>
          </div>
          <small>Exact fields + timestamp order</small>
        </div>
        <div className="timeline">
          {timeline.map((node, index) => (
            <article key={`${node.object_ref}-${index}`}>
              <div className="timeline-dot">{index + 1}</div>
              <div>
                <time>{new Date(node.timestamp).toLocaleTimeString()}</time>
                <SourceBadge source={node.source_type} />
                <h3>{node.event_type}</h3>
                <p>{node.summary}</p>
                <small>
                  {node.object_ref} · {node.association_basis}
                </small>
                <button
                  className="link-button"
                  onClick={() => {
                    const evidence = bundle.evidence.find(
                      (item) => item.evidence_id === node.evidence_refs[0],
                    );
                    if (evidence) void openEvidence(evidence);
                  }}
                >
                  View Evidence
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

function ResponseWorkspace({
  bundle,
  role,
  busy,
  decide,
}: {
  bundle: IncidentBundle | null;
  role: Role;
  busy: boolean;
  decide: (decision: "APPROVED" | "REJECTED") => Promise<void>;
}) {
  if (!bundle) return <Empty>请先启动重放。</Empty>;
  const recommendation = bundle.actions.recommendations.at(-1);
  const request = bundle.actions.requests.at(-1);
  const policy = bundle.actions.policies.at(-1);
  const preauthorization = bundle.actions.preauthorizations.at(-1);
  const execution = bundle.actions.executions.at(-1);
  const verification = bundle.verification.at(-1);
  return (
    <>
      <section className="page-heading">
        <div>
          <span>03 / RESPOND & VERIFY</span>
          <h1>建议、授权、执行、验证彼此分离</h1>
        </div>
        <p>
          {bundle.runtime.run_mode === "COMPETITION_AUTONOMOUS"
            ? "比赛自治模式只允许 Synthetic / Mock / Sandbox，经确定性预授权后由 SYSTEM_EXECUTOR 执行。"
            : "Approval 只恢复 LangGraph；只有 SYSTEM_EXECUTOR 能改变 Mock/Sandbox 状态。"}
        </p>
      </section>
      <div className="two-column">
        <section className="card" data-testid="action-recommendation">
          <div className="card-title">
            <div>
              <span>RECOMMENDATION</span>
              <h2>
                {String(recommendation?.recommendation_type ?? "Pending")}
              </h2>
            </div>
            <StatusBadge value={request?.risk_level ?? "PENDING"} />
          </div>
          {recommendation ? (
            <>
              <p>{String(recommendation.rationale)}</p>
              <dl className="detail-list">
                <dt>Expected effect</dt>
                <dd>{String(recommendation.expected_effect)}</dd>
                <dt>Proposed by</dt>
                <dd>{String(recommendation.proposed_by)}</dd>
                <dt>Fact refs</dt>
                <dd>
                  {Array.isArray(recommendation.fact_refs)
                    ? recommendation.fact_refs.length
                    : 0}{" "}
                  confirmed
                </dd>
              </dl>
            </>
          ) : (
            <Empty>No recommendation</Empty>
          )}
        </section>
        <section className="card" data-testid="policy-engine">
          <div className="card-title">
            <div>
              <span>POLICY ENGINE</span>
              <h2>Deterministic Checks</h2>
            </div>
            <StatusBadge value={policy?.decision ?? "PENDING"} />
          </div>
          {policy?.checks.map((check) => (
            <div
              className={
                check.passed ? "policy-check pass" : "policy-check fail"
              }
              key={check.check_id}
            >
              <span>{check.passed ? "✓" : "×"}</span>
              <div>
                <b>{check.check_id}</b>
                <small>{check.reason}</small>
              </div>
            </div>
          ))}
        </section>
      </div>
      {preauthorization && (
        <section
          className="card preauthorization-panel"
          data-testid="preauthorization-panel"
        >
          <div className="card-title">
            <div>
              <span>POLICY PRE-AUTHORIZATION</span>
              <h2>Competition Autonomous Sandbox</h2>
            </div>
            <StatusBadge value={preauthorization.decision} />
          </div>
          <p>
            Human Approval Count: <b>{bundle.actions.approvals.length}</b> ·
            Environment: <b>{preauthorization.environment}</b>
          </p>
          {preauthorization.guard_checks.map((check) => (
            <div
              className={
                check.passed ? "policy-check pass" : "policy-check fail"
              }
              key={check.check_id}
            >
              <span>{check.passed ? "✓" : "×"}</span>
              <div>
                <b>{check.check_id}</b>
                <small>{check.reason}</small>
              </div>
            </div>
          ))}
        </section>
      )}
      {request && (
        <section className="card approval-panel" data-testid="approval-panel">
          <div>
            <span>ACTION REQUEST</span>
            <h2>
              {preauthorization
                ? "策略预授权的三步沙箱处置计划"
                : "等待人类批准的三步处置计划"}
            </h2>
            <p className="mono">{request.action_request_id}</p>
            <p className="digest">Digest · {bundle.actions.request_digest}</p>
          </div>
          <div className="operations">
            {request.operations.map((operation, index) => (
              <div key={operation.operation_id}>
                <span>{index + 1}</span>
                <b>{operation.operation_type}</b>
                <small>{operation.operation_id}</small>
              </div>
            ))}
          </div>
          <div className="mock-before" data-testid="mock-state-before">
            <label>
              Current Mock/Sandbox State ·{" "}
              {execution ? "after controlled execution" : "before approval"}
            </label>
            <p>
              Old credential{" "}
              <b>{String(bundle.mock_state?.credential.old_version_status)}</b>
            </p>
            <p>
              New credential{" "}
              <b>{String(bundle.mock_state?.credential.new_version_status)}</b>
            </p>
            <p>
              Malicious attempt{" "}
              <b>{String(bundle.mock_state?.attack.last_attempt_result)}</b>
            </p>
            <p>
              CI binding{" "}
              <b>
                {String(bundle.mock_state?.ci.bound_credential_version_ref)}
              </b>
            </p>
            <p>
              CI build <b>{String(bundle.mock_state?.ci.last_build_status)}</b>
            </p>
            <p>
              High-cost creation{" "}
              <b>{String(bundle.mock_state?.resource.last_creation_result)}</b>
            </p>
            <p>
              Environment{" "}
              <b>{String(bundle.mock_state?.resource_environment)}</b>
            </p>
          </div>
          <div className="approval-actions">
            {role === "APPROVER" &&
            !execution &&
            bundle.runtime.stage === "WAITING_APPROVAL" ? (
              <>
                <button
                  className="secondary danger"
                  data-testid="reject-action"
                  onClick={() => void decide("REJECTED")}
                  disabled={busy}
                >
                  Reject
                </button>
                <button
                  className="primary"
                  data-testid="approve-action"
                  onClick={() => void decide("APPROVED")}
                  disabled={busy}
                >
                  Approve & Resume
                </button>
              </>
            ) : (
              <p>
                {execution
                  ? "Approval recorded · workflow resumed"
                  : "Switch to APPROVER to decide"}
              </p>
            )}
          </div>
        </section>
      )}
      {execution && (
        <section className="card" data-testid="execution-results">
          <div className="card-title">
            <div>
              <span>CONTROLLED EXECUTION</span>
              <h2>Three-step state change</h2>
            </div>
            <StatusBadge value={execution.overall_status} />
          </div>
          <div className="execution-grid">
            {execution.operation_results.map((operation, index) => (
              <article key={operation.operation_id}>
                <span>STEP 0{index + 1}</span>
                <h3>{operation.operation_id}</h3>
                <StatusBadge value={operation.status} />
                <small>Before · {operation.state_snapshot_before}</small>
                <small>After · {operation.state_snapshot_after}</small>
                <small>Receipt · {operation.receipt_ref}</small>
              </article>
            ))}
          </div>
        </section>
      )}
      {verification && (
        <section className="card" data-testid="verification-results">
          <div className="card-title">
            <div>
              <span>RECOVERY ASSERTIONS</span>
              <h2>Execution Success ≠ Incident Resolved</h2>
            </div>
            <StatusBadge
              value={`${verification.assertions.filter((item) => item.passed).length}/6 PASS`}
            />
          </div>
          <div className="verification-grid">
            {verification.assertions.map((assertion) => (
              <article
                className={
                  assertion.passed ? "assertion pass" : "assertion fail"
                }
                key={assertion.assertion_type}
              >
                <span>{assertion.passed ? "✓" : "×"}</span>
                <div>
                  <b>{assertion.assertion_type}</b>
                  <small>
                    Observed: {JSON.stringify(assertion.observed_value.actual)}
                  </small>
                  <small>Evidence: {assertion.evidence_refs[0]}</small>
                </div>
              </article>
            ))}
          </div>
          {verification.next_step === "REPLAN" && (
            <div className="error-banner">
              Verification FAILED · Incident remains ROTATED · Next step REPLAN
            </div>
          )}
        </section>
      )}
    </>
  );
}

function AuditWorkspace({ bundle }: { bundle: IncidentBundle | null }) {
  if (!bundle) return <Empty>请先启动重放。</Empty>;
  return (
    <>
      <section className="page-heading">
        <div>
          <span>04 / AUDIT & REASONING</span>
          <h1>可审计结构化推理轨迹</h1>
        </div>
        <p>
          展示 Observation、Evidence、Task、Finding、Fact 与
          Decision，不展示隐藏 CoT。
        </p>
      </section>
      <section className="integrity-banner" data-testid="audit-integrity">
        <div>
          <span>AUDIT CHAIN</span>
          <h2>{bundle.audit.chain_valid ? "VALID" : "INVALID"}</h2>
        </div>
        <p>
          {bundle.audit.chain_valid
            ? `${bundle.audit.records.length} records · SHA-256 hash chain verified`
            : "Incident cannot be CLOSED"}
        </p>
      </section>
      <div className="two-column wide-left">
        <section className="card" data-testid="reasoning-trace">
          <div className="card-title">
            <div>
              <span>REASONING TRACE</span>
              <h2>Evidence-driven object chain</h2>
            </div>
            <small>{bundle.reasoning_trace.length} nodes</small>
          </div>
          <div className="trace-list">
            {bundle.reasoning_trace.map((node, index) => (
              <article key={`${node.object_id}-${index}`}>
                <span className={`trace-stage ${node.stage.toLowerCase()}`}>
                  {node.stage}
                </span>
                <div>
                  <b>{node.summary}</b>
                  <p>
                    <SourceBadge source={node.source_type} /> {node.actor} ·{" "}
                    {node.object_type}
                  </p>
                  <small>{node.object_id}</small>
                </div>
                <time>{new Date(node.timestamp).toLocaleTimeString()}</time>
              </article>
            ))}
          </div>
        </section>
        <section className="card" data-testid="audit-records">
          <div className="card-title">
            <div>
              <span>AUDIT RECORDS</span>
              <h2>Append-only Ledger</h2>
            </div>
          </div>
          <div className="audit-list">
            {bundle.audit.records
              .slice()
              .reverse()
              .map((record) => (
                <article key={record.audit_id}>
                  <span>{record.event_type}</span>
                  <b>{record.summary}</b>
                  <small>
                    {record.actor_id} · {record.audit_id}
                  </small>
                </article>
              ))}
          </div>
        </section>
      </div>
    </>
  );
}
