"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  Download,
  ArrowRight,
  RotateCw,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  Play,
  RotateCcw,
  Check,
  X,
  FileText,
  Sliders,
  Sparkles,
} from "lucide-react";
import {
  api,
  downloadUrl,
  type AIAnalysis,
  type IncidentDetail,
  type IncidentStatus,
  type MitreMapping,
  type TraceAIResult,
  type ResponseProposal,
  type ResponseExecutionRecord,
  type ActionType,
} from "@/lib/api";
import { ThreatLensShell } from "@/components/threatlens/shell";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SeverityBadge,
} from "@/components/threatlens/ui";
import {
  durationMinutes,
  entityList,
  formatDate,
  titleCase,
} from "@/components/threatlens/format";

export default function IncidentInvestigationPage() {
  const params = useParams();
  const id =
    typeof params?.id === "string"
      ? params.id
      : Array.isArray(params?.id)
        ? params.id[0]
        : "";

  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [trace, setTrace] = useState<TraceAIResult | null>(null);
  const [mitre, setMitre] = useState<MitreMapping | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [proposal, setProposal] = useState<ResponseProposal | null>(null);
  const [executions, setExecutions] = useState<ResponseExecutionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [executingAction, setExecutingAction] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [responseActionSuccess, setResponseActionSuccess] = useState<
    string | null
  >(null);
  const [showAiDrawer, setShowAiDrawer] = useState(false);
  const [activeCenterTab, setActiveCenterTab] = useState<
    "timeline" | "graph" | "response" | "mitre" | "alerts"
  >("timeline");

  const loadData = () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    Promise.all([
      api.incident(id),
      api.incidentTrace(id),
      api.incidentMitre(id),
      api.responseExecutions(),
    ])
      .then(([incidentDetail, traceData, mitreData, allExecs]) => {
        setDetail(incidentDetail);
        setTrace(traceData);
        setMitre(mitreData);
        setExecutions(allExecs.filter((e) => e.incident_id === id));
      })
      .catch((err) => {
        setError(
          err instanceof Error ? err.message : "Unable to load incident.",
        );
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, [id]);

  const runAnalysis = () => {
    if (!id) return;
    setAnalyzing(true);
    setShowAiDrawer(true);
    api
      .analyzeIncident(id)
      .then((result) => {
        setAnalysis(result.analysis);
      })
      .catch((err) => {
        setError(
          err instanceof Error
            ? err.message
            : "AI analyst investigation failed.",
        );
      })
      .finally(() => setAnalyzing(false));
  };

  const runResponseAgent = () => {
    if (!id) return;
    setPlanning(true);
    api
      .planIncidentResponse(id)
      .then((prop) => {
        setProposal(prop);
        setActiveCenterTab("response");
      })
      .catch((err) => {
        setError(
          err instanceof Error
            ? err.message
            : "Response Agent planning failed.",
        );
      })
      .finally(() => setPlanning(false));
  };

  const handleExecuteResponse = async (dryRun = false) => {
    if (!id || !proposal) return;
    setExecutingAction(true);
    setResponseActionSuccess(null);
    try {
      const record = await api.executeIncidentResponse(id, {
        action: proposal.recommended_action,
        target: proposal.target,
        playbook_id: proposal.playbook_id,
        dry_run: dryRun,
        approved_by: proposal.requires_approval
          ? "SOC Incident Commander"
          : "policy_engine",
      });

      setExecutions((prev) => [record, ...prev]);
      if (!dryRun && record.status === "verified") {
        if (detail) {
          setDetail({
            ...detail,
            incident: { ...detail.incident, status: "contained" },
          });
        }
        setResponseActionSuccess(
          `Action [${titleCase(record.action)}] verified and executed. Incident status updated to CONTAINED.`,
        );
      } else if (dryRun) {
        setResponseActionSuccess(
          `Dry-run simulation completed. Safe preview verified without modifying host state.`,
        );
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Defensive action execution failed.",
      );
    } finally {
      setExecutingAction(false);
    }
  };

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!detail) return;
    setStatusUpdating(true);
    try {
      const updated = await api.updateIncidentStatus(id, newStatus);
      setDetail({ ...detail, incident: updated.incident });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update status.");
    } finally {
      setStatusUpdating(false);
    }
  };

  const incident = detail?.incident;

  return (
    <ThreatLensShell>
      {loading ? (
        <LoadingState label="Loading incident context..." />
      ) : error ? (
        <ErrorState error={error} retry={loadData} />
      ) : incident ? (
        <>
          {/* Header */}
          <section className="page-heading">
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-surface-raised border border-border text-muted">
                  {incident.id}
                </span>
                <SeverityBadge value={incident.severity} />
                <span className="text-[11px] font-mono text-faint">
                  {Math.round(incident.confidence * 100)}% confidence
                </span>
              </div>
              <h1>{incident.title}</h1>
            </div>
            <div className="heading-actions">
              <div className="flex items-center gap-1.5">
                <label className="text-[11px] text-muted">Status:</label>
                <select
                  className="bg-surface-raised border border-border text-[11.5px] rounded px-2 py-1 font-mono text-text focus:outline-none"
                  value={incident.status}
                  onChange={(e) =>
                    handleStatusChange(e.target.value as IncidentStatus)
                  }
                  disabled={statusUpdating}
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>
              <button
                className="secondary-button"
                onClick={() =>
                  downloadUrl(`/api/v1/incidents/export/${id}/export/json`)
                }
              >
                <Download className="w-3.5 h-3.5 mr-1" /> JSON
              </button>
              <button
                className="secondary-button"
                onClick={() =>
                  downloadUrl(`/api/v1/incidents/export/${id}/export/csv`)
                }
              >
                <Download className="w-3.5 h-3.5 mr-1" /> CSV
              </button>
              <button
                className="secondary-button"
                onClick={() => {
                  if (!analysis) runAnalysis();
                  else setShowAiDrawer((v) => !v);
                }}
                disabled={analyzing}
              >
                <Sparkles className="w-3.5 h-3.5 mr-1" />
                {analyzing
                  ? "Analyzing..."
                  : showAiDrawer
                    ? "Hide AI Analyst"
                    : "AI Analyst"}
              </button>
              <button
                className="secondary-button font-medium"
                onClick={runResponseAgent}
                disabled={planning}
              >
                <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                {planning ? "Evaluating..." : "Response Agent"}
              </button>
            </div>
          </section>

          {responseActionSuccess && (
            <div className="p-3 rounded bg-surface-raised border border-success text-success text-[12px] font-mono mb-4 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 shrink-0" />
              <span>{responseActionSuccess}</span>
            </div>
          )}

          {detail.escalation?.requires_human_review && (
            <section className="panel mb-4 border-danger">
              <div className="panel-header">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-danger" />
                  <h2>HUMAN REVIEW REQUIRED</h2>
                </div>
                <span className="font-mono text-[10px] text-muted">
                  SOC notification:{" "}
                  {titleCase(detail.escalation.slack_notification_status)}
                </span>
              </div>
              <div className="p-4">
                <p className="text-[12px] text-text mb-3">
                  {detail.escalation.reason}
                </p>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-[11px]">
                  <div>
                    <span className="text-muted block">Source</span>
                    <strong className="font-mono">
                      {detail.escalation.source_ip}
                    </strong>
                  </div>
                  <div>
                    <span className="text-muted block">Target</span>
                    <strong className="font-mono">
                      {detail.escalation.target ?? "Unknown"}
                    </strong>
                  </div>
                  <div>
                    <span className="text-muted block">Recurrence count</span>
                    <strong className="font-mono">
                      {detail.escalation.recurrence_count}
                    </strong>
                  </div>
                  <div>
                    <span className="text-muted block">Status</span>
                    <strong className="font-mono">
                      {detail.escalation.status}
                    </strong>
                  </div>
                  <div>
                    <span className="text-muted block">Previous action</span>
                    <strong className="font-mono">
                      {titleCase(detail.escalation.previous_action)}
                    </strong>
                  </div>
                  <div>
                    <span className="text-muted block">
                      Previous verification
                    </span>
                    <strong className="font-mono">
                      {formatDate(detail.escalation.previous_verification_at)}
                    </strong>
                  </div>
                  <div>
                    <span className="text-muted block">Current activity</span>
                    <strong className="font-mono">
                      {formatDate(detail.escalation.last_activity_at)}
                    </strong>
                  </div>
                  <div>
                    <span className="text-muted block">Assigned analyst</span>
                    <strong className="font-mono">
                      {detail.escalation.assigned_to ?? "Unassigned"}
                    </strong>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* Metric Cards */}
          <section className="metric-grid mb-4">
            <article className="metric-card-clean">
              <strong>{entityList(incident.source_entities)}</strong>
              <span>Attacking Source</span>
              <small>External origin IP</small>
            </article>

            <article className="metric-card-clean">
              <strong>{entityList(incident.target_entities)}</strong>
              <span>Target Asset</span>
              <small>Host system</small>
            </article>

            <article className="metric-card-clean">
              <strong>{formatDate(incident.first_seen)}</strong>
              <span>First Observed</span>
              <small>Telemetry inception</small>
            </article>

            <article className="metric-card-clean">
              <strong>{formatDate(incident.last_seen)}</strong>
              <span>Last Observed</span>
              <small>
                Duration:{" "}
                {trace?.duration_minutes ??
                  durationMinutes(incident.first_seen, incident.last_seen)}{" "}
                min
              </small>
            </article>
          </section>

          {/* AI Analyst Guidance Panel */}
          {showAiDrawer && (
            <article className="panel ai-grounded-panel mb-4">
              <div className="ai-header">
                <div>
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-surface-raised border border-border text-muted">
                      AI ANALYST (EXPLAIN &amp; REASON)
                    </span>
                  </div>
                  <h2 className="text-[13px]">
                    Investigative Evidence Interpretation
                  </h2>
                  <p className="text-[11px] text-muted">
                    Evidence-first reasoning. Grounded strictly on observed
                    telemetry; does not generate arbitrary commands.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    className="secondary-button text-[11px]"
                    onClick={runAnalysis}
                    disabled={analyzing}
                  >
                    {analyzing ? "Refreshing..." : "Re-run analysis"}
                  </button>
                  <button
                    className="secondary-button text-[11px]"
                    onClick={() => setShowAiDrawer(false)}
                  >
                    Close
                  </button>
                </div>
              </div>

              {analysis ? (
                <div className="ai-content p-4">
                  <div className="ai-section mb-3">
                    <span className="ai-section-title text-[11px] font-semibold text-muted block mb-1">
                      OBSERVED EVIDENCE
                    </span>
                    <div className="space-y-1">
                      {analysis.findings.map((ev, i) => (
                        <div
                          key={i}
                          className="text-[11.5px] font-mono text-text"
                        >
                          • {ev}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="ai-section mb-3">
                    <span className="ai-section-title text-[11px] font-semibold text-muted block mb-1">
                      ANALYST ASSESSMENT
                    </span>
                    <p className="text-[12px] text-text bg-surface-raised p-2.5 rounded border border-border leading-relaxed">
                      {analysis.attack_narrative || analysis.summary}
                    </p>
                  </div>

                  <div className="ai-section">
                    <span className="ai-section-title text-[11px] font-semibold text-muted block mb-1">
                      RECOMMENDED INVESTIGATION &amp; CONTAINMENT
                    </span>
                    <div className="space-y-1 font-mono text-[11.5px]">
                      {analysis.recommendations.map((step, i) => (
                        <div key={i} className="text-muted">
                          {step}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="quiet-empty p-4 text-[11.5px] text-muted font-mono">
                  Generating evidence-grounded analysis...
                </div>
              )}
            </article>
          )}

          {/* Center Tabs Navigation */}
          <div className="flex items-center gap-2 border-b border-border mb-4">
            <button
              className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
                activeCenterTab === "timeline"
                  ? "border-accent text-text"
                  : "border-transparent text-muted hover:text-text"
              }`}
              onClick={() => setActiveCenterTab("timeline")}
            >
              TraceAI Timeline ({trace?.timeline?.length ?? 0})
            </button>
            <button
              className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
                activeCenterTab === "graph"
                  ? "border-accent text-text"
                  : "border-transparent text-muted hover:text-text"
              }`}
              onClick={() => setActiveCenterTab("graph")}
            >
              Attack Graph ({trace?.attack_graph?.nodes?.length ?? 0} Nodes)
            </button>
            <button
              className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
                activeCenterTab === "response"
                  ? "border-accent text-text"
                  : "border-transparent text-muted hover:text-text"
              }`}
              onClick={() => setActiveCenterTab("response")}
            >
              Response Agent &amp; Containment {proposal ? "• Active Plan" : ""}
            </button>
            <button
              className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
                activeCenterTab === "alerts"
                  ? "border-accent text-text"
                  : "border-transparent text-muted hover:text-text"
              }`}
              onClick={() => setActiveCenterTab("alerts")}
            >
              Correlated Alerts ({detail.alerts.length})
            </button>
            <button
              className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
                activeCenterTab === "mitre"
                  ? "border-accent text-text"
                  : "border-transparent text-muted hover:text-text"
              }`}
              onClick={() => setActiveCenterTab("mitre")}
            >
              MITRE ATT&amp;CK ({mitre?.techniques?.length ?? 0})
            </button>
          </div>

          {/* Tab 1: TraceAI Timeline */}
          {activeCenterTab === "timeline" && (
            <article className="panel">
              <div className="panel-header">
                <h2>Reconstructed Attack Stages &amp; Chronology</h2>
                <span className="text-[10.5px] font-mono text-faint">
                  {trace?.timeline?.length ?? 0} events
                </span>
              </div>
              <div className="p-4">
                {trace?.stages && trace.stages.length > 0 && (
                  <div className="mb-4 pb-3 border-b border-border flex flex-wrap gap-2">
                    {trace.stages.map((st) => (
                      <div
                        key={st.stage}
                        className="px-2 py-1 rounded bg-surface-raised border border-border text-[11px] font-mono flex items-center gap-1.5"
                      >
                        <span className="text-muted font-medium">
                          #{st.order}
                        </span>
                        <strong className="text-text">{st.stage}</strong>
                        <span className="text-faint">
                          ({st.event_count} events)
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {trace?.timeline && trace.timeline.length > 0 ? (
                  <div className="timeline-stream">
                    {trace.timeline.map((item, idx) => (
                      <div
                        key={`${item.type}-${item.id}-${idx}`}
                        className="timeline-entry"
                      >
                        <div className="timeline-bullet" />
                        <div className="timeline-content">
                          <div className="timeline-meta">
                            <span className="text-text">
                              {formatDate(item.timestamp)}
                            </span>
                            <span>•</span>
                            <span className="text-muted font-medium">
                              {item.stage}
                            </span>
                            <span>•</span>
                            <SeverityBadge value={item.severity} />
                            {item.mitre_technique && (
                              <span className="px-1.5 py-0.2 rounded bg-surface-raised border border-border text-[9.5px]">
                                {item.mitre_technique}
                              </span>
                            )}
                          </div>
                          <div className="timeline-title">
                            {item.description}
                          </div>
                          <div className="timeline-desc font-mono text-[10.5px]">
                            {item.type.toUpperCase()}:{" "}
                            {item.source_ip ?? "Unknown"} →{" "}
                            {item.target_host ?? "Unknown"}{" "}
                            {item.username ? `(User: ${item.username})` : ""}
                          </div>
                          {item.telemetry_source && (
                            <div className="font-mono text-[10px] text-faint">
                              Telemetry Source:{" "}
                              {titleCase(item.telemetry_source)}
                              {item.agent_id ? ` · Agent ${item.agent_id}` : ""}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    title="No timeline"
                    description="No timeline events reconstructed for this incident."
                  />
                )}
              </div>
            </article>
          )}

          {/* Tab 2: Attack Graph */}
          {activeCenterTab === "graph" && (
            <article className="panel">
              <div className="panel-header">
                <h2>Attack Incursion Topology</h2>
                <span className="text-[10px] font-mono text-faint">
                  {trace?.attack_graph?.nodes?.length ?? 0} nodes ·{" "}
                  {trace?.attack_graph?.edges?.length ?? 0} edges
                </span>
              </div>
              <div className="p-4">
                {trace?.attack_graph?.nodes?.length ? (
                  <div className="attack-graph-container">
                    <div className="attack-flow flex flex-wrap gap-2 items-center">
                      {trace.attack_graph.nodes.map((node, i) => (
                        <div key={node.id} className="flex items-center gap-2">
                          <div
                            className={`attack-node p-2 rounded border border-border bg-surface-raised ${node.type === "incident" ? "border-accent" : ""}`}
                          >
                            <small className="block text-[9px] uppercase font-mono text-muted">
                              {node.type}
                            </small>
                            <strong className="text-[11.5px] font-mono">
                              {node.label}
                            </strong>
                          </div>
                          {i < trace.attack_graph.nodes.length - 1 && (
                            <ArrowRight className="w-3.5 h-3.5 text-faint" />
                          )}
                        </div>
                      ))}
                    </div>
                    {trace.attack_graph.edges.length > 0 && (
                      <div className="mt-4 pt-3 border-t border-border flex flex-wrap gap-2">
                        {trace.attack_graph.edges.map((edge) => (
                          <span
                            key={edge.id}
                            className="text-[10px] font-mono text-muted bg-surface-raised px-2 py-0.5 rounded border border-border"
                          >
                            {edge.source} → {edge.target} ({edge.label})
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <EmptyState
                    title="No attack graph"
                    description="Attack graph nodes not available."
                  />
                )}
              </div>
            </article>
          )}

          {/* Tab 3: Response Agent & Containment */}
          {activeCenterTab === "response" && (
            <div className="dashboard-grid">
              {/* Proposal & Policy Decision */}
              <article className="panel">
                <div className="panel-header">
                  <h2>AI Response Agent &amp; Policy Engine</h2>
                  <button
                    className="secondary-button text-[11px] py-1"
                    onClick={runResponseAgent}
                    disabled={planning}
                  >
                    <RotateCw className="w-3 h-3 mr-1" /> Re-evaluate Proposal
                  </button>
                </div>

                <div className="p-4 space-y-4">
                  {proposal ? (
                    <>
                      <div className="p-3 bg-surface-raised border border-border rounded space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border text-muted">
                              RECOMMENDED ACTION
                            </span>
                            <strong className="font-mono text-[13px] text-text">
                              {titleCase(proposal.recommended_action)}
                            </strong>
                          </div>
                          <span
                            className={`text-[10.5px] font-mono px-2 py-0.5 rounded ${
                              proposal.policy_evaluation?.auto_execute
                                ? "bg-success-bg text-success border border-success-border"
                                : "bg-sev-high-bg text-sev-high border border-sev-high-border"
                            }`}
                          >
                            {proposal.policy_evaluation?.auto_execute
                              ? "AUTO-RESPONSE ALLOWED"
                              : "HUMAN APPROVAL REQUIRED"}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-[11.5px] font-mono pt-2 border-t border-border">
                          <div>
                            <span className="text-muted block text-[10.5px]">
                              Classification:
                            </span>
                            <span>{proposal.classification}</span>
                          </div>
                          <div>
                            <span className="text-muted block text-[10.5px]">
                              Target Entity:
                            </span>
                            <span className="font-semibold text-accent">
                              {proposal.target}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted block text-[10.5px]">
                              Confidence:
                            </span>
                            <span>
                              {Math.round(proposal.confidence * 100)}%
                            </span>
                          </div>
                          <div>
                            <span className="text-muted block text-[10.5px]">
                              Playbook ID:
                            </span>
                            <span>{proposal.playbook_id}</span>
                          </div>
                        </div>

                        <div className="pt-2 border-t border-border">
                          <span className="text-[10.5px] text-muted uppercase font-mono block mb-1">
                            Policy Engine Decision
                          </span>
                          <p className="text-[11.5px] text-text">
                            {proposal.policy_evaluation?.reason}
                          </p>
                        </div>
                      </div>

                      {/* Dry Run Preview Box */}
                      {proposal.dry_run_preview && (
                        <div className="p-3 bg-surface rounded border border-border space-y-2 text-[11.5px]">
                          <div className="flex items-center gap-1.5 text-accent font-semibold font-mono text-[11px]">
                            <Sliders className="w-3.5 h-3.5" /> DRY RUN IMPACT
                            PREVIEW
                          </div>
                          <div className="space-y-1 font-mono text-[11px]">
                            <div>
                              <strong className="text-muted">
                                Expected Effect:{" "}
                              </strong>
                              <span>
                                {proposal.dry_run_preview.expected_effect}
                              </span>
                            </div>
                            <div>
                              <strong className="text-muted">
                                Potential Impact:{" "}
                              </strong>
                              <span>
                                {proposal.dry_run_preview.potential_impact}
                              </span>
                            </div>
                            <div>
                              <strong className="text-muted">
                                Rollback Method:{" "}
                              </strong>
                              <span>
                                {proposal.dry_run_preview.rollback_method}
                              </span>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Actions Buttons */}
                      <div className="flex items-center gap-2 pt-2">
                        <button
                          className="secondary-button text-[11.5px]"
                          onClick={() => handleExecuteResponse(true)}
                          disabled={executingAction}
                        >
                          <FileText className="w-3.5 h-3.5 mr-1" /> Dry Run
                          (Safe Preview)
                        </button>

                        <button
                          className="primary-button text-[11.5px] font-medium"
                          onClick={() => handleExecuteResponse(false)}
                          disabled={executingAction}
                        >
                          <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                          {executingAction
                            ? "Executing..."
                            : proposal.requires_approval
                              ? "Approve & Execute (Demo Mode)"
                              : "Execute Response Action"}
                        </button>
                      </div>
                    </>
                  ) : (
                    <div className="text-center py-6 space-y-2">
                      <p className="text-muted text-[12px]">
                        No active response proposal formulated for this incident
                        yet.
                      </p>
                      <button
                        className="secondary-button text-[12px]"
                        onClick={runResponseAgent}
                        disabled={planning}
                      >
                        <Play className="w-3.5 h-3.5 mr-1" /> Generate AI
                        Response Proposal
                      </button>
                    </div>
                  )}
                </div>
              </article>

              {/* Execution History for this Incident */}
              <article className="panel">
                <div className="panel-header">
                  <h2>Defensive Action History</h2>
                  <Link
                    href="/response"
                    className="text-[11px] font-mono text-muted hover:text-text underline"
                  >
                    All Executions →
                  </Link>
                </div>
                <div className="p-4">
                  {executions.length === 0 ? (
                    <EmptyState
                      title="No executions recorded"
                      description="Click Dry Run or Execute Response Action to trigger containment."
                    />
                  ) : (
                    <div className="space-y-3">
                      {executions.map((exec) => (
                        <div
                          key={exec.execution_id}
                          className="p-3 rounded bg-surface-raised border border-border space-y-1.5"
                        >
                          <div className="flex items-center justify-between text-[11px] font-mono">
                            <span className="font-semibold text-accent">
                              {exec.execution_id}
                            </span>
                            <span
                              className={`px-1.5 py-0.2 rounded ${
                                exec.status === "verified"
                                  ? "bg-success-bg text-success border border-success-border"
                                  : "bg-accent-soft text-accent"
                              }`}
                            >
                              {exec.dry_run
                                ? "DRY RUN"
                                : exec.status.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-[11.5px] font-mono">
                            <strong>{titleCase(exec.action)}</strong> on target{" "}
                            <span className="font-semibold">{exec.target}</span>
                          </div>
                          {exec.verification_result && (
                            <div className="text-[11px] text-muted flex items-center gap-1">
                              <Check className="w-3 h-3 text-success" />
                              <span>{exec.verification_result.details}</span>
                            </div>
                          )}
                          <div className="text-[10px] text-faint font-mono">
                            Initiated: {formatDate(exec.started_at)} by{" "}
                            {exec.requested_by}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </article>
            </div>
          )}

          {/* Tab 4: Correlated Alerts */}
          {activeCenterTab === "alerts" && (
            <article className="panel">
              <div className="panel-header">
                <h2>Correlated Alerts ({detail.alerts.length})</h2>
              </div>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Alert Type</th>
                      <th>Source → Target</th>
                      <th>Rule / MITRE</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.alerts.map((alert) => (
                      <tr key={alert.id}>
                        <td>
                          <SeverityBadge value={alert.severity} />
                        </td>
                        <td>{titleCase(alert.alert_type)}</td>
                        <td className="font-mono text-[11px]">
                          {alert.source_ip ?? "Unknown"} →{" "}
                          {alert.target_host ?? "Unknown"}
                        </td>
                        <td className="font-mono text-[11px] text-muted">
                          {alert.mitre_technique ?? "-"}
                        </td>
                        <td className="font-mono text-[10.5px] text-muted">
                          {formatDate(alert.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>
          )}

          {/* Tab 5: MITRE ATT&CK */}
          {activeCenterTab === "mitre" && (
            <article className="panel">
              <div className="panel-header">
                <h2>MITRE ATT&amp;CK Mapping</h2>
                <span className="text-[10px] font-mono text-faint">
                  {mitre?.techniques?.length ?? 0} mapped
                </span>
              </div>
              <div className="p-4 space-y-2.5">
                {mitre?.techniques && mitre.techniques.length > 0 ? (
                  mitre.techniques.map((tech) => (
                    <div
                      key={tech.id}
                      className="p-3 rounded bg-surface-raised border border-border space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-muted text-[11px] font-medium">
                            {tech.id}
                          </span>
                          <strong className="text-[12px] font-medium">
                            {tech.name}
                          </strong>
                        </div>
                        <span className="text-[10px] font-mono uppercase text-faint">
                          {tech.tactic}
                        </span>
                      </div>
                      <p className="text-[11.5px] text-muted line-clamp-2">
                        {tech.description}
                      </p>
                      {tech.url && (
                        <a
                          href={tech.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-[10px] font-mono text-faint hover:underline pt-0.5"
                        >
                          Reference <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                    </div>
                  ))
                ) : (
                  <EmptyState
                    title="No techniques"
                    description="No MITRE ATT&CK techniques mapped for this incident."
                  />
                )}
              </div>
            </article>
          )}
        </>
      ) : (
        <EmptyState
          title="Incident not found"
          description="The requested incident could not be found."
        />
      )}
    </ThreatLensShell>
  );
}
