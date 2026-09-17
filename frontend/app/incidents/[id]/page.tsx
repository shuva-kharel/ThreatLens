'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import {
  Download,
  ArrowRight,
  RotateCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import {
  api,
  downloadUrl,
  type AIAnalysis,
  type IncidentDetail,
  type IncidentStatus,
  type MitreMapping,
  type TraceAIResult,
} from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { durationMinutes, entityList, formatDate, titleCase } from '@/components/threatlens/format'

export default function IncidentInvestigationPage() {
  const params = useParams()
  const id = typeof params?.id === 'string' ? params.id : Array.isArray(params?.id) ? params.id[0] : ''

  const [detail, setDetail] = useState<IncidentDetail | null>(null)
  const [trace, setTrace] = useState<TraceAIResult | null>(null)
  const [mitre, setMitre] = useState<MitreMapping | null>(null)
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [analysisError, setAnalysisError] = useState<string | null>(null)
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [responseActionSuccess, setResponseActionSuccess] = useState<string | null>(null)
  const [showAiDrawer, setShowAiDrawer] = useState(false)

  const loadData = () => {
    if (!id) return
    setLoading(true)
    setError(null)
    Promise.all([api.incident(id), api.incidentTrace(id), api.incidentMitre(id)])
      .then(([incidentDetail, traceData, mitreData]) => {
        setDetail(incidentDetail)
        setTrace(traceData)
        setMitre(mitreData)
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Unable to load incident.')
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [id])

  const runAnalysis = () => {
    if (!id) return
    setAnalyzing(true)
    setAnalysisError(null)
    setShowAiDrawer(true)
    api.analyzeIncident(id)
      .then((result) => {
        setAnalysis(result.analysis)
      })
      .catch((err) => {
        setAnalysisError(err instanceof Error ? err.message : 'AI investigation failed.')
      })
      .finally(() => setAnalyzing(false))
  }

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!detail) return
    setStatusUpdating(true)
    try {
      const updated = await api.updateIncidentStatus(id, newStatus)
      setDetail({ ...detail, incident: { ...detail.incident, status: updated.status } })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update status.')
    } finally {
      setStatusUpdating(false)
    }
  }

  const handleResponseAction = async (action: string) => {
    if (!detail) return
    setResponseActionSuccess(null)
    try {
      const res = await api.recordResponse(id, action, { source: 'Analyst' })
      setDetail({ ...detail, incident: { ...detail.incident, status: res.incident_status } })
      setResponseActionSuccess(`Action [${action}] recorded. Status: ${res.incident_status}.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to execute ${action}.`)
    }
  }

  const incident = detail?.incident

  return (
    <ThreatLensShell>
      {loading ? (
        <LoadingState label="Loading incident context..." />
      ) : error ? (
        <ErrorState error={error} retry={loadData} />
      ) : incident ? (
        <>
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
                  onChange={(e) => handleStatusChange(e.target.value as IncidentStatus)}
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
                onClick={() => downloadUrl(`/api/v1/incidents/export/${id}/export/json`)}
              >
                <Download /> JSON
              </button>
              <button
                className="secondary-button"
                onClick={() => downloadUrl(`/api/v1/incidents/export/${id}/export/csv`)}
              >
                <Download /> CSV
              </button>
              <button
                className="secondary-button"
                onClick={() => {
                  if (!analysis) {
                    runAnalysis()
                  } else {
                    setShowAiDrawer((v) => !v)
                  }
                }}
                disabled={analyzing}
              >
                {analyzing ? 'Analyzing...' : showAiDrawer ? 'Hide AI Guidance' : 'AI Guidance'}
              </button>
            </div>
          </section>

          {responseActionSuccess && (
            <div className="p-2.5 rounded bg-surface-raised border border-border text-[11.5px] font-mono mb-4 text-text">
              {responseActionSuccess}
            </div>
          )}

          {/* Clean Metric Cards */}
          <section className="metric-grid">
            <article className="metric-card-clean">
              <strong>{entityList(incident.source_entities)}</strong>
              <span>Attacking Source</span>
              <small>External source IP</small>
            </article>

            <article className="metric-card-clean">
              <strong>{entityList(incident.target_entities)}</strong>
              <span>Target Asset</span>
              <small>Host system</small>
            </article>

            <article className="metric-card-clean">
              <strong>{formatDate(incident.first_seen)}</strong>
              <span>First Observed</span>
              <small>Initial telemetry</small>
            </article>

            <article className="metric-card-clean">
              <strong>{formatDate(incident.last_seen)}</strong>
              <span>Last Observed</span>
              <small>Duration: {trace?.duration_minutes ?? durationMinutes(incident.first_seen, incident.last_seen)}</small>
            </article>
          </section>

          {/* Collapsible/Discreet AI Guidance Panel */}
          {showAiDrawer && (
            <article className="panel ai-grounded-panel">
              <div className="ai-header">
                <div>
                  <h2 className="text-[12.5px]">AI Investigation Guidance (Evidence-Grounded)</h2>
                  <p className="text-[11px] text-muted">
                    Deterministic detection remains the source of truth. AI assists with evidence interpretation.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button className="secondary-button" onClick={runAnalysis} disabled={analyzing}>
                    {analyzing ? 'Refreshing...' : 'Re-run analysis'}
                  </button>
                  <button className="secondary-button" onClick={() => setShowAiDrawer(false)}>
                    Close
                  </button>
                </div>
              </div>

              {analysisError && (
                <div className="p-2.5 bg-surface-raised border-b border-border text-sev-critical text-[11px] font-mono">
                  {analysisError}
                </div>
              )}

              {analysis ? (
                <div className="ai-content">
                  <div className="ai-section">
                    <span className="ai-section-title">Observed Evidence</span>
                    <div className="ai-item-list">
                      {(analysis.observed_evidence || analysis.evidence_list || []).map((ev, i) => (
                        <div key={i} className="ai-item">
                          • {ev}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="ai-section">
                    <span className="ai-section-title">Assessment</span>
                    <div className="ai-item-list">
                      <div className="ai-item font-medium text-text bg-surface">
                        {analysis.attack_explanation || analysis.summary}
                      </div>
                      {(analysis.inferences || analysis.attack_progression || []).map((prog, i) => (
                        <div key={i} className="ai-item">
                          → {prog}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="ai-section">
                    <span className="ai-section-title">Recommended Steps</span>
                    <div className="ai-item-list">
                      {(analysis.investigation_steps || []).map((step, i) => (
                        <div key={i} className="ai-item">
                          {i + 1}. {step}
                        </div>
                      ))}
                      {(analysis.containment_steps || []).map((step, i) => (
                        <div key={i} className="ai-item text-sev-high">
                          [Containment] {step}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="quiet-empty">Generating evidence-backed guidance...</div>
              )}
            </article>
          )}

          {/* 1. Attack Narrative & Containment Actions */}
          <div className="dashboard-grid">
            <article className="panel">
              <div className="panel-header">
                <h2>Attack Narrative</h2>
              </div>
              <div className="p-4 space-y-3">
                <p className="text-[12px] text-text leading-relaxed">
                  {incident.ai_summary ||
                    `ThreatLens correlated an attack sequence from ${entityList(
                      incident.source_entities
                    )} against ${entityList(
                      incident.target_entities
                    )}. The adversary progressed through reconnaissance, authentication brute forcing, initial access, and subsequent execution.`}
                </p>

                {trace?.stages && trace.stages.length > 0 && (
                  <div className="pt-2 border-t border-border">
                    <span className="text-[10px] text-muted uppercase block mb-1.5 font-medium">
                      Progression Stages
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {trace.stages.map((st) => (
                        <div
                          key={st.stage}
                          className="px-2 py-0.5 rounded bg-surface-raised border border-border text-[10.5px] font-mono flex items-center gap-1.5"
                        >
                          <span className="text-muted font-medium">#{st.order}</span>
                          <span>{st.stage}</span>
                          <span className="text-faint">({st.event_count})</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </article>

            {/* Response Actions */}
            <article className="panel">
              <div className="panel-header">
                <h2>Containment Actions</h2>
              </div>
              <div className="p-4 space-y-2">
                <button
                  className="secondary-button justify-between py-1.5 w-full text-[11.5px]"
                  onClick={() => handleResponseAction('block_ip')}
                >
                  <span>Block source IP ({entityList(incident.source_entities)})</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
                <button
                  className="secondary-button justify-between py-1.5 w-full text-[11.5px]"
                  onClick={() => handleResponseAction('isolate_host')}
                >
                  <span>Isolate host ({entityList(incident.target_entities)})</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
                <button
                  className="secondary-button justify-between py-1.5 w-full text-[11.5px]"
                  onClick={() => handleResponseAction('disable_account')}
                >
                  <span>Disable account</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </article>
          </div>

          {/* 2. Attack Graph */}
          <article className="panel">
            <div className="panel-header">
              <h2>Attack Graph</h2>
              <span className="text-[10px] font-mono text-faint">
                {trace?.attack_graph?.nodes?.length ?? 0} nodes · {trace?.attack_graph?.edges?.length ?? 0} edges
              </span>
            </div>
            <div className="p-4">
              {trace?.attack_graph?.nodes?.length ? (
                <div className="attack-graph-container">
                  <div className="attack-flow">
                    {trace.attack_graph.nodes.map((node, i) => (
                      <div key={node.id} className="flex items-center gap-2">
                        <div className={`attack-node ${node.type === 'incident' ? 'highlighted' : ''}`}>
                          <small>{node.type}</small>
                          <strong>{node.label}</strong>
                        </div>
                        {i < trace.attack_graph.nodes.length - 1 && (
                          <div className="attack-edge">
                            <ArrowRight className="w-3.5 h-3.5" />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                  {trace.attack_graph.edges.length > 0 && (
                    <div className="mt-2.5 pt-2 border-t border-border flex flex-wrap gap-2">
                      {trace.attack_graph.edges.map((edge) => (
                        <span
                          key={edge.id}
                          className="text-[10px] font-mono text-muted bg-surface px-2 py-0.5 rounded border border-border"
                        >
                          {edge.source} → {edge.target} ({edge.label})
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState>No attack graph available for this incident.</EmptyState>
              )}
            </div>
          </article>

          {/* 3. Attack Timeline */}
          <article className="panel">
            <div className="panel-header">
              <h2>Chronological Attack Timeline</h2>
              <span className="text-[10.5px] font-mono text-faint">{trace?.timeline?.length ?? 0} entries</span>
            </div>
            <div className="p-4">
              {trace?.timeline && trace.timeline.length > 0 ? (
                <div className="timeline-stream">
                  {trace.timeline.map((item, idx) => (
                    <div key={`${item.type}-${item.id}-${idx}`} className="timeline-entry">
                      <div className="timeline-bullet" />
                      <div className="timeline-content">
                        <div className="timeline-meta">
                          <span className="text-text">{formatDate(item.timestamp)}</span>
                          <span>•</span>
                          <span className="text-muted font-medium">{item.stage}</span>
                          <span>•</span>
                          <SeverityBadge value={item.severity} />
                          {item.mitre_technique && (
                            <span className="px-1.5 py-0.2 rounded bg-surface-raised border border-border text-[9.5px]">
                              {item.mitre_technique}
                            </span>
                          )}
                        </div>
                        <div className="timeline-title">{item.description}</div>
                        <div className="timeline-desc font-mono text-[10.5px]">
                          {item.type.toUpperCase()}: {item.source_ip ?? 'Unknown'} →{' '}
                          {item.target_host ?? 'Unknown'} {item.username ? `(User: ${item.username})` : ''}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState>No timeline events returned for this incident.</EmptyState>
              )}
            </div>
          </article>

          {/* 4. Associated Alerts & MITRE Techniques */}
          <div className="dashboard-grid">
            <article className="panel">
              <div className="panel-header">
                <h2>Correlated Alerts ({detail.alerts.length})</h2>
              </div>
              <div className="soc-table-wrap">
                <table className="soc-table">
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
                          {alert.source_ip ?? 'Unknown'} → {alert.target_host ?? 'Unknown'}
                        </td>
                        <td className="font-mono text-[11px] text-muted">
                          {alert.mitre_technique ?? '-'}
                        </td>
                        <td className="font-mono text-[10.5px] text-muted">{formatDate(alert.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>

            {/* MITRE ATT&CK Mapping */}
            <article className="panel">
              <div className="panel-header">
                <h2>MITRE ATT&amp;CK Mapping</h2>
                <span className="text-[10px] font-mono text-faint">{mitre?.techniques?.length ?? 0} mapped</span>
              </div>
              <div className="p-4 space-y-2.5">
                {mitre?.techniques && mitre.techniques.length > 0 ? (
                  mitre.techniques.map((tech) => (
                    <div key={tech.id} className="p-2 rounded bg-surface-raised border border-border space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-muted text-[11px] font-medium">{tech.id}</span>
                          <strong className="text-[11.5px] font-medium">{tech.name}</strong>
                        </div>
                        <span className="text-[10px] font-mono uppercase text-faint">
                          {tech.tactic}
                        </span>
                      </div>
                      <p className="text-[11px] text-muted line-clamp-2">{tech.description}</p>
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
                  <EmptyState>No MITRE techniques mapped for this incident.</EmptyState>
                )}
              </div>
            </article>
          </div>
        </>
      ) : (
        <EmptyState>Incident not found.</EmptyState>
      )}
    </ThreatLensShell>
  )
}
