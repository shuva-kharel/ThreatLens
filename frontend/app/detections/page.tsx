'use client'

import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import {
  api,
  type DetectionCoverage,
  type DetectionRule,
  type DetectionStats,
  type DetectionTimeline,
} from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

export default function DetectionsPage() {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [stats, setStats] = useState<DetectionStats | null>(null)
  const [timeline, setTimeline] = useState<DetectionTimeline | null>(null)
  const [coverage, setCoverage] = useState<DetectionCoverage | null>(null)
  const [selected, setSelected] = useState<DetectionRule | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadData = () => {
    setLoading(true)
    setError(null)
    Promise.all([api.detectionRules(), api.detectionStats(), api.detectionTimeline(), api.detectionCoverage()])
      .then(([r, s, t, c]) => {
        setRules(r.rules)
        setStats(s)
        setTimeline(t)
        setCoverage(c)
        setSelected(s.rules[0] ?? r.rules[0] ?? null)
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load detection rules.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Detection Rules</h1>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={loadData}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      {error ? (
        <ErrorState error={error} retry={loadData} />
      ) : loading ? (
        <LoadingState label="Loading detection rules..." />
      ) : (
        <>
          {/* Top KPI row - clean cards */}
          <section className="metric-grid">
            <article className="metric-card-clean">
              <strong>{stats?.total_rules ?? rules.length}</strong>
              <span>Active Rules</span>
              <small>Rule registry</small>
            </article>

            <article className="metric-card-clean">
              <strong>{stats?.total_alerts_generated ?? 0}</strong>
              <span>Alerts Generated</span>
              <small>Rule executions</small>
            </article>

            <article className="metric-card-clean">
              <strong>{coverage?.total_techniques_covered ?? 0}</strong>
              <span>MITRE Coverage</span>
              <small>Observed techniques</small>
            </article>

            <article className="metric-card-clean">
              <strong>{timeline?.timeline.filter((p) => p.count > 0).length ?? 0}</strong>
              <span>Active Hourly Windows</span>
              <small>Last 24 hours</small>
            </article>
          </section>

          {/* Rules Table & Rule Detail View */}
          <div className="dashboard-grid">
            <section className="panel">
              <div className="panel-header">
                <h2>Rules</h2>
              </div>
              <div className="soc-table-wrap">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Rule ID</th>
                      <th>Rule Name</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>MITRE</th>
                      <th>Triggers</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((rule) => (
                      <tr
                        key={rule.id}
                        onClick={() => setSelected(rule)}
                        className={`cursor-pointer transition-colors ${
                          selected?.id === rule.id ? 'bg-surface-raised font-medium' : ''
                        }`}
                      >
                        <td className="font-mono text-[11px] text-text">{rule.id}</td>
                        <td>
                          <span className="text-text text-[11.5px] block">{rule.name}</span>
                          <span className="text-[10px] text-muted line-clamp-1">{rule.description}</span>
                        </td>
                        <td className="font-mono text-[10.5px] text-muted">{rule.category ?? 'General'}</td>
                        <td>
                          <SeverityBadge value={rule.severity} />
                        </td>
                        <td className="font-mono text-[10.5px] text-muted">
                          {rule.mitre_technique ? `${rule.mitre_technique}` : '-'}
                        </td>
                        <td className="font-mono text-[11px] text-text">
                          {rule.trigger_count ?? 0}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            {/* Rule Detail Card */}
            <section className="panel">
              <div className="panel-header">
                <h2>Rule Specification</h2>
                {selected && <SeverityBadge value={selected.severity} />}
              </div>

              {selected ? (
                <div className="p-4 space-y-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-[10.5px] text-muted">{selected.id}</span>
                      <span className="text-[10px] font-mono text-faint px-1.5 py-0.5 rounded bg-surface-raised border border-border">
                        {selected.category ?? 'Network'}
                      </span>
                    </div>
                    <strong className="text-[13px] block text-text">{selected.name}</strong>
                    <p className="text-[11.5px] text-muted mt-1 leading-relaxed">{selected.description}</p>
                  </div>

                  <div className="pt-2 border-t border-border prop-list">
                    <div className="prop-row">
                      <span>Threshold / Logic:</span>
                      <strong className="font-mono text-[11px] text-text">
                        {selected.threshold ? String(selected.threshold) : 'Configured pattern'}
                      </strong>
                    </div>
                    <div className="prop-row">
                      <span>Evaluation Window:</span>
                      <strong className="font-mono text-[11px]">
                        {selected.window_seconds ? `${selected.window_seconds}s` : 'Continuous'}
                      </strong>
                    </div>
                    <div className="prop-row">
                      <span>MITRE Technique:</span>
                      <strong className="font-mono text-[11px]">
                        {selected.mitre_technique ? `${selected.mitre_technique} (${selected.mitre_name ?? ''})` : 'None'}
                      </strong>
                    </div>
                    <div className="prop-row">
                      <span>Total Fired:</span>
                      <strong className="font-mono text-[11px]">{selected.trigger_count ?? 0} alerts</strong>
                    </div>
                    <div className="prop-row">
                      <span>Last Triggered:</span>
                      <strong className="font-mono text-[11px]">{formatDate(selected.last_triggered)}</strong>
                    </div>
                  </div>

                  {selected.false_positives && (
                    <div className="p-2.5 rounded bg-surface-raised border border-border">
                      <span className="text-[10px] text-faint block mb-1">
                        False Positive Considerations
                      </span>
                      <p className="text-[11px] text-muted leading-relaxed">{selected.false_positives}</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="quiet-empty">Select a detection rule to view details.</div>
              )}
            </section>
          </div>

          {/* Active Technique Coverage */}
          <section className="panel">
            <div className="panel-header">
              <h2>Observed MITRE ATT&amp;CK Coverage</h2>
            </div>
            <div className="p-4">
              {coverage?.techniques?.length ? (
                <div className="grid grid-cols-4 gap-2.5">
                  {coverage.techniques.map((t) => (
                    <div key={t.id} className="p-2 rounded bg-surface-raised border border-border">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[11.5px] text-text">{t.id}</span>
                        <span className="text-[10px] font-mono text-muted">{t.alert_count} alert(s)</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState>No MITRE techniques triggered in telemetry yet.</EmptyState>
              )}
            </div>
          </section>
        </>
      )}
    </ThreatLensShell>
  )
}
