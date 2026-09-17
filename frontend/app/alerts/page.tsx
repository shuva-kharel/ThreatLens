'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { RefreshCw, ArrowUpRight } from 'lucide-react'
import { api, type Alert, type Severity } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [severity, setSeverity] = useState('')
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)

  const fetchAlerts = () => {
    const params = new URLSearchParams({ limit: '100' })
    if (severity) params.set('severity', severity)
    if (q) params.set('q', q)
    setLoading(true)
    setError(null)
    api.alerts(params)
      .then((data) => {
        setAlerts(data)
        if (data.length > 0 && !selectedAlert) {
          setSelectedAlert(data[0])
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load alerts.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchAlerts()
  }, [severity, q])

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Alerts Queue</h1>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={fetchAlerts}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Active Alerts</h2>
            <div className="toolbar">
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search alerts, rules, or IPs..."
              />
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">All Severities</option>
                {(['critical', 'high', 'medium', 'low'] satisfies Severity[]).map((item) => (
                  <option key={item} value={item}>
                    {titleCase(item)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {error ? (
            <ErrorState error={error} retry={fetchAlerts} />
          ) : loading ? (
            <LoadingState label="Loading alerts..." />
          ) : alerts.length ? (
            <div className="soc-table-wrap">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Alert Type</th>
                    <th>Source → Target</th>
                    <th>MITRE</th>
                    <th>Incident</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => setSelectedAlert(alert)}
                      className={`cursor-pointer transition-colors ${
                        selectedAlert?.id === alert.id ? 'bg-surface-raised font-medium' : ''
                      }`}
                    >
                      <td>
                        <SeverityBadge value={alert.severity} />
                      </td>
                      <td>
                        <span className="block text-text text-[11.5px]">{titleCase(alert.alert_type)}</span>
                        <span className="text-[10px] text-muted line-clamp-1">{alert.description}</span>
                      </td>
                      <td className="font-mono text-[11px]">
                        {alert.source_ip ?? 'Unknown'} → {alert.target_host ?? 'Unknown'}
                      </td>
                      <td>
                        {alert.mitre_technique ? (
                          <span className="font-mono text-[9.5px] text-muted bg-surface-raised px-1.5 py-0.5 rounded border border-border">
                            {alert.mitre_technique}
                          </span>
                        ) : (
                          <span className="text-[10px] text-faint">-</span>
                        )}
                      </td>
                      <td>
                        {alert.incident_id ? (
                          <Link
                            href={`/incidents/${alert.incident_id}`}
                            className="font-mono text-[10px] text-muted hover:underline flex items-center gap-0.5"
                            onClick={(e) => e.stopPropagation()}
                          >
                            Linked <ArrowUpRight className="w-2.5 h-2.5" />
                          </Link>
                        ) : (
                          <span className="font-mono text-[10px] text-faint">-</span>
                        )}
                      </td>
                      <td className="font-mono text-[10px] text-muted">{formatDate(alert.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>No alerts found matching current filters.</EmptyState>
          )}
        </section>

        {/* Detail Inspector */}
        <section className="panel">
          <div className="panel-header">
            <h2>Alert Details</h2>
            {selectedAlert && <SeverityBadge value={selectedAlert.severity} />}
          </div>

          {selectedAlert ? (
            <div className="p-4 space-y-4">
              <div>
                <strong className="text-[13px] block text-text">{titleCase(selectedAlert.alert_type)}</strong>
                <p className="text-[11.5px] text-muted mt-1 leading-relaxed">{selectedAlert.description}</p>
              </div>

              <div className="pt-2 border-t border-border prop-list">
                <div className="prop-row">
                  <span>Alert ID:</span>
                  <strong className="font-mono text-[11px] text-faint">{selectedAlert.id}</strong>
                </div>
                <div className="prop-row">
                  <span>Source IP:</span>
                  <strong className="font-mono text-[11px] text-text">
                    {selectedAlert.source_ip ?? 'Unknown'}
                  </strong>
                </div>
                <div className="prop-row">
                  <span>Target Endpoint:</span>
                  <strong className="font-mono text-[11px] text-text">
                    {selectedAlert.target_host ?? 'Unknown'}
                  </strong>
                </div>
                <div className="prop-row">
                  <span>Confidence:</span>
                  <strong className="font-mono text-[11px]">{Math.round(selectedAlert.confidence * 100)}%</strong>
                </div>
                <div className="prop-row">
                  <span>MITRE Technique:</span>
                  <strong className="font-mono text-[11px]">
                    {selectedAlert.mitre_technique ?? 'None'}
                  </strong>
                </div>
                <div className="prop-row">
                  <span>Timestamp:</span>
                  <strong className="font-mono text-[11px]">{formatDate(selectedAlert.created_at)}</strong>
                </div>
              </div>

              {selectedAlert.evidence && selectedAlert.evidence.length > 0 && (
                <div className="pt-2 border-t border-border">
                  <span className="text-[10px] text-muted uppercase block mb-1 font-medium">
                    Evidence
                  </span>
                  <div className="space-y-1">
                    {selectedAlert.evidence.map((ev, i) => (
                      <div
                        key={i}
                        className="p-1.5 rounded bg-surface-raised border border-border font-mono text-[10.5px] text-text"
                      >
                        {ev}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="pt-2 border-t border-border">
                {selectedAlert.incident_id ? (
                  <div className="p-2.5 rounded bg-surface-raised border border-border flex items-center justify-between">
                    <div>
                      <span className="text-[10px] text-faint uppercase block">
                        Linked Incident
                      </span>
                      <span className="font-mono text-[10.5px] text-muted">{selectedAlert.incident_id}</span>
                    </div>
                    <Link className="secondary-button text-[10.5px] py-1" href={`/incidents/${selectedAlert.incident_id}`}>
                      View Incident <ArrowUpRight className="w-3 h-3 ml-0.5" />
                    </Link>
                  </div>
                ) : (
                  <div className="text-[11px] text-faint">
                    Alert unlinked to any incident.
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="quiet-empty">Select an alert to view details.</div>
          )}
        </section>
      </div>
    </ThreatLensShell>
  )
}
