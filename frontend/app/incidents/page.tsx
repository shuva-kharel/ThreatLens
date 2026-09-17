'use client'

import Link from 'next/link'
import { useEffect, useMemo, useState } from 'react'
import { Download, RefreshCw, ArrowUpRight } from 'lucide-react'
import { api, downloadUrl, type Incident, type IncidentStatus, type Severity } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { entityList, formatDate, titleCase } from '@/components/threatlens/format'

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')

  const fetchIncidents = () => {
    const params = new URLSearchParams()
    if (q) params.set('q', q)
    if (severity) params.set('severity', severity)
    if (status) params.set('status', status)
    setLoading(true)
    setError(null)
    const request = q || severity ? api.searchIncidents(params) : api.incidents(status ? new URLSearchParams({ status }) : undefined)
    request
      .then(setIncidents)
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load incidents.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchIncidents()
  }, [q, severity, status])

  const counts = useMemo(
    () =>
      incidents.reduce<Record<string, number>>(
        (acc, item) => ({ ...acc, [item.status]: (acc[item.status] ?? 0) + 1 }),
        {}
      ),
    [incidents]
  )

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Incidents Queue</h1>
        </div>
        <div className="heading-actions">
          <button
            className="secondary-button"
            onClick={() => downloadUrl('/api/v1/incidents/export/export/all?format=csv')}
          >
            <Download className="w-3.5 h-3.5 mr-1" /> Export CSV
          </button>
          <button className="secondary-button" onClick={fetchIncidents}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      {/* Metrics Row - Clean KPI cards */}
      <section className="metric-grid">
        <article className="metric-card-clean">
          <strong>{incidents.length}</strong>
          <span>Total Incidents</span>
          <small>Current query</small>
        </article>

        <article className="metric-card-clean">
          <strong>{counts.open ?? 0}</strong>
          <span>Open</span>
          <small>Needs triage</small>
        </article>

        <article className="metric-card-clean">
          <strong>{counts.investigating ?? 0}</strong>
          <span>Investigating</span>
          <small>Active response</small>
        </article>

        <article className="metric-card-clean">
          <strong>{counts.contained ?? 0}</strong>
          <span>Contained</span>
          <small>Mitigation recorded</small>
        </article>
      </section>

      {/* Incidents Table Panel */}
      <section className="panel">
        <div className="panel-header">
          <h2>Incident Inventory</h2>
          <div className="toolbar">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search title, ID, or entity..."
            />
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All Severities</option>
              {(['critical', 'high', 'medium', 'low'] satisfies Severity[]).map((item) => (
                <option key={item} value={item}>
                  {titleCase(item)}
                </option>
              ))}
            </select>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">All Statuses</option>
              {(['open', 'investigating', 'contained', 'resolved', 'false_positive'] satisfies IncidentStatus[]).map(
                (item) => (
                  <option key={item} value={item}>
                    {titleCase(item)}
                  </option>
                )
              )}
            </select>
          </div>
        </div>

        {error ? (
          <ErrorState error={error} retry={fetchIncidents} />
        ) : loading ? (
          <LoadingState label="Loading incidents..." />
        ) : incidents.length ? (
          <div className="soc-table-wrap">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Incident Title &amp; ID</th>
                  <th>Source Entity</th>
                  <th>Target Host</th>
                  <th>MITRE Techniques</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((incident) => (
                  <tr key={incident.id}>
                    <td>
                      <SeverityBadge value={incident.severity} />
                    </td>
                    <td>
                      <Link href={`/incidents/${incident.id}`} className="hover:underline block text-text">
                        {incident.title}
                      </Link>
                      <span className="font-mono text-[10px] text-faint">{incident.id}</span>
                    </td>
                    <td className="font-mono text-[11px]">{entityList(incident.source_entities)}</td>
                    <td className="font-mono text-[11px]">{entityList(incident.target_entities)}</td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {incident.mitre_techniques?.length ? (
                          incident.mitre_techniques.map((t) => (
                            <span
                              key={t}
                              className="font-mono text-[9.5px] px-1.5 py-0.5 rounded bg-surface-raised border border-border text-muted"
                            >
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-[10px] text-faint">-</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="font-mono text-[10.5px] text-muted">
                        {titleCase(incident.status)}
                      </span>
                    </td>
                    <td className="font-mono text-[10.5px] text-muted">{formatDate(incident.last_seen)}</td>
                    <td className="text-right">
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="secondary-button text-[10.5px] py-1 px-2 inline-flex"
                      >
                        Investigate <ArrowUpRight className="w-3 h-3 ml-0.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState>No incidents found matching current filters.</EmptyState>
        )}
      </section>
    </ThreatLensShell>
  )
}
