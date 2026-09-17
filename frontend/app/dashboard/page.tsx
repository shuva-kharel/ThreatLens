'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { Download, RefreshCw, Play } from 'lucide-react'
import { downloadUrl, loadDashboardData, type Alert, type DashboardData, type Incident } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { entityList, formatDate, titleCase } from '@/components/threatlens/format'

export default function DashboardPage() {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const loadData = () => {
    setLoading(true)
    setError(null)
    loadDashboardData()
      .then((data) => {
        const failures = Object.values(data.errors)
        setDashboard(data)
        setError(failures.length ? failures.join(' | ') : null)
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load dashboard telemetry.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  const incidents = dashboard?.incidents ?? []
  const alerts = dashboard?.alerts ?? []
  const events = dashboard?.events ?? []
  const detectionTimeline = dashboard?.detectionsTimeline?.timeline ?? []
  const criticalAlerts = dashboard?.alertStats?.by_severity?.critical ?? 0
  const observedAssets = dashboard?.networkStats
    ? dashboard.networkStats.unique_sources + dashboard.networkStats.unique_targets
    : undefined

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Security Operations Overview</h1>
        </div>
        <div className="heading-actions">
          <Link className="secondary-button" href="/simulator">
            <Play className="w-3.5 h-3.5 mr-1" /> Run Attack Simulation
          </Link>
          <button
            className="secondary-button"
            onClick={() => downloadUrl('/api/v1/incidents/export/export/all?format=csv')}
          >
            <Download className="w-3.5 h-3.5 mr-1" /> Export CSV
          </button>
          <button className="secondary-button" onClick={loadData}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      {error && <ErrorState error={error} retry={loadData} />}

      {/* Clean KPI Cards without icons, only numbers and labels */}
      <section className="metric-grid">
        <article className="metric-card-clean">
          <strong>{loading ? '-' : String(dashboard?.overview?.total_incidents ?? incidents.length)}</strong>
          <span>Correlated Incidents</span>
          <small>{dashboard?.overview?.open_incidents ?? 0} open</small>
        </article>

        <article className="metric-card-clean">
          <strong>{loading ? '-' : String(dashboard?.alertStats?.total ?? alerts.length)}</strong>
          <span>Active Alerts</span>
          <small>{criticalAlerts} critical</small>
        </article>

        <article className="metric-card-clean">
          <strong>{loading ? '-' : String(dashboard?.networkStats?.total_events ?? events.length)}</strong>
          <span>Events Ingested</span>
          <small>Raw and normalized</small>
        </article>

        <article className="metric-card-clean">
          <strong>{loading ? '-' : String(observedAssets ?? (dashboard?.networkStats?.unique_targets ?? 1))}</strong>
          <span>Monitored Assets</span>
          <small>Hosts and endpoints</small>
        </article>
      </section>

      {/* Middle Grid: Detection Activity & Network Telemetry */}
      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Detection Activity (24h)</h2>
          </div>
          <div className="p-4">
            {detectionTimeline.length > 0 ? (
              <div className="space-y-3">
                <div className="grid grid-cols-6 gap-2">
                  {detectionTimeline.slice(-12).map((point, idx) => {
                    const maxCount = Math.max(...detectionTimeline.map((p) => p.count), 1)
                    const heightPercent = Math.max(8, Math.round((point.count / maxCount) * 100))
                    return (
                      <div key={idx} className="flex flex-col items-center gap-1.5">
                        <div className="w-full bg-surface-raised h-16 rounded relative flex items-end justify-center p-1 border border-border">
                          <div
                            className="w-full bg-border-strong rounded-sm"
                            style={{ height: `${heightPercent}%` }}
                          />
                        </div>
                        <span className="text-[9px] font-mono text-muted">
                          {point.hour.split('T')[1]?.slice(0, 5) ?? point.hour.slice(-5)}
                        </span>
                        <span className="text-[10px] font-mono text-text">{point.count}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            ) : (
              <EmptyState>No active detections in the last 24h.</EmptyState>
            )}
          </div>
        </article>

        {/* NetSentinel Network Overview */}
        <article className="panel">
          <div className="panel-header">
            <h2>NetSentinel Network Telemetry</h2>
            <Link href="/network" className="text-[11px] text-muted hover:underline">
              View network
            </Link>
          </div>
          <div className="prop-list">
            <div className="prop-row">
              <span>Recent events (1h)</span>
              <strong>{dashboard?.networkStats?.recent_events ?? 0}</strong>
            </div>
            <div className="prop-row">
              <span>Unique sources (IPs)</span>
              <strong>{dashboard?.networkStats?.unique_sources ?? 0}</strong>
            </div>
            <div className="prop-row">
              <span>Unique target hosts</span>
              <strong>{dashboard?.networkStats?.unique_targets ?? 0}</strong>
            </div>
            {dashboard?.networkStats?.top_sources && dashboard.networkStats.top_sources.length > 0 && (
              <div className="pt-2 border-t border-border">
                <span className="text-[10px] text-muted block mb-1">Top source IP</span>
                <div className="flex items-center justify-between font-mono text-[11px] bg-surface-raised p-2 rounded border border-border">
                  <span>{dashboard.networkStats.top_sources[0].ip}</span>
                  <span className="text-muted">{dashboard.networkStats.top_sources[0].count} events</span>
                </div>
              </div>
            )}
          </div>
        </article>
      </section>

      {/* Lower Grid: Correlated Incidents & Recent Alerts */}
      <section className="lower-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Recent Correlated Incidents</h2>
            <Link href="/incidents" className="text-[11px] text-muted hover:underline">
              View all ({incidents.length})
            </Link>
          </div>
          {loading ? (
            <LoadingState label="Loading incidents..." />
          ) : incidents.length ? (
            <div className="soc-table-wrap">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Incident</th>
                    <th>Source → Target</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.slice(0, 5).map((inc) => (
                    <tr key={inc.id}>
                      <td>
                        <SeverityBadge value={inc.severity} />
                      </td>
                      <td>
                        <Link href={`/incidents/${inc.id}`} className="hover:underline text-text">
                          {inc.title}
                        </Link>
                        <span className="text-[10px] font-mono text-muted block">{formatDate(inc.last_seen)}</span>
                      </td>
                      <td className="font-mono text-[11px]">
                        {entityList(inc.source_entities)} → {entityList(inc.target_entities)}
                      </td>
                      <td>
                        <span className="font-mono text-[10.5px] text-muted">{titleCase(inc.status)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>No incidents correlated yet.</EmptyState>
          )}
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Latest Deterministic Alerts</h2>
            <Link href="/alerts" className="text-[11px] text-muted hover:underline">
              View all ({alerts.length})
            </Link>
          </div>
          {loading ? (
            <LoadingState label="Loading alerts..." />
          ) : alerts.length ? (
            <div className="soc-table-wrap">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Alert Type</th>
                    <th>Source → Target</th>
                    <th>Correlation</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 5).map((alert) => (
                    <tr key={alert.id}>
                      <td>
                        <SeverityBadge value={alert.severity} />
                      </td>
                      <td>
                        <span className="block">{titleCase(alert.alert_type)}</span>
                        <span className="font-mono text-[10px] text-muted">
                          {alert.mitre_technique ?? 'General'}
                        </span>
                      </td>
                      <td className="font-mono text-[11px]">
                        {alert.source_ip ?? 'Unknown'} → {alert.target_host ?? 'Unknown'}
                      </td>
                      <td>
                        {alert.incident_id ? (
                          <Link
                            href={`/incidents/${alert.incident_id}`}
                            className="font-mono text-[10px] text-muted hover:underline"
                          >
                            Linked
                          </Link>
                        ) : (
                          <span className="font-mono text-[10px] text-faint">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>No alerts logged in the database.</EmptyState>
          )}
        </article>
      </section>
    </ThreatLensShell>
  )
}
