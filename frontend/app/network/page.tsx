'use client'

import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import {
  api,
  type NetworkAnomalies,
  type NetworkConnection,
  type NetworkHost,
  type NetworkStats,
} from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

export default function NetworkPage() {
  const [stats, setStats] = useState<NetworkStats | null>(null)
  const [hosts, setHosts] = useState<NetworkHost[]>([])
  const [connections, setConnections] = useState<NetworkConnection[]>([])
  const [anomalies, setAnomalies] = useState<NetworkAnomalies | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadData = () => {
    setLoading(true)
    setError(null)
    Promise.all([api.networkStats(), api.networkHosts(), api.networkConnections(50), api.networkAnomalies()])
      .then(([s, h, c, a]) => {
        setStats(s)
        setHosts(h)
        setConnections(c)
        setAnomalies(a)
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load network telemetry.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Network Telemetry</h1>
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
        <LoadingState label="Loading network telemetry..." />
      ) : (
        <>
          <section className="metric-grid">
            <article className="metric-card-clean">
              <strong>{stats?.total_events ?? 0}</strong>
              <span>Total Events</span>
              <small>All time</small>
            </article>

            <article className="metric-card-clean">
              <strong>{stats?.recent_events ?? 0}</strong>
              <span>Recent Events</span>
              <small>Past hour</small>
            </article>

            <article className="metric-card-clean">
              <strong>{stats?.unique_sources ?? 0}</strong>
              <span>Unique Sources</span>
              <small>Source IPs</small>
            </article>

            <article className="metric-card-clean">
              <strong>{stats?.unique_targets ?? hosts.length}</strong>
              <span>Monitored Hosts</span>
              <small>Target endpoints</small>
            </article>
          </section>

          <div className="dashboard-grid">
            <section className="panel">
              <div className="panel-header">
                <h2>Monitored Hosts ({hosts.length})</h2>
              </div>
              {hosts.length ? (
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Events</th>
                        <th>Alerts</th>
                        <th>Telemetry</th>
                        <th>Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hosts.map((host) => (
                        <tr key={host.hostname}>
                          <td className="font-mono text-[11.5px] text-text">{host.hostname}</td>
                          <td className="font-mono text-[11px]">{host.event_count}</td>
                          <td className="font-mono text-[11px]">
                            {host.alert_count > 0 ? (
                              <span className="text-sev-high">{host.alert_count}</span>
                            ) : (
                              <span className="text-faint">0</span>
                            )}
                          </td>
                          <td className="font-mono text-[10.5px] text-muted">{host.telemetry_sources.map(titleCase).join(', ') || 'Unknown'}</td>
                          <td className="font-mono text-[10.5px] text-muted">{formatDate(host.last_seen)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState>No host records exist in current telemetry.</EmptyState>
              )}
            </section>

            <section className="panel">
              <div className="panel-header">
                <h2>Detected Anomalies</h2>
                <span className="text-[10px] font-mono text-faint">{anomalies?.total ?? 0}</span>
              </div>
              <div className="p-4 space-y-2">
                {anomalies?.anomalies && anomalies.anomalies.length > 0 ? (
                  anomalies.anomalies.map((anom, i) => (
                    <div key={i} className="p-2.5 rounded bg-surface-raised border border-border space-y-1">
                      <div className="flex items-center justify-between">
                        <strong className="text-[12px] text-text">
                          {anom.title || anom.type || 'Unusual Pattern'}
                        </strong>
                        <SeverityBadge value={anom.severity || 'medium'} />
                      </div>
                      <p className="text-[11px] text-muted">
                        {anom.description || `Anomaly on ${anom.target_host || 'target host'}.`}
                      </p>
                      {anom.source_ip && (
                        <div className="font-mono text-[10px] text-faint">Source: {anom.source_ip}</div>
                      )}
                    </div>
                  ))
                ) : (
                  <EmptyState>No network anomalies detected.</EmptyState>
                )}
              </div>
            </section>
          </div>

          <section className="panel">
            <div className="panel-header">
              <h2>Recent Connections</h2>
              <span className="text-[10px] font-mono text-faint">Latest 50</span>
            </div>
            {connections.length ? (
              <div className="soc-table-wrap">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Event Type</th>
                      <th>Source IP</th>
                      <th>Target Host</th>
                      <th>Telemetry</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {connections.map((conn) => (
                      <tr key={conn.id}>
                        <td>
                          <SeverityBadge value={conn.severity} />
                        </td>
                        <td className="font-mono text-[11px] text-text">
                          {titleCase(conn.event_type)}
                        </td>
                        <td className="font-mono text-[11px] text-muted">{conn.source_ip ?? 'Unknown'}</td>
                        <td className="font-mono text-[11px] text-muted">{conn.target_host}</td>
                        <td className="font-mono text-[10.5px] text-muted">{conn.telemetry_source ? titleCase(conn.telemetry_source) : 'Unknown'}</td>
                        <td className="font-mono text-[10.5px] text-muted">{formatDate(conn.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState>No connection events found in database.</EmptyState>
            )}
          </section>
        </>
      )}
    </ThreatLensShell>
  )
}
