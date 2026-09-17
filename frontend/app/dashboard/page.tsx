'use client'

import Link from 'next/link'
import { useEffect, useRef, useState } from 'react'
import {
  Download,
  RefreshCw,
  Play,
  ShieldCheck,
  ArrowRight,
} from 'lucide-react'
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'

import {
  downloadUrl,
  loadDashboardData,
  type DashboardData,
} from '@/lib/api'

import { ThreatLensShell } from '@/components/threatlens/shell'
import { useRealtime } from '@/components/threatlens/realtime'

import {
  EmptyState,
  ErrorState,
  LoadingState,
  SeverityBadge,
} from '@/components/threatlens/ui'

import {
  entityList,
  formatDate,
  formatTime,
  timestampMs,
  titleCase,
} from '@/components/threatlens/format'

export default function DashboardPage() {
  const { activity, connected: liveConnected } = useRealtime()
  const [dashboard, setDashboard] = useState<DashboardData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const liveRefresh = useRef<number | undefined>(undefined)

  const loadData = () => {
    setLoading(true)
    setError(null)

    loadDashboardData()
      .then((data) => {
        const failures = Object.values(data.errors)

        setDashboard(data)
        setError(failures.length ? failures.join(' | ') : null)
      })
      .catch((err) => {
        setError(
          err instanceof Error
            ? err.message
            : 'Unable to load dashboard telemetry.',
        )
      })
      .finally(() => {
        setLoading(false)
      })
  }

  useEffect(() => {
    loadData()
    const onTelemetry = () => {
      if (liveRefresh.current) window.clearTimeout(liveRefresh.current)
      liveRefresh.current = window.setTimeout(loadData, 600)
    }
    window.addEventListener('threatlens:telemetry', onTelemetry)
    return () => {
      window.removeEventListener('threatlens:telemetry', onTelemetry)
      if (liveRefresh.current) window.clearTimeout(liveRefresh.current)
    }
  }, [])

  const incidents = dashboard?.incidents ?? []
  const alerts = dashboard?.alerts ?? []
  const events = dashboard?.events ?? []

  const detectionTimeline = [
    ...(dashboard?.detectionsTimeline?.timeline ?? []),
  ].sort((a, b) => timestampMs(a.hour) - timestampMs(b.hour))

  const criticalAlerts =
    dashboard?.alertStats?.by_severity?.critical ?? 0

  const observedAssets = dashboard?.overview?.observed_assets

  return (
    <ThreatLensShell>
      {/* Page Heading */}
      <section className="page-heading">
        <div>
          <h1>Security Operations Overview</h1>
        </div>

        <div className="heading-actions">
          <Link
            className="secondary-button"
            href="/simulator"
          >
            <Play className="w-3.5 h-3.5 mr-1" />
            Run Attack Simulation
          </Link>

          <button
            className="secondary-button"
            onClick={() =>
              downloadUrl(
                '/api/v1/incidents/export/export/all?format=csv',
              )
            }
          >
            <Download className="w-3.5 h-3.5 mr-1" />
            Export CSV
          </button>

          <button
            className="secondary-button"
            onClick={loadData}
            disabled={loading}
          >
            <RefreshCw
              className={`w-3.5 h-3.5 mr-1 ${loading ? 'animate-spin' : ''
                }`}
            />
            Refresh
          </button>
        </div>
      </section>

      <section className="live-soc-grid">
        <article className="panel live-activity-panel">
          <div className="panel-header"><div className="live-heading"><span className={`live-dot ${liveConnected ? 'online' : ''}`} /><h2>Live SOC Activity</h2></div><small className="text-muted">{liveConnected ? 'LIVE' : 'RECONNECTING'}</small></div>
          <div className="live-activity-list">
            {activity.length ? activity.slice(0, 18).map((item) => <Link href={item.href ?? '#'} key={item.id} className="live-activity-row">
              <time>{formatTime(item.timestamp)}</time><span className={`activity-type ${item.severity ?? ''}`}>{titleCase(item.type)}</span><span className="activity-copy"><strong>{titleCase(item.label)}</strong>{item.detail && <small>{item.detail}</small>}</span>
            </Link>) : <EmptyState>No backend activity has been recorded.</EmptyState>}
          </div>
        </article>
        <article className="panel live-pipeline-panel">
          <div className="panel-header"><h2>Live Pipeline</h2><small className="text-muted">Recent backend state</small></div>
          <div className="pipeline-stages">
            {[
              ['observe', 'Observe'], ['detect', 'Detect'], ['correlate', 'Correlate'], ['trace', 'Trace'], ['understand', 'Understand'], ['respond', 'Respond'], ['verify', 'Verify'],
            ].map(([stage, label]) => {
              const latest = activity.find((item) => item.stage === stage)
              return <div className={latest ? 'active' : ''} key={stage}><span>{label}</span><strong>{latest ? titleCase(latest.label) : 'No recent activity'}</strong>{latest && <time>{formatTime(latest.timestamp)}</time>}</div>
            })}
          </div>
        </article>
      </section>

      {/* Error */}
      {error && (
        <ErrorState
          error={error}
          retry={loadData}
        />
      )}

      {/* KPI Cards */}
      <section className="metric-grid">
        <article className="metric-card-clean">
          <strong>
            {loading
              ? '-'
              : String(
                dashboard?.overview?.total_incidents ??
                incidents.length,
              )}
          </strong>

          <span>Correlated Incidents</span>

          <small>
            {dashboard?.overview?.open_incidents ?? 0} open
          </small>
        </article>

        <article className="metric-card-clean">
          <strong>
            {loading
              ? '-'
              : String(
                dashboard?.alertStats?.total ??
                alerts.length,
              )}
          </strong>

          <span>Stored Alerts</span>

          <small>{criticalAlerts} critical</small>
        </article>

        <article className="metric-card-clean">
          <strong>
            {loading
              ? '-'
              : String(
                dashboard?.networkStats?.total_events ??
                events.length,
              )}
          </strong>

          <span>Events Ingested</span>

          <small>Raw and normalized</small>
        </article>

        <article className="metric-card-clean">
          <strong>
            {loading
              ? '-'
              : String(
                observedAssets ?? 0,
              )}
          </strong>

          <span>Monitored Assets</span>

          <small>Hosts and endpoints</small>
        </article>
      </section>

      <section className="metric-grid">
        <article className="metric-card-clean"><strong>{loading ? '-' : dashboard?.overview?.open_incidents ?? 0}</strong><span>Open Incidents</span><small>Awaiting resolution</small></article>
        <article className="metric-card-clean"><strong>{loading ? '-' : dashboard?.overview?.contained_incidents ?? 0}</strong><span>Contained Incidents</span><small>Defensive action recorded</small></article>
        <article className="metric-card-clean"><strong>{loading ? '-' : dashboard?.overview?.critical_incidents ?? 0}</strong><span>Critical Incidents</span><small>{dashboard?.overview?.alerts_24h ?? 0} alerts in 24h</small></article>
        <article className="metric-card-clean"><strong>{loading ? '-' : dashboard?.overview?.repeat_threats ?? 0}</strong><span>Repeat Threats</span><small>{dashboard?.overview?.human_escalations ?? 0} human escalations</small></article>
        <article className="metric-card-clean"><strong>{loading ? '-' : dashboard?.overview?.agents_online ?? 0}</strong><span>Agents Online</span><small>Heartbeat within 2 minutes</small></article>
        <article className="metric-card-clean"><strong>{loading ? '-' : dashboard?.responseStats?.total_executions ?? 0}</strong><span>Responses Executed</span><small>{dashboard?.responseStats?.verified_actions ?? 0} verified</small></article>
      </section>

      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-header"><h2>Incident Timeline</h2></div>
          <div className="p-4 space-y-2">
            {(dashboard?.incidentsTimeline?.timeline ?? []).length ? dashboard?.incidentsTimeline?.timeline.map((point) => (
              <div className="prop-row" key={point.date}>
                <span>{point.date}</span>
                <strong>{point.low + point.medium + point.high + point.critical} incidents</strong>
              </div>
            )) : <EmptyState>No incidents in the selected period.</EmptyState>}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header"><h2>Top Attack Types</h2></div>
          <div className="p-4 space-y-2">
            {(dashboard?.overview?.top_attack_types ?? []).length ? dashboard?.overview?.top_attack_types.map((item) => (
              <div className="prop-row" key={item.type}><span>{titleCase(item.type)}</span><strong>{item.count}</strong></div>
            )) : <EmptyState>No attack types observed.</EmptyState>}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header"><h2>MITRE Distribution</h2></div>
          <div className="p-4 space-y-2">
            {(dashboard?.overview?.mitre_distribution ?? []).length ? dashboard?.overview?.mitre_distribution.map((item) => (
              <div className="prop-row" key={item.technique}><span className="font-mono">{item.technique}</span><strong>{item.count}</strong></div>
            )) : <EmptyState>No MITRE techniques observed.</EmptyState>}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header"><h2>Current Activity</h2></div>
          <div className="prop-list">
            <div className="prop-row"><span>Alerts, last 24 hours</span><strong>{dashboard?.overview?.alerts_24h ?? 0}</strong></div>
            <div className="prop-row"><span>Critical alerts</span><strong>{dashboard?.overview?.critical_alerts ?? criticalAlerts}</strong></div>
            <div className="prop-row"><span>Events ingested</span><strong>{dashboard?.overview?.events_ingested ?? 0}</strong></div>
            <div className="prop-row"><span>Human escalations</span><strong>{dashboard?.overview?.human_escalations ?? 0}</strong></div>
          </div>
        </article>
      </section>

      {/* Middle Grid: Detection Activity + Network Telemetry */}
      <section className="dashboard-grid">
        {/* Detection Activity */}
        <article className="panel">
          <div className="panel-header">
            <h2>Detection Activity (24h)</h2>
          </div>

          <div className="p-4">
            {detectionTimeline.length > 0 ? (
              <div className="h-56 w-full">
                <ResponsiveContainer
                  width="100%"
                  height="100%"
                >
                  <LineChart
                    data={detectionTimeline.slice(-24)}
                    margin={{
                      top: 10,
                      right: 10,
                      left: -20,
                      bottom: 0,
                    }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      className="stroke-border"
                      vertical={false}
                    />

                    <XAxis
                      dataKey="hour"
                      tickFormatter={(value) => formatTime(String(value))}
                      tick={{
                        fontSize: 9,
                      }}
                      className="fill-muted"
                      axisLine={false}
                      tickLine={false}
                    />

                    <YAxis
                      allowDecimals={false}
                      tick={{
                        fontSize: 9,
                      }}
                      className="fill-muted"
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={{
                        background:
                          'var(--surface-raised)',
                        border:
                          '1px solid var(--border)',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontFamily: 'monospace',
                      }}
                      labelStyle={{
                        color: 'var(--text)',
                        marginBottom: '2px',
                      }}
                      itemStyle={{
                        color: 'var(--text)',
                      }}
                      labelFormatter={(value) => formatDate(String(value))}
                      formatter={(value) => [
                        value,
                        'Detections',
                      ]}
                    />

                    <Line
                      type="monotone"
                      dataKey="count"
                      stroke="currentColor"
                      className="text-text"
                      strokeWidth={1.5}
                      dot={false}
                      activeDot={{
                        r: 3,
                      }}
                      isAnimationActive={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState>
                No active detections in the last 24h.
              </EmptyState>
            )}
          </div>
        </article>

        {/* Network Telemetry */}
        <article className="panel">
          <div className="panel-header">
            <h2>NetSentinel Network Telemetry</h2>

            <Link
              href="/network"
              className="text-[11px] text-muted hover:underline"
            >
              View network
            </Link>
          </div>

          <div className="prop-list">
            <div className="prop-row">
              <span>Recent events (1h)</span>

              <strong>
                {dashboard?.networkStats
                  ?.recent_events ?? 0}
              </strong>
            </div>

            <div className="prop-row">
              <span>Unique sources (IPs)</span>

              <strong>
                {dashboard?.networkStats
                  ?.unique_sources ?? 0}
              </strong>
            </div>

            <div className="prop-row">
              <span>Unique target hosts</span>

              <strong>
                {dashboard?.networkStats
                  ?.unique_targets ?? 0}
              </strong>
            </div>

            {dashboard?.networkStats?.top_sources &&
              dashboard.networkStats.top_sources.length >
              0 && (
                <div className="pt-2 border-t border-border">
                  <span className="text-[10px] text-muted block mb-1">
                    Top source IP
                  </span>

                  <div className="flex items-center justify-between font-mono text-[11px] bg-surface-raised p-2 rounded border border-border">
                    <span>
                      {
                        dashboard.networkStats
                          .top_sources[0].ip
                      }
                    </span>

                    <span className="text-muted">
                      {
                        dashboard.networkStats
                          .top_sources[0].count
                      }{' '}
                      events
                    </span>
                  </div>
                </div>
              )}
          </div>
        </article>
      </section>

      {/* Response Automation */}
      <section className="panel mb-6">
        <div className="panel-header flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />

            <h2 className="text-sm font-semibold">
              AI Defensive Response Automation
            </h2>

            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />

              {dashboard?.responseStats
                ?.response_agent_status
                ? titleCase(
                  dashboard.responseStats
                    .response_agent_status,
                )
                : 'Operational'}
            </span>
          </div>

          <Link
            href="/response"
            className="text-[11px] text-muted hover:text-text flex items-center gap-1 hover:underline"
          >
            Open Response Center
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        <div className="p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {/* Proposals */}
          <div className="bg-surface-raised border border-border p-3 rounded flex flex-col">
            <span className="text-[10px] uppercase font-mono tracking-wider text-muted mb-1">
              Proposals
            </span>

            <strong className="text-xl font-mono text-text">
              {loading
                ? '-'
                : String(
                  dashboard?.responseStats
                    ?.response_proposals ?? 0,
                )}
            </strong>

            <span className="text-[10.5px] text-muted mt-1">
              AI formulated
            </span>
          </div>

          {/* Automated Execution */}
          <div className="bg-surface-raised border border-border p-3 rounded flex flex-col">
            <span className="text-[10px] uppercase font-mono tracking-wider text-muted mb-1">
              Automated Exec
            </span>

            <strong className="text-xl font-mono text-text">
              {loading
                ? '-'
                : String(
                  dashboard?.responseStats
                    ?.automated_executions ?? 0,
                )}
            </strong>

            <span className="text-[10.5px] text-muted mt-1">
              Policy auto-fired
            </span>
          </div>

          {/* Awaiting Approval */}
          <div className="bg-surface-raised border border-border p-3 rounded flex flex-col">
            <span className="text-[10px] uppercase font-mono tracking-wider text-muted mb-1">
              Awaiting Approval
            </span>

            <strong className="text-xl font-mono text-amber-400">
              {loading
                ? '-'
                : String(
                  dashboard?.responseStats
                    ?.actions_awaiting_approval ?? 0,
                )}
            </strong>

            <span className="text-[10.5px] text-muted mt-1">
              Manual review
            </span>
          </div>

          {/* Verified Actions */}
          <div className="bg-surface-raised border border-border p-3 rounded flex flex-col">
            <span className="text-[10px] uppercase font-mono tracking-wider text-muted mb-1">
              Verified Actions
            </span>

            <strong className="text-xl font-mono text-emerald-400">
              {loading
                ? '-'
                : String(
                  dashboard?.responseStats
                    ?.verified_actions ?? 0,
                )}
            </strong>

            <span className="text-[10.5px] text-muted mt-1">
              Telemetry checked
            </span>
          </div>

          {/* Active Policies */}
          <div className="bg-surface-raised border border-border p-3 rounded flex flex-col">
            <span className="text-[10px] uppercase font-mono tracking-wider text-muted mb-1">
              Active Policies
            </span>

            <strong className="text-xl font-mono text-text">
              {loading
                ? '-'
                : String(
                  dashboard?.responseStats
                    ?.active_response_policies ?? 0,
                )}
            </strong>

            <span className="text-[10.5px] text-muted mt-1">
              {dashboard?.responseStats
                ?.auto_execute_policies ?? 0}{' '}
              auto-execute
            </span>
          </div>

          {/* Total Playbooks */}
          <div className="bg-surface-raised border border-border p-3 rounded flex flex-col">
            <span className="text-[10px] uppercase font-mono tracking-wider text-muted mb-1">
              Total Playbooks
            </span>

            <strong className="text-xl font-mono text-text">
              {loading
                ? '-'
                : String(
                  dashboard?.responseStats
                    ?.total_playbooks ?? 0,
                )}
            </strong>

            <span className="text-[10.5px] text-muted mt-1">
              Bounded routines
            </span>
          </div>
        </div>
      </section>

      {/* Lower Grid: Incidents + Alerts */}
      <section className="lower-grid">
        {/* Correlated Incidents */}
        <article className="panel">
          <div className="panel-header">
            <h2>Recent Correlated Incidents</h2>

            <Link
              href="/incidents"
              className="text-[11px] text-muted hover:underline"
            >
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
                  {incidents
                    .slice(0, 5)
                    .map((inc) => (
                      <tr key={inc.id}>
                        <td>
                          <SeverityBadge
                            value={inc.severity}
                          />
                        </td>

                        <td>
                          <Link
                            href={`/incidents/${inc.id}`}
                            className="hover:underline text-text"
                          >
                            {inc.title}
                          </Link>

                          <span className="text-[10px] font-mono text-muted block">
                            {formatDate(inc.last_seen)}
                          </span>
                        </td>

                        <td className="font-mono text-[11px]">
                          {entityList(
                            inc.source_entities,
                          )}{' '}
                          →{' '}
                          {entityList(
                            inc.target_entities,
                          )}
                        </td>

                        <td>
                          <span className="font-mono text-[10.5px] text-muted">
                            {titleCase(inc.status)}
                          </span>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>
              No incidents correlated yet.
            </EmptyState>
          )}
        </article>

        {/* Deterministic Alerts */}
        <article className="panel">
          <div className="panel-header">
            <h2>Latest Deterministic Alerts</h2>

            <Link
              href="/alerts"
              className="text-[11px] text-muted hover:underline"
            >
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
                  {alerts
                    .slice(0, 5)
                    .map((alert) => (
                      <tr key={alert.id}>
                        <td>
                          <SeverityBadge
                            value={alert.severity}
                          />
                        </td>

                        <td>
                          <span className="block">
                            {titleCase(
                              alert.alert_type,
                            )}
                          </span>

                          <span className="font-mono text-[10px] text-muted">
                            {alert.mitre_technique ??
                              'General'}
                          </span>
                        </td>

                        <td className="font-mono text-[11px]">
                          {alert.source_ip ??
                            'Unknown'}{' '}
                          →{' '}
                          {alert.target_host ??
                            'Unknown'}
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
                            <span className="font-mono text-[10px] text-faint">
                              -
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>
              No alerts logged in the database.
            </EmptyState>
          )}
        </article>
      </section>
    </ThreatLensShell>
  )
}
