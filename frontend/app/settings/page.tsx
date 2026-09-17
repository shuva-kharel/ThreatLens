'use client'

import { useEffect, useState } from 'react'
import {
  Trash2,
  RefreshCw,
  CheckCircle,
} from 'lucide-react'
import { api, type EndpointAgent, type HealthDetailed, type ResponsePolicy } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { ErrorState, LoadingState } from '@/components/threatlens/ui'
import { formatDate } from '@/components/threatlens/format'

export default function SettingsPage() {
  const [health, setHealth] = useState<HealthDetailed | null>(null)
  const [basicHealth, setBasicHealth] = useState<{
    status: string
    timestamp: string
    database: string
    ai_providers: string[]
    stats: { events: number; alerts: number; incidents: number }
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [cleaningEvents, setCleaningEvents] = useState(false)
  const [cleaningIncidents, setCleaningIncidents] = useState(false)
  const [cleanupMessage, setCleanupMessage] = useState<string | null>(null)
  const [policies, setPolicies] = useState<ResponsePolicy[]>([])
  const [agents, setAgents] = useState<EndpointAgent[]>([])

  const loadHealthData = async () => {
    setLoading(true)
    setError(null)
    try {
      const [detailedRes, basicRes, policyRes, agentRes] = await Promise.allSettled([
        api.healthDetailed(),
        api.health(),
        api.responsePolicies(),
        api.agents(),
      ])
      if (detailedRes.status === 'fulfilled') setHealth(detailedRes.value)
      if (basicRes.status === 'fulfilled') setBasicHealth(basicRes.value)
      if (policyRes.status === 'fulfilled') setPolicies(policyRes.value)
      if (agentRes.status === 'fulfilled') setAgents(agentRes.value)
      const failures = [detailedRes, basicRes, policyRes, agentRes].filter((result) => result.status === 'rejected')
      if (failures.length) setError(`${failures.length} settings data source(s) could not be loaded.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to connect to health diagnostics.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadHealthData()
  }, [])

  const handleCleanupEvents = async () => {
    setCleaningEvents(true)
    setCleanupMessage(null)
    try {
      const res = await api.cleanupEvents(30)
      setCleanupMessage(`Cleaned up ${res.deleted} events older than ${res.days} days.`)
      loadHealthData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Event cleanup failed.')
    } finally {
      setCleaningEvents(false)
    }
  }

  const handleCleanupIncidents = async () => {
    setCleaningIncidents(true)
    setCleanupMessage(null)
    try {
      const res = await api.cleanupIncidents(90)
      setCleanupMessage(`Cleaned up ${res.deleted} resolved incidents older than ${res.days} days.`)
      loadHealthData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Incident cleanup failed.')
    } finally {
      setCleaningIncidents(false)
    }
  }

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Settings &amp; System Health</h1>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={loadHealthData}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      {error && <ErrorState error={error} retry={loadHealthData} />}

      {cleanupMessage && (
        <div className="p-2.5 rounded bg-surface-raised border border-border text-text text-[11.5px] font-mono mb-4 flex items-center gap-2">
          <CheckCircle className="w-3.5 h-3.5 shrink-0" />
          <span>{cleanupMessage}</span>
        </div>
      )}

      {loading ? (
        <LoadingState label="Inspecting diagnostics..." />
      ) : (
        <>
          <section className="metric-grid">
            <article className="metric-card-clean">
              <strong>{basicHealth?.database === 'healthy' ? 'Operational' : 'Unavailable'}</strong>
              <span>Database Engine</span>
              <small>SQLite Telemetry Store</small>
            </article>

            <article className="metric-card-clean">
              <strong>{basicHealth?.stats?.events ?? health?.database?.events ?? 0}</strong>
              <span>Stored Events</span>
              <small>Total telemetry</small>
            </article>

            <article className="metric-card-clean">
              <strong>{health?.system ? `${health.system.cpu_percent}%` : 'Unavailable'}</strong>
              <span>CPU Utilization</span>
              <small>Backend host</small>
            </article>

            <article className="metric-card-clean">
              <strong>{health?.system ? health.system.memory_used : 'Unavailable'}</strong>
              <span>Memory Used</span>
              <small>{health?.system ? `of ${health.system.memory_total}` : 'Host RAM'}</small>
            </article>
          </section>

          <div className="dashboard-grid">
            <article className="panel">
              <div className="panel-header"><h2>Endpoint Agents</h2></div>
              {agents.length ? (
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead><tr><th>Agent</th><th>Address</th><th>Status</th><th>Telemetry Health</th><th>Last Seen</th></tr></thead>
                    <tbody>{agents.map((agent) => (
                      <tr key={agent.id}>
                        <td><strong>{agent.hostname}</strong><span className="block text-[10px] text-muted">{agent.os} · v{agent.version}</span></td>
                        <td className="font-mono text-[10.5px]">{agent.ip_addresses.join(', ') || 'Unavailable'}<span className="block text-muted">{agent.capabilities.join(', ')}</span></td>
                        <td><span className="font-mono text-[10.5px]">{agent.status}</span></td>
                        <td className="font-mono text-[10.5px]"><strong>{agent.events_received}</strong> events<span className="block text-muted">{agent.telemetry_sources.map((source) => source.replaceAll('_', ' ')).join(', ') || 'No sources'}</span><span className="block text-muted">Last event: {formatDate(agent.last_event)}</span></td>
                        <td className="font-mono text-[10.5px]">{formatDate(agent.last_seen)}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              ) : <div className="quiet-empty">No endpoint agents registered.</div>}
            </article>

            <article className="panel">
              <div className="panel-header">
                <h2>AI Providers</h2>
              </div>
              <div className="p-4 space-y-2">
                <div className="p-2.5 rounded bg-surface-raised border border-border flex items-center justify-between">
                  <div>
                    <strong className="text-[12px] block">Groq (qwen-3.6-27b)</strong>
                    <span className="text-[10.5px] font-mono text-muted">Primary</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      basicHealth?.ai_providers?.includes('groq')
                        ? 'bg-surface text-text border border-border'
                        : 'bg-surface text-faint border border-border'
                    }`}
                  >
                    {basicHealth?.ai_providers?.includes('groq') ? 'Configured' : 'Missing Key'}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-surface-raised border border-border flex items-center justify-between">
                  <div>
                    <strong className="text-[12px] block">Google Gemini (gemini-2.0-flash-lite)</strong>
                    <span className="text-[10.5px] font-mono text-muted">Fallback 1</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      basicHealth?.ai_providers?.includes('gemini')
                        ? 'bg-surface text-text border border-border'
                        : 'bg-surface text-faint border border-border'
                    }`}
                  >
                    {basicHealth?.ai_providers?.includes('gemini') ? 'Configured' : 'Missing Key'}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-surface-raised border border-border flex items-center justify-between">
                  <div>
                    <strong className="text-[12px] block">OpenRouter</strong>
                    <span className="text-[10.5px] font-mono text-muted">Fallback 2</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      basicHealth?.ai_providers?.includes('openrouter')
                        ? 'bg-surface text-text border border-border'
                        : 'bg-surface text-faint border border-border'
                    }`}
                  >
                    {basicHealth?.ai_providers?.includes('openrouter') ? 'Configured' : 'Missing Key'}
                  </span>
                </div>
              </div>
            </article>

            {/* Response Policy Summary */}
            <article className="panel">
              <div className="panel-header">
                <h2>Defensive Response Policies</h2>
              </div>
              <div className="p-4 space-y-2 text-[11.5px] font-mono">
                {policies.length ? policies.map((policy) => (
                  <div key={policy.action_type} className="p-2 rounded bg-surface-raised border border-border flex items-center justify-between gap-3">
                    <span>{policy.action_type.replaceAll('_', ' ')}</span>
                    <span className="text-muted font-semibold">
                      {!policy.enabled ? 'Disabled' : policy.requires_approval ? 'Approval Required' : policy.auto_execute ? 'Autonomous Allowed' : 'Manual Execution'}
                    </span>
                  </div>
                )) : <p className="text-muted">No response policies returned by the backend.</p>}
              </div>
            </article>

            {/* Storage Management */}
            <article className="panel">
              <div className="panel-header">
                <h2>Storage Retention</h2>
              </div>
              <div className="p-4 space-y-3">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11.5px]">
                    <span className="text-muted">Database:</span>
                    <span className="font-mono text-text">minisoc.db</span>
                  </div>
                  <div className="flex items-center justify-between text-[11.5px]">
                    <span className="text-muted">Stored Events:</span>
                    <span className="font-mono text-text">{basicHealth?.stats?.events ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11.5px]">
                    <span className="text-muted">Generated Alerts:</span>
                    <span className="font-mono text-text">{basicHealth?.stats?.alerts ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11.5px]">
                    <span className="text-muted">Correlated Incidents:</span>
                    <span className="font-mono text-text">{basicHealth?.stats?.incidents ?? 0}</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-border flex flex-col gap-2">
                  <button
                    className="secondary-button justify-center py-1.5"
                    onClick={handleCleanupEvents}
                    disabled={cleaningEvents}
                  >
                    <Trash2 className="w-3.5 h-3.5 mr-1" />
                    {cleaningEvents ? 'Purging Events...' : 'Purge Raw Events (>30 Days)'}
                  </button>

                  <button
                    className="secondary-button justify-center py-1.5"
                    onClick={handleCleanupIncidents}
                    disabled={cleaningIncidents}
                  >
                    <Trash2 className="w-3.5 h-3.5 mr-1" />
                    {cleaningIncidents ? 'Purging Incidents...' : 'Purge Resolved Incidents (>90 Days)'}
                  </button>
                </div>
              </div>
            </article>
          </div>
        </>
      )}
    </ThreatLensShell>
  )
}
