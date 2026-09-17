'use client'

import { useEffect, useState } from 'react'
import {
  Trash2,
  RefreshCw,
  CheckCircle,
} from 'lucide-react'
import { api, type HealthDetailed, type ResponsePolicy } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { ErrorState, LoadingState } from '@/components/threatlens/ui'

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

  const loadHealthData = async () => {
    setLoading(true)
    setError(null)
    try {
      const [detailedRes, basicRes, policyRes] = await Promise.allSettled([
        api.healthDetailed(),
        api.health(),
        api.responsePolicies(),
      ])
      if (detailedRes.status === 'fulfilled') setHealth(detailedRes.value)
      if (basicRes.status === 'fulfilled') setBasicHealth(basicRes.value)
      if (policyRes.status === 'fulfilled') setPolicies(policyRes.value)
      const failures = [detailedRes, basicRes, policyRes].filter((result) => result.status === 'rejected')
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
