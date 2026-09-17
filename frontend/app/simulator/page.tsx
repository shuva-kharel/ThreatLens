'use client'

import Link from 'next/link'
import { CircleStop, Play, RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'

import { formatDate, formatTime, titleCase } from '@/components/threatlens/format'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState } from '@/components/threatlens/ui'
import { api, type DemoAsset, type DemoRun, type DemoScenario } from '@/lib/api'

const pipelineLabels: Record<string, string> = {
  telemetry: 'Telemetry received', detection: 'Detection fired', alert: 'Alert generated',
  incident: 'Incident correlated', traceai: 'TraceAI reconstructed attack', mitre: 'MITRE mapped',
  ai_analyst: 'AI Analyst', response_agent: 'Response Agent', policy: 'Policy evaluated',
  execution: 'Response execution', verification: 'Verification', audit: 'Audit recorded',
  escalation: 'Human escalation',
}

export default function DemoLabPage() {
  const [assets, setAssets] = useState<DemoAsset[]>([])
  const [scenarios, setScenarios] = useState<DemoScenario[]>([])
  const [assetId, setAssetId] = useState('')
  const [scenario, setScenario] = useState('full-attack')
  const [run, setRun] = useState<DemoRun | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadConfiguration = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [assetData, scenarioData] = await Promise.all([api.demoAssets(), api.demoScenarios()])
      setAssets(assetData)
      setScenarios(scenarioData)
      setAssetId((current) => current || assetData[0]?.id || '')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load Demo Lab configuration.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void loadConfiguration() }, [loadConfiguration])

  useEffect(() => {
    if (!run || !['queued', 'running'].includes(run.status)) return
    const refresh = async () => {
      try { setRun(await api.demoRun(run.id)) } catch { /* next poll or WebSocket update can recover */ }
    }
    const listener = (event: Event) => {
      const update = (event as CustomEvent<{ type?: string; data?: DemoRun }>).detail
      if (update.type === 'demo_lab_update' && update.data?.id === run.id) setRun(update.data)
    }
    window.addEventListener('threatlens:telemetry', listener)
    const timer = window.setInterval(refresh, 1500)
    return () => { window.removeEventListener('threatlens:telemetry', listener); window.clearInterval(timer) }
  }, [run])

  const start = async (selectedScenario = scenario) => {
    if (!assetId) return
    setError(null)
    try {
      setScenario(selectedScenario)
      setRun(await api.startDemoRun(assetId, selectedScenario))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to start Demo Lab scenario.')
    }
  }

  const stop = async () => {
    if (!run) return
    try { setRun(await api.stopDemoRun(run.id)) }
    catch (err) { setError(err instanceof Error ? err.message : 'Emergency stop failed.') }
  }

  const selectedAsset = assets.find((asset) => asset.id === assetId)
  const active = run && ['queued', 'running'].includes(run.status)

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div><h1>Demo Lab</h1></div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={loadConfiguration} disabled={loading}><RefreshCw className="w-3.5 h-3.5 mr-1" />Refresh</button>
          <button className="secondary-button" onClick={stop} disabled={!active}><CircleStop className="w-3.5 h-3.5 mr-1" />Emergency Stop</button>
        </div>
      </section>

      {error && <ErrorState error={error} retry={loadConfiguration} />}
      {loading ? <LoadingState label="Loading controlled lab assets..." /> : !assets.length ? (
        <EmptyState title="No lab assets configured" description="Configure DEMO_LAB_ASSETS on the backend before running scenarios." />
      ) : (
        <div className="dashboard-grid">
          <div className="space-y-3">
            <article className="panel">
              <div className="panel-header"><h2>Controlled Target</h2></div>
              <div className="p-4 space-y-3">
                <label className="block text-[11px] text-muted">Target
                  <select className="block w-full mt-1" value={assetId} onChange={(event) => setAssetId(event.target.value)} disabled={Boolean(active)}>
                    {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.hostname} ({asset.ip})</option>)}
                  </select>
                </label>
                <div className="prop-list">
                  <div className="prop-row"><span>Agent status</span><strong>{selectedAsset?.agent?.status ?? 'NOT REGISTERED'}</strong></div>
                  <div className="prop-row"><span>Operating system</span><strong>{selectedAsset?.os}</strong></div>
                  <div className="prop-row"><span>Safety mode</span><strong>SYNTHETIC TELEMETRY</strong></div>
                  <div className="prop-row"><span>Duration limit</span><strong>Backend controlled</strong></div>
                </div>
              </div>
            </article>

            <article className="panel">
              <div className="panel-header"><h2>Scenarios</h2></div>
              <div className="p-3 space-y-2">
                {scenarios.map((item) => (
                  <button key={item.id} className="secondary-button w-full justify-between" disabled={Boolean(active)} onClick={() => start(item.id)}>
                    <span>{item.name}</span><span className="font-mono text-[10px]">{item.event_count} bounded events</span>
                  </button>
                ))}
              </div>
            </article>
          </div>

          <div className="space-y-3">
            <article className="panel">
              <div className="panel-header"><h2>Pipeline Progress</h2><span className="font-mono text-[10px]">{run ? titleCase(run.status) : 'Idle'}</span></div>
              {!run ? <EmptyState>Select a scenario to begin.</EmptyState> : (
                <div className="p-4 space-y-1.5">
                  {Object.entries(pipelineLabels).map(([key, label]) => {
                    const state = run.pipeline[key] ?? 'pending'
                    return <div className="prop-row" key={key}><span>{label}</span><strong>{state === 'complete' ? 'Complete' : titleCase(state)}</strong></div>
                  })}
                  <div className="pt-2 border-t border-border grid grid-cols-2 gap-2 text-[11px]">
                    <span>Events: <strong>{run.events_sent}</strong></span><span>Alerts: <strong>{run.alerts_created}</strong></span>
                    <span>Started: <strong>{formatDate(run.started_at)}</strong></span><span>Mode: <strong>{titleCase(run.safety_mode)}</strong></span>
                  </div>
                  {run.error && <p className="text-sev-critical text-[11px]">{run.error}</p>}
                  {run.incident_id && <Link className="secondary-button justify-center" href={`/incidents/${run.incident_id}`}>Investigate Incident</Link>}
                </div>
              )}
            </article>

            <article className="terminal-window">
              <div className="terminal-header"><span>demo_lab_stream.log</span><span>{active ? 'LIVE' : 'IDLE'}</span></div>
              <div className="terminal-body">
                {run?.log.length ? run.log.map((entry, index) => (
                  <div className="terminal-line" key={`${entry.timestamp}-${index}`}>
                    <span className="terminal-time">[{formatTime(entry.timestamp, true)}]</span>
                    <span className="terminal-tag">&lt;{entry.stage}&gt;</span><span>{entry.message}</span>
                  </div>
                )) : <div className="text-faint text-center py-8">No scenario output.</div>}
              </div>
            </article>

            {!active && assets.length > 0 && (
              <button className="secondary-button w-full justify-center" onClick={() => start()}><Play className="w-3.5 h-3.5 mr-1" />Run Selected Scenario</button>
            )}
          </div>
        </div>
      )}
    </ThreatLensShell>
  )
}
