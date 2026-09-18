'use client'

import Link from 'next/link'
import { CircleStop, Play, RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'

import { formatDate, formatTime, titleCase } from '@/components/threatlens/format'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState } from '@/components/threatlens/ui'
import { api, type DemoAsset, type DemoLabStatus, type DemoRun, type DemoScenario } from '@/lib/api'

const pipelineLabels: Record<string, string> = {
  telemetry: 'Telemetry received', detection: 'Detection fired', alert: 'Alert generated',
  incident: 'Incident correlated', traceai: 'TraceAI reconstructed attack', mitre: 'MITRE mapped',
  ai_analyst: 'AI Analyst', response_agent: 'Response Agent', policy: 'Policy evaluated',
  execution: 'Response execution', verification: 'Verification', audit: 'Audit recorded',
  escalation: 'Human escalation',
}

export default function DemoLabPage() {
  const [assets, setAssets] = useState<DemoAsset[]>([])
  const [labStatus, setLabStatus] = useState<DemoLabStatus | null>(null)
  const [scenarios, setScenarios] = useState<DemoScenario[]>([])
  const [assetId, setAssetId] = useState('')
  const [scenario, setScenario] = useState('full-attack')
  const [mode, setMode] = useState<'simulation' | 'lab'>('simulation')
  const [run, setRun] = useState<DemoRun | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadConfiguration = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [statusData, assetData, scenarioData] = await Promise.all([api.demoLabStatus(), api.demoAssets(), api.demoScenarios()])
      setLabStatus(statusData)
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
    setError(null)
    try {
      setScenario(selectedScenario)
      if (mode === 'simulation') {
        const status = await api.runFullAttack()
        const generatedAt = status.started_at ?? status.completed_at ?? new Date().toISOString()
        setRun({
          id: `simulation-${generatedAt}`,
          scenario: selectedScenario,
          asset_id: 'controlled-simulation',
          target_host: 'synthetic-target',
          target_ip: 'synthetic',
          source_ip: '10.10.10.99',
          status: status.status ?? 'completed',
          safety_mode: 'controlled_simulation',
          stop_requested: false,
          events_sent: status.events_sent ?? 0,
          alerts_created: status.alerts_created ?? 0,
          incident_id: null,
          pipeline: Object.fromEntries(Object.keys(pipelineLabels).map((key) => [key, 'complete'])),
          log: [{ timestamp: new Date().toISOString(), stage: 'SIMULATION', message: status.message ?? 'Controlled synthetic telemetry submitted to ThreatLens.' }],
          error: null,
          created_at: generatedAt,
          started_at: status.started_at ?? generatedAt,
          completed_at: status.completed_at ?? generatedAt,
        })
        return
      }
      if (!assetId) {
        setError('Select a configured isolated lab asset before running lab mode.')
        return
      }
      setRun(await api.startDemoRun(assetId, selectedScenario))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to start simulator scenario.')
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
      {loading ? <LoadingState label="Loading simulator configuration..." /> : (
        <div className="dashboard-grid">
          <div className="space-y-3">
            <article className="panel">
              <div className="panel-header"><h2>Mode</h2></div>
              <div className="p-3 space-y-2">
                <label className={`mode-option ${mode === 'simulation' ? 'active' : ''}`}>
                  <input type="radio" checked={mode === 'simulation'} onChange={() => setMode('simulation')} />
                  <span><strong>Controlled Simulation</strong><small>Generates controlled security telemetry and processes it through the real ThreatLens detection, correlation, and investigation pipeline.</small></span>
                </label>
                <label className={`mode-option ${mode === 'lab' ? 'active' : ''}`}>
                  <input type="radio" checked={mode === 'lab'} onChange={() => setMode('lab')} />
                  <span><strong>Isolated Demo Lab</strong><small>Runs bounded scenarios only against explicitly configured private lab assets.</small></span>
                </label>
              </div>
            </article>

            {mode === 'lab' && <article className="panel">
              <div className="panel-header"><h2>Isolated Demo Lab</h2></div>
              <div className="p-4 space-y-3">
                {assets.length ? <>
                  <label className="block text-[11px] text-muted">Target
                    <select className="block w-full mt-1" value={assetId} onChange={(event) => setAssetId(event.target.value)} disabled={Boolean(active)}>
                      {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.hostname} ({asset.ip})</option>)}
                    </select>
                  </label>
                  <div className="prop-list">
                    <div className="prop-row"><span>Agent status</span><strong>{selectedAsset?.agent?.status ?? 'NOT REGISTERED'}</strong></div>
                    <div className="prop-row"><span>Operating system</span><strong>{selectedAsset?.os}</strong></div>
                    <div className="prop-row"><span>Safety mode</span><strong>ALLOWLISTED LAB TELEMETRY</strong></div>
                    <div className="prop-row"><span>Duration limit</span><strong>Backend controlled</strong></div>
                  </div>
                </> : <EmptyState title="No isolated lab assets configured" description="Controlled Simulation is still available. Configure allowed lab assets in the ThreatLens backend to enable isolated lab scenarios." />}
              </div>
            </article>}

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

            <article className="panel">
              <div className="panel-header"><h2>Demo Lab Setup</h2><span className="font-mono text-[10px]">{labStatus?.configured ? 'Configured' : 'Not Configured'}</span></div>
              <div className="prop-list">
                <div className="prop-row"><span>Controlled Simulation</span><strong>AVAILABLE</strong></div>
                <div className="prop-row"><span>Isolated Lab Execution</span><strong>{labStatus?.configured ? 'AVAILABLE' : 'UNAVAILABLE'}</strong></div>
                <div className="prop-row"><span>Required backend configuration</span><strong>{labStatus?.configuration.required ?? 'DEMO_LAB_ASSETS'}</strong></div>
                <div className="prop-row"><span>Example</span><strong>{labStatus?.configuration.example ?? '192.168.50.20,192.168.50.21'}</strong></div>
                <div className="prop-row"><span>Restart required</span><strong>{labStatus?.configuration.restart_required ? 'Yes' : 'No'}</strong></div>
                {labStatus?.configuration_error && <div className="prop-row"><span>Configuration issue</span><strong>{labStatus.configuration_error}</strong></div>}
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

            {!active && (mode === 'simulation' || assets.length > 0) && (
              <button className="secondary-button w-full justify-center" onClick={() => start()}><Play className="w-3.5 h-3.5 mr-1" />Run {mode === 'simulation' ? 'Controlled Simulation' : 'Selected Scenario'}</button>
            )}
          </div>
        </div>
      )}
    </ThreatLensShell>
  )
}
