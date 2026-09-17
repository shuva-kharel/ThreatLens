'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Play,
  RotateCw,
  ExternalLink,
} from 'lucide-react'
import { api, type Scenario, type SimulationStatus } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { ErrorState } from '@/components/threatlens/ui'

interface LogEntry {
  time: string
  stage: string
  message: string
}

export default function SimulatorPage() {
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [selectedScenario, setSelectedScenario] = useState<string>('full-attack')
  const [attackerIp, setAttackerIp] = useState('10.10.10.50')
  const [targetIp, setTargetIp] = useState('10.10.10.10')
  const [running, setRunning] = useState(false)
  const [status, setStatus] = useState<SimulationStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [resultingIncidentId, setResultingIncidentId] = useState<string | null>(null)

  useEffect(() => {
    api.simulatorScenarios()
      .then((res) => {
        setScenarios(res.scenarios)
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Unable to load simulation scenarios.')
      })
  }, [])

  const addLog = (stage: string, message: string) => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false })
    setLogs((prev) => [...prev, { time, stage, message }])
  }

  const handleRunSimulation = async () => {
    setRunning(true)
    setError(null)
    setStatus(null)
    setResultingIncidentId(null)
    setLogs([])

    addLog('SETUP', `Initializing scenario [${selectedScenario}] with Attacker=${attackerIp}, Target=${targetIp}...`)

    try {
      if (selectedScenario === 'full-attack') {
        addLog('PIPELINE', 'Triggering 7-stage attack chain simulation...')
        const result = await api.runFullAttack({ target_ip: targetIp, attacker_ip: attackerIp })
        setStatus(result)

        addLog('RECON', 'Phase 1: Port Scanning events dispatched')
        addLog('AUTH', 'Phase 2: SSH Brute Force authentication failure sequence')
        addLog('ACCESS', 'Phase 3: Successful authentication after credential attempts')
        addLog('EXEC', 'Phase 4: Malicious command execution (wget payload.sh | sh)')
        addLog('PRIVESC', 'Phase 5: Privilege escalation activity (sudo su -)')
        addLog('CREDS', 'Phase 6: Shadow file access (/etc/shadow)')
        addLog('C2', 'Phase 7: Reverse shell initiated')
        addLog(
          'CORRELATION',
          `Simulation complete: ${result.events_sent} events, ${result.alerts_created} alerts, ${result.incidents_created} incident(s).`
        )

        try {
          const recentIncidents = await api.incidents()
          if (recentIncidents.length > 0) {
            setResultingIncidentId(recentIncidents[0].id)
          }
        } catch {
          // ignore
        }
      } else {
        addLog('PIPELINE', `Triggering scenario [${selectedScenario}]...`)
        const result = await api.runSimulation(selectedScenario, { target_ip: targetIp, attacker_ip: attackerIp })
        setStatus(result)
        addLog('CORRELATION', result.message || 'Simulation completed successfully.')

        const recentIncidents = await api.incidents()
        if (recentIncidents.length > 0) {
          setResultingIncidentId(recentIncidents[0].id)
        }
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Simulation failed.'
      setError(errMsg)
      addLog('ERROR', errMsg)
    } finally {
      setRunning(false)
    }
  }

  const activeScenarioObj = scenarios.find((s) => s.id === selectedScenario)

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Attack Simulator</h1>
        </div>
        <div className="heading-actions">
          {resultingIncidentId && (
            <Link className="secondary-button" href={`/incidents/${resultingIncidentId}`}>
              Investigate Incident <ExternalLink className="w-3.5 h-3.5 ml-1" />
            </Link>
          )}
        </div>
      </section>

      {error && <ErrorState error={error} retry={handleRunSimulation} />}

      <div className="dashboard-grid">
        <div className="space-y-3">
          <article className="panel">
            <div className="panel-header">
              <h2>Parameters</h2>
            </div>
            <div className="p-4 space-y-3">
              <div>
                <label className="block text-[11px] text-muted mb-1.5 font-medium">
                  Scenario Selection
                </label>
                <div className="grid grid-cols-1 gap-1.5">
                  {scenarios.map((sc) => (
                    <div
                      key={sc.id}
                      onClick={() => setSelectedScenario(sc.id)}
                      className={`p-2.5 rounded border cursor-pointer transition-all ${
                        selectedScenario === sc.id
                          ? 'border-border-strong bg-surface-raised'
                          : 'border-border bg-surface hover:bg-surface-hover'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <strong className="text-[12px] font-medium">{sc.name}</strong>
                        <span className="text-[10px] font-mono text-faint">{sc.stages.length} stages</span>
                      </div>
                      <p className="text-[11px] text-muted mt-0.5">{sc.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-border">
                <div>
                  <label className="block text-[10.5px] text-muted mb-1 font-medium">
                    Attacker IP
                  </label>
                  <input
                    className="w-full bg-surface-raised border border-border rounded px-2.5 py-1 text-[11.5px] font-mono text-text focus:outline-none"
                    value={attackerIp}
                    onChange={(e) => setAttackerIp(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-[10.5px] text-muted mb-1 font-medium">
                    Target Host
                  </label>
                  <input
                    className="w-full bg-surface-raised border border-border rounded px-2.5 py-1 text-[11.5px] font-mono text-text focus:outline-none"
                    value={targetIp}
                    onChange={(e) => setTargetIp(e.target.value)}
                  />
                </div>
              </div>

              <div className="pt-2">
                <button
                  className="secondary-button w-full justify-center py-2"
                  onClick={handleRunSimulation}
                  disabled={running}
                >
                  {running ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin mr-1" /> Simulating...
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 mr-1" /> Run Simulation
                    </>
                  )}
                </button>
              </div>
            </div>
          </article>

          {activeScenarioObj && (
            <article className="panel">
              <div className="panel-header">
                <h2>Stages ({activeScenarioObj.name})</h2>
              </div>
              <div className="p-3 space-y-1.5">
                {activeScenarioObj.stages.map((st, idx) => {
                  const completed = status?.stages_completed?.includes(st)
                  return (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-1.5 rounded border border-border text-[11px] font-mono text-muted bg-surface-raised"
                    >
                      <span>#{idx + 1} {st}</span>
                      <span className="text-[10px] text-faint">
                        {completed ? 'Triggered' : running ? 'In progress' : 'Pending'}
                      </span>
                    </div>
                  )
                })}
              </div>
            </article>
          )}
        </div>

        {/* Terminal and Results */}
        <div className="space-y-3">
          <article className="terminal-window">
            <div className="terminal-header">
              <span>simulation_output.log</span>
              <span className="text-[10px] font-mono">{running ? 'BUSY' : 'IDLE'}</span>
            </div>
            <div className="terminal-body">
              {logs.length === 0 ? (
                <div className="text-faint italic py-8 text-center">
                  Press &quot;Run Simulation&quot; to begin.
                </div>
              ) : (
                logs.map((log, index) => (
                  <div key={index} className="terminal-line">
                    <span className="terminal-time">[{log.time}]</span>
                    <span className="terminal-tag">&lt;{log.stage}&gt;</span>
                    <span className="text-text">{log.message}</span>
                  </div>
                ))
              )}
            </div>
          </article>

          {status && (
            <article className="panel">
              <div className="panel-header">
                <h2>Results</h2>
              </div>
              <div className="p-4">
                <div className="grid grid-cols-3 gap-2 mb-3">
                  <div className="p-2.5 rounded bg-surface-raised border border-border text-center">
                    <span className="text-[10px] text-faint uppercase block">Events</span>
                    <strong className="block text-[18px] font-mono text-text mt-0.5">{status.events_sent}</strong>
                  </div>
                  <div className="p-2.5 rounded bg-surface-raised border border-border text-center">
                    <span className="text-[10px] text-faint uppercase block">Alerts</span>
                    <strong className="block text-[18px] font-mono text-text mt-0.5">{status.alerts_created}</strong>
                  </div>
                  <div className="p-2.5 rounded bg-surface-raised border border-border text-center">
                    <span className="text-[10px] text-faint uppercase block">Incidents</span>
                    <strong className="block text-[18px] font-mono text-text mt-0.5">{status.incidents_created}</strong>
                  </div>
                </div>

                {resultingIncidentId && (
                  <div className="p-2.5 rounded bg-surface-raised border border-border flex items-center justify-between">
                    <span className="text-[11px] font-mono text-muted">ID: {resultingIncidentId}</span>
                    <Link className="secondary-button text-[11px] py-1" href={`/incidents/${resultingIncidentId}`}>
                      Investigate Incident
                    </Link>
                  </div>
                )}
              </div>
            </article>
          )}
        </div>
      </div>
    </ThreatLensShell>
  )
}
