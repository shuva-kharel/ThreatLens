'use client'

import { useEffect, useMemo, useState } from 'react'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { api, type MitreTactic, type MitreTechnique } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

export default function MitrePage() {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([])
  const [tactics, setTactics] = useState<MitreTactic[]>([])
  const [selected, setSelected] = useState<MitreTechnique | null>(null)
  const [q, setQ] = useState('')
  const [tactic, setTactic] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadData = () => {
    setLoading(true)
    setError(null)
    Promise.all([api.mitreTechniques(), api.mitreTactics()])
      .then(([tech, tac]) => {
        setTechniques(tech.techniques)
        setTactics(tac.tactics)
        setSelected(tech.techniques[0] ?? null)
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load MITRE ATT&CK framework.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  const filtered = useMemo(
    () =>
      techniques.filter(
        (t) =>
          (!tactic || t.tactic.toLowerCase() === tactic.toLowerCase()) &&
          `${t.id} ${t.name} ${t.tactic} ${t.description}`.toLowerCase().includes(q.toLowerCase())
      ),
    [q, tactic, techniques]
  )

  const selectTechnique = (id: string) => {
    api.mitreTechnique(id)
      .then(setSelected)
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load technique detail.'))
  }

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>MITRE ATT&amp;CK Matrix</h1>
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
        <LoadingState label="Loading MITRE techniques..." />
      ) : (
        <div className="dashboard-grid">
          <section className="panel">
            <div className="panel-header">
              <h2>Techniques ({filtered.length})</h2>
              <div className="toolbar">
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search technique ID or name..."
                />
                <select value={tactic} onChange={(e) => setTactic(e.target.value)}>
                  <option value="">All Tactics</option>
                  {tactics.map((tac) => (
                    <option key={tac.tactic} value={tac.tactic}>
                      {tac.tactic} ({tac.total_alerts})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {filtered.length ? (
              <div className="soc-table-wrap">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Technique ID</th>
                      <th>Technique Name</th>
                      <th>Tactic</th>
                      <th>Alerts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((t) => (
                      <tr
                        key={t.id}
                        onClick={() => selectTechnique(t.id)}
                        className={`cursor-pointer transition-colors ${
                          selected?.id === t.id ? 'bg-surface-raised font-medium' : ''
                        }`}
                      >
                        <td className="font-mono text-[11px] text-text">{t.id}</td>
                        <td>
                          <span className="text-text text-[11.5px] block">{t.name}</span>
                          <span className="text-[10px] text-muted line-clamp-1">{t.description}</span>
                        </td>
                        <td className="font-mono text-[10.5px] text-muted">{t.tactic}</td>
                        <td className="font-mono text-[11px] text-text">
                          {t.alert_count ?? 0}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState>No techniques match the current filter.</EmptyState>
            )}
          </section>

          {/* Selected Technique Inspector */}
          <section className="panel">
            <div className="panel-header">
              <h2>Technique Detail</h2>
              {selected && (
                <span className="font-mono text-[11px] text-muted px-1.5 py-0.5 rounded bg-surface-raised border border-border">
                  {selected.id}
                </span>
              )}
            </div>

            {selected ? (
              <div className="p-4 space-y-3">
                <div>
                  <span className="text-[10.5px] text-faint block mb-0.5">
                    Tactic: {selected.tactic}
                  </span>
                  <strong className="text-[13px] block text-text">{selected.name}</strong>
                  <p className="text-[11.5px] text-muted mt-1 leading-relaxed">{selected.description}</p>
                  {selected.url && (
                    <a
                      href={selected.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-[11px] font-mono text-muted hover:underline mt-1.5"
                    >
                      MITRE Reference <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>

                <div className="pt-2 border-t border-border prop-list">
                  <div className="prop-row">
                    <span>Alerts Observed:</span>
                    <strong className="font-mono text-[11px]">{selected.alert_count ?? 0}</strong>
                  </div>
                  <div className="prop-row">
                    <span>Associated Incidents:</span>
                    <strong className="font-mono text-[11px]">{selected.incident_count ?? 0}</strong>
                  </div>
                </div>

                {selected.recent_alerts && selected.recent_alerts.length > 0 && (
                  <div className="pt-2 border-t border-border">
                    <span className="text-[10.5px] text-faint block mb-1.5">
                      Recent Alert Firings
                    </span>
                    <div className="space-y-1">
                      {selected.recent_alerts.map((al) => (
                        <div
                          key={al.id}
                          className="p-2 rounded bg-surface-raised border border-border flex items-center justify-between text-[11px]"
                        >
                          <div>
                            <span className="block text-text">{titleCase(al.alert_type)}</span>
                            <span className="font-mono text-[10px] text-muted">
                              {al.source_ip ?? 'Unknown'} → {al.target_host ?? 'Unknown'}
                            </span>
                          </div>
                          <SeverityBadge value={al.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="quiet-empty">Select a technique to view details.</div>
            )}
          </section>
        </div>
      )}
    </ThreatLensShell>
  )
}
