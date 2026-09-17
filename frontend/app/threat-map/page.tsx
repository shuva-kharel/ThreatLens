'use client'

import Link from 'next/link'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArrowRight, RefreshCw } from 'lucide-react'

import { api, type ThreatMapData, type ThreatMapRelationship } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

export default function ThreatMapPage() {
  const [data, setData] = useState<ThreatMapData | null>(null)
  const [selected, setSelected] = useState<ThreatMapRelationship | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadData = useCallback((quiet = false) => {
    if (!quiet) setLoading(true)
    setError(null)
    api.threatMap()
      .then((result) => {
        setData(result)
        setSelected((current) => {
          if (!current) return result.relationships[0] ?? null
          return result.relationships.find((item) =>
            item.source_ip === current.source_ip &&
            item.target === current.target &&
            item.attack_type === current.attack_type
          ) ?? result.relationships[0] ?? null
        })
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load threat relationships.'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    loadData()
    const timer = window.setInterval(() => loadData(true), 15000)
    return () => window.clearInterval(timer)
  }, [loadData])

  const relationships = data?.relationships ?? []
  const sources = useMemo(() => new Set(relationships.map((item) => item.source_ip)).size, [relationships])
  const targets = useMemo(() => new Set(relationships.map((item) => item.target)).size, [relationships])
  const incidents = useMemo(() => new Set(relationships.flatMap((item) => item.incident_ids)).size, [relationships])

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div><h1>Threat Map</h1></div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={() => loadData()} disabled={loading}>
            <RefreshCw className={`w-3.5 h-3.5 mr-1 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </section>

      {error ? <ErrorState error={error} retry={() => loadData()} /> : loading && !data ? (
        <LoadingState label="Aggregating stored threat telemetry..." />
      ) : (
        <>
          <section className="metric-grid">
            <article className="metric-card-clean"><strong>{relationships.length}</strong><span>Attack Relationships</span><small>Alert-derived groupings</small></article>
            <article className="metric-card-clean"><strong>{sources}</strong><span>Observed Sources</span><small>Public and internal</small></article>
            <article className="metric-card-clean"><strong>{targets}</strong><span>Target Assets</span><small>Telemetry destinations</small></article>
            <article className="metric-card-clean"><strong>{incidents}</strong><span>Linked Incidents</span><small>Correlated investigations</small></article>
          </section>

          {relationships.length === 0 ? (
            <section className="panel"><EmptyState>No detected attack relationships exist in stored telemetry.</EmptyState></section>
          ) : (
            <div className="dashboard-grid">
              <section className="panel">
                <div className="panel-header">
                  <h2>Observed Source to Target Topology</h2>
                  <small className="text-muted">{data?.geolocation.enabled ? data.geolocation.provider : 'Geolocation not configured'}</small>
                </div>
                <div className="divide-y divide-border">
                  {relationships.map((item) => {
                    const key = `${item.source_ip}:${item.target}:${item.attack_type}`
                    const active = selected && key === `${selected.source_ip}:${selected.target}:${selected.attack_type}`
                    return (
                      <button key={key} className={`w-full p-3 text-left hover:bg-surface-raised ${active ? 'bg-surface-raised' : ''}`} onClick={() => setSelected(item)}>
                        <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3">
                          <div className="min-w-0"><strong className="font-mono text-[11px] block truncate">{item.source_ip}</strong><span className="text-[10px] text-muted">{item.source_network}</span></div>
                          <ArrowRight className="w-4 h-4 text-muted" />
                          <div className="min-w-0 text-right"><strong className="font-mono text-[11px] block truncate">{item.target}</strong><span className="text-[10px] text-muted">{titleCase(item.attack_type)}</span></div>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </section>

              <section className="panel">
                <div className="panel-header"><h2>Relationship Detail</h2></div>
                {selected && (
                  <div className="prop-list">
                    <div className="prop-row"><span>Severity</span><SeverityBadge value={selected.severity} /></div>
                    <div className="prop-row"><span>Source</span><strong className="font-mono">{selected.source_ip}</strong></div>
                    <div className="prop-row"><span>Classification</span><strong>{titleCase(selected.source_classification)}</strong></div>
                    <div className="prop-row"><span>Target</span><strong className="font-mono">{selected.target}</strong></div>
                    <div className="prop-row"><span>Attack type</span><strong>{titleCase(selected.attack_type)}</strong></div>
                    <div className="prop-row"><span>Events / alerts</span><strong>{selected.event_count} / {selected.alert_count}</strong></div>
                    <div className="prop-row"><span>Incidents</span><strong>{selected.incident_count}</strong></div>
                    <div className="prop-row"><span>Last seen</span><strong className="font-mono">{formatDate(selected.last_seen)}</strong></div>
                    <div className="prop-row"><span>MITRE</span><strong className="font-mono">{selected.mitre_techniques.join(', ') || 'None'}</strong></div>
                    <div className="prop-row"><span>Response</span><strong>{selected.response_status.map(titleCase).join(', ') || 'None'}</strong></div>
                    <div className="prop-row"><span>Human escalation</span><strong>{selected.escalation_status.join(', ') || 'None'}</strong></div>
                    {selected.incident_ids[0] && <div className="p-3"><Link href={`/incidents/${selected.incident_ids[0]}`} className="secondary-button inline-flex">Open incident <ArrowRight className="w-3.5 h-3.5 ml-1" /></Link></div>}
                  </div>
                )}
              </section>
            </div>
          )}
        </>
      )}
    </ThreatLensShell>
  )
}
