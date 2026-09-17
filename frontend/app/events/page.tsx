'use client'

import { useEffect, useMemo, useState } from 'react'
import { RefreshCw, Terminal } from 'lucide-react'
import { api, type Event } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

export default function EventsPage() {
  const [events, setEvents] = useState<Event[]>([])
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)

  const fetchEvents = () => {
    setLoading(true)
    setError(null)
    api.events(150)
      .then((data) => {
        setEvents(data)
        if (data.length > 0 && !selectedEvent) {
          setSelectedEvent(data[0])
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to load security events.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchEvents()
  }, [])

  const filtered = useMemo(
    () =>
      events.filter((event) =>
        `${event.event_type} ${event.host} ${event.source_ip} ${event.username} ${event.raw_event}`
          .toLowerCase()
          .includes(q.toLowerCase())
      ),
    [events, q]
  )

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <h1>Security Events Log</h1>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={fetchEvents}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Ingested Telemetry ({filtered.length})</h2>
            <div className="toolbar">
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter events..."
              />
            </div>
          </div>

          {error ? (
            <ErrorState error={error} retry={fetchEvents} />
          ) : loading ? (
            <LoadingState label="Loading telemetry logs..." />
          ) : filtered.length ? (
            <div className="soc-table-wrap">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Event Type</th>
                    <th>Source IP</th>
                    <th>Target Host</th>
                    <th>User</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((event) => (
                    <tr
                      key={event.id}
                      onClick={() => setSelectedEvent(event)}
                      className={`cursor-pointer transition-colors ${
                        selectedEvent?.id === event.id ? 'bg-surface-raised font-medium' : ''
                      }`}
                    >
                      <td>
                        <SeverityBadge value={event.severity} />
                      </td>
                      <td className="font-mono text-[11px] text-text">
                        {titleCase(event.event_type)}
                      </td>
                      <td className="font-mono text-[11px] text-muted">{event.source_ip ?? '-'}</td>
                      <td className="font-mono text-[11px] text-muted">{event.host}</td>
                      <td className="font-mono text-[11px] text-muted">{event.username ?? '-'}</td>
                      <td className="font-mono text-[10px] text-muted">{formatDate(event.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>No events match your filter.</EmptyState>
          )}
        </section>

        {/* Selected Event Details */}
        <section className="panel">
          <div className="panel-header">
            <h2>Event Record</h2>
            {selectedEvent && <SeverityBadge value={selectedEvent.severity} />}
          </div>

          {selectedEvent ? (
            <div className="p-4 space-y-4">
              <div>
                <strong className="text-[13px] block text-text">{titleCase(selectedEvent.event_type)}</strong>
                <span className="font-mono text-[10.5px] text-faint block mt-0.5">{selectedEvent.id}</span>
              </div>

              <div className="pt-2 border-t border-border prop-list">
                <div className="prop-row">
                  <span>Source IP:</span>
                  <strong className="font-mono text-[11px]">{selectedEvent.source_ip ?? 'None'}</strong>
                </div>
                <div className="prop-row">
                  <span>Target Host:</span>
                  <strong className="font-mono text-[11px]">{selectedEvent.host}</strong>
                </div>
                <div className="prop-row">
                  <span>User Principal:</span>
                  <strong className="font-mono text-[11px]">{selectedEvent.username ?? 'None'}</strong>
                </div>
                <div className="prop-row">
                  <span>Timestamp:</span>
                  <strong className="font-mono text-[11px]">{formatDate(selectedEvent.timestamp)}</strong>
                </div>
              </div>

              {selectedEvent.raw_event && (
                <div className="pt-2 border-t border-border">
                  <span className="text-[10px] text-faint block mb-1 font-medium">
                    Raw Payload
                  </span>
                  <div className="p-2.5 rounded bg-surface-raised border border-border font-mono text-[11px] text-muted leading-relaxed break-all">
                    {selectedEvent.raw_event}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="quiet-empty">Select an event to view details.</div>
          )}
        </section>
      </div>
    </ThreatLensShell>
  )
}
