'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  Bell,
  Crosshair,
  LayoutDashboard,
  ListChecks,
  Menu,
  Network,
  Play,
  Search,
  Settings,
  ShieldAlert,
  X,
  Shield,
  ShieldCheck,
  Bug,
  MapPinned,
} from 'lucide-react'
import {
  api,
  checkHealth,
  wsEventsUrl,
  type Alert,
  type Incident,
  type ResponsePlaybook,
  type VulnerabilityFinding,
} from '@/lib/api'
import { formatDate, titleCase } from './format'

const nav = [
  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { label: 'Incidents', href: '/incidents', icon: ShieldAlert },
  { label: 'Response Center', href: '/response', icon: ShieldCheck },
  { label: 'Vulnerabilities', href: '/vulnerabilities', icon: Bug },
  { label: 'Alerts', href: '/alerts', icon: Bell },
  { label: 'Events', href: '/events', icon: Activity },
  { label: 'Network', href: '/network', icon: Network },
  { label: 'Threat Map', href: '/threat-map', icon: MapPinned },
  { label: 'Detection Rules', href: '/detections', icon: ListChecks },
  { label: 'MITRE ATT&CK', href: '/mitre', icon: Crosshair },
  { label: 'Simulator', href: '/simulator', icon: Play },
]

interface NotificationItem {
  id: string
  type: string
  label: string
  href?: string
  at: string
}

export function ThreatLensShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [connected, setConnected] = useState(false)
  const [liveConnected, setLiveConnected] = useState(false)
  const [theme, setTheme] = useState('dark')
  const [searchOpen, setSearchOpen] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [notifications, setNotifications] = useState<NotificationItem[]>([])
  const receivedMessages = useRef(new Set<string>())

  useEffect(() => {
    const saved = window.localStorage.getItem('threatlens-theme') || 'dark'
    setTheme(saved)
    document.documentElement.dataset.theme = saved
    const check = async () => setConnected(await checkHealth())
    check()
    const timer = window.setInterval(check, 15000)
    return () => window.clearInterval(timer)
  }, [])

  const [playbooks, setPlaybooks] = useState<ResponsePlaybook[]>([])
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityFinding[]>([])

  useEffect(() => {
    Promise.allSettled([
      api.incidents(),
      api.alerts(new URLSearchParams({ limit: '25' })),
      api.responsePlaybooks(),
      api.vulnerabilities(),
    ]).then(([incidentResult, alertResult, playbookResult, vulnResult]) => {
      if (incidentResult.status === 'fulfilled') setIncidents(incidentResult.value)
      if (alertResult.status === 'fulfilled') setAlerts(alertResult.value)
      if (playbookResult.status === 'fulfilled') setPlaybooks(playbookResult.value)
      if (vulnResult.status === 'fulfilled') setVulnerabilities(vulnResult.value)
    })
  }, [pathname])

  useEffect(() => {
    let socket: WebSocket | null = null
    let retryTimer: number | undefined
    let delay = 1000
    let closed = false

    const connect = () => {
      try {
        socket = new WebSocket(wsEventsUrl)
        socket.onopen = () => {
          delay = 1000
          setLiveConnected(true)
        }
        socket.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data) as {
              type?: string
              data?: { id?: string; incident_id?: string; alert_type?: string; title?: string; event_type?: string }
            }
            if (!message.type || message.type === 'ping' || message.type === 'connected') return

            const messageKey = `${message.type}:${message.data?.id ?? message.data?.incident_id ?? event.data}`
            if (receivedMessages.current.has(messageKey)) return
            receivedMessages.current.add(messageKey)
            if (receivedMessages.current.size > 500) {
              receivedMessages.current = new Set(Array.from(receivedMessages.current).slice(-250))
            }

            const messageType = message.type
            const href = message.data?.incident_id
              ? `/incidents/${message.data.incident_id}`
              : messageType.includes('incident') && message.data?.id
              ? `/incidents/${message.data.id}`
              : messageType.includes('alert')
              ? '/alerts'
              : undefined

            const label = message.data?.title || message.data?.alert_type || message.data?.event_type || titleCase(messageType)

            setNotifications((items) => [
              {
                id: crypto.randomUUID(),
                type: messageType,
                href,
                label,
                at: new Date().toISOString(),
              },
              ...items,
            ].slice(0, 15))
            window.dispatchEvent(new CustomEvent('threatlens:telemetry', { detail: message }))
          } catch {
            // ignore
          }
        }
        socket.onerror = () => setLiveConnected(false)
        socket.onclose = () => {
          setLiveConnected(false)
          if (!closed) {
            retryTimer = window.setTimeout(connect, delay)
            delay = Math.min(delay * 2, 15000)
          }
        }
      } catch {
        setLiveConnected(false)
        if (!closed) {
          retryTimer = window.setTimeout(connect, delay)
          delay = Math.min(delay * 2, 15000)
        }
      }
    }

    connect()
    return () => {
      closed = true
      if (retryTimer) window.clearTimeout(retryTimer)
      socket?.close()
    }
  }, [])

  const results = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return []
    return [
      ...incidents
        .filter((item) => `${item.id} ${item.title} ${item.severity} ${item.status}`.toLowerCase().includes(needle))
        .map((item) => ({
          label: item.title,
          detail: `Incident · ${titleCase(item.severity)} · ${formatDate(item.last_seen)}`,
          href: `/incidents/${item.id}`,
        })),
      ...alerts
        .filter((item) => `${item.id} ${item.alert_type} ${item.description} ${item.source_ip} ${item.target_host} ${item.mitre_technique}`.toLowerCase().includes(needle))
        .map((item) => ({
          label: titleCase(item.alert_type),
          detail: `Alert · ${item.mitre_technique ?? 'No MITRE'} · ${formatDate(item.created_at)}`,
          href: item.incident_id ? `/incidents/${item.incident_id}` : '/alerts',
        })),
      ...playbooks
        .filter((item) => `${item.id} ${item.name} ${item.description} ${item.action_type}`.toLowerCase().includes(needle))
        .map((item) => ({
          label: item.name,
          detail: `Playbook [${item.id}] · ${titleCase(item.action_type)}`,
          href: '/response',
        })),
      ...vulnerabilities
        .filter((item) => `${item.cve_id} ${item.title} ${item.affected_product}`.toLowerCase().includes(needle))
        .map((item) => ({
          label: `${item.cve_id}: ${item.title}`,
          detail: `Vulnerability · ${titleCase(item.severity)} · ${item.affected_product}`,
          href: '/vulnerabilities',
        })),
    ].slice(0, 10)
  }, [alerts, incidents, playbooks, vulnerabilities, query])

  const selectTheme = (next: string) => {
    setTheme(next)
    document.documentElement.dataset.theme = next
    window.localStorage.setItem('threatlens-theme', next)
  }

  return (
    <div className="app-shell">
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="brand-row">
          <Shield className="w-4 h-4 text-muted" />
          <strong>ThreatLens</strong>
          <button className="icon-button mobile-close" onClick={() => setSidebarOpen(false)} aria-label="Close navigation">
            <X />
          </button>
        </div>

        <p className="nav-label">Investigation</p>
        <nav className="main-nav" aria-label="Primary navigation">
          {nav.map(({ label, href, icon: Icon }) => {
            const isActive = pathname === href || pathname.startsWith(`${href}/`)
            return (
              <Link
                key={href}
                className={`nav-item ${isActive ? 'active' : ''}`}
                href={href}
                onClick={() => setSidebarOpen(false)}
              >
                <Icon />
                <span>{label}</span>
              </Link>
            )
          })}
        </nav>

        <div className="sidebar-bottom">
          <Link className={`nav-item ${pathname === '/settings' ? 'active' : ''}`} href="/settings">
            <Settings />
            <span>Settings</span>
          </Link>
          <div className="connection-card">
            <span className="connection-dot" />
            <div>
              <strong>{connected ? 'ThreatLens API Online' : 'ThreatLens API Offline'}</strong>
              <small>{liveConnected ? 'WebSocket Live' : connected ? 'REST Polling' : 'Connecting...'}</small>
            </div>
          </div>
          <div className="theme-row">
            <span>Theme</span>
            <select value={theme} onChange={(event) => selectTheme(event.target.value)} aria-label="Select appearance">
              <option value="dark">Dark (Zinc)</option>
              <option value="light">Light</option>
              <option value="contrast">High Contrast</option>
            </select>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <button className="icon-button menu-button" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
            <Menu />
          </button>
          <div className="breadcrumbs">
            <span>ThreatLens</span>
            <span>/</span>
            <strong>
              {nav.find((item) => pathname === item.href || pathname.startsWith(`${item.href}/`))?.label ??
                (pathname === '/settings' ? 'Settings' : 'Console')}
            </strong>
          </div>

          <div className="top-actions">
            <div className={`backend-status ${connected ? 'online' : ''}`}>
              <span />
              {connected ? 'Connected' : 'Offline'}
            </div>
            <button className="icon-button" onClick={() => setSearchOpen((open) => !open)} aria-label="Search">
              <Search />
            </button>
            <button className="icon-button" onClick={() => setNotificationsOpen((open) => !open)} aria-label="Notifications">
              <Bell />
              {notifications.length > 0 && <i />}
            </button>
          </div>
        </header>

        {searchOpen && (
          <div className="floating-panel">
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              autoFocus
              placeholder="Search incidents, alerts, or IPs..."
            />
            {results.length ? (
              results.map((result) => (
                <button
                  key={result.href + result.label}
                  onClick={() => {
                    router.push(result.href)
                    setSearchOpen(false)
                  }}
                >
                  <strong>{result.label}</strong>
                  <span>{result.detail}</span>
                </button>
              ))
            ) : (
              <small className="text-muted p-2 text-[11px] font-mono">
                {query ? 'No matching records.' : 'Type to search records.'}
              </small>
            )}
          </div>
        )}

        {notificationsOpen && (
          <div className="floating-panel">
            <div className="flex items-center justify-between pb-1 border-b border-border text-[11px] font-mono text-muted">
              <span>Telemetry Stream</span>
              <span>{notifications.length} events</span>
            </div>
            {notifications.length ? (
              notifications.map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    if (item.href) router.push(item.href)
                    setNotificationsOpen(false)
                  }}
                >
                  <strong className="text-[11px]">{titleCase(item.type)}</strong>
                  <span>
                    {item.label} · {formatDate(item.at)}
                  </span>
                </button>
              ))
            ) : (
              <small className="text-muted p-2 text-[11px] font-mono">No live events in this session.</small>
            )}
          </div>
        )}

        <div className="content-wrap">{children}</div>
      </main>
    </div>
  )
}
