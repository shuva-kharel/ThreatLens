'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Activity, Bell, Bug, Crosshair, LayoutDashboard, ListChecks, MapPinned, Menu, Network, Play, Search, Settings, Shield, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import { api, checkHealth, type SearchResponse, type SearchResult } from '@/lib/api'
import { formatDate, titleCase } from './format'
import { useRealtime } from './realtime'

const nav = [
  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard }, { label: 'Incidents', href: '/incidents', icon: ShieldAlert },
  { label: 'Response Center', href: '/response', icon: ShieldCheck }, { label: 'Vulnerabilities', href: '/vulnerabilities', icon: Bug },
  { label: 'Alerts', href: '/alerts', icon: Bell }, { label: 'Events', href: '/events', icon: Activity },
  { label: 'Network', href: '/network', icon: Network }, { label: 'Threat Map', href: '/threat-map', icon: MapPinned },
  { label: 'Detection Rules', href: '/detections', icon: ListChecks }, { label: 'MITRE ATT&CK', href: '/mitre', icon: Crosshair },
  { label: 'Simulator', href: '/simulator', icon: Play },
]
const RECENT_KEY = 'threatlens-recent-searches-v1'

export function ThreatLensShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname(); const router = useRouter()
  const { connected: liveConnected, notifications, unreadCount, markRead, markAllRead } = useRealtime()
  const [sidebarOpen, setSidebarOpen] = useState(false); const [connected, setConnected] = useState(false)
  const [theme, setTheme] = useState('dark'); const [searchOpen, setSearchOpen] = useState(false); const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [query, setQuery] = useState(''); const [searchData, setSearchData] = useState<SearchResponse | null>(null)
  const [searching, setSearching] = useState(false); const [searchError, setSearchError] = useState(false); const [selectedIndex, setSelectedIndex] = useState(0)
  const [recent, setRecent] = useState<string[]>([]); const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const saved = window.localStorage.getItem('threatlens-theme') || 'dark'; setTheme(saved); document.documentElement.dataset.theme = saved
    try { setRecent(JSON.parse(window.localStorage.getItem(RECENT_KEY) ?? '[]')) } catch { setRecent([]) }
    const check = async () => setConnected(await checkHealth()); check(); const timer = window.setInterval(check, 15000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null; const typing = target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setSearchOpen(true) }
      else if (event.key === '/' && !typing && !searchOpen) { event.preventDefault(); setSearchOpen(true) }
      else if (event.key === 'Escape' && searchOpen) setSearchOpen(false)
    }
    window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey)
  }, [searchOpen])

  useEffect(() => {
    if (!searchOpen) return
    window.setTimeout(() => inputRef.current?.focus(), 0)
    const trimmed = query.trim()
    if (trimmed.length < 2) { setSearchData(null); setSearching(false); setSearchError(false); return }
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      setSearching(true); setSearchError(false)
      api.globalSearch(trimmed, controller.signal).then((result) => { setSearchData(result); setSelectedIndex(0) })
        .catch(() => { if (!controller.signal.aborted) setSearchError(true) })
        .finally(() => { if (!controller.signal.aborted) setSearching(false) })
    }, 250)
    return () => { window.clearTimeout(timer); controller.abort() }
  }, [query, searchOpen])

  const groups = useMemo(() => Object.entries(searchData?.results ?? {}).filter(([, items]) => items.length), [searchData])
  const flatResults = useMemo(() => groups.flatMap(([, items]) => items), [groups])
  const openResult = (result: SearchResult) => {
    const next = [query.trim(), ...recent.filter((item) => item !== query.trim())].filter(Boolean).slice(0, 6)
    setRecent(next); window.localStorage.setItem(RECENT_KEY, JSON.stringify(next)); router.push(result.href); setSearchOpen(false)
  }
  const onSearchKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' && flatResults.length) { event.preventDefault(); setSelectedIndex((value) => (value + 1) % flatResults.length) }
    if (event.key === 'ArrowUp' && flatResults.length) { event.preventDefault(); setSelectedIndex((value) => (value - 1 + flatResults.length) % flatResults.length) }
    if (event.key === 'Enter' && flatResults[selectedIndex]) { event.preventDefault(); openResult(flatResults[selectedIndex]) }
  }
  const selectTheme = (next: string) => { setTheme(next); document.documentElement.dataset.theme = next; window.localStorage.setItem('threatlens-theme', next) }

  return <div className="app-shell">
    {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
    <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
      <div className="brand-row"><Shield className="w-4 h-4 text-muted" /><strong>ThreatLens</strong><button className="icon-button mobile-close" onClick={() => setSidebarOpen(false)} aria-label="Close navigation"><X /></button></div>
      <p className="nav-label">Investigation</p><nav className="main-nav" aria-label="Primary navigation">{nav.map(({ label, href, icon: Icon }) => <Link key={href} className={`nav-item ${pathname === href || pathname.startsWith(`${href}/`) ? 'active' : ''}`} href={href} onClick={() => setSidebarOpen(false)}><Icon /><span>{label}</span></Link>)}</nav>
      <div className="sidebar-bottom"><Link className={`nav-item ${pathname === '/settings' ? 'active' : ''}`} href="/settings"><Settings /><span>Settings</span></Link>
        <div className="connection-card"><span className="connection-dot" /><div><strong>{connected ? 'ThreatLens API Online' : 'ThreatLens API Offline'}</strong><small>{liveConnected ? 'WebSocket Live' : connected ? 'Reconnecting live stream' : 'Connecting...'}</small></div></div>
        <div className="theme-row"><span>Theme</span><select value={theme} onChange={(event) => selectTheme(event.target.value)} aria-label="Select appearance"><option value="dark">Dark (Zinc)</option><option value="light">Light</option><option value="contrast">High Contrast</option></select></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><button className="icon-button menu-button" onClick={() => setSidebarOpen(true)} aria-label="Open navigation"><Menu /></button>
        <div className="breadcrumbs"><span>ThreatLens</span><span>/</span><strong>{nav.find((item) => pathname === item.href || pathname.startsWith(`${item.href}/`))?.label ?? (pathname === '/settings' ? 'Settings' : 'Console')}</strong></div>
        <button className="global-search-trigger" onClick={() => setSearchOpen(true)}><Search /><span>Search ThreatLens</span><kbd>Ctrl K</kbd></button>
        <div className="top-actions"><div className={`backend-status ${connected ? 'online' : ''}`}><span />{connected ? 'Connected' : 'Offline'}</div><button className="icon-button" onClick={() => setNotificationsOpen((open) => !open)} aria-label={`${unreadCount} unread notifications`}><Bell />{unreadCount > 0 && <b className="notification-count">{unreadCount > 9 ? '9+' : unreadCount}</b>}</button></div>
      </header>
      {searchOpen && <div className="command-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSearchOpen(false) }}><section className="command-palette" role="dialog" aria-label="Universal ThreatLens search">
        <div className="command-input"><Search /><input ref={inputRef} value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={onSearchKeyDown} placeholder="Search incidents, IPs, agents, MITRE, responses..." /><kbd>Esc</kbd></div>
        <div className="command-results">
          {!query.trim() && <div className="command-empty"><span>Recent searches</span>{recent.length ? recent.map((item) => <button key={item} onClick={() => setQuery(item)}>{item}</button>) : <p>Start typing to search ThreatLens.</p>}{recent.length > 0 && <button className="clear-history" onClick={() => { setRecent([]); window.localStorage.removeItem(RECENT_KEY) }}>Clear history</button>}</div>}
          {query.trim().length === 1 && <div className="command-state">Type one more character to search.</div>}{searching && <div className="command-state">Searching...</div>}
          {searchError && <div className="command-state">Search unavailable. <button onClick={() => setQuery((value) => `${value} `)}>Retry</button></div>}
          {!searching && !searchError && query.trim().length >= 2 && searchData?.total === 0 && <div className="command-state">No results for &quot;{query.trim()}&quot;.</div>}
          {groups.map(([group, items]) => <div className="command-group" key={group}><div className="command-group-label">{titleCase(group)} <span>{items.length}</span></div>{items.map((result) => { const index = flatResults.indexOf(result); return <button key={`${result.entity}:${result.id}`} className={index === selectedIndex ? 'selected' : ''} onMouseEnter={() => setSelectedIndex(index)} onClick={() => openResult(result)}><span><strong>{result.label}</strong><small>{result.detail}</small></span>{result.severity && <i>{String(result.severity).toUpperCase()}</i>}</button> })}</div>)}
        </div></section></div>}
      {notificationsOpen && <div className="floating-panel notification-panel"><div className="notification-header"><span>Notifications</span><button onClick={markAllRead}>Mark all read</button></div>{notifications.length ? notifications.map((item) => <button key={item.id} className={item.read ? '' : 'unread'} onClick={() => { markRead(item.id); if (item.href) router.push(item.href); setNotificationsOpen(false) }}><span className="notification-category">{titleCase(item.category)}</span><strong>{item.label}</strong><small>{item.detail ? `${item.detail} - ` : ''}{formatDate(item.timestamp)}</small></button>) : <small className="command-state">No priority notifications.</small>}</div>}
      <div className="content-wrap">{children}</div>
    </main>
  </div>
}
