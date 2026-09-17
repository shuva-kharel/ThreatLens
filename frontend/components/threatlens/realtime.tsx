'use client'

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'

import { api, wsEventsUrl, type SocActivityItem } from '@/lib/api'

export interface SocNotification extends SocActivityItem {
  category: string
  read: boolean
}

interface RealtimeContextValue {
  connected: boolean
  activity: SocActivityItem[]
  notifications: SocNotification[]
  unreadCount: number
  markRead: (id: string) => void
  markAllRead: () => void
}

const RealtimeContext = createContext<RealtimeContextValue | null>(null)
const NOTIFICATION_KEY = 'threatlens-notifications-v1'

type SocketMessage = {
  type?: string
  data?: Record<string, unknown>
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

export function activityFromMessage(message: SocketMessage): SocActivityItem | null {
  if (!message.type || !message.data) return null
  const data = message.data
  const type = message.type === 'alert' ? 'detection' : message.type
  const incidentId = stringValue(data.incident_id) ?? (type.includes('incident') ? stringValue(data.id) : undefined)
  const timestamp = stringValue(data.timestamp) ?? stringValue(data.created_at) ?? stringValue(data.updated_at) ?? new Date().toISOString()
  const label = stringValue(data.title) ?? stringValue(data.alert_type) ?? stringValue(data.event_type) ?? stringValue(data.status) ?? type
  const source = stringValue(data.source_ip)
  const target = stringValue(data.host) ?? stringValue(data.target_host) ?? stringValue(data.target)
  const identity = stringValue(data.execution_id) ?? stringValue(data.id) ?? incidentId ?? `${label}:${timestamp}`
  return {
    id: `${type}:${identity}`,
    type,
    label,
    detail: source || target ? `${source ?? 'Local'} -> ${target ?? 'Unknown'}` : stringValue(data.reason),
    timestamp,
    severity: stringValue(data.severity),
    href: incidentId ? `/incidents/${incidentId}` : type.includes('response') ? '/response' : type === 'event' ? '/events' : undefined,
    stage: type === 'event' ? 'observe' : type === 'detection' ? 'detect' : type.includes('incident') ? 'correlate' : type.includes('response') ? 'respond' : type.includes('verif') ? 'verify' : undefined,
  }
}

export function importantNotification(item: SocActivityItem): SocNotification | null {
  const failed = item.type.includes('failed') || item.label.toLowerCase().includes('failed')
  const approval = item.label.toLowerCase().includes('approval')
  const important = item.severity === 'critical' || item.type.includes('escalat') || failed || approval || item.type === 'agent_offline'
  if (!important) return null
  return { ...item, category: item.type, read: false }
}

export function RealtimeProvider({ children }: { children: React.ReactNode }) {
  const [connected, setConnected] = useState(false)
  const [activity, setActivity] = useState<SocActivityItem[]>([])
  const [notifications, setNotifications] = useState<SocNotification[]>([])
  const received = useRef(new Set<string>())

  useEffect(() => {
    try {
      const stored = JSON.parse(window.localStorage.getItem(NOTIFICATION_KEY) ?? '[]') as SocNotification[]
      setNotifications(Array.isArray(stored) ? stored.slice(0, 50) : [])
    } catch {
      setNotifications([])
    }
    api.activity().then((result) => {
      setActivity(result.activity)
      const important = result.activity.map(importantNotification).filter((item): item is SocNotification => item !== null)
      setNotifications((items) => [...important.filter((item) => !items.some((existing) => existing.id === item.id)), ...items].slice(0, 50))
    }).catch(() => undefined)
  }, [])

  useEffect(() => {
    window.localStorage.setItem(NOTIFICATION_KEY, JSON.stringify(notifications.slice(0, 50)))
  }, [notifications])

  useEffect(() => {
    let socket: WebSocket | null = null
    let retryTimer: number | undefined
    let delay = 1000
    let stopped = false

    const connect = () => {
      socket = new WebSocket(wsEventsUrl)
      socket.onopen = () => { delay = 1000; setConnected(true) }
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as SocketMessage
          if (!message.type || message.type === 'ping' || message.type === 'connected') return
          const item = activityFromMessage(message)
          if (!item || received.current.has(item.id)) return
          received.current.add(item.id)
          if (received.current.size > 1000) received.current = new Set(Array.from(received.current).slice(-500))
          setActivity((items) => [item, ...items.filter((existing) => existing.id !== item.id)].slice(0, 100))
          const notification = importantNotification(item)
          if (notification) setNotifications((items) => [notification, ...items.filter((existing) => existing.id !== notification.id)].slice(0, 50))
          window.dispatchEvent(new CustomEvent('threatlens:telemetry', { detail: message }))
        } catch {
          // Malformed messages are ignored; the socket remains healthy.
        }
      }
      socket.onerror = () => setConnected(false)
      socket.onclose = () => {
        setConnected(false)
        if (!stopped) {
          retryTimer = window.setTimeout(connect, delay)
          delay = Math.min(delay * 2, 15000)
        }
      }
    }
    connect()
    return () => {
      stopped = true
      if (retryTimer) window.clearTimeout(retryTimer)
      socket?.close()
    }
  }, [])

  const markRead = useCallback((id: string) => setNotifications((items) => items.map((item) => item.id === id ? { ...item, read: true } : item)), [])
  const markAllRead = useCallback(() => setNotifications((items) => items.map((item) => ({ ...item, read: true }))), [])
  const value = useMemo(() => ({ connected, activity, notifications, unreadCount: notifications.filter((item) => !item.read).length, markRead, markAllRead }), [activity, connected, markAllRead, markRead, notifications])
  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>
}

export function useRealtime() {
  const value = useContext(RealtimeContext)
  if (!value) throw new Error('useRealtime must be used inside RealtimeProvider')
  return value
}
