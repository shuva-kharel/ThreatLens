import type { ReactNode } from 'react'
import type { Severity } from '@/lib/api'
import { titleCase } from './format'
import { Loader2 } from 'lucide-react'

export function SeverityBadge({ value }: { value: Severity | string | null | undefined }) {
  const normalized = (value || 'unknown').toLowerCase()
  const displayClass = ['critical', 'high', 'medium', 'low'].includes(normalized) ? normalized : 'unknown'
  return <span className={`sev-badge ${displayClass}`}>{titleCase(value || 'Unknown')}</span>
}

export function EmptyState({ title, description, children }: { title?: string; description?: string; children?: ReactNode }) {
  return (
    <div className="quiet-empty">
      {title && <strong className="block text-text mb-1">{title}</strong>}
      {description && <p className="text-muted text-[11px] mb-1">{description}</p>}
      {children}
      {!title && !description && !children && 'No records found.'}
    </div>
  )
}

export function LoadingState({ label }: { label: string }) {
  return (
    <div className="quiet-empty flex items-center justify-center gap-2">
      <Loader2 className="w-3.5 h-3.5 animate-spin text-muted" />
      <span>{label}</span>
    </div>
  )
}

export function ErrorState({ error, retry }: { error: string; retry?: () => void }) {
  return (
    <div className="error-banner">
      <div>
        <strong>Unable to load data</strong>
        <p>{error}</p>
      </div>
      {retry && (
        <button className="secondary-button" onClick={retry}>
          Retry
        </button>
      )}
    </div>
  )
}
