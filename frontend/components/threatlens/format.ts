export function titleCase(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

export const DISPLAY_TIME_ZONE = 'Asia/Kathmandu'

export function parseTimestamp(value: string) {
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value)
  return new Date(hasZone ? value : `${value}Z`)
}

export function timestampMs(value?: string | null) {
  if (!value) return Number.NaN
  return parseTimestamp(value).getTime()
}

export function formatDate(value?: string | null) {
  if (!value) return 'Unavailable'
  const date = parseTimestamp(value)
  if (Number.isNaN(date.getTime())) return 'Unavailable'
  return new Intl.DateTimeFormat(undefined, {
    timeZone: DISPLAY_TIME_ZONE,
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

export function formatTime(value?: string | null, includeSeconds = false) {
  if (!value) return 'Unavailable'
  const date = parseTimestamp(value)
  if (Number.isNaN(date.getTime())) return 'Unavailable'
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: DISPLAY_TIME_ZONE,
    hour: '2-digit',
    minute: '2-digit',
    second: includeSeconds ? '2-digit' : undefined,
    hour12: false,
  }).format(date)
}

export function entityList(values?: string[] | null) {
  return values?.length ? values.join(', ') : 'Unavailable'
}

export function durationMinutes(first?: string | null, last?: string | null) {
  if (!first || !last) return 'Unavailable'
  const minutes = Math.max(0, Math.round((timestampMs(last) - timestampMs(first)) / 60000))
  return `${minutes} min`
}
