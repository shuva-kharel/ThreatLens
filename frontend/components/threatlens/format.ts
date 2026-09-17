export function titleCase(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

export function formatDate(value?: string | null) {
  if (!value) return 'Unavailable'
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}

export function entityList(values?: string[] | null) {
  return values?.length ? values.join(', ') : 'Unavailable'
}

export function durationMinutes(first?: string | null, last?: string | null) {
  if (!first || !last) return 'Unavailable'
  const minutes = Math.max(0, Math.round((new Date(last).getTime() - new Date(first).getTime()) / 60000))
  return `${minutes} min`
}
