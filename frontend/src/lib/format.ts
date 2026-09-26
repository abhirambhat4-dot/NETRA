import type { ContainmentActionType } from '@/api/types'

/** "10:42:18" (UTC) */
export function formatClock(iso: string): string {
  return new Date(iso).toISOString().slice(11, 19)
}

/** "26 Sep, 10:42" (UTC) */
export function formatDateTime(iso: string): string {
  const d = new Date(iso)
  const day = d.getUTCDate()
  const month = d.toLocaleString('en-GB', { month: 'short', timeZone: 'UTC' })
  return `${day} ${month}, ${d.toISOString().slice(11, 16)}`
}

/** "4m ago", "3h ago", "2d ago" */
export function timeAgo(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

export function formatNumber(n: number): string {
  return n >= 10_000 ? `${(n / 1000).toFixed(1)}k` : n.toLocaleString('en-US')
}

export function formatPercent(v: number, digits = 0): string {
  return `${(v * 100).toFixed(digits)}%`
}

export const ACTION_LABEL: Record<ContainmentActionType, string> = {
  BLOCK_IP: 'Block IP',
  ISOLATE_HOST: 'Isolate host',
  DISABLE_ACCOUNT: 'Disable account',
  RATE_LIMIT: 'Rate limit',
  MONITOR: 'Monitor',
}
