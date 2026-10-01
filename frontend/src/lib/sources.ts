import type { LucideIcon } from 'lucide-react'
import { Brain, Bug, Globe, Layers, Radar, UserRound } from 'lucide-react'
import type { BackendEventSource, DetectionSource } from '@/api/types'

interface SourceMeta {
  label: string
  short: string
  icon: LucideIcon
  /** CSS colour for charts — fixed categorical order, validated CVD-safe. */
  color: string
  dot: string
}

export const detectionSourceMeta: Record<DetectionSource, SourceMeta> = {
  SURICATA: { label: 'Suricata IDS', short: 'Suricata', icon: Radar, color: 'var(--chart-1)', dot: 'bg-chart-1' },
  THREAT_INTEL: { label: 'Threat Intelligence', short: 'Threat Intel', icon: Globe, color: 'var(--chart-2)', dot: 'bg-chart-2' },
  ML_ANOMALY: { label: 'ML Anomaly Detector', short: 'ML Detector', icon: Brain, color: 'var(--chart-3)', dot: 'bg-chart-3' },
  HYBRID: { label: 'Correlation Engine', short: 'Correlation', icon: Layers, color: 'var(--chart-4)', dot: 'bg-chart-4' },
}

/** Series order for stacked event charts. */
export const EVENT_SOURCES = ['SURICATA', 'THREAT_INTEL', 'ML_ANOMALY'] as const

export const BACKEND_EVENT_SOURCES: readonly BackendEventSource[] = [
  'SURICATA',
  'ML_ANOMALY',
  'THREAT_INTEL',
  'VULNERABILITY_SCAN',
  'MANUAL',
]

export function eventSourceMeta(source: BackendEventSource | DetectionSource): SourceMeta {
  if (source === 'VULNERABILITY_SCAN') {
    return { label: 'Vulnerability Scan', short: 'Vulnerability', icon: Bug, color: 'var(--chart-5)', dot: 'bg-chart-5' }
  }
  if (source === 'MANUAL') {
    return { label: 'Manual', short: 'Manual', icon: UserRound, color: 'var(--muted-foreground)', dot: 'bg-muted-foreground' }
  }
  return detectionSourceMeta[source as DetectionSource]
}
