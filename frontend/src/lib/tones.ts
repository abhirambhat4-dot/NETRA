import type {
  AssetPosture,
  AssetStatus,
  AuthorizationStatus,
  ContainmentStatus,
  DecisionStatus,
  EventStatus,
  HealthStatus,
  IncidentStatus,
  MemoryOutcome,
  Severity,
} from '@/api/types'

/**
 * NETRA visual semantics. Every badge, dot, gauge and chart that expresses
 * risk or state resolves to one of these tones — never hard-code colours.
 */
export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'accent' | 'neutral'

interface ToneStyle {
  text: string
  soft: string // tinted background
  border: string
  solid: string // dots, bars, fills
  stroke: string // SVG stroke
  glow: string
}

// Full literal class names so Tailwind can detect them.
export const toneStyles: Record<Tone, ToneStyle> = {
  critical: {
    text: 'text-critical',
    soft: 'bg-critical/10',
    border: 'border-critical/25',
    solid: 'bg-critical',
    stroke: 'stroke-critical',
    glow: 'shadow-[0_0_10px_0] shadow-critical/60',
  },
  high: {
    text: 'text-high',
    soft: 'bg-high/10',
    border: 'border-high/25',
    solid: 'bg-high',
    stroke: 'stroke-high',
    glow: 'shadow-[0_0_10px_0] shadow-high/60',
  },
  medium: {
    text: 'text-medium',
    soft: 'bg-medium/10',
    border: 'border-medium/25',
    solid: 'bg-medium',
    stroke: 'stroke-medium',
    glow: 'shadow-[0_0_10px_0] shadow-medium/60',
  },
  low: {
    text: 'text-low',
    soft: 'bg-low/10',
    border: 'border-low/25',
    solid: 'bg-low',
    stroke: 'stroke-low',
    glow: 'shadow-[0_0_10px_0] shadow-low/60',
  },
  info: {
    text: 'text-info',
    soft: 'bg-info/10',
    border: 'border-info/25',
    solid: 'bg-info',
    stroke: 'stroke-info',
    glow: 'shadow-[0_0_10px_0] shadow-info/60',
  },
  accent: {
    text: 'text-primary',
    soft: 'bg-primary/10',
    border: 'border-primary/25',
    solid: 'bg-primary',
    stroke: 'stroke-primary',
    glow: 'shadow-[0_0_10px_0] shadow-primary/60',
  },
  neutral: {
    text: 'text-muted-foreground',
    soft: 'bg-muted/60',
    border: 'border-border',
    solid: 'bg-muted-foreground',
    stroke: 'stroke-muted-foreground',
    glow: '',
  },
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export const severityTone: Record<Severity, Tone> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
}

/** Risk score (0–100) → severity band. Keep in sync with backend scoring. */
export function riskToSeverity(score: number): Severity {
  if (score >= 85) return 'CRITICAL'
  if (score >= 65) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  if (score >= 15) return 'LOW'
  return 'INFO'
}

// ---------------------------------------------------------------------------
// Status (all workflow status enums share one lookup)
// ---------------------------------------------------------------------------

export type AnyStatus =
  | IncidentStatus
  | EventStatus
  | DecisionStatus
  | AuthorizationStatus
  | ContainmentStatus
  | AssetStatus
  | HealthStatus
  | MemoryOutcome
  | AssetPosture

interface StatusMeta {
  label: string
  tone: Tone
  pulse?: boolean // live / in-flight states
}

export const statusMeta: Record<AnyStatus, StatusMeta> = {
  // Incident
  NEW: { label: 'New', tone: 'info' },
  INVESTIGATING: { label: 'Investigating', tone: 'accent', pulse: true },
  AWAITING_AUTHORIZATION: { label: 'Awaiting Authorization', tone: 'medium', pulse: true },
  CONTAINING: { label: 'Containing', tone: 'high', pulse: true },
  CONTAINED: { label: 'Contained', tone: 'low' },
  RESOLVED: { label: 'Resolved', tone: 'neutral' },
  FALSE_POSITIVE: { label: 'False Positive', tone: 'neutral' },
  // Event
  CORRELATED: { label: 'Correlated', tone: 'accent' },
  DISMISSED: { label: 'Dismissed', tone: 'neutral' },
  // Decision / Authorization
  PENDING_AUTHORIZATION: { label: 'Pending Authorization', tone: 'medium', pulse: true },
  PENDING: { label: 'Pending', tone: 'medium' },
  OTP_SENT: { label: 'OTP Sent', tone: 'accent', pulse: true },
  APPROVED: { label: 'Approved', tone: 'low' },
  REJECTED: { label: 'Rejected', tone: 'critical' },
  EXPIRED: { label: 'Expired', tone: 'neutral' },
  // Containment
  IN_PROGRESS: { label: 'In Progress', tone: 'accent', pulse: true },
  EXECUTED: { label: 'Executed', tone: 'info' },
  VERIFIED: { label: 'Verified', tone: 'low' },
  FAILED: { label: 'Failed', tone: 'critical' },
  ROLLED_BACK: { label: 'Rolled Back', tone: 'neutral' },
  // Asset
  ONLINE: { label: 'Online', tone: 'low' },
  ISOLATED: { label: 'Isolated', tone: 'high' },
  OFFLINE: { label: 'Offline', tone: 'neutral' },
  // Health
  HEALTHY: { label: 'Healthy', tone: 'low' },
  DEGRADED: { label: 'Degraded', tone: 'medium', pulse: true },
  DOWN: { label: 'Down', tone: 'critical', pulse: true },
  // Memory
  ESCALATED: { label: 'Escalated', tone: 'high' },
  // Asset posture
  AT_RISK: { label: 'At Risk', tone: 'critical', pulse: true },
  MONITORED: { label: 'Monitored', tone: 'medium' },
  SECURE: { label: 'Secure', tone: 'low' },
}
