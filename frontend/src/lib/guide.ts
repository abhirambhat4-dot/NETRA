import { ROUTES } from './navigation'

/**
 * NETRA Guide — contextual, per-page guidance shown by the robot assistant.
 * MOCK persistence: dismissals live in sessionStorage (reset per browser
 * session); the auto-tip preference lives in localStorage. Storage may be
 * unavailable, so every access is guarded.
 */

export type GuideKey =
  | 'login'
  | 'briefing'
  | 'dashboard'
  | 'events'
  | 'incidents'
  | 'incident'
  | 'assets'
  | 'threatIntelligence'
  | 'cyberMemory'
  | 'settings'

export type GuideTone = 'normal' | 'warning' | 'critical'

export interface GuideContent {
  /** Short context label, e.g. "Incident Prioritization". */
  context: string
  message: string
  /** `data-guide-target` of the section "Show me" points at. */
  target?: string
  targetLabel?: string
}

export const GUIDE: Record<GuideKey, GuideContent> = {
  login: { context: 'Secure Command Access', message: 'Authenticate to enter NETRA.' },
  briefing: {
    context: 'Security Briefing',
    message: 'NETRA transforms detections into explainable security decisions.',
    target: 'decision-pipeline',
    targetLabel: 'Decision pipeline',
  },
  dashboard: {
    context: 'Command Center',
    message: 'Start with Security Posture to understand current system risk.',
    target: 'security-posture',
    targetLabel: 'Security posture',
  },
  events: {
    context: 'Security Events',
    message: 'Security Events are the raw signals NETRA uses to understand activity.',
    target: 'event-stream',
    targetLabel: 'Event stream',
  },
  incidents: {
    context: 'Incident Prioritization',
    message: 'NETRA prioritizes incidents using contextual risk, not severity alone.',
    target: 'incident-queue',
    targetLabel: 'Incident queue',
  },
  incident: {
    context: 'Incident Investigation',
    message: 'Review why NETRA prioritised this incident before authorizing action.',
    target: 'risk-rationale',
    targetLabel: 'Risk rationale',
  },
  assets: {
    context: 'Asset Context',
    message: 'Asset criticality and exposure influence contextual risk.',
    target: 'asset-inventory',
    targetLabel: 'Asset inventory',
  },
  threatIntelligence: {
    context: 'Threat Intelligence',
    message: 'Threat indicators provide additional context for observed activity.',
    target: 'indicators',
    targetLabel: 'Indicators',
  },
  cyberMemory: {
    context: 'Cyber Memory',
    message: 'Cyber Memory records decisions, outcomes and lessons for future response.',
    target: 'memory-trail',
    targetLabel: 'Decision trail',
  },
  settings: { context: 'Settings', message: 'Manage your NETRA environment and operator preferences.' },
}

/** Resolve the guide for a pathname; unknown routes get no guide. */
export function guideKeyFor(pathname: string): GuideKey | null {
  if (pathname === ROUTES.login) return 'login'
  if (pathname === ROUTES.briefing) return 'briefing'
  if (pathname === '/' || pathname === ROUTES.dashboard) return 'dashboard'
  if (pathname === ROUTES.events) return 'events'
  if (pathname === ROUTES.incidents) return 'incidents'
  if (pathname.startsWith(`${ROUTES.incidents}/`)) return 'incident'
  if (pathname === ROUTES.assets) return 'assets'
  if (pathname === ROUTES.threatIntelligence) return 'threatIntelligence'
  if (pathname === ROUTES.cyberMemory) return 'cyberMemory'
  if (pathname === ROUTES.settings) return 'settings'
  return null
}

// ---------------------------------------------------------------------------

const DISMISSED_KEY = 'netra.guide.dismissed'
const AUTO_KEY = 'netra.guide.autoTips'

function readDismissed(): GuideKey[] {
  try {
    const raw = window.sessionStorage.getItem(DISMISSED_KEY)
    return raw ? (JSON.parse(raw) as GuideKey[]) : []
  } catch {
    return []
  }
}

export function isGuideDismissed(key: GuideKey): boolean {
  return readDismissed().includes(key)
}

export function dismissGuide(key: GuideKey): void {
  try {
    const next = [...new Set([...readDismissed(), key])]
    window.sessionStorage.setItem(DISMISSED_KEY, JSON.stringify(next))
  } catch {
    // Non-critical: the tip may open once more this session.
  }
}

/** Forget this session's dismissals so every page's tip can show again. */
export function resetGuideDismissals(): void {
  try {
    window.sessionStorage.removeItem(DISMISSED_KEY)
  } catch {
    // Nothing to reset.
  }
}

/** Whether tips open by themselves on first visit to a page (default on). */
export function guideAutoTips(): boolean {
  try {
    return window.localStorage.getItem(AUTO_KEY) !== '0'
  } catch {
    return true
  }
}

export function setGuideAutoTips(on: boolean): void {
  try {
    window.localStorage.setItem(AUTO_KEY, on ? '1' : '0')
  } catch {
    // Preference simply won't persist.
  }
}
