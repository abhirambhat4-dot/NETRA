import type { AssessmentFindingResult, AssessmentGrade, BackendAssessmentFinding } from '@/api/types'
import type { Tone } from '@/lib/tones'

export const GRADE_TONE: Record<AssessmentGrade, Tone> = {
  A: 'low',
  B: 'info',
  C: 'medium',
  D: 'high',
  F: 'critical',
}

export const RESULT_TONE: Record<AssessmentFindingResult, Tone> = {
  FAIL: 'critical',
  WARN: 'medium',
  INFO: 'info',
  PASS: 'low',
}

export const RESULT_LABEL: Record<AssessmentFindingResult, string> = {
  FAIL: 'Fail',
  WARN: 'Warning',
  INFO: 'Info',
  PASS: 'Pass',
}

/** Labels for the assessment-v1 categories; unknown categories fall back to their key. */
const CATEGORY_LABEL: Record<string, string> = {
  exposure: 'Exposure',
  vulnerability: 'Vulnerabilities',
  data_quality: 'Data quality',
  incident: 'Incidents',
  detection: 'Detection',
  threat_intelligence: 'Threat intelligence',
  inventory: 'Inventory',
}

export function categoryLabel(category: string): string {
  const label = CATEGORY_LABEL[category] ?? category.replaceAll('_', ' ')
  return label.charAt(0).toUpperCase() + label.slice(1)
}

/** Groups findings by category, keeping the methodology's check order (finding position). */
export function groupFindingsByCategory(findings: BackendAssessmentFinding[]) {
  const groups = new Map<string, BackendAssessmentFinding[]>()
  for (const finding of [...findings].sort((a, b) => a.position - b.position)) {
    const group = groups.get(finding.category)
    if (group) group.push(finding)
    else groups.set(finding.category, [finding])
  }
  return [...groups].map(([category, items]) => ({ category, label: categoryLabel(category), findings: items }))
}

/**
 * The optional end of an assessment's 7-day event window, from a YYYY-MM-DD date field read as the end of
 * that day in UTC. Empty means "now" (the API default). Historical datasets such as CIC-IDS2017 (July 2017)
 * fall outside a window ending now. Only events are bounded; other evidence is its current state.
 */
export function assessmentAsOf(date: string, now: Date = new Date()): { asOf?: string; error?: string } {
  const value = date.trim()
  if (!value) return {}
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return { error: 'Use a date in YYYY-MM-DD format.' }
  const end = new Date(`${value}T23:59:59Z`)
  if (Number.isNaN(end.getTime()) || end.toISOString().slice(0, 10) !== value) return { error: 'Enter a valid calendar date.' }
  // The API refuses a future asOf; today's date ends in the future, so it is sent as "now" instead.
  if (end.getTime() > now.getTime()) {
    return value === now.toISOString().slice(0, 10) ? {} : { error: 'The event window cannot end in the future.' }
  }
  return { asOf: end.toISOString().replace('.000Z', 'Z') }
}
