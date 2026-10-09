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
