// Dependency-free so it runs under `node --test` (tests/riskEvaluation.test.ts).

/** A stored risk scoring run as GET /api/incidents/{id}/risk-evaluations returns it. */
export interface BackendRiskEvaluation {
  id: string
  incidentId: string
  methodologyVersion: string
  riskScore: number
  riskLevel: string
  previousRiskScore: number | null
  factors: Record<string, { normalizedValue?: number; weight?: number; contribution?: number; reason?: string }>
  missingEvidence: string[]
  matchedIndicators: Array<{ id?: string; indicatorType?: string; value?: string; source?: string }>
  trigger: string
  actor: string
  createdAt: string
}

export interface RiskEvaluationFactor {
  key: string
  label: string
  normalizedValue: number
  weight: number
  contribution: number
  reason: string
}

export interface RiskEvaluationView {
  id: string
  createdAt: string
  riskScore: number
  riskLevel: string
  methodologyVersion: string
  trigger: string
  actor: string
  previousRiskScore: number | null
  /** Highest contribution first; ties keep the engine's order. */
  factors: RiskEvaluationFactor[]
  missingEvidence: string[]
  /** "source: type value", one per matched active indicator. */
  matchedIndicators: string[]
}

const FACTOR_LABELS: Record<string, string> = {
  asset_criticality: 'Asset criticality',
  vulnerability: 'Vulnerability',
  anomaly: 'Behavioural anomaly',
  detection: 'Detection source',
  threat_intelligence: 'Threat intelligence',
  attack_context: 'Attack context',
}

const number = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : 0)

export function factorLabel(key: string): string {
  return FACTOR_LABELS[key] ?? key.replaceAll('_', ' ')
}

export function adaptRiskEvaluation(evaluation: BackendRiskEvaluation): RiskEvaluationView {
  const factors = Object.entries(evaluation.factors ?? {})
    .map(([key, factor]) => ({
      key,
      label: factorLabel(key),
      normalizedValue: number(factor?.normalizedValue),
      weight: number(factor?.weight),
      contribution: number(factor?.contribution),
      reason: typeof factor?.reason === 'string' ? factor.reason : '',
    }))
    .map((factor, index) => ({ factor, index }))
    .sort((left, right) => right.factor.contribution - left.factor.contribution || left.index - right.index)
    .map(({ factor }) => factor)
  return {
    id: evaluation.id,
    createdAt: evaluation.createdAt,
    riskScore: evaluation.riskScore,
    riskLevel: evaluation.riskLevel,
    methodologyVersion: evaluation.methodologyVersion,
    trigger: evaluation.trigger,
    actor: evaluation.actor,
    previousRiskScore: evaluation.previousRiskScore,
    factors,
    missingEvidence: [...(evaluation.missingEvidence ?? [])],
    matchedIndicators: (evaluation.matchedIndicators ?? []).map(
      (indicator) => `${indicator.source ?? 'Unknown source'}: ${indicator.indicatorType ?? 'indicator'} ${indicator.value ?? ''}`.trim(),
    ),
  }
}

/** Oldest first, as the API returns them; the latest evaluation is the last one. */
export function latestRiskEvaluation(evaluations: RiskEvaluationView[]): RiskEvaluationView | null {
  return evaluations.length ? evaluations[evaluations.length - 1] : null
}

/** One-line summary for the incident's risk assessment fact. */
export function riskEvaluationSummary(evaluation: RiskEvaluationView | null): string {
  if (!evaluation) return 'Not calculated yet'
  return `${evaluation.riskScore}/100 ${evaluation.riskLevel} · ${evaluation.methodologyVersion}`
}

/** "+12.5 since the previous score", or null for a first evaluation. */
export function riskChange(evaluation: RiskEvaluationView): string | null {
  if (evaluation.previousRiskScore == null) return null
  const delta = Math.round((evaluation.riskScore - evaluation.previousRiskScore) * 100) / 100
  return `${delta > 0 ? '+' : ''}${delta} since the previous score (${evaluation.previousRiskScore})`
}
