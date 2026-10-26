import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { adaptRiskTrend, CHARTED_TREND_SOURCES, type BackendRiskTrendPoint } from '../src/lib/riskTrend.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

const point = (overrides: Partial<BackendRiskTrendPoint> = {}): BackendRiskTrendPoint => ({
  timestamp: '2026-10-25T10:00:00Z',
  riskScore: 64,
  activeIncidents: 2,
  scoredIncidents: 1,
  events: { SURICATA: 2, THREAT_INTEL: 0, ML_ANOMALY: 1, MANUAL: 0, VULNERABILITY_SCAN: 0, DATASET_IMPORT: 4 },
  ...overrides,
})

test('API buckets map onto the chart rows, keeping only the charted sources', () => {
  assert.deepEqual(adaptRiskTrend([point()]), [
    { timestamp: '2026-10-25T10:00:00Z', riskScore: 64, activeIncidents: 2, events: { SURICATA: 2, THREAT_INTEL: 0, ML_ANOMALY: 1 } },
  ])
  assert.deepEqual([...CHARTED_TREND_SOURCES], ['SURICATA', 'THREAT_INTEL', 'ML_ANOMALY'])
})

test('a bucket without a scored active incident stays null, never 0', () => {
  const [adapted] = adaptRiskTrend([point({ riskScore: null, activeIncidents: 1, scoredIncidents: 0 })])
  assert.equal(adapted.riskScore, null)
  assert.equal(adapted.activeIncidents, 1)
})

test('missing event counts read as 0', () => {
  const [adapted] = adaptRiskTrend([point({ events: { SURICATA: 3 } })])
  assert.deepEqual(adapted.events, { SURICATA: 3, THREAT_INTEL: 0, ML_ANOMALY: 0 })
})

test('live mode reads the trend endpoint instead of returning an empty list', () => {
  const live = source('../src/services/liveDashboard.ts')
  assert.match(live, /http\.get<BackendRiskTrendPoint\[\]>\('\/dashboard\/risk-trend', \{ range \}\)/)
  assert.doesNotMatch(live, /getRiskTrend: async \(_range: TrendRange\): Promise<RiskTrendPoint\[\]> => \[\]/)
})

test('the trend panel shows an unscored bucket as not scored rather than as zero risk', () => {
  const panel = source('../src/pages/dashboard/RiskTrendPanel.tsx')
  assert.match(panel, /risk: number \| null/)
  assert.match(panel, /value=\{rows\.at\(-1\)!\.risk \?\? '—'\}/)
  assert.match(panel, /Not scored/)
})

test('the live variant is labelled as average active incident risk; the demo variant is unchanged', () => {
  const panel = source('../src/pages/dashboard/RiskTrendPanel.tsx')
  assert.match(panel, /title=\{live \? 'Average active incident risk trend' : 'System risk trend'\}/)
  assert.match(panel, /average risk of the incidents active at each bucket end/)
  assert.match(panel, /\{live \? 'Average active risk' : 'System risk'\}/)
  assert.match(panel, /export function RiskTrendPanel\(\{ live = false, className \}/)
})

test('both ranges and every panel state are handled', () => {
  const panel = source('../src/pages/dashboard/RiskTrendPanel.tsx')
  assert.match(panel, /\{ value: '24h', label: '24h' \}/)
  assert.match(panel, /\{ value: '7d', label: '7d' \}/)
  assert.match(panel, /dashboardService\.getRiskTrend\(range\)/)
  assert.match(panel, /error \? \(\s*<ErrorState onRetry=\{reload\} \/>/) // error with retry
  assert.match(panel, /!data \? \(\s*<LoadingState variant="inline" label="Loading trend…"/) // loading
  assert.match(panel, /rows\.length === 0 \? \([\s\S]*Trend data unavailable/) // empty
})

test('24h and 7d buckets keep their count and order, and the latest point is the value the panel calls Current', () => {
  for (const count of [24, 28]) {
    const points = Array.from({ length: count }, (_, index) =>
      point({ timestamp: new Date(Date.UTC(2026, 9, 25) + index * 3_600_000).toISOString(), riskScore: index === count - 1 ? 64 : null }),
    )
    const adapted = adaptRiskTrend(points)
    assert.equal(adapted.length, count)
    assert.deepEqual(adapted.map((item) => item.timestamp), points.map((item) => item.timestamp))
    // The API's last bucket equals the gauge's averageRiskScore (backend test); the adapter passes it through unchanged.
    assert.equal(adapted.at(-1)!.riskScore, 64)
    assert.ok(adapted.slice(0, -1).every((item) => item.riskScore === null))
  }
  const page = source('../src/pages/CommandCenterPage.tsx')
  assert.match(page, /const riskScore = USE_MOCKS \? stats\.data\?\.overallRisk \?\? null : stats\.data\?\.averageRiskScore \?\? null/)
  assert.match(source('../src/pages/dashboard/RiskTrendPanel.tsx'), /<Kpi label="Current" value=\{rows\.at\(-1\)!\.risk \?\? '—'\} tone \/>/)
})
