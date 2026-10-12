import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  CLOSING_CTA,
  EVIDENCE_PREVIEW,
  FEATURES,
  HERO,
  LANDING_LINKS,
  LIFECYCLE,
  LIFECYCLE_NOTE,
  NAV_ANCHORS,
  NON_CLAIMS,
  SECTION_IDS,
  STATUS_META,
  WORKFLOW,
  type FeatureId,
  type FeatureStatus,
} from '../src/components/landing/content.ts'
import { ROUTES } from '../src/lib/navigation.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

/** Copy that states what NETRA does. Boundaries and non-claims are excluded: they negate. */
const positiveCopy = [
  HERO.eyebrow,
  HERO.title,
  HERO.description,
  ...HERO.highlights,
  EVIDENCE_PREVIEW.title,
  ...EVIDENCE_PREVIEW.steps.map((s) => s.text),
  ...LIFECYCLE.flatMap((s) => [s.summary, s.detail]),
  ...WORKFLOW.flatMap((s) => [s.label, s.summary, s.detail]),
  ...FEATURES.flatMap((f) => [f.name, f.description]),
  CLOSING_CTA.title,
  CLOSING_CTA.description,
]

const allCopy = [
  ...positiveCopy,
  LIFECYCLE_NOTE,
  ...FEATURES.map((f) => f.boundary),
  ...NON_CLAIMS,
  ...Object.values(STATUS_META).map((s) => s.description),
]

test('lifecycle has exactly the seven PDF stages, in order', () => {
  assert.deepEqual(
    LIFECYCLE.map((s) => s.key),
    ['DETECT', 'UNDERSTAND', 'PRIORITISE', 'VERIFY', 'AUTHORIZE', 'CONTAIN', 'LEARN'],
  )
  assert.deepEqual(
    LIFECYCLE.map((s) => s.summary),
    [
      'Find candidate activity',
      'Add supported context',
      'Rank by evidence and risk',
      'Check findings',
      'Record approval',
      'Simulate or execute an approved action',
      'Record outcome and lesson',
    ],
  )
})

test('CONTAIN is present and containment is stated as simulated', () => {
  const contain = LIFECYCLE.find((s) => s.key === 'CONTAIN')
  assert.ok(contain)
  assert.match(contain.detail, /simulated/i)
  assert.match(LIFECYCLE_NOTE, /simulated/i)
})

test('the landing workflow is the six-step sequence and Respond is marked simulated', () => {
  assert.deepEqual(
    WORKFLOW.map((s) => s.label),
    ['Monitor', 'Detect', 'Assess', 'Authorize', 'Respond', 'Learn'],
  )
  const simulated = WORKFLOW.filter((s) => s.simulated)
  assert.deepEqual(simulated.map((s) => s.key), ['RESPOND'])
  assert.match(simulated[0].detail, /simulated/i)
  assert.match(source('../src/components/landing/LifecycleFlow.tsx'), /WORKFLOW\.map/)
})

test('exactly the six locked feature areas, each with a status and a boundary', () => {
  assert.deepEqual(
    FEATURES.map((f) => f.name),
    [
      'Live Event Tracking',
      'Security Data Ingestion',
      'Detection & Evidence Correlation',
      'Explainable Risk Assessment',
      'Decision & Controlled Response',
      'Security Assessment',
    ],
  )
  for (const f of FEATURES) {
    assert.ok(f.status in STATUS_META, `${f.name} has an unknown status`)
    assert.ok(f.boundary.trim().length > 20, `${f.name} needs a real boundary`)
    assert.ok(f.description.trim().length > 20, `${f.name} needs a description`)
  }
})

test('feature statuses match the verified implementation; upgrading one must be deliberate', () => {
  const expected: Record<FeatureId, FeatureStatus> = {
    tracking: 'available', // collector status polling + incident lifecycle; no external feeds
    ingestion: 'in-progress', // CIC-IDS2017 rows stored as events; no detection over datasets
    correlation: 'in-progress', // rule-based correlation only; no detection over datasets
    risk: 'available',
    response: 'available', // containment simulated
    assessment: 'in-progress', // end-to-end verification pending
  }
  assert.deepEqual(Object.fromEntries(FEATURES.map((f) => [f.id, f.status])), expected)
})

test('known boundaries are preserved', () => {
  const boundary = (id: FeatureId) => FEATURES.find((f) => f.id === id)!.boundary
  assert.match(boundary('tracking'), /no external feeds/i)
  assert.match(boundary('ingestion'), /not treated as proof of detection/i)
  assert.match(boundary('correlation'), /not implemented yet/i)
  assert.match(boundary('response'), /simulated/i)
  assert.match(boundary('assessment'), /verification .* pending/i)
})

test('live tracking is described as tracking submitted data, not external monitoring', () => {
  const tracking = FEATURES.find((f) => f.id === 'tracking')!
  assert.match(tracking.description, /Live Event Collector/)
  assert.match(tracking.description, /submitted to NETRA/)
  assert.match(source('../src/pages/CollectorPage.tsx'), /REFRESH_INTERVAL_MS/)
  assert.match(NON_CLAIMS.join(' '), /external live threat feeds/)
})

test('no numeric operational metrics in any copy', () => {
  // Dataset names are identifiers, not metrics.
  const allowed = /CIC-IDS2017|UNSW-NB15/g
  for (const text of allCopy) {
    const stripped = text.replace(allowed, '')
    assert.doesNotMatch(stripped, /\d/, `digits in: "${text}"`)
    assert.doesNotMatch(stripped, /%/, `percentage in: "${text}"`)
  }
})

test('no misleading capability claims in positive copy', () => {
  const forbidden = [
    /autonomous/i,
    /\bAI\b/,
    /\bLLM\b/,
    /machine learning/i,
    /self-learning/i,
    /\blearns\b/i,
    /improves? (future|over time)/i,
    /real[- ]time/i,
    /guarantee/i,
    /policy engine/i,
    /\b(SIEM|EDR)\b/,
    /phishing|\bQR\b/i,
    /across the environment/i,
  ]
  for (const text of positiveCopy) {
    for (const pattern of forbidden) {
      assert.doesNotMatch(text, pattern, `"${text}" matches ${pattern}`)
    }
  }
})

test('non-claims cover the PDF scope boundaries', () => {
  const joined = NON_CLAIMS.join(' ')
  for (const pattern of [/AI or LLM analyst/, /autonomous learning/, /phishing/i, /QR/, /SIEM or EDR/, /firewall/, /arbitrary datasets/, /Guaranteed detection/]) {
    assert.match(joined, pattern)
  }
})

test('the evidence preview is labelled illustrative and follows the evidence trail', () => {
  assert.equal(EVIDENCE_PREVIEW.label, 'Illustrative — not a real finding')
  assert.deepEqual(
    EVIDENCE_PREVIEW.steps.map((s) => s.label),
    ['Evidence', 'Reason', 'Risk', 'Next step', 'Traceability'],
  )
  assert.match(source('../src/components/landing/EvidencePreview.tsx'), /\{EVIDENCE_PREVIEW\.label\}/)
})

test('CTA paths match the application routes', () => {
  assert.equal(LANDING_LINKS.signIn, ROUTES.login)
  assert.equal(LANDING_LINKS.register, ROUTES.register)
  const router = source('../src/router.tsx')
  assert.match(router, /path: ROUTES\.login,/)
  assert.match(router, /path: ROUTES\.register,/)
  assert.match(router, /path: ROUTES\.home, element: <RedirectAuthenticated><PublicLandingPage \/>/)
})

test('anchor ids are unique and every linked section is rendered', () => {
  const ids = Object.values(SECTION_IDS)
  assert.equal(new Set(ids).size, ids.length)
  for (const anchor of NAV_ANCHORS) assert.ok(ids.includes(anchor.id))

  const page = source('../src/pages/PublicLandingPage.tsx')
  for (const key of Object.keys(SECTION_IDS)) {
    assert.match(page, new RegExp(`id=\\{SECTION_IDS\\.${key}\\}`), `section ${key} is not rendered`)
  }
  assert.match(page, /href=\{`#\$\{SECTION_IDS\.main\}`\}/, 'skip link must target main')
  assert.match(source('../src/components/landing/LandingHero.tsx'), /href=\{`#\$\{SECTION_IDS\.lifecycle\}`\}/)
})
