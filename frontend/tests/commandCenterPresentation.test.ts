import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  DEMO_NOTICE,
  NOT_SCORED,
  allTimeEventSeverityHint,
  formatLifecycleState,
  incidentIdentity,
  incidentRiskLabel,
  showRiskDriverScale,
  unsupportedIncidentsNotice,
} from '../src/pages/dashboard/presentation.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const page = source('../src/pages/CommandCenterPage.tsx')
const lifecyclePanel = source('../src/pages/dashboard/LifecyclePanel.tsx')
const login = source('../src/pages/LoginPage.tsx')
const loginTrail = source('../src/pages/login/LoginEvidenceTrail.tsx')

test('an incident without its own risk score reads "Not scored"', () => {
  assert.equal(NOT_SCORED, 'Not scored')
  for (const missing of [null, undefined, Number.NaN]) assert.equal(incidentRiskLabel(missing), NOT_SCORED)
  assert.equal(incidentRiskLabel(0), '0')
  assert.equal(incidentRiskLabel(72.4), '72')
})

test('the primary incident never borrows the dashboard-wide risk', () => {
  assert.match(page, /incidentRiskLabel\(primaryIncident\.riskScore\)/)
  assert.doesNotMatch(page, /riskScore \?\? stats\.data/)
  assert.doesNotMatch(page, /primaryRisk/)
})

test('all-time event counts are labelled as all-time', () => {
  assert.equal(allTimeEventSeverityHint(3, 5), 'All-time: Critical 3 / High 5')
  assert.equal(allTimeEventSeverityHint(null, undefined), 'All-time: Critical 0 / High 0')
  assert.match(page, /allTimeEventSeverityHint\(stats\.data\.criticalEvents, stats\.data\.highEvents\)/)
  assert.doesNotMatch(page, /`Critical \$\{/)
})

test('the readable incident key is shown instead of the database id', () => {
  assert.equal(incidentIdentity({ key: 'INC-0042', id: '0b9c2a3e-5d41-4c1f' }), 'INC-0042')
  assert.equal(incidentIdentity({ key: '  ', id: '0b9c2a3e-5d41-4c1f' }), 'Incident 0b9c2a3e')
  assert.match(page, /incidentIdentity\(primaryIncident\)/)
  assert.doesNotMatch(page, />\{primaryIncident\.id\}</)
})

test('the driver scale is shown only when there are drivers', () => {
  assert.equal(showRiskDriverScale([]), false)
  assert.equal(showRiskDriverScale(undefined), false)
  assert.equal(showRiskDriverScale([{}]), true)
  assert.doesNotMatch(page, /pts \/ 100/)
  assert.match(page, /showRiskDriverScale\(drivers\) &&/)
})

test('unknown lifecycle states are reported, not fatal and not relabelled', () => {
  assert.equal(unsupportedIncidentsNotice(0), null)
  assert.match(unsupportedIncidentsNotice(1)!, /^One incident/)
  assert.match(unsupportedIncidentsNotice(3)!, /^3 incidents/)
  assert.equal(formatLifecycleState('PRIORITISED'), 'Prioritised')
  assert.match(page, /incidentQueueService\.listTolerant\(/)
})

test('no staged analysis, AI imagery or fabricated narrative on the Command Center', () => {
  for (const banned of [
    'Sparkles',
    'setTimeout',
    'high-confidence escalation',
    'narrow containment window',
    'Risk assessment complete',
    'Priority incident identified',
    'Decision context assembled',
    'RECOMMENDATION READY',
    'Recommendation ready',
    'median risk threshold',
    'heartbeat nominal',
    'improve future',
    'pipelineStages',
    'reasoningSteps',
  ]) {
    assert.ok(!page.includes(banned), `CommandCenterPage still contains "${banned}"`)
  }
  assert.equal(DEMO_NOTICE, 'Demo data — illustrative only')
  assert.match(page, /\{DEMO_NOTICE\}/)
  assert.match(page, /Not returned by the current API/)
})

test('the lifecycle panel uses the shared seven stages with visible text and simulated containment', () => {
  assert.match(lifecyclePanel, /import \{ LIFECYCLE(, LIFECYCLE_NOTE)? \} from '@\/components\/landing\/content'/)
  assert.match(lifecyclePanel, /stage\.key === 'CONTAIN'[\s\S]*Simulated/)
  assert.match(lifecyclePanel, /\{stage\.summary\}/)
  assert.doesNotMatch(lifecyclePanel, /group-hover:opacity-100/, 'descriptions must not be hover-only')
  assert.match(page, /<LifecyclePanel/)
})

test('the severity summary uses the API counts and never fills missing ones', () => {
  const panel = source('../src/pages/dashboard/PrioritizedIncidentsPanel.tsx')
  assert.match(page, /bySeverity=\{stats\.data\?\.incidentsBySeverity\}/)
  assert.match(panel, /known \? count : 'Not returned'/)
  assert.match(panel, /allKnown && total > 0/, 'the proportion bar needs every count to be known')
  assert.doesNotMatch(panel, /count \?\? 0\)\s*:\s*'Not returned'|\?\? 0\}/, 'missing counts must not render as zero')
})

test('the guide target for the dashboard exists on the page', () => {
  const guide = source('../src/lib/guide.ts')
  const target = guide.match(/dashboard: \{[\s\S]*?target: '([^']+)'/)?.[1]
  assert.ok(target, 'dashboard guide target not found')
  assert.ok(page.includes(`data-guide-target="${target}"`), `no element with data-guide-target="${target}"`)
})

test('Recharts loads lazily, only for the trend panel', () => {
  assert.doesNotMatch(page, /import \{ RiskTrendPanel \}/)
  assert.match(page, /lazy\(\(\) => import\('\.\/dashboard\/RiskTrendPanel'\)/)
  assert.equal(page.match(/<Suspense/g)?.length, 2)
})

test('the risk trend is shown once per mode: live variant on the live dashboard, unchanged in the demo section', () => {
  const uses = page.match(/<RiskTrendPanel[^>]*\/>/g) ?? []
  assert.deepEqual(uses, ['<RiskTrendPanel live className="cc-card rounded-2xl" />', '<RiskTrendPanel />'])
  // The live instance sits in a !USE_MOCKS block; the original one stays inside the USE_MOCKS demo disclosure.
  const live = page.indexOf('<RiskTrendPanel live')
  assert.ok(page.lastIndexOf('{!USE_MOCKS && (', live) > page.lastIndexOf('{USE_MOCKS && (', live))
  const demo = page.indexOf('<RiskTrendPanel />')
  assert.ok(page.lastIndexOf('Open demo-only dashboard enrichment', demo) > live)
})

test('the live availability list says drivers are still missing while risk history is now available', () => {
  assert.doesNotMatch(page, /Risk history and drivers/)
  assert.match(page, /<Availability label="Risk drivers \(risk history is now shown in the trend below\)" \/>/)
  assert.match(page, /<Availability label="ATT&CK activity" \/>/)
  assert.match(page, /<Availability label="Asset risk scores" \/>/)
})

test('login authentication behaviour is unchanged', () => {
  for (const kept of [
    'await login(email.trim(), password, remember)',
    // Post-sign-in destination: a safe requested route, else Command Home (tests/postLoginRedirect.test.ts).
    'navigate(postLoginPath(location.state), { replace: true })',
    "'Email or password is incorrect.'",
    "'Unable to sign in right now. Please try again.'",
    'cause instanceof HttpError && cause.status === 401',
    'Account created. Sign in with your new credentials.',
    'Password reset. Sign in with your new password.',
    'id="email"',
    'autoComplete="username"',
    'id="password"',
    'autoComplete="current-password"',
    'to={ROUTES.forgotPassword}',
    'to={ROUTES.register}',
  ]) {
    assert.ok(login.includes(kept), `LoginPage lost: ${kept}`)
  }
})

test('login accessibility improvements are in place', () => {
  assert.match(login, /aria-busy=\{loading\}/)
  assert.match(login, /'aria-describedby': fieldError \? ERROR_ID : undefined/)
  assert.match(login, /'aria-invalid': fieldError \|\| undefined/)
  assert.doesNotMatch(login, /aria-label="Remember this session"/)
  assert.match(login, /<Checkbox\s+id="remember-session"/)
  assert.match(login, /<Label htmlFor="remember-session"/)
})

test('the login visual is truthful and scoped to the login page', () => {
  assert.doesNotMatch(login, /CyberBackdrop/)
  assert.match(login, /className="netra-auth /)
  // The guide bubble is dark-styled, so it must render outside the light scope.
  assert.ok(login.lastIndexOf('<NetraGuide') > login.lastIndexOf('</div>'), 'NetraGuide must sit outside .netra-auth')
  for (const banned of [/\d+\s*\/\s*100/, /%/, /EVT-/, /T1\d{3}/, /\d+\.\d+\.\d+\.\d+/, /SURICATA|ML DETECTOR|TLS/i, /CRITICAL|ALERT/]) {
    assert.doesNotMatch(loginTrail, banned)
  }
  assert.doesNotMatch(loginTrail, /repeatCount|infinite/)
})
