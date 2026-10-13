import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { ROUTES } from '../src/lib/navigation.ts'
import { COMMAND_HOME, WORKSPACES } from '../src/pages/home/content.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

test('offers exactly the two workspaces, each pointing at an existing route', () => {
  assert.deepEqual(
    WORKSPACES.map((w) => [w.name, w.summary, w.to]),
    [
      ['Live Tracking', 'Monitor security activity.', ROUTES.liveTracking],
      ['Security Workspace', 'Investigate and assess threats.', ROUTES.securityWorkspace],
    ],
  )
})

test('workspace landing pages are protected routes inside the app shell; existing pages stay routed', () => {
  const router = source('../src/router.tsx')
  const start = router.indexOf('<RequireAuth><AppLayout /></RequireAuth>')
  assert.ok(start > 0)
  const shell = router.slice(start)
  assert.match(shell, /path: ROUTES\.liveTracking,\s+lazy: page\(\(\) => import\('@\/pages\/LiveTrackingPage'\)/)
  assert.match(shell, /path: ROUTES\.securityWorkspace,\s+lazy: page\(\(\) => import\('@\/pages\/SecurityWorkspacePage'\)/)
  for (const route of ['collector', 'dashboard', 'events', 'incidents', 'imports', 'assessments', 'threatIntelligence', 'assets', 'cyberMemory', 'settings']) {
    assert.match(shell, new RegExp(`path: ROUTES\\.${route},`), `${route} route missing`)
  }
  assert.equal(ROUTES.liveTracking, '/live')
  assert.equal(ROUTES.securityWorkspace, '/workspace')
})

test('keeps the agreed heading and quote', () => {
  assert.equal(`${COMMAND_HOME.heading.lead} ${COMMAND_HOME.heading.accent}`, 'Your Security. One Command.')
  assert.equal(COMMAND_HOME.quote, 'In cybersecurity, vigilance is the first line of defense.')
})

test('Command Home is a protected route outside the app shell', () => {
  const router = source('../src/router.tsx')
  const block = router.slice(router.indexOf('path: ROUTES.commandHome'), router.indexOf('<AppLayout />'))
  assert.match(block, /<RequireAuth><Outlet \/><\/RequireAuth>/)
  assert.match(block, /import\('@\/pages\/CommandHomePage'\)/)
})

test('signed-in users land on Command Home; the public landing page stays public', () => {
  // The guard and LoginPage must agree, or the guard's redirect wins the race and skips the briefing.
  assert.match(source('../src/auth/RouteGuards.tsx'), /isAuthenticated\) return <Navigate to=\{hasCompletedBriefing\(\) \? ROUTES\.commandHome : ROUTES\.briefing\} replace \/>/)
  assert.match(source('../src/pages/LoginPage.tsx'), /hasCompletedBriefing\(\) \? ROUTES\.commandHome : ROUTES\.briefing/)
  assert.match(source('../src/router.tsx'), /path: ROUTES\.home, element: <RedirectAuthenticated><PublicLandingPage \/><\/RedirectAuthenticated>/)
})

test('workspace selection is navigation only', () => {
  const page = source('../src/pages/CommandHomePage.tsx')
  assert.doesNotMatch(page, /@\/services|useAuth|localStorage|fetch\(/)
  assert.match(page, /<Link\s+to=\{workspace\.to\}/)
})

test('backdrop animations stop under reduced motion', () => {
  const css = source('../src/index.css')
  const reduced = css.slice(css.lastIndexOf('@media (prefers-reduced-motion: reduce)'))
  for (const cls of ['.ch-rise', '.ch-particle', '.ch-scan']) assert.ok(reduced.includes(cls), `${cls} not handled`)
  assert.match(css, /\.cb-spin, \.cb-flow, \.cb-pulse, \.cb-node[^{]*\{\s*animation: none;/)
})
