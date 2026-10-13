import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { POST_LOGIN_DEFAULT, postLoginPath } from '../src/auth/postLoginRedirect.ts'
import { ROUTES } from '../src/lib/navigation.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const from = (pathname: unknown, search: unknown = '', hash: unknown = '') => ({ from: { pathname, search, hash } })

test('a successful sign-in lands on Command Home by default, never on the briefing', () => {
  assert.equal(POST_LOGIN_DEFAULT, ROUTES.commandHome)
  assert.equal(POST_LOGIN_DEFAULT, '/home')
  for (const state of [null, undefined, {}, { registered: true }, { passwordReset: true }, 'x', 42]) {
    assert.equal(postLoginPath(state), '/home', JSON.stringify(state))
  }
})

test('after registration the sign-in that follows also lands on Command Home', () => {
  // RegisterPage creates the account and sends the user to sign in; that sign-in uses postLoginPath.
  assert.match(source('../src/pages/RegisterPage.tsx'), /navigate\(ROUTES\.login, \{ replace: true, state: \{ registered: true \} \}\)/)
  assert.equal(postLoginPath({ registered: true }), ROUTES.commandHome)
})

test('a protected route requested before signing in is restored, with its query and hash', () => {
  assert.equal(postLoginPath(from('/live')), '/live')
  assert.equal(postLoginPath(from('/workspace')), '/workspace')
  assert.equal(postLoginPath(from('/incidents/abc-123')), '/incidents/abc-123')
  assert.equal(postLoginPath(from('/events', '?event=e1', '#top')), '/events?event=e1#top')
  assert.equal(postLoginPath(from('/imports', '?batch=b%201')), '/imports?batch=b%201')
  // The briefing keeps its direct route: asked for explicitly, it is returned to.
  assert.equal(postLoginPath(from('/briefing')), '/briefing')
})

test('unsafe or external return destinations fall back to Command Home', () => {
  for (const [pathname, search = '', hash = ''] of [
    ['//evil.example'],
    ['//evil.example/path'],
    ['/\\evil.example'],
    ['\\\\evil.example'],
    ['https://evil.example/'],
    ['javascript:alert(1)'],
    ['evil.example'],
    [''],
    ['/live\n//evil.example'],
    ['/live', '//evil'],
    ['/live', '?a=1', 'x'],
    ['/ live'],
    ['/%0d%0a'.replace('%0d%0a', '\r\n')],
  ]) {
    assert.equal(postLoginPath(from(pathname, search, hash)), '/home', JSON.stringify([pathname, search, hash]))
  }
  for (const bad of [from(42), from(null), from(['/live']), { from: '/live' }, { from: null }]) {
    assert.equal(postLoginPath(bad), '/home', JSON.stringify(bad))
  }
})

test('public and sign-in pages are never returned to', () => {
  for (const pathname of ['/', '/login', '/login/', '/register', '/forgot-password', '/reset-password']) {
    assert.equal(postLoginPath(from(pathname)), '/home', pathname)
  }
})

test('the login page and the signed-in redirect use the same destination; the briefing is out of the flow', () => {
  const guards = source('../src/auth/RouteGuards.tsx')
  const login = source('../src/pages/LoginPage.tsx')
  assert.match(login, /navigate\(postLoginPath\(location\.state\), \{ replace: true \}\)/)
  assert.match(guards, /if \(isAuthenticated\) return <Navigate to=\{postLoginPath\(location\.state\)\} replace \/>/)
  for (const file of [guards, login]) {
    assert.doesNotMatch(file, /hasCompletedBriefing|ROUTES\.briefing/)
  }
  // RequireAuth still records the protected route the user asked for.
  assert.match(guards, /if \(!isAuthenticated\) return <Navigate to=\{ROUTES\.login\} replace state=\{\{ from: location \}\} \/>/)
})

test('the briefing route and the protected workspaces stay routed and guarded', () => {
  const router = source('../src/router.tsx')
  assert.match(router, /path: ROUTES\.briefing,/)
  const shell = router.slice(router.indexOf('<RequireAuth><AppLayout /></RequireAuth>'))
  assert.match(shell, /path: ROUTES\.liveTracking,/)
  assert.match(shell, /path: ROUTES\.securityWorkspace,/)
  assert.match(router, /path: ROUTES\.login, element: <RedirectAuthenticated><LoginPage \/><\/RedirectAuthenticated>/)
})
