import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

const AUTH_PAGES = ['../src/pages/RegisterPage.tsx', '../src/pages/login/AuthCard.tsx']
const LIGHT_PAGES = [
  ...AUTH_PAGES,
  '../src/pages/ForgotPasswordPage.tsx',
  '../src/pages/ResetPasswordPage.tsx',
  '../src/pages/login/CyberBackdrop.tsx',
  '../src/pages/CommandHomePage.tsx',
]

test('Command Home uses the light app theme, like the briefing', () => {
  assert.match(source('../src/pages/CommandHomePage.tsx'), /export function CommandHomePage\(\) \{\n {2}useAppTheme\(\)/)
  assert.match(source('../src/pages/BriefingPage.tsx'), /useAppTheme\(\)/)
})

test('register and password-recovery pages use the login page’s light scope, with the guide outside it', () => {
  for (const path of AUTH_PAGES) {
    const page = source(path)
    assert.match(page, /<div className="netra-auth relative isolate flex min-h-svh/, path)
    assert.match(page, /className="nl-surface relative overflow-hidden rounded-2xl"/, path)
    // Same placement as LoginPage: the dark-styled guide bubble is rendered after the scoped page, not inside it.
    assert.ok(page.lastIndexOf('<NetraGuide') > page.lastIndexOf('</main>'), path)
    assert.match(page, /<\/div>\n\s+\{\/\* Rendered outside \.netra-auth[^\n]*\*\/\}\n\s+<NetraGuide page="login" \/>\n\s+<\/>/, path)
  }
  assert.match(source('../src/pages/LoginPage.tsx'), /Rendered outside \.netra-auth/)
})

test('no hard-coded dark surfaces remain on the formerly dark pages', () => {
  for (const path of LIGHT_PAGES) {
    const page = source(path)
    for (const dark of ['bg-black/', 'rgb(21_26_35', 'rgb(10_13_19', 'border-white/10', 'rgb(3_4_7', 'rgb(9 12 17']) {
      assert.ok(!page.includes(dark), `${path} still has ${dark}`)
    }
  }
  const css = source('../src/index.css')
  const card = css.slice(css.indexOf('.ch-workspace {'), css.indexOf('.ch-workspace::before'))
  assert.match(card, /border: 1px solid var\(--border\);\s+background: var\(--card\);\s+box-shadow: var\(--panel-shadow-lift\);/)
  assert.ok(!css.includes('rgba(18, 28, 44'), 'Command Home cards still use the dark glass surface')
})

test('auth inputs get the white card fill the login page uses, even under the dark html class', () => {
  for (const path of ['../src/pages/RegisterPage.tsx', '../src/pages/ForgotPasswordPage.tsx', '../src/pages/ResetPasswordPage.tsx']) {
    const inputs = source(path).match(/<Input [^\n]*\/>/g) ?? []
    assert.ok(inputs.length > 0, path)
    for (const input of inputs) assert.match(input, /className="h-10 bg-card dark:bg-card"/, path)
  }
})

/** WCAG relative luminance and contrast ratio. */
const luminance = (hex: string) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}
const contrast = (a: string, b: string) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}
/** `colour` at `alpha` over white, as the /10 message tints render. */
const tint = (hex: string, alpha: number) =>
  '#' + [1, 3, 5].map((i) => Math.round(255 + (parseInt(hex.slice(i, i + 2), 16) - 255) * alpha).toString(16).padStart(2, '0')).join('')

test('light auth pages define readable success and error colours (WCAG AA, 4.5:1)', () => {
  const css = source('../src/index.css')
  // Every rule whose selector is exactly `.netra-auth` (not the selector list shared with the landing page).
  const block = [...css.matchAll(/(?:^|[^,]\n)\.netra-auth \{\n([^}]*)\}/g)].map((m) => m[1]).join('')
  const success = block.match(/--success: (#[0-9A-Fa-f]{6});/)?.[1]
  const critical = block.match(/--sev-critical: (#[0-9A-Fa-f]{6});/)?.[1]
  assert.ok(success && critical, 'the .netra-auth scope defines --success and --sev-critical')
  // Same colours as the login page's own messages.
  const login = source('../src/pages/LoginPage.tsx')
  assert.ok(login.includes(`text-[${success}]`) && login.includes(`text-[${critical}]`))
  for (const [name, colour] of [['success', success], ['error', critical]] as const) {
    assert.ok(contrast(colour, '#FFFFFF') >= 4.5, `${name} text on white: ${contrast(colour, '#FFFFFF').toFixed(2)}`)
    assert.ok(contrast(colour, tint(colour, 0.1)) >= 4.5, `${name} text on its /10 tint: ${contrast(colour, tint(colour, 0.1)).toFixed(2)}`)
  }
  // The dark theme's values these pages used to inherit fail the same check.
  assert.ok(contrast('#39D98A', '#FFFFFF') < 4.5 && contrast('#FF4D5E', '#FFFFFF') < 4.5)
})

test('the status classes on the auth pages resolve through those tokens', () => {
  const css = source('../src/index.css')
  assert.match(css, /--color-success: var\(--success\);/)
  assert.match(css, /--color-critical: var\(--sev-critical\);/)
  assert.match(source('../src/pages/ResetPasswordPage.tsx'), /met \? 'text-success' : 'text-muted-foreground'/)
  assert.match(source('../src/pages/ForgotPasswordPage.tsx'), /border-success\/30 bg-success\/10[^"]*text-success/)
  for (const path of ['../src/pages/RegisterPage.tsx', '../src/pages/ForgotPasswordPage.tsx', '../src/pages/ResetPasswordPage.tsx']) {
    assert.match(source(path), /border-critical\/30 bg-critical\/10[^"]*text-critical/, path)
  }
})
