import type * as React from 'react'
import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Eye, EyeOff, Loader2 } from 'lucide-react'
import { useAuth } from '@/auth/AuthProvider'
import { NetraGuide } from '@/components/guide'
import { LANDING_TAGLINE } from '@/components/landing/content'
import { NetraLogo } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { postLoginPath } from '@/auth/postLoginRedirect'
import { ROUTES } from '@/lib/navigation'
import { HttpError } from '@/services/http'
import { LoginEvidenceTrail } from './login/LoginEvidenceTrail'
import { loginFailureMessage } from './login/loginError'

const INVALID_CREDENTIALS = 'Email or password is incorrect.'
const ERROR_ID = 'login-error'

const delay = (ms: number) => ({ '--na-delay': `${ms}ms` }) as React.CSSProperties

const INPUT =
  'h-11 rounded-xl border-(--nl-line-strong) bg-white px-3.5 text-[15px] text-foreground shadow-[0_1px_2px_rgba(11,27,51,0.04)] placeholder:text-[#64748B] dark:bg-white md:text-[15px]'

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [remember, setRemember] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const registered = (location.state as { registered?: boolean } | null)?.registered === true
  const passwordReset = (location.state as { passwordReset?: boolean } | null)?.passwordReset === true

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(email.trim(), password, remember)
      navigate(postLoginPath(location.state), { replace: true })
    } catch (cause) {
      setError(cause instanceof HttpError && cause.status === 401
        ? INVALID_CREDENTIALS
        : loginFailureMessage(cause, { showApiAddress: import.meta.env.DEV }) ?? 'Unable to sign in right now. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // Only a credential rejection marks the fields invalid; other failures are not about the input.
  const fieldError = error === INVALID_CREDENTIALS
  const fieldProps = {
    'aria-invalid': fieldError || undefined,
    'aria-describedby': fieldError ? ERROR_ID : undefined,
  }

  return (
    <>
      <div className="netra-auth relative isolate flex min-h-svh lg:grid lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
        {/* Visual panel — desktop only */}
        <aside
          aria-label="About NETRA"
          className="relative hidden flex-col overflow-hidden border-r border-(--nl-line) bg-(--nl-band) px-12 py-10 lg:flex xl:px-16"
        >
          <div aria-hidden className="nl-hero-grid absolute inset-0" />
          <Link
            to={ROUTES.home}
            className="relative self-start rounded-lg text-foreground outline-none focus-visible:ring-3 focus-visible:ring-ring"
          >
            <NetraLogo />
          </Link>

          <div className="relative mt-14 max-w-md">
            <p className="na-rise text-sm font-semibold text-primary" style={delay(80)}>
              {LANDING_TAGLINE}
            </p>
            <p
              className="na-rise mt-3 text-3xl leading-tight font-semibold tracking-tight text-balance text-foreground xl:text-4xl"
              style={delay(160)}
            >
              Know what to investigate first — and why.
            </p>
            <p className="na-rise mt-4 text-base leading-relaxed text-muted-foreground" style={delay(240)}>
              Sign in to review prioritised incidents, the evidence and reasons behind each priority, and the decisions
              that follow.
            </p>
          </div>

          <div className="relative mt-auto pt-10">
            <LoginEvidenceTrail className="mx-auto h-auto w-full max-w-[520px]" />
            <p className="na-fade mt-4 text-center text-sm text-muted-foreground" style={delay(2400)}>
              Containment is simulated in the current scope.
            </p>
          </div>
        </aside>

        {/* Form column */}
        <div className="flex min-h-svh flex-1 flex-col bg-white">
          <header className="flex items-center justify-between gap-4 px-4 pt-5 sm:px-8">
            <Link
              to={ROUTES.home}
              className="rounded-lg text-foreground outline-none focus-visible:ring-3 focus-visible:ring-ring lg:invisible"
            >
              <NetraLogo />
            </Link>
            <Link
              to={ROUTES.home}
              className="inline-flex items-center gap-1.5 rounded-full px-3 py-2 text-sm font-medium text-muted-foreground transition-colors outline-none hover:bg-(--nl-accent-soft) hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring"
            >
              <ArrowLeft className="size-4" aria-hidden />
              Back to home
            </Link>
          </header>

          <main className="flex flex-1 items-center justify-center px-4 py-10 sm:px-8">
            <section
              aria-labelledby="login-title"
              className="na-rise nl-surface w-full max-w-[420px] rounded-3xl p-6 sm:p-8"
              style={delay(120)}
            >
              <h1 id="login-title" className="text-[1.75rem] leading-tight font-semibold tracking-tight text-foreground">
                Sign in
              </h1>
              <p className="mt-2 text-[15px] leading-relaxed text-muted-foreground">
                Access your NETRA workspace and continue your review.
              </p>

              <form onSubmit={handleSubmit} aria-busy={loading} className="mt-7 space-y-5">
                {registered && (
                  <p role="status" className="rounded-xl border border-[#A7F3D0] bg-[#ECFDF5] px-3.5 py-2.5 text-sm text-[#065F46]">
                    Account created. Sign in with your new credentials.
                  </p>
                )}
                {passwordReset && (
                  <p role="status" className="rounded-xl border border-[#A7F3D0] bg-[#ECFDF5] px-3.5 py-2.5 text-sm text-[#065F46]">
                    Password reset. Sign in with your new password.
                  </p>
                )}
                {error && (
                  <p id={ERROR_ID} role="alert" className="rounded-xl border border-[#FECACA] bg-[#FEF2F2] px-3.5 py-2.5 text-sm text-[#991B1B]">
                    {error}
                  </p>
                )}

                <div className="space-y-2">
                  <Label htmlFor="email" className="text-sm font-medium text-foreground">
                    Email
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    autoComplete="username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className={INPUT}
                    placeholder="name@organization.com"
                    required
                    {...fieldProps}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password" className="text-sm font-medium text-foreground">
                    Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={show ? 'text' : 'password'}
                      autoComplete="current-password"
                      placeholder="Enter your password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className={`${INPUT} pr-12`}
                      required
                      {...fieldProps}
                    />
                    <button
                      type="button"
                      onClick={() => setShow((s) => !s)}
                      className="absolute top-1/2 right-1.5 grid size-9 -translate-y-1/2 place-items-center rounded-lg text-muted-foreground transition-colors outline-none hover:bg-(--nl-accent-soft) hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring"
                      aria-label={show ? 'Hide password' : 'Show password'}
                    >
                      {show ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <Checkbox
                      id="remember-session"
                      checked={remember}
                      onCheckedChange={(v) => setRemember(v === true)}
                      className="size-4.5 border-(--nl-line-strong) dark:bg-white"
                    />
                    <Label htmlFor="remember-session" className="cursor-pointer text-sm font-normal text-muted-foreground select-none">
                      Remember this session
                    </Label>
                  </div>
                  <Link
                    to={ROUTES.forgotPassword}
                    className="rounded-md text-sm font-medium text-primary outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring"
                  >
                    Forgot password?
                  </Link>
                </div>

                <Button
                  type="submit"
                  disabled={loading}
                  aria-busy={loading}
                  className="h-11 w-full rounded-full text-[15px] font-semibold shadow-sm hover:bg-[#1E40AF]"
                >
                  {loading ? (
                    <>
                      <Loader2 className="size-4 animate-spin" aria-hidden /> Signing in…
                    </>
                  ) : (
                    <>
                      Sign in <ArrowRight className="nl-arrow size-4" aria-hidden />
                    </>
                  )}
                </Button>
              </form>

              <p className="mt-6 text-center text-sm text-muted-foreground">
                Need an account?{' '}
                <Link
                  to={ROUTES.register}
                  className="rounded-md font-medium text-primary outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring"
                >
                  Create account
                </Link>
              </p>
            </section>
          </main>
        </div>
      </div>

      {/* Rendered outside .netra-auth: the guide bubble is dark-styled and needs the app's dark tokens. */}
      <NetraGuide page="login" />
    </>
  )
}
