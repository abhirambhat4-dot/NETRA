import type * as React from 'react'
import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ArrowRight, Eye, EyeOff, Loader2, ShieldCheck } from 'lucide-react'
import { useAuth } from '@/auth/AuthProvider'
import { NetraGuide } from '@/components/guide'
import { NetraLogo } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { hasCompletedBriefing } from '@/lib/briefing'
import { ROUTES } from '@/lib/navigation'
import { HttpError } from '@/services/http'
import { CyberBackdrop } from './login/CyberBackdrop'

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
      navigate(hasCompletedBriefing() ? ROUTES.dashboard : ROUTES.briefing, { replace: true })
    } catch (cause) {
      setError(cause instanceof HttpError && cause.status === 401
        ? 'Email or password is incorrect.'
        : 'Unable to sign in right now. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative isolate flex min-h-svh flex-col overflow-hidden bg-background">
      <CyberBackdrop />

      <header className="relative z-10 mx-auto w-full max-w-[1440px] px-4 pt-5 sm:px-6 lg:px-8">
        <Link to={ROUTES.home} className="inline-flex items-center gap-3 text-foreground transition-opacity hover:opacity-90">
          <NetraLogo className="h-8 w-auto" />
        </Link>
      </header>

      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-10 sm:px-6">
        <div className="w-full max-w-[430px]">
          <section
            aria-labelledby="login-title"
            className="relative overflow-hidden rounded-[28px] border border-border/80 bg-[linear-gradient(180deg,rgba(16,23,32,0.9),rgba(9,13,18,0.92))] shadow-[0_30px_90px_-40px_rgba(56,217,255,0.3)] backdrop-blur-sm"
          >
            <div className="absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,rgba(56,217,255,0.9),transparent)]" />
            <div className="px-5 py-5 sm:px-6 sm:py-6">
              <div className="flex items-center justify-between gap-3">
                <NetraLogo className="h-8 w-auto" />
                <div className="inline-flex items-center gap-2 rounded-full border border-success/20 bg-success/10 px-2.5 py-1 text-[10px] font-medium tracking-[0.16em] text-success uppercase">
                  <ShieldCheck className="size-3" />
                  Secure access
                </div>
              </div>

              <h1 id="login-title" className="mt-6 text-[2rem] leading-tight font-semibold tracking-[-0.06em] text-foreground">
                Sign in
              </h1>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                Access the NETRA cyber decision workspace and continue your operational review.
              </p>

              <form onSubmit={handleSubmit} className="mt-6 space-y-4">
                {registered && <p role="status" className="rounded-xl border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">Account created. Sign in with your new credentials.</p>}
                {passwordReset && <p role="status" className="rounded-xl border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">Password reset. Sign in with your new password.</p>}
                {error && <p role="alert" className="rounded-xl border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">{error}</p>}

                <div className="space-y-2">
                  <Label htmlFor="email" className="text-[11px] font-medium tracking-[0.12em] text-foreground/85 uppercase">
                    Email
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    autoComplete="username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="h-11 bg-background/45 text-sm text-foreground placeholder:text-muted-foreground/80"
                    placeholder="name@organization.com"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password" className="text-[11px] font-medium tracking-[0.12em] text-foreground/85 uppercase">
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
                      className="h-11 bg-background/45 pr-10 text-sm text-foreground placeholder:text-muted-foreground/80"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShow((s) => !s)}
                      className="absolute top-1/2 right-2 grid size-7 -translate-y-1/2 place-items-center rounded-md text-muted-foreground transition-colors hover:text-foreground"
                      aria-label={show ? 'Hide password' : 'Show password'}
                    >
                      {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-3">
                  <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground select-none">
                    <Checkbox checked={remember} onCheckedChange={(v) => setRemember(v === true)} aria-label="Remember this session" />
                    Remember this session
                  </label>
                  <Link to={ROUTES.forgotPassword} className="text-xs font-medium text-primary hover:underline">
                    Forgot password?
                  </Link>
                </div>

                <Button type="submit" size="lg" disabled={loading} className="mt-1 h-11 w-full rounded-full text-[11px] font-semibold tracking-[0.16em] uppercase">
                  {loading ? (
                    <>
                      <Loader2 className="size-4 animate-spin" /> Signing in
                    </>
                  ) : (
                    <>
                      Sign in <ArrowRight className="size-4" />
                    </>
                  )}
                </Button>
              </form>

              <div className="mt-5 text-center text-xs text-muted-foreground">
                Need an account? <Link to={ROUTES.register} className="font-medium text-primary hover:underline">Create account</Link>
              </div>
            </div>
          </section>

          <p className="mt-5 text-center text-[10px] font-medium tracking-[0.22em] text-muted-foreground/80 uppercase">
            NETRA · Cyber Decision Intelligence
          </p>
        </div>
      </main>

      <NetraGuide page="login" />
    </div>
  )
}
