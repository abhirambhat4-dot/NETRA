import type * as React from 'react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Eye, EyeOff, Loader2, Lock, ShieldCheck } from 'lucide-react'
import { NetraLogo, StatusDot } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useNow } from '@/hooks/useNow'
import { ROUTES } from '@/lib/navigation'
import { STAGE_ORDER, stageMeta } from '@/lib/stages'

const STAGE_TEXT: Record<(typeof STAGE_ORDER)[number], string> = {
  DETECT: 'Suricata signatures and ML anomaly detection',
  UNDERSTAND: 'Events correlated into incidents with asset context',
  PRIORITISE: 'Explainable risk scoring on a 0–100 scale',
  VERIFY: 'Human authorization with OTP before any action',
  CONTAIN: 'Targeted containment with post-action verification',
  LEARN: 'Outcomes captured in Cyber Memory',
}

const COMPONENTS = ['Suricata IDS', 'ML Detection', 'Risk Engine', 'Cyber Memory']

export function LoginPage() {
  const navigate = useNavigate()
  const now = useNow()
  const [email, setEmail] = useState('admin@netra.local')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [loading, setLoading] = useState(false)

  // MOCK authentication — any credentials succeed. Real JWT auth arrives with the backend.
  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setTimeout(() => navigate(ROUTES.dashboard), 700)
  }

  return (
    <div className="relative grid min-h-svh bg-background lg:grid-cols-[1.15fr_1fr]">
      <div aria-hidden className="netra-atmosphere pointer-events-none fixed inset-0" />
      <div aria-hidden className="netra-grid pointer-events-none fixed inset-0" />

      {/* Brand panel */}
      <section className="relative hidden flex-col justify-between overflow-hidden border-r border-border p-12 lg:flex">
        <span aria-hidden className="pointer-events-none absolute -top-40 -left-40 size-[520px] rounded-full bg-primary/10 blur-3xl" />
        <span aria-hidden className="pointer-events-none absolute -bottom-48 left-1/3 size-[420px] rounded-full bg-violet/8 blur-3xl" />

        <NetraLogo className="relative" />

        <div className="relative max-w-md space-y-9">
          <div className="space-y-4">
            <div className="text-[11px] font-semibold tracking-[0.2em] text-primary uppercase">Cyber Decision Intelligence</div>
            <h1 className="text-[2.5rem] leading-[1.1] font-semibold tracking-tight text-balance">
              From detection to decision — with a human in the loop.
            </h1>
            <p className="text-[15px] leading-relaxed text-muted-foreground">
              Collaborative risk prioritisation and explainable security decision support.
            </p>
          </div>

          <ol className="space-y-3.5">
            {STAGE_ORDER.map((s) => {
              const meta = stageMeta[s]
              return (
                <li key={s} className="flex items-start gap-3.5">
                  <span className="surface-inset grid size-8 shrink-0 place-items-center rounded-lg text-primary">
                    <meta.icon className="size-4" />
                  </span>
                  <div>
                    <div className="text-sm font-medium">{meta.label}</div>
                    <div className="text-xs text-muted-foreground">{STAGE_TEXT[s]}</div>
                  </div>
                </li>
              )
            })}
          </ol>
        </div>

        <div className="relative text-xs text-muted-foreground">© 2026 NETRA · Final-year Cyber Security project</div>
      </section>

      {/* Sign-in */}
      <section className="relative flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <NetraLogo className="mb-10 lg:hidden" />

          <div className="space-y-2">
            <div className="text-[11px] font-semibold tracking-[0.2em] text-primary uppercase lg:hidden">Cyber Decision Intelligence</div>
            <h2 className="text-[1.75rem] font-semibold tracking-tight">Sign in to NETRA</h2>
            <p className="text-sm text-muted-foreground">Secure access to the security command center.</p>
          </div>

          <form onSubmit={handleSubmit} className="surface-panel mt-8 space-y-5 rounded-xl p-6">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} className="h-10" required />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Password</Label>
                <button type="button" className="text-xs text-muted-foreground transition-colors hover:text-primary">
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Input
                  id="password"
                  type={show ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="h-10 pr-10"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShow((s) => !s)}
                  className="absolute top-1/2 right-2.5 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  aria-label={show ? 'Hide password' : 'Show password'}
                >
                  {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                </button>
              </div>
            </div>
            <Button type="submit" size="lg" disabled={loading} className="h-10 w-full font-semibold tracking-[0.12em] shadow-[0_8px_24px_-8px] shadow-primary/60">
              {loading ? <Loader2 className="animate-spin" /> : null}
              {loading ? 'VERIFYING' : 'SIGN IN'}
              {!loading && <ArrowRight />}
            </Button>
            <p className="text-center text-[11px] text-muted-foreground">Demo build — any credentials sign in.</p>
          </form>

          {/* Subtle system status */}
          <div className="surface-inset mt-6 rounded-lg px-4 py-3">
            <div className="flex items-center justify-between text-xs">
              <span className="inline-flex items-center gap-2 font-medium text-low">
                <StatusDot tone="low" pulse /> All systems operational
              </span>
              <span className="font-mono text-muted-foreground">{now.toISOString().slice(11, 19)} UTC</span>
            </div>
            <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
              {COMPONENTS.map((c) => (
                <span key={c} className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
                  <span className="size-1.5 rounded-full bg-low" /> {c}
                </span>
              ))}
            </div>
          </div>

          <div className="mt-5 space-y-1.5 text-xs text-muted-foreground">
            <p className="flex items-center gap-2">
              <ShieldCheck className="size-3.5 text-low" /> Containment actions require OTP authorization
            </p>
            <p className="flex items-center gap-2">
              <Lock className="size-3.5" /> Sessions are monitored and audited
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}
