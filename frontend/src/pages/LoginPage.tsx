import type * as React from 'react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Eye, EyeOff, Loader2, LockKeyhole } from 'lucide-react'
import { NetraLogo } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useNow } from '@/hooks/useNow'
import { ROUTES } from '@/lib/navigation'
import { CyberBackdrop } from './login/CyberBackdrop'

const STATUS = ['Authentication service operational', 'Secure session channel', 'Audit logging enabled']

export function LoginPage() {
  const navigate = useNavigate()
  const now = useNow()
  const [email, setEmail] = useState('admin@netra.local')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [remember, setRemember] = useState(true)
  const [loading, setLoading] = useState(false)

  // MOCK authentication — any credentials succeed. Real JWT auth arrives with the backend.
  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setTimeout(() => navigate(ROUTES.dashboard), 700)
  }

  return (
    <div className="relative isolate flex min-h-svh flex-col overflow-hidden bg-background">
      <CyberBackdrop />

      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-10 sm:px-6">
        <div className="relative w-full max-w-[420px]">
          {/* Soft outer glow */}
          <div aria-hidden className="absolute -inset-6 -z-10 rounded-[2rem] bg-[radial-gradient(ellipse_at_top,rgb(79_140_255/0.22),transparent_65%),radial-gradient(ellipse_at_bottom,rgb(139_92_246/0.14),transparent_60%)] blur-2xl" />

          <section
            aria-labelledby="login-title"
            className="relative overflow-hidden rounded-2xl border border-white/10 bg-[linear-gradient(180deg,rgb(21_26_35/0.82),rgb(10_13_19/0.86))] shadow-[inset_0_1px_0_rgb(255_255_255/0.06),0_1px_2px_rgb(0_0_0/0.5),0_24px_60px_-20px_rgb(0_0_0/0.85),0_0_0_1px_rgb(79_140_255/0.06)] backdrop-blur-xl"
          >
            {/* Top accent line */}
            <span aria-hidden className="absolute inset-x-10 top-0 h-px bg-linear-to-r from-transparent via-primary/70 to-transparent" />

            <div className="px-7 pt-7 pb-6 sm:px-8">
              <NetraLogo />

              <div className="mt-7 inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/8 px-2.5 py-1 text-[10px] font-semibold tracking-[0.18em] text-primary uppercase">
                <LockKeyhole className="size-3" /> Secure command access
              </div>
              <h1 id="login-title" className="mt-3 text-[1.625rem] leading-tight font-semibold tracking-tight">
                Sign in to NETRA
              </h1>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
                Authenticate to access the Cyber Decision Intelligence Center.
              </p>

              <form onSubmit={handleSubmit} className="mt-6 space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="email" className="text-xs text-foreground/85">
                    Email
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    autoComplete="username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="h-10 bg-black/25"
                    required
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="password" className="text-xs text-foreground/85">
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
                      className="h-10 bg-black/25 pr-10"
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

                <div className="flex items-center justify-between gap-3 pt-0.5">
                  <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground select-none">
                    <Checkbox checked={remember} onCheckedChange={(v) => setRemember(v === true)} aria-label="Remember this session" />
                    Remember this session
                  </label>
                  <a
                    href="#"
                    onClick={(e) => e.preventDefault()}
                    className="text-xs text-muted-foreground transition-colors hover:text-primary"
                    title="Not available in the demo environment"
                  >
                    Forgot password?
                  </a>
                </div>

                <Button
                  type="submit"
                  size="lg"
                  disabled={loading}
                  className="mt-1 h-11 w-full text-[13px] font-semibold tracking-[0.14em] shadow-[0_10px_28px_-10px] shadow-primary/70"
                >
                  {loading ? (
                    <>
                      <Loader2 className="animate-spin" /> VERIFYING
                    </>
                  ) : (
                    <>
                      SIGN IN <ArrowRight />
                    </>
                  )}
                </Button>
              </form>

              <div className="mt-4 flex items-center justify-center gap-2 text-[11px] text-muted-foreground">
                <span className="rounded border border-medium/30 bg-medium/10 px-1.5 py-px text-[9px] font-semibold tracking-wider text-medium uppercase">
                  Demo environment
                </span>
                Any credentials are accepted
              </div>
            </div>

            {/* Security status */}
            <ul className="space-y-1.5 border-t border-white/6 bg-black/20 px-7 py-4 sm:px-8">
              {STATUS.map((s) => (
                <li key={s} className="flex items-center gap-2.5 text-[11px] text-muted-foreground">
                  <span className="relative flex size-1.5">
                    <span className="absolute inset-0 animate-status-pulse rounded-full bg-low" />
                    <span className="relative size-1.5 rounded-full bg-low" />
                  </span>
                  {s}
                </li>
              ))}
            </ul>
          </section>

          <p className="mt-5 text-center font-mono text-[10px] tracking-wider text-muted-foreground/70">
            NETRA GATEWAY · TLS 1.3 · {now.toISOString().slice(11, 19)} UTC
          </p>
        </div>
      </main>
    </div>
  )
}
