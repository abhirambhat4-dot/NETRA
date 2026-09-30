import type * as React from 'react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, Loader2, LockKeyhole } from 'lucide-react'
import { NetraGuide } from '@/components/guide'
import { NetraLogo } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useAuth } from '@/auth/AuthProvider'
import { ROUTES } from '@/lib/navigation'
import { HttpError } from '@/services/http'
import { CyberBackdrop } from './login/CyberBackdrop'

export function RegisterPage() {
  const navigate = useNavigate()
  const { register } = useAuth()
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setError('')
    if (!fullName.trim()) {
      setError('Enter your full name.')
      return
    }
    if (password.length < 8 || password.length > 128) {
      setError('Password must be between 8 and 128 characters.')
      return
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      await register({ email: email.trim(), full_name: fullName.trim(), password })
      navigate(ROUTES.login, { replace: true, state: { registered: true } })
    } catch (cause) {
      setError(cause instanceof HttpError && cause.status === 409
        ? 'An account with this email already exists.'
        : 'Unable to create your account right now. Please check your details and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative isolate flex min-h-svh flex-col overflow-hidden bg-background">
      <CyberBackdrop />
      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-10 sm:px-6">
        <div className="relative w-full max-w-[420px]">
          <div aria-hidden className="absolute -inset-6 -z-10 rounded-[2rem] bg-[radial-gradient(ellipse_at_top,rgb(79_140_255/0.22),transparent_65%),radial-gradient(ellipse_at_bottom,rgb(139_92_246/0.14),transparent_60%)] blur-2xl" />
          <section aria-labelledby="register-title" className="relative overflow-hidden rounded-2xl border border-white/10 bg-[linear-gradient(180deg,rgb(21_26_35/0.82),rgb(10_13_19/0.86))] shadow-[inset_0_1px_0_rgb(255_255_255/0.06),0_1px_2px_rgb(0_0_0/0.5),0_24px_60px_-20px_rgb(0_0_0/0.85),0_0_0_1px_rgb(79_140_255/0.06)] backdrop-blur-xl">
            <span aria-hidden className="absolute inset-x-10 top-0 h-px bg-linear-to-r from-transparent via-primary/70 to-transparent" />
            <div className="px-7 pt-7 pb-6 sm:px-8">
              <NetraLogo />
              <div className="mt-7 inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/8 px-2.5 py-1 text-[10px] font-semibold tracking-[0.18em] text-primary uppercase">
                <LockKeyhole className="size-3" /> Secure command access
              </div>
              <h1 id="register-title" className="mt-3 text-[1.625rem] leading-tight font-semibold tracking-tight">Create your account</h1>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">Register to access the NETRA command center.</p>

              <form onSubmit={handleSubmit} className="mt-6 space-y-4">
                {error && <p role="alert" className="rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">{error}</p>}
                <div className="space-y-1.5">
                  <Label htmlFor="full-name" className="text-xs text-foreground/85">Full Name</Label>
                  <Input id="full-name" autoComplete="name" value={fullName} onChange={(event) => setFullName(event.target.value)} className="h-10 bg-black/25" maxLength={255} required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="register-email" className="text-xs text-foreground/85">Email</Label>
                  <Input id="register-email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} className="h-10 bg-black/25" required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="register-password" className="text-xs text-foreground/85">Password</Label>
                  <Input id="register-password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} className="h-10 bg-black/25" minLength={8} maxLength={128} required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="confirm-password" className="text-xs text-foreground/85">Confirm Password</Label>
                  <Input id="confirm-password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} className="h-10 bg-black/25" required />
                </div>
                <Button type="submit" size="lg" disabled={loading} className="mt-1 h-11 w-full text-[13px] font-semibold tracking-[0.14em] shadow-[0_10px_28px_-10px] shadow-primary/70">
                  {loading ? <><Loader2 className="animate-spin" /> CREATING ACCOUNT</> : <>CREATE ACCOUNT <ArrowRight /></>}
                </Button>
              </form>

              <div className="mt-4 text-center text-xs text-muted-foreground">
                Already registered? <Link to={ROUTES.login} className="font-medium text-primary hover:underline">Sign in</Link>
              </div>
            </div>
          </section>
        </div>
      </main>
      <NetraGuide page="login" />
    </div>
  )
}