import type * as React from 'react'
import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Check, CircleAlert, Loader2, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { authService } from '@/services/auth'
import { HttpError } from '@/services/http'
import { AuthCard } from './login/AuthCard'

// Mirrors the backend policy shared with registration; the API remains authoritative.
const PASSWORD_MIN_LENGTH = 8
const PASSWORD_MAX_LENGTH = 128

type LinkState = 'ready' | 'invalid' | 'expired' | 'success'

export function ResetPasswordPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  // Read once, then drop the token from the address bar so it does not linger in history.
  const [token] = useState(() => params.get('token') ?? '')
  const [linkState, setLinkState] = useState<LinkState>(token ? 'ready' : 'invalid')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (params.has('token')) setParams({}, { replace: true })
  }, [params, setParams])

  const lengthOk = password.length >= PASSWORD_MIN_LENGTH && password.length <= PASSWORD_MAX_LENGTH
  const matches = password.length > 0 && password === confirmPassword

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setError('')
    if (!password || !confirmPassword) {
      setError('Enter and confirm your new password.')
      return
    }
    if (!lengthOk) {
      setError(`Password must be between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters.`)
      return
    }
    if (!matches) {
      setError('Passwords do not match.')
      return
    }

    setSubmitting(true)
    try {
      await authService.resetPassword(token, password)
      setPassword('')
      setConfirmPassword('')
      setLinkState('success')
    } catch (cause) {
      if (cause instanceof HttpError && cause.status === 400) setLinkState('invalid')
      else if (cause instanceof HttpError && cause.status === 410) setLinkState('expired')
      else if (cause instanceof HttpError && cause.status === 422) setError(cause.message)
      else if (cause instanceof HttpError && cause.status === 429) setError('Too many reset attempts. Wait a few minutes and try again.')
      else setError('Unable to reset your password right now. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  if (linkState === 'success') {
    return (
      <AuthCard titleId="reset-password-title" title="Password reset successfully." description="Your password has been changed. The reset link can no longer be used.">
        <div className="mt-6 space-y-4">
          <p role="status" className="flex gap-2.5 rounded-md border border-success/30 bg-success/10 px-3 py-2.5 text-xs leading-relaxed text-success">
            <ShieldCheck className="mt-0.5 size-4 shrink-0" /> Sign in with your new password to continue.
          </p>
          <Button size="lg" className="h-11 w-full text-[13px] font-semibold tracking-[0.14em]" onClick={() => navigate(ROUTES.login, { replace: true, state: { passwordReset: true } })}>
            RETURN TO SIGN IN <ArrowRight />
          </Button>
        </div>
      </AuthCard>
    )
  }

  if (linkState === 'invalid' || linkState === 'expired') {
    const expired = linkState === 'expired'
    return (
      <AuthCard
        titleId="reset-password-title"
        title={expired ? 'Reset link expired' : 'Reset link invalid'}
        description={expired
          ? 'This password reset link has expired. Request a new link to continue.'
          : 'This password reset link is invalid or has already been used. Request a new link to continue.'}
      >
        <div className="mt-6 space-y-3">
          <p role="alert" className="flex gap-2.5 rounded-md border border-critical/30 bg-critical/10 px-3 py-2.5 text-xs leading-relaxed text-critical">
            <CircleAlert className="mt-0.5 size-4 shrink-0" /> Your password has not been changed.
          </p>
          <Button asChild size="lg" className="h-11 w-full text-[13px] font-semibold tracking-[0.14em]">
            <Link to={ROUTES.forgotPassword}>REQUEST A NEW LINK <ArrowRight /></Link>
          </Button>
          <Button asChild variant="outline" size="lg" className="h-11 w-full text-[13px] font-semibold tracking-[0.14em]">
            <Link to={ROUTES.login}><ArrowLeft /> RETURN TO SIGN IN</Link>
          </Button>
        </div>
      </AuthCard>
    )
  }

  return (
    <AuthCard titleId="reset-password-title" title="Reset password" description="Choose a new password for your NETRA account.">
      <form onSubmit={handleSubmit} className="mt-6 space-y-4" noValidate>
        {error && <p role="alert" className="rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">{error}</p>}
        <div className="space-y-1.5">
          <Label htmlFor="new-password" className="text-xs text-foreground/85">New Password</Label>
          <Input id="new-password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} className="h-10 bg-black/25" maxLength={PASSWORD_MAX_LENGTH} required />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="confirm-new-password" className="text-xs text-foreground/85">Confirm Password</Label>
          <Input id="confirm-new-password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} className="h-10 bg-black/25" maxLength={PASSWORD_MAX_LENGTH} required />
        </div>
        <ul aria-label="Password requirements" className="space-y-1 text-[11px]">
          <Requirement met={lengthOk}>{PASSWORD_MIN_LENGTH}–{PASSWORD_MAX_LENGTH} characters</Requirement>
          <Requirement met={matches}>Both passwords match</Requirement>
        </ul>
        <Button type="submit" size="lg" disabled={submitting} className="mt-1 h-11 w-full text-[13px] font-semibold tracking-[0.14em] shadow-[0_10px_28px_-10px] shadow-primary/70">
          {submitting ? <><Loader2 className="animate-spin" /> RESETTING PASSWORD</> : <>RESET PASSWORD <ArrowRight /></>}
        </Button>
      </form>
      <div className="mt-4 text-center text-xs text-muted-foreground">
        <Link to={ROUTES.login} className="font-medium text-primary hover:underline">Return to Sign in</Link>
      </div>
    </AuthCard>
  )
}

function Requirement({ met, children }: { met: boolean; children: React.ReactNode }) {
  return (
    <li className={cn('flex items-center gap-1.5', met ? 'text-success' : 'text-muted-foreground')}>
      <Check className={cn('size-3', !met && 'opacity-40')} aria-hidden />
      {children}
      <span className="sr-only">{met ? '(met)' : '(not met)'}</span>
    </li>
  )
}
