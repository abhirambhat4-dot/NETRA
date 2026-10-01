import type * as React from 'react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Loader2, MailCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ROUTES } from '@/lib/navigation'
import { authService } from '@/services/auth'
import { HttpError } from '@/services/http'
import { AuthCard } from './login/AuthCard'

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function requestError(cause: unknown): string {
  if (cause instanceof HttpError) {
    if (cause.status === 422) return 'Enter a valid email address.'
    if (cause.status === 429) return 'Too many reset requests. Wait a few minutes and try again.'
    if (cause.status === 503) return 'Password reset is temporarily unavailable. Contact your NETRA administrator.'
  }
  return 'Unable to send a reset link right now. Please try again.'
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setError('')
    if (!EMAIL_PATTERN.test(email.trim())) {
      setError('Enter a valid email address.')
      return
    }

    setSubmitting(true)
    try {
      await authService.forgotPassword(email.trim())
      setSent(true)
    } catch (cause) {
      setError(requestError(cause))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <AuthCard
      titleId="forgot-password-title"
      title="Forgot password"
      description="Enter your account email and NETRA will send a single-use link to reset your password."
    >
      {sent ? (
        <div className="mt-6 space-y-4">
          <p role="status" className="flex gap-2.5 rounded-md border border-success/30 bg-success/10 px-3 py-2.5 text-xs leading-relaxed text-success">
            <MailCheck className="mt-0.5 size-4 shrink-0" />
            If an account exists for this email, you will receive password reset instructions. The link expires shortly and can be used once.
          </p>
          <Button asChild variant="outline" size="lg" className="h-11 w-full text-[13px] font-semibold tracking-[0.14em]">
            <Link to={ROUTES.login}><ArrowLeft /> BACK TO SIGN IN</Link>
          </Button>
        </div>
      ) : (
        <>
          <form onSubmit={handleSubmit} className="mt-6 space-y-4" noValidate>
            {error && <p role="alert" className="rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">{error}</p>}
            <div className="space-y-1.5">
              <Label htmlFor="forgot-email" className="text-xs text-foreground/85">Email</Label>
              <Input id="forgot-email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} className="h-10 bg-black/25" placeholder="name@organization.com" required />
            </div>
            <Button type="submit" size="lg" disabled={submitting} className="mt-1 h-11 w-full text-[13px] font-semibold tracking-[0.14em] shadow-[0_10px_28px_-10px] shadow-primary/70">
              {submitting ? <><Loader2 className="animate-spin" /> SENDING RESET LINK</> : <>SEND RESET LINK <ArrowRight /></>}
            </Button>
          </form>
          <div className="mt-4 text-center text-xs text-muted-foreground">
            Remembered it? <Link to={ROUTES.login} className="font-medium text-primary hover:underline">Back to Sign in</Link>
          </div>
        </>
      )}
    </AuthCard>
  )
}
