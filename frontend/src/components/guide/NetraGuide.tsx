import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import {
  GUIDE,
  dismissGuide,
  guideAutoTips,
  guideKeyFor,
  isGuideDismissed,
  type GuideKey,
  type GuideTone,
} from '@/lib/guide'
import { cn } from '@/lib/utils'
import { useGuideToneState } from './toneContext'
import { NetraGuideBubble } from './NetraGuideBubble'
import type { RobotState } from './NetraGuideRobot'
import { NetraGuideTrigger } from './NetraGuideTrigger'

const AUTO_OPEN_DELAY = 1200
const SPEAKING_MS = 1800
const SPOTLIGHT_MS = 2400
const AUTO_CLOSE_MS = 10_000

const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches

interface NetraGuideProps {
  /** Override the page key (otherwise resolved from the route). */
  page?: GuideKey
  /** Override the alert tone (otherwise read from GuideToneProvider). */
  tone?: GuideTone
  className?: string
}

/**
 * NETRA Guide — a small robot docked in the bottom-right corner.
 * - Opens a compact tip once per page per session (desktop/tablet only; on
 *   phones it just shows an unread dot so it never covers content). Automatic
 *   tips close themselves after 10 s unless hovered/focused.
 * - "Got it" / Esc / × dismiss it for the session; it stays manually available.
 * - "Show …" scrolls to the relevant section and briefly spotlights it while
 *   the robot leans toward it — the only movement it ever makes.
 */
export function NetraGuide({ page, tone: toneOverride, className }: NetraGuideProps) {
  const { pathname } = useLocation()
  const key = page ?? guideKeyFor(pathname)
  const { tone: contextTone } = useGuideToneState()
  const tone = toneOverride ?? contextTone

  // The page whose tip is open — navigating elsewhere closes it without an effect.
  const [openFor, setOpenFor] = useState<GuideKey | null>(null)
  const open = openFor !== null && openFor === key
  const [manual, setManual] = useState(false)
  const [speaking, setSpeaking] = useState(false)
  const [nudging, setNudging] = useState(false)
  const [hasTarget, setHasTarget] = useState(false)
  const [engaged, setEngaged] = useState(false) // pointer / focus inside the bubble
  const [, bump] = useState(0) // re-render after a dismissal
  const triggerRef = useRef<HTMLButtonElement>(null)

  const content = key ? GUIDE[key] : null
  const unread = key ? !isGuideDismissed(key) : false

  const show = useCallback(
    (byUser: boolean) => {
      setManual(byUser)
      setEngaged(false)
      setSpeaking(true) // "speaking" while the tip is first read
      setOpenFor(key)
      setHasTarget(!!content?.target && !!document.querySelector(`[data-guide-target="${content.target}"]`))
    },
    [content, key],
  )

  // Auto-open each page's tip once per session.
  useEffect(() => {
    if (!key || isGuideDismissed(key) || !guideAutoTips()) return
    if (!window.matchMedia('(min-width: 640px)').matches) return
    const t = window.setTimeout(() => show(false), AUTO_OPEN_DELAY)
    return () => window.clearTimeout(t)
  }, [key, show])

  useEffect(() => {
    if (!speaking) return
    const t = window.setTimeout(() => setSpeaking(false), SPEAKING_MS)
    return () => window.clearTimeout(t)
  }, [speaking])

  const dismiss = useCallback(() => {
    if (key) dismissGuide(key)
    setOpenFor(null)
    bump((n) => n + 1)
    if (manual) triggerRef.current?.focus({ preventScroll: true })
  }, [key, manual])

  // An automatic tip never lingers over content: it tucks itself away after a
  // short read unless the operator is interacting with it.
  useEffect(() => {
    if (!open || manual || engaged) return
    const t = window.setTimeout(dismiss, AUTO_CLOSE_MS)
    return () => window.clearTimeout(t)
  }, [open, manual, engaged, dismiss])

  const showMe = useCallback(() => {
    const el = content?.target ? document.querySelector<HTMLElement>(`[data-guide-target="${content.target}"]`) : null
    dismiss()
    if (!el) return
    const reduced = prefersReducedMotion()
    el.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' })
    el.classList.add('ng-spotlight')
    window.setTimeout(() => el.classList.remove('ng-spotlight'), SPOTLIGHT_MS)
    if (!reduced) {
      setNudging(true)
      window.setTimeout(() => setNudging(false), 900)
    }
  }, [content, dismiss])

  if (!key || !content) return null

  const state: RobotState = speaking ? 'speaking' : open ? 'guiding' : 'idle'

  return (
    <div
      data-tone={tone}
      className={cn(
        'ng-root pointer-events-none fixed right-3 bottom-3 z-40 flex flex-col items-end gap-3 sm:right-5 sm:bottom-5 print:hidden',
        className,
      )}
    >
      {open && (
        <div
          className="pointer-events-auto"
          onPointerEnter={() => setEngaged(true)}
          onPointerLeave={() => setEngaged(false)}
          onFocus={() => setEngaged(true)}
          onBlur={() => setEngaged(false)}
        >
          <NetraGuideBubble
            content={content}
            tone={tone}
            onDismiss={dismiss}
            onShowMe={hasTarget ? showMe : undefined}
            autoFocus={manual}
          />
        </div>
      )}
      <NetraGuideTrigger
        ref={triggerRef}
        className="pointer-events-auto"
        open={open}
        tone={tone}
        state={state}
        unread={unread}
        nudging={nudging}
        context={content.context}
        onClick={() => (open ? dismiss() : show(true))}
      />
    </div>
  )
}
