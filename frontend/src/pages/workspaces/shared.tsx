import type * as React from 'react'
import { Link } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import { Activity, ArrowRight, ChevronRight, ClipboardCheck, FileWarning, RadioTower, ShieldAlert } from 'lucide-react'
import type { Severity } from '@/api/types'
import { ErrorState, MeterBar, SeverityBadge, StatusDot, SurfaceCard } from '@/components/netra'
import { Button } from '@/components/ui/button'
import type { AttentionItem, AttentionKind } from '@/lib/attention'
import { formatDateTime, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { SEVERITY_ORDER, severityTone, type Tone } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { HttpError } from '@/services/http'

const KIND_META: Record<AttentionKind, { icon: LucideIcon; label: string }> = {
  incident: { icon: ShieldAlert, label: 'Incident' },
  event: { icon: Activity, label: 'Unlinked event' },
  activity: { icon: RadioTower, label: 'Collector event' },
  assessment: { icon: ClipboardCheck, label: 'Assessment finding' },
  dataset: { icon: FileWarning, label: 'Import issue' },
}

/**
 * Compact, linked attention rows; each opens the item's existing detail page.
 * `showDetail` prints the API's own explanation (e.g. the priority rationale) under each row.
 */
export function AttentionList({ items, showDetail = false }: { items: AttentionItem[]; showDetail?: boolean }) {
  return (
    <ul className="border-t border-border">
      {items.map((item) => {
        const kind = KIND_META[item.kind]
        return (
          <li key={item.key} className="border-b border-border/70 last:border-b-0">
            <Link
              to={item.to}
              title={item.detail}
              className="group grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3.5 px-5 py-3 transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6"
            >
              <span className="grid size-8 place-items-center rounded-lg border border-border bg-muted text-muted-foreground" aria-hidden>
                <kind.icon className="size-4" />
              </span>
              <span className="min-w-0">
                <span className="sr-only">{kind.label}: </span>
                <span className="block truncate text-[13px] font-medium text-foreground">{item.title}</span>
                <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">
                  <span className="text-foreground/75">{item.source}</span>
                  {item.reason && <span> · {item.reason}</span>}
                  {item.at && (
                    <>
                      <span className="text-muted-foreground/40"> · </span>
                      <time dateTime={item.at} title={`${formatDateTime(item.at)} UTC`}>{timeAgo(item.at)}</time>
                    </>
                  )}
                </span>
                {showDetail && item.detail && (
                  <span className="mt-1 line-clamp-2 block text-[12px] leading-snug text-muted-foreground">{item.detail}</span>
                )}
              </span>
              <span className="flex items-center gap-2">
                {item.severity && <SeverityBadge severity={item.severity} size="sm" />}
                <ChevronRight className="size-4 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-foreground max-sm:hidden" />
              </span>
            </Link>
          </li>
        )
      })}
    </ul>
  )
}

export interface StatusItem {
  label: string
  value: React.ReactNode
  /** Shows a status dot before the value. */
  tone?: Tone
  pulse?: boolean
  hint?: string
}

/** One compact status line instead of a row of metric cards. */
export function StatusRow({ items, footer, label }: { items: StatusItem[]; footer?: React.ReactNode; label: string }) {
  return (
    <SurfaceCard className="px-5 py-4">
      <dl aria-label={label} className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 lg:flex lg:flex-wrap lg:gap-x-10">
        {items.map((item) => (
          <div key={item.label} className="min-w-0" title={item.hint}>
            <dt className="text-[11px] font-medium text-muted-foreground">{item.label}</dt>
            <dd className="mt-1 flex items-center gap-2 truncate text-sm font-semibold text-foreground">
              {item.tone && <StatusDot tone={item.tone} pulse={item.pulse} size="sm" />}
              {item.value}
            </dd>
          </div>
        ))}
      </dl>
      {footer && <p className="mt-3 border-t border-border/70 pt-3 text-[12px] leading-relaxed text-muted-foreground">{footer}</p>}
    </SurfaceCard>
  )
}

/** Error body for a landing-page panel; a 401 offers sign-in instead of a retry. */
export function PanelError({ error, title, onRetry, className }: { error: Error; title: string; onRetry: () => void; className?: string }) {
  const unauthorized = error instanceof HttpError && error.status === 401
  return (
    <div className={cn(className)}>
      <ErrorState
        title={unauthorized ? 'Authentication required' : title}
        message={unauthorized ? undefined : error.message}
        onRetry={unauthorized ? undefined : onRetry}
      />
      {unauthorized && (
        <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
      )}
    </div>
  )
}

/** Count per severity as labelled meters; severities with no records still show 0. */
export function SeverityBreakdown({ mix, label }: { mix: Record<Severity, number>; label: string }) {
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + mix[severity], 0)
  return (
    <ul aria-label={label} className="space-y-3">
      {SEVERITY_ORDER.filter((severity) => severity !== 'INFO' || mix.INFO > 0).map((severity) => (
        <li key={severity} className="grid grid-cols-[5.5rem_minmax(0,1fr)_2.5rem] items-center gap-3">
          <SeverityBadge severity={severity} size="sm" />
          <MeterBar value={mix[severity]} max={Math.max(total, 1)} tone={severityTone[severity]} className="h-1.5" />
          <span className="text-right font-mono text-[12px] font-semibold text-foreground tabular-nums">{mix[severity].toLocaleString('en-US')}</span>
        </li>
      ))}
    </ul>
  )
}

export interface CapabilityFact {
  label: string
  value: React.ReactNode
  tone?: Tone
}

/**
 * One project capability: what NETRA stores for it, its stated limits, and links into the existing
 * workflow. `body` replaces the facts while loading or after an error.
 */
export function CapabilityCard({
  index,
  icon: Icon,
  title,
  facts,
  body,
  note,
  links,
}: {
  index: number
  icon: LucideIcon
  title: string
  facts?: CapabilityFact[]
  body?: React.ReactNode
  note: React.ReactNode
  links: Array<{ label: string; to: string }>
}) {
  return (
    <SurfaceCard className="flex flex-col gap-4">
      <header className="flex items-center gap-3">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg border border-border bg-muted text-primary" aria-hidden>
          <Icon className="size-4" />
        </span>
        <h3 className="min-w-0 text-[14px] font-semibold tracking-tight text-foreground">
          <span className="mr-1.5 font-mono text-[11px] text-muted-foreground">{String(index).padStart(2, '0')}</span>
          {title}
        </h3>
      </header>
      {body ?? (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          {facts?.map((fact) => (
            <div key={fact.label} className="min-w-0">
              <dt className="truncate text-[11px] font-medium text-muted-foreground" title={fact.label}>{fact.label}</dt>
              <dd className="mt-0.5 flex items-center gap-1.5 truncate text-[15px] font-semibold text-foreground tabular-nums">
                {fact.tone && <StatusDot tone={fact.tone} size="sm" />}
                {fact.value}
              </dd>
            </div>
          ))}
        </dl>
      )}
      <p className="text-[12px] leading-relaxed text-muted-foreground">{note}</p>
      <div className="mt-auto flex flex-wrap gap-x-4 gap-y-1 border-t border-border/70 pt-3">
        {links.map((link) => (
          <Link key={link.to} to={link.to} className="group inline-flex items-center gap-1 text-[12px] font-medium text-primary hover:underline">
            {link.label}
            <ArrowRight className="size-3 transition-transform group-hover:translate-x-0.5" />
          </Link>
        ))}
      </div>
    </SurfaceCard>
  )
}

/** Concise, always-visible notes under a list; empty notes are dropped and each ends with a full stop. */
export function ListNotes({ notes, centered = false }: { notes: Array<string | null | false | undefined>; centered?: boolean }) {
  const shown = notes.filter((note): note is string => Boolean(note))
  if (shown.length === 0) return null
  return (
    <ul className={cn('space-y-0.5 px-5 pt-3 pb-2 text-[12px] leading-relaxed text-muted-foreground', centered && 'pt-0 pb-3 text-center')}>
      {shown.map((note) => <li key={note}>{note.endsWith('.') ? note : `${note}.`}</li>)}
    </ul>
  )
}
