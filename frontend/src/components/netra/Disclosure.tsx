import type * as React from 'react'
import { useId, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

interface DisclosureProps {
  /** Label of the toggle, e.g. "Incident metadata". */
  label: React.ReactNode
  /** Quiet trailing hint, e.g. a count. */
  hint?: React.ReactNode
  defaultOpen?: boolean
  /** Toggle text when open / closed; defaults to Show / Hide. */
  openText?: string
  closedText?: string
  className?: string
  toggleClassName?: string
  children: React.ReactNode
}

/**
 * Progressive disclosure: secondary detail stays one click away instead of
 * competing with the primary information. Collapsed content is `inert`, so it
 * is skipped by keyboard and screen readers until opened.
 */
export function Disclosure({
  label,
  hint,
  defaultOpen = false,
  openText = 'Hide',
  closedText = 'Show',
  className,
  toggleClassName,
  children,
}: DisclosureProps) {
  const [open, setOpen] = useState(defaultOpen)
  const id = useId()

  return (
    <div className={className}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          'group flex w-full items-center gap-2 rounded-md py-1.5 text-left text-xs text-muted-foreground transition-colors outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring',
          toggleClassName,
        )}
      >
        <ChevronDown className={cn('size-3.5 shrink-0 transition-transform duration-200', open && 'rotate-180')} />
        <span className="font-medium text-foreground/85 group-hover:text-foreground">{label}</span>
        {hint && <span className="min-w-0 truncate font-mono text-[11px] text-muted-foreground/80 max-sm:hidden">{hint}</span>}
        <span className="ml-auto shrink-0 text-[11px]">{open ? openText : closedText}</span>
      </button>
      <div id={id} className="netra-disclosure-body" data-open={open}>
        <div inert={!open}>
          <div className="pt-3">{children}</div>
        </div>
      </div>
    </div>
  )
}
