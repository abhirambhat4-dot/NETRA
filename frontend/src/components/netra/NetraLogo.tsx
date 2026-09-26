import { useId } from 'react'
import { cn } from '@/lib/utils'

/** NETRA mark — a stylised eye/radar: "netra" is Sanskrit for eye. */
export function NetraMark({ className }: { className?: string }) {
  // Unique per instance: a shared id breaks when another copy is display:none.
  const gradientId = useId()
  return (
    <svg viewBox="0 0 32 32" fill="none" className={cn('size-8', className)} aria-hidden>
      <defs>
        <linearGradient id={gradientId} x1="4" y1="6" x2="28" y2="26" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--primary)" />
          <stop offset="1" stopColor="var(--brand-violet)" />
        </linearGradient>
      </defs>
      <rect x="0.5" y="0.5" width="31" height="31" rx="8.5" className="fill-primary/8 stroke-primary/25" />
      <path
        d="M5 16c2.8-4.9 6.6-7.3 11-7.3s8.2 2.4 11 7.3c-2.8 4.9-6.6 7.3-11 7.3S7.8 20.9 5 16Z"
        stroke={`url(#${gradientId})`}
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="16" r="3.6" stroke={`url(#${gradientId})`} strokeWidth="1.8" />
      <circle cx="16" cy="16" r="1.2" fill="var(--primary)" />
    </svg>
  )
}

export function NetraLogo({ collapsed, className }: { collapsed?: boolean; className?: string }) {
  return (
    <div className={cn('flex items-center gap-3', className)}>
      <NetraMark className="shrink-0" />
      {!collapsed && (
        <div className="min-w-0 leading-none">
          <div className="text-[15px] font-semibold tracking-[0.22em]">NETRA</div>
          <div className="mt-1 truncate text-[10px] font-medium tracking-[0.06em] text-muted-foreground">
            Cyber Decision Intelligence
          </div>
        </div>
      )}
    </div>
  )
}
