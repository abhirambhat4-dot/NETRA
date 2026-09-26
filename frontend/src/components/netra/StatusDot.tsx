import { cn } from '@/lib/utils'
import { toneStyles, type Tone } from '@/lib/tones'

interface StatusDotProps {
  tone: Tone
  pulse?: boolean
  size?: 'sm' | 'md'
  className?: string
}

export function StatusDot({ tone, pulse, size = 'md', className }: StatusDotProps) {
  const style = toneStyles[tone]
  const dim = size === 'sm' ? 'size-1.5' : 'size-2'
  return (
    <span className={cn('relative inline-flex shrink-0', dim, className)} aria-hidden>
      {pulse && (
        <span className={cn('absolute inset-0 rounded-full animate-status-pulse', style.solid)} />
      )}
      <span className={cn('relative inline-flex rounded-full', dim, style.solid)} />
    </span>
  )
}
