import type { LucideIcon } from 'lucide-react'
import { CircleCheck, CircleDashed, Milestone } from 'lucide-react'
import { cn } from '@/lib/utils'
import { STATUS_META, type FeatureStatus } from './content'

// Text label + icon carry the meaning; colour only reinforces it.
const STYLE: Record<FeatureStatus, { icon: LucideIcon; className: string }> = {
  available: { icon: CircleCheck, className: 'border-[#A7F3D0] bg-[#ECFDF5] text-[#065F46]' },
  'in-progress': { icon: CircleDashed, className: 'border-[#FDE68A] bg-[#FFFBEB] text-[#92400E]' },
  planned: { icon: Milestone, className: 'border-[#CBD5E1] bg-[#F1F5F9] text-[#334155]' },
}

export function StatusChip({ status, className }: { status: FeatureStatus; className?: string }) {
  const { icon: Icon, className: tone } = STYLE[status]
  return (
    <span
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold whitespace-nowrap',
        tone,
        className,
      )}
    >
      <Icon className="size-3.5" aria-hidden />
      <span>
        <span className="sr-only">Status: </span>
        {STATUS_META[status].label}
      </span>
    </span>
  )
}
