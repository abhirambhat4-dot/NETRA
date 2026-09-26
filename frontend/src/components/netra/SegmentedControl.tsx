import { cn } from '@/lib/utils'

interface SegmentedControlProps<T extends string> {
  value: T
  options: { value: T; label: string }[]
  onChange: (value: T) => void
  className?: string
  'aria-label'?: string
}

export function SegmentedControl<T extends string>({ value, options, onChange, className, ...aria }: SegmentedControlProps<T>) {
  return (
    <div role="radiogroup" aria-label={aria['aria-label']} className={cn('inline-flex rounded-lg border border-border bg-foreground/3 p-0.5', className)}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          onClick={() => onChange(o.value)}
          className={cn(
            'h-6 rounded-md px-2.5 text-xs font-medium transition-colors',
            o.value === value
              ? 'bg-surface-raised text-foreground shadow-sm ring-1 ring-foreground/8'
              : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
