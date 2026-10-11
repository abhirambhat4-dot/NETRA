import { cn } from '@/lib/utils'

interface SectionHeaderProps {
  eyebrow: string
  title: string
  /** Id for the heading, so the enclosing section can use aria-labelledby. */
  titleId: string
  description?: string
  align?: 'left' | 'center'
  className?: string
}

export function SectionHeader({ eyebrow, title, titleId, description, align = 'left', className }: SectionHeaderProps) {
  return (
    <div data-reveal className={cn(align === 'center' ? 'mx-auto max-w-2xl text-center' : 'max-w-2xl', className)}>
      <p className="text-sm font-semibold text-primary">{eyebrow}</p>
      <h2 id={titleId} className="mt-3 text-3xl font-semibold tracking-tight text-balance text-foreground sm:text-4xl">
        {title}
      </h2>
      {description ? (
        <p className="mt-4 text-base leading-relaxed text-pretty text-muted-foreground sm:text-lg">{description}</p>
      ) : null}
    </div>
  )
}
