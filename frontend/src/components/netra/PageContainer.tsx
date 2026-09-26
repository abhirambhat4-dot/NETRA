import type * as React from 'react'
import { cn } from '@/lib/utils'

/** Vertical rhythm for page bodies. Every page renders inside one. */
export function PageContainer({ className, ...props }: React.ComponentProps<'div'>) {
  return <div className={cn('flex flex-col gap-6 lg:gap-8', className)} {...props} />
}
