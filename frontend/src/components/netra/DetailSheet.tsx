import type * as React from 'react'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'

interface DetailSheetProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  eyebrow?: React.ReactNode
  title: React.ReactNode
  description?: React.ReactNode
  children: React.ReactNode
}

/** Right-hand drawer for inspecting a row (event, asset, indicator). */
export function DetailSheet({ open, onOpenChange, eyebrow, title, description, children }: DetailSheetProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full gap-0 border-border bg-popover p-0 sm:max-w-lg">
        <SheetHeader className="border-b border-border px-6 pt-5 pb-4">
          {eyebrow && <div className="font-mono text-[11px] text-muted-foreground">{eyebrow}</div>}
          <SheetTitle className="pr-6 text-lg leading-snug font-semibold tracking-tight">{title}</SheetTitle>
          {description ? <SheetDescription>{description}</SheetDescription> : <SheetDescription className="sr-only">Details</SheetDescription>}
        </SheetHeader>
        <div className="flex-1 space-y-6 overflow-y-auto px-6 py-5">{children}</div>
      </SheetContent>
    </Sheet>
  )
}

/** Titled block inside a detail sheet or panel. */
export function DetailSection({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section>
      <div className="mb-2.5 flex items-center justify-between gap-3">
        <h3 className="text-xs font-medium text-foreground/85">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  )
}
