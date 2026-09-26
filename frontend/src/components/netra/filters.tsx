import type * as React from 'react'
import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'

// ---------------------------------------------------------------------------

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
}

export function SearchInput({ value, onChange, placeholder = 'Search…', className }: SearchInputProps) {
  return (
    <div className={cn('relative', className)}>
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="h-8 pr-8 pl-8 text-[13px]"
        aria-label={placeholder}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
          aria-label="Clear search"
        >
          <X className="size-3.5" />
        </button>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------

interface FilterChipsProps<T extends string> {
  value: T
  options: { value: T; label: string; count?: number; dot?: string }[]
  onChange: (value: T) => void
  className?: string
  'aria-label'?: string
}

/** Single-select chip group with optional counts. */
export function FilterChips<T extends string>({ value, options, onChange, className, ...aria }: FilterChipsProps<T>) {
  return (
    <div role="radiogroup" aria-label={aria['aria-label']} className={cn('flex flex-wrap items-center gap-1.5', className)}>
      {options.map((o) => {
        const active = o.value === value
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(o.value)}
            className={cn(
              'inline-flex h-7 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-medium transition-colors',
              active
                ? 'border-primary/30 bg-primary/12 text-foreground'
                : 'border-border bg-foreground/2 text-muted-foreground hover:border-foreground/15 hover:text-foreground',
            )}
          >
            {o.dot && <span className={cn('size-1.5 rounded-full', o.dot)} />}
            {o.label}
            {o.count !== undefined && (
              <span className={cn('font-mono text-[10px] tabular-nums', active ? 'text-foreground/70' : 'text-muted-foreground/70')}>
                {o.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------

interface SelectFilterProps<T extends string> {
  value: T
  onChange: (value: T) => void
  options: { value: T; label: string }[]
  label: string
  className?: string
}

/** Compact labelled dropdown filter. Use 'ALL' as the unfiltered value. */
export function SelectFilter<T extends string>({ value, onChange, options, label, className }: SelectFilterProps<T>) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as T)}>
      <SelectTrigger size="sm" className={cn('h-8 min-w-36 gap-2 text-[13px]', className)} aria-label={label}>
        <span className="text-muted-foreground">{label}</span>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

// ---------------------------------------------------------------------------

interface PaginationProps {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
}

export function Pagination({ page, pageSize, total, onChange }: PaginationProps) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)
  return (
    <div className="flex items-center justify-between gap-4 px-5 py-3 text-xs text-muted-foreground">
      <span>
        Showing <span className="font-mono text-foreground/85">{from}–{to}</span> of{' '}
        <span className="font-mono text-foreground/85">{total}</span>
      </span>
      <div className="flex items-center gap-1">
        <PageButton disabled={page <= 1} onClick={() => onChange(page - 1)}>
          Prev
        </PageButton>
        {Array.from({ length: pages }, (_, i) => i + 1).map((p) => (
          <PageButton key={p} active={p === page} onClick={() => onChange(p)}>
            {p}
          </PageButton>
        ))}
        <PageButton disabled={page >= pages} onClick={() => onChange(page + 1)}>
          Next
        </PageButton>
      </div>
    </div>
  )
}

function PageButton({ active, disabled, onClick, children }: { active?: boolean; disabled?: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      aria-current={active ? 'page' : undefined}
      className={cn(
        'h-7 min-w-7 rounded-md px-2 font-mono text-[11px] transition-colors disabled:pointer-events-none disabled:opacity-40',
        active ? 'bg-primary/15 text-foreground ring-1 ring-primary/25' : 'hover:bg-foreground/5 hover:text-foreground',
      )}
    >
      {children}
    </button>
  )
}
