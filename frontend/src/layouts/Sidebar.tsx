import { NavLink } from 'react-router-dom'
import { NetraLogo, NetraMark, StatusDot } from '@/components/netra'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useQuery } from '@/hooks/useQuery'
import { NAV_GROUPS, type NavItem } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { dashboardService } from '@/services'

interface SidebarProps {
  /**
   * `responsive`: icon rail on tablet (md), full width on desktop (lg).
   * `expanded`: always full width (mobile drawer).
   */
  mode?: 'responsive' | 'expanded'
  onNavigate?: () => void
}

export function Sidebar({ mode = 'responsive', onNavigate }: SidebarProps) {
  const expanded = mode === 'expanded'
  const full = expanded ? '' : 'hidden lg:block'
  const { data: stats } = useQuery('sidebar-stats', dashboardService.getStats)
  const { data: systemHealth } = useQuery('sidebar-health', dashboardService.getSystemHealth)
  const healthy = systemHealth?.length ? systemHealth.every((c) => c.status === 'HEALTHY') : null

  return (
    <div className="flex h-full flex-col bg-sidebar/85">
      <div className={cn('flex h-16 shrink-0 items-center border-b border-sidebar-border/80', expanded ? 'px-4' : 'justify-center lg:justify-start lg:px-4')}>
        <div className="flex items-center gap-2.5">
          <div className="relative flex h-8 w-8 items-center justify-center rounded-md border border-primary/25 bg-primary/10">
            <span className="absolute inset-1 rounded-sm border border-primary/30" />
            <span className="relative h-2.5 w-2.5 rounded-full bg-primary shadow-[0_0_18px_rgba(56,217,255,0.8)]" />
          </div>
          <NetraLogo className={expanded ? '' : 'hidden lg:flex'} />
          <NetraMark className={expanded ? 'hidden' : 'lg:hidden'} />
        </div>
      </div>

      <nav className="flex-1 space-y-5 overflow-y-auto px-2.5 pt-4 pb-4" aria-label="Main">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <div className={cn('mb-2 px-2.5 text-[10px] font-semibold tracking-[0.18em] text-muted-foreground/70 uppercase', full)}>
              {group.label}
            </div>
            {!expanded && <div className="mx-auto mb-2 h-px w-6 bg-sidebar-border lg:hidden" />}
            <ul className="space-y-1">
              {group.items.map((item) => (
                <li key={item.to}>
                  <SidebarLink
                    item={item}
                    expanded={expanded}
                    onNavigate={onNavigate}
                    count={item.badge === 'activeIncidents' ? stats?.activeIncidents : undefined}
                  />
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="shrink-0 p-2.5">
        <div className={cn('surface-inset rounded-xl px-3 py-2.5', !expanded && 'max-lg:flex max-lg:justify-center max-lg:px-0')}>
          <div className={cn('text-[10px] font-semibold tracking-[0.14em] text-muted-foreground/70 uppercase', full)}>System status</div>
          <div className={cn('flex items-center gap-2', expanded ? 'mt-1.5' : 'lg:mt-1.5')}>
            <StatusDot tone={healthy === null ? 'info' : healthy ? 'low' : 'medium'} pulse={healthy !== null} />
            <span className={cn('text-xs font-medium', healthy === null ? 'text-muted-foreground' : healthy ? 'text-low' : 'text-medium', full)}>
              {healthy === null ? 'Status unavailable' : healthy ? 'Operational' : 'Degraded'}
            </span>
            {systemHealth && systemHealth.length > 0 && (
              <span className={cn('ml-auto font-mono text-[10px] text-muted-foreground', full)}>
                {systemHealth.filter((c) => c.status === 'HEALTHY').length}/{systemHealth.length}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function SidebarLink({
  item,
  expanded,
  onNavigate,
  count,
}: {
  item: NavItem
  expanded: boolean
  onNavigate?: () => void
  count?: number
}) {
  const Icon = item.icon

  const link = (
    <NavLink
      to={item.to}
      onClick={onNavigate}
      className={({ isActive }) =>
        cn(
          'group relative flex h-9 items-center gap-2.5 rounded-lg px-2.5 text-[13px] font-medium transition-all duration-200',
          !expanded && 'max-lg:justify-center max-lg:px-0',
          isActive
            ? 'bg-primary/10 text-foreground ring-1 ring-inset ring-primary/20'
            : 'text-muted-foreground hover:bg-foreground/4 hover:text-foreground',
        )
      }
    >
      {({ isActive }) => (
        <>
          <span
            aria-hidden
            className={cn(
              'absolute top-2 bottom-2 left-0 w-0.5 rounded-full bg-primary transition-all duration-200',
              isActive ? 'opacity-100' : 'scale-y-0 opacity-0',
            )}
          />
          <Icon className={cn('size-4 shrink-0 transition-colors', isActive ? 'text-primary' : 'group-hover:text-foreground')} />
          <span className={cn('truncate', !expanded && 'hidden lg:block')}>{item.label}</span>
          {count !== undefined && count > 0 && (
            <span
              className={cn(
                'ml-auto rounded-md bg-critical/12 px-1.5 font-mono text-[10px] leading-4.5 font-semibold text-critical',
                !expanded && 'max-lg:absolute max-lg:top-0.5 max-lg:right-1.5 max-lg:ml-0 max-lg:px-1 max-lg:text-[9px]',
              )}
            >
              {count}
            </span>
          )}
        </>
      )}
    </NavLink>
  )

  if (expanded) return link

  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right" sideOffset={8} className="lg:hidden">
        {item.label}
      </TooltipContent>
    </Tooltip>
  )
}
