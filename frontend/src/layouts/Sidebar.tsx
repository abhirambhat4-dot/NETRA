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
  const full = expanded ? '' : 'hidden lg:block' // visible only when not a rail
  const { data: stats } = useQuery('sidebar-stats', dashboardService.getStats)
  const healthy = stats?.systemHealth.every((c) => c.status === 'HEALTHY') ?? true

  return (
    <div className="flex h-full flex-col bg-sidebar/85">
      {/* Brand */}
      <div className={cn('flex h-14 shrink-0 items-center', expanded ? 'px-4' : 'justify-center lg:justify-start lg:px-4')}>
        <NetraLogo className={expanded ? '' : 'hidden lg:flex'} />
        <NetraMark className={expanded ? 'hidden' : 'lg:hidden'} />
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-5 overflow-y-auto px-2.5 pt-3 pb-4" aria-label="Main">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <div className={cn('mb-1.5 px-2.5 text-[10px] font-semibold tracking-[0.14em] text-muted-foreground/70 uppercase', full)}>
              {group.label}
            </div>
            {!expanded && <div className="mx-auto mb-2 h-px w-6 bg-sidebar-border lg:hidden" />}
            <ul className="space-y-0.5">
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

      {/* System status */}
      <div className="shrink-0 p-2.5">
        <div className={cn('surface-inset rounded-lg px-3 py-2.5', !expanded && 'max-lg:flex max-lg:justify-center max-lg:px-0')}>
          <div className={cn('text-[10px] font-semibold tracking-[0.14em] text-muted-foreground/70 uppercase', full)}>System status</div>
          <div className={cn('flex items-center gap-2', expanded ? 'mt-1.5' : 'lg:mt-1.5')}>
            <StatusDot tone={healthy ? 'low' : 'medium'} pulse />
            <span className={cn('text-xs font-medium', healthy ? 'text-low' : 'text-medium', full)}>
              {healthy ? 'Operational' : 'Degraded'}
            </span>
            {stats && (
              <span className={cn('ml-auto font-mono text-[10px] text-muted-foreground', full)}>
                {stats.systemHealth.filter((c) => c.status === 'HEALTHY').length}/{stats.systemHealth.length}
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
            ? 'bg-linear-to-r from-primary/16 via-primary/7 to-violet/5 text-foreground shadow-[inset_0_0_0_1px_rgb(79_140_255/0.16)]'
            : 'text-muted-foreground hover:bg-foreground/4 hover:text-foreground',
        )
      }
    >
      {({ isActive }) => (
        <>
          <span
            aria-hidden
            className={cn(
              'absolute top-2 bottom-2 left-0 w-0.5 rounded-full bg-linear-to-b from-primary to-violet transition-all duration-300',
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
