import { Link, NavLink } from 'react-router-dom'
import { NetraLogo, NetraMark, StatusDot } from '@/components/netra'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useQuery } from '@/hooks/useQuery'
import { NAV_GROUPS, ROUTES, type NavItem } from '@/lib/navigation'
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
  const healthyCount = systemHealth?.filter((c) => c.status === 'HEALTHY').length ?? 0

  return (
    <div className="flex h-full flex-col bg-sidebar">
      <div className={cn('flex h-16 shrink-0 items-center', expanded ? 'px-5' : 'justify-center lg:justify-start lg:px-5')}>
        <Link
          to={ROUTES.commandHome}
          onClick={onNavigate}
          aria-label="NETRA Command Home"
          title="Command Home"
          className="rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <NetraLogo className={expanded ? '' : 'hidden lg:flex'} />
          <NetraMark className={expanded ? 'hidden' : 'lg:hidden'} />
        </Link>
      </div>

      <nav className="flex-1 space-y-6 overflow-y-auto px-2.5 pt-3 pb-4" aria-label="Main">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <div className={cn('mb-1.5 px-3 text-[11px] font-semibold tracking-[0.08em] text-muted-foreground/80 uppercase', full)}>
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

      <div className="shrink-0 border-t border-sidebar-border p-3">
        <div
          className={cn('flex items-center gap-2.5 rounded-lg px-2.5 py-2', !expanded && 'max-lg:justify-center max-lg:px-0')}
          title={healthy === null ? 'System health is not available from the current API' : `${healthyCount} of ${systemHealth?.length} components healthy`}
        >
          <StatusDot tone={healthy === null ? 'neutral' : healthy ? 'low' : 'medium'} pulse={healthy === false} />
          <div className={cn('min-w-0 flex-1 leading-tight', full)}>
            <div className="text-[12px] font-medium text-foreground">
              {healthy === null ? 'Status unavailable' : healthy ? 'All systems operational' : 'Degraded service'}
            </div>
            <div className="text-[11px] text-muted-foreground">
              {systemHealth?.length ? `${healthyCount}/${systemHealth.length} components healthy` : 'No health report'}
            </div>
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
      className={cn(
        'app-nav-link group relative flex h-9 items-center gap-3 rounded-lg px-3 text-[13px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground',
        !expanded && 'max-lg:justify-center max-lg:px-0',
      )}
    >
      {({ isActive }) => (
        <>
          <Icon className={cn('size-[17px] shrink-0', isActive ? 'text-primary' : 'text-muted-foreground/80 group-hover:text-foreground')} strokeWidth={isActive ? 2.1 : 1.8} />
          <span className={cn('truncate', !expanded && 'hidden lg:block')}>{item.label}</span>
          {count !== undefined && count > 0 && (
            <span
              className={cn(
                'ml-auto rounded-full bg-critical/10 px-1.5 font-mono text-[10px] leading-[18px] font-semibold text-critical',
                !expanded && 'max-lg:absolute max-lg:top-0 max-lg:right-1.5 max-lg:ml-0 max-lg:bg-critical max-lg:px-1 max-lg:text-[9px] max-lg:leading-4 max-lg:text-white',
              )}
              aria-label={`${count} active incidents`}
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
