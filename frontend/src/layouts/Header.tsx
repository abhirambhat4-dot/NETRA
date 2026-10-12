import { Fragment } from 'react'
import { Link, useMatches, useNavigate } from 'react-router-dom'
import { Bell, ChevronRight, LogOut, Menu, Settings, User } from 'lucide-react'
import { useAuth } from '@/auth/AuthProvider'
import { StatusDot } from '@/components/netra'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useNow } from '@/hooks/useNow'
import { useQuery } from '@/hooks/useQuery'
import { timeAgo } from '@/lib/format'
import { ROUTES, isRouteHandle } from '@/lib/navigation'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { dashboardService, incidentQueueService } from '@/services'
import { USE_MOCKS } from '@/services/http'

const ACTIVE_STATES = new Set(['DETECTED', 'UNDERSTOOD', 'PRIORITISED', 'VERIFIED', 'AUTHORIZED'])

const Divider = () => <span aria-hidden className="hidden h-6 w-px bg-border md:block" />

export function Header({ onOpenNav }: { onOpenNav: () => void }) {
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const now = useNow()
  const alertsQuery = useQuery('header-alerts', () => incidentQueueService.list({ state: 'ACTIVE', sort: 'risk' }))
  const incidents = alertsQuery.data
  const { data: systemHealth } = useQuery('header-health', dashboardService.getSystemHealth)
  const health = systemHealth?.length ? systemHealth.every((component) => component.status === 'HEALTHY') : null
  const alerts = (incidents ?? [])
    .filter((i) => ACTIVE_STATES.has(i.lifecycle))
    .filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH')
    .slice(0, 4)
  const displayName = user?.full_name ?? 'User'
  const initials = displayName.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('').toUpperCase()

  const crumbs = useMatches()
    .filter((m) => isRouteHandle(m.handle))
    .map((m) => {
      const { crumb } = m.handle as { crumb: string | ((p: typeof m.params) => string) }
      return { path: m.pathname, label: typeof crumb === 'function' ? crumb(m.params) : crumb }
    })

  return (
    <header className="surface-glass sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border px-4 md:px-6 lg:px-8">
      <Button variant="ghost" size="icon" className="-ml-1 md:hidden" onClick={onOpenNav} aria-label="Open navigation">
        <Menu />
      </Button>

      <div className="flex min-w-0 flex-1 items-center gap-3">
        <span className={cn(
          'inline-flex h-6 shrink-0 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold',
          USE_MOCKS ? 'border-medium/25 bg-medium/10 text-medium' : 'border-low/20 bg-low/8 text-low',
        )}>
          {!USE_MOCKS && <span className="size-1.5 rounded-full bg-low" />}
          {USE_MOCKS ? 'Demo data' : 'Live'}
        </span>

        <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-1.5 text-[13px]">
          <span className="hidden font-medium text-muted-foreground sm:inline">NETRA</span>
          {crumbs.map((c, i) => (
            <Fragment key={c.path}>
              <ChevronRight className={cn('size-3.5 shrink-0 text-muted-foreground/50', i === 0 && 'hidden sm:block')} />
              {i < crumbs.length - 1 ? (
                <Link to={c.path} className="truncate text-muted-foreground transition-colors hover:text-foreground">
                  {c.label}
                </Link>
              ) : (
                <span className="truncate font-semibold text-foreground">{c.label}</span>
              )}
            </Fragment>
          ))}
        </nav>
      </div>

      <div className="flex items-center gap-3">
        <div className="hidden items-center gap-2 rounded-full border border-border bg-card px-2.5 py-1 sm:flex" title={health === null ? 'System health is not available from the current API' : USE_MOCKS ? 'Demo health data' : 'Health reported by the API'}>
          <StatusDot tone={health === null ? 'neutral' : health ? 'low' : 'medium'} pulse={health === false} size="sm" />
          <span className="text-xs font-medium text-muted-foreground max-lg:sr-only">
            {health === null ? 'Health unavailable' : USE_MOCKS ? `Demo health ${health ? 'operational' : 'degraded'}` : health ? 'Operational' : 'Degraded'}
          </span>
        </div>

        <Divider />

        <div className="hidden items-center gap-1.5 font-mono text-xs text-muted-foreground tabular-nums md:flex" title="Current time (UTC)">
          <span className="text-foreground">{now.toISOString().slice(11, 19)}</span>
          <span className="text-[10px] tracking-wider">UTC</span>
        </div>

        <Divider />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative size-9 rounded-lg text-muted-foreground hover:text-foreground" aria-label={`Notifications (${alertsQuery.error ? 'unavailable' : incidents ? alerts.length : 'loading'})`}>
              <Bell className="size-4.5" />
              {incidents && alerts.length > 0 && (
                <span className="absolute top-1 right-1 grid h-3.5 min-w-3.5 place-items-center rounded-full bg-critical px-0.5 font-mono text-[9px] leading-none font-semibold text-white ring-2 ring-background">
                  {alerts.length}
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80 p-1.5">
            <DropdownMenuLabel className="flex items-center justify-between px-2 text-xs font-medium text-muted-foreground">
              Needs attention
              <span className="font-mono">{alerts.length}</span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {alertsQuery.error ? (
              <div className="px-3 py-6 text-center text-sm text-muted-foreground">Incident summary unavailable</div>
            ) : !incidents ? (
              <div className="px-3 py-6 text-center text-sm text-muted-foreground">Loading incidents…</div>
            ) : (
              alerts.map((i) => (
                <DropdownMenuItem key={i.id} className="items-start gap-3 px-2 py-2" onSelect={() => navigate(ROUTES.incident(i.id))}>
                  <span className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', toneStyles[severityTone[i.severity]].solid)} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px] font-medium">{i.title}</span>
                    <span className="block text-[11px] text-muted-foreground">
                      <span className="font-mono">{i.id}</span> · risk {i.riskScore ?? 'N/A'} · {timeAgo(i.updatedAt, now.getTime())}
                    </span>
                  </span>
                </DropdownMenuItem>
              ))
            )}
            {incidents && alerts.length === 0 && <div className="px-3 py-6 text-center text-sm text-muted-foreground">No active high-priority incidents</div>}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button aria-label={`Account menu for ${displayName}`} className="flex items-center gap-2.5 rounded-lg p-1 transition-colors outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring lg:pr-2.5">
              <Avatar className="size-8 rounded-full">
                <AvatarFallback className="rounded-full bg-primary text-[11px] font-semibold text-primary-foreground">
                  {initials || 'U'}
                </AvatarFallback>
              </Avatar>
              <div className="hidden text-left leading-tight lg:block">
                <div className="text-[13px] font-medium">{displayName}</div>
                <div className="text-[11px] text-muted-foreground">{user?.role ?? 'Authenticated user'}</div>
              </div>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>
              <div className="text-sm font-medium">{displayName}</div>
              <div className="text-xs font-normal text-muted-foreground">{user?.email}</div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem>
              <User /> Profile
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => navigate(ROUTES.settings)}>
              <Settings /> Settings
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onSelect={() => { logout(); navigate(ROUTES.login, { replace: true }) }}>
              <LogOut /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
