import { Fragment } from 'react'
import { Link, useMatches, useNavigate } from 'react-router-dom'
import { Bell, ChevronRight, LogOut, Menu, Settings, User } from 'lucide-react'
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
import { incidentService } from '@/services'

const Divider = () => <span aria-hidden className="hidden h-5 w-px bg-border sm:block" />

export function Header({ onOpenNav }: { onOpenNav: () => void }) {
  const navigate = useNavigate()
  const now = useNow()
  const { data: incidents } = useQuery('header-alerts', () => incidentService.list({ pageSize: 50 }))
  const alerts = (incidents?.items ?? [])
    .filter((i) => i.status === 'NEW' || i.status === 'INVESTIGATING' || i.status === 'AWAITING_AUTHORIZATION')
    .filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH')
    .slice(0, 4)

  const crumbs = useMatches()
    .filter((m) => isRouteHandle(m.handle))
    .map((m) => {
      const { crumb } = m.handle as { crumb: string | ((p: typeof m.params) => string) }
      return { path: m.pathname, label: typeof crumb === 'function' ? crumb(m.params) : crumb }
    })

  return (
    <header className="surface-glass sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border px-4 md:px-6 lg:px-8">
      <Button variant="ghost" size="icon" className="-ml-1 md:hidden" onClick={onOpenNav} aria-label="Open navigation">
        <Menu />
      </Button>

      {/* Breadcrumb */}
      <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-1.5 text-[13px]">
        <span className="hidden text-muted-foreground sm:inline">NETRA</span>
        {crumbs.map((c, i) => (
          <Fragment key={c.path}>
            <ChevronRight className={cn('size-3.5 shrink-0 text-muted-foreground/50', i === 0 && 'hidden sm:block')} />
            {i < crumbs.length - 1 ? (
              <Link to={c.path} className="truncate text-muted-foreground transition-colors hover:text-foreground">
                {c.label}
              </Link>
            ) : (
              <span className="truncate font-medium text-foreground">{c.label}</span>
            )}
          </Fragment>
        ))}
      </nav>

      {/* Right cluster */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2" title="All NETRA components operational">
          <StatusDot tone="low" pulse />
          <span className="hidden text-xs font-medium text-foreground/85 lg:inline">All systems operational</span>
        </div>

        <Divider />

        <div className="hidden items-center gap-2 font-mono text-xs text-muted-foreground tabular-nums sm:flex">
          <span className="text-foreground/85">{now.toISOString().slice(11, 19)}</span>
          <span className="text-[10px] tracking-wider">UTC</span>
        </div>

        <Divider />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative text-muted-foreground hover:text-foreground" aria-label={`Notifications (${alerts.length})`}>
              <Bell className="size-4.5" />
              {alerts.length > 0 && (
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
            {alerts.map((i) => (
              <DropdownMenuItem key={i.id} className="items-start gap-3 px-2 py-2" onSelect={() => navigate(ROUTES.incident(i.id))}>
                <span className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', toneStyles[severityTone[i.severity]].solid)} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[13px] font-medium">{i.threatName}</span>
                  <span className="block text-[11px] text-muted-foreground">
                    <span className="font-mono">{i.id}</span> · risk {i.riskScore} · {timeAgo(i.lastSeen, now.getTime())}
                  </span>
                </span>
              </DropdownMenuItem>
            ))}
            {alerts.length === 0 && <div className="px-3 py-6 text-center text-sm text-muted-foreground">No new alerts</div>}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center gap-2.5 rounded-lg p-1 transition-colors outline-none hover:bg-foreground/4 focus-visible:ring-2 focus-visible:ring-ring lg:pr-2">
              <Avatar className="size-7 rounded-md">
                <AvatarFallback className="rounded-md bg-linear-to-br from-primary/30 to-violet/30 text-[11px] font-semibold text-foreground">
                  AD
                </AvatarFallback>
              </Avatar>
              <div className="hidden text-left leading-tight lg:block">
                <div className="text-[13px] font-medium">Admin</div>
                <div className="text-[11px] text-muted-foreground">Security Administrator</div>
              </div>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>
              <div className="text-sm font-medium">Admin</div>
              <div className="text-xs font-normal text-muted-foreground">admin@netra.local</div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem>
              <User /> Profile
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => navigate(ROUTES.settings)}>
              <Settings /> Settings
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onSelect={() => navigate(ROUTES.login)}>
              <LogOut /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
