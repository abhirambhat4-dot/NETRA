import { useState, type ComponentType, type ReactNode } from 'react'
import { Monitor, RotateCcw, ShieldCheck, UserRound } from 'lucide-react'
import { toast } from 'sonner'
import { useAuth } from '@/auth/AuthProvider'
import { NetraGuideRobot } from '@/components/guide'
import { PageContainer, PageHeader, Panel, ToneBadge } from '@/components/netra'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { guideAutoTips, resetGuideDismissals, setGuideAutoTips } from '@/lib/guide'
import { BASE_URL, USE_MOCKS } from '@/services/http'

const SECTIONS = [
  { id: 'account', label: 'Account', icon: UserRound },
  { id: 'preferences', label: 'Preferences', icon: ShieldCheck },
  { id: 'environment', label: 'Environment', icon: Monitor },
] as const

export function SettingsPage() {
  const { user } = useAuth()
  const [autoTips, setAutoTips] = useState(guideAutoTips)
  const displayName = user?.full_name || user?.email || 'Account unavailable'
  const initials = displayName
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part: string) => part[0].toUpperCase())
    .join('') || 'NA'

  return (
    <PageContainer>
      <PageHeader
        eyebrow="Administration"
        title="Settings"
        description="Account context, browser-local preferences, and this frontend's current data mode."
      />

      <div className="grid items-start gap-5 lg:grid-cols-[190px_minmax(0,1fr)] lg:gap-8">
        <nav aria-label="Settings sections" className="lg:sticky lg:top-20">
          <ul className="flex gap-1 overflow-x-auto border-b border-border pb-2 lg:block lg:space-y-0.5 lg:overflow-visible lg:border-0 lg:pb-0">
            {SECTIONS.map((section) => (
              <li key={section.id} className="shrink-0">
                <a
                  href={`#${section.id}`}
                  className="flex h-9 items-center gap-2.5 rounded-md px-2.5 text-[13px] text-muted-foreground transition-colors hover:bg-foreground/4 hover:text-foreground focus-visible:outline-2 focus-visible:outline-primary"
                >
                  <section.icon className="size-4" /> {section.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <div className="flex min-w-0 max-w-3xl flex-col gap-4">
          <Panel
            id="account"
            className="scroll-mt-20"
            title={<SectionTitle icon={UserRound}>Account</SectionTitle>}
            description="Authenticated account details. Profile editing is not available in this frontend."
          >
            <div className="flex items-center gap-4 border-b border-border pb-4">
              <Avatar className="size-12 rounded-lg">
                <AvatarFallback className="rounded-lg bg-primary/12 text-sm font-semibold text-primary">{initials}</AvatarFallback>
              </Avatar>
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">{displayName}</div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <ToneBadge tone="accent" size="sm">{user?.role?.replaceAll('_', ' ') ?? 'Role unavailable'}</ToneBadge>
                  <span className="text-[11px] text-muted-foreground">
                    {user?.is_active === true ? 'Account active' : user?.is_active === false ? 'Account inactive' : 'Account status unavailable'}
                  </span>
                </div>
              </div>
            </div>
            <dl className="mt-4 grid gap-x-6 gap-y-4 sm:grid-cols-2">
              <Fact label="Email" value={user?.email ?? 'Not available'} />
              <Fact label="Account ID" value={user?.id ?? 'Not available'} mono />
              <Fact label="Created" value={user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Not available'} />
              <Fact label="Profile changes" value="Managed by the account service" />
            </dl>
          </Panel>

          <Panel
            id="preferences"
            className="scroll-mt-20"
            title={<SectionTitle icon={ShieldCheck}>Preferences</SectionTitle>}
            description="The NETRA Guide preference is stored in this browser."
          >
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex min-w-0 items-center gap-3">
                <NetraGuideRobot className="size-9 shrink-0" />
                <div className="min-w-0">
                  <div className="text-[13px] font-medium">Automatically show Guide tips</div>
                  <div className="text-[11px] text-muted-foreground">The Guide remains available when automatic tips are off.</div>
                </div>
              </div>
              <Switch
                checked={autoTips}
                onCheckedChange={(value) => {
                  setAutoTips(value)
                  setGuideAutoTips(value)
                }}
                aria-label="Automatically show NETRA Guide tips"
              />
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
              <p className="text-[11px] text-muted-foreground">Replay dismissed contextual tips for this browser session.</p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  resetGuideDismissals()
                  toast.success('Guide tips will show again')
                }}
              >
                <RotateCcw /> Replay guide tips
              </Button>
            </div>
          </Panel>

          <Panel
            id="environment"
            className="scroll-mt-20"
            title={<SectionTitle icon={Monitor}>Environment</SectionTitle>}
            description="Read-only runtime information for this frontend session."
          >
            <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
              <Fact label="Operational data source" value={USE_MOCKS ? 'Interconnected frontend mock scenarios' : 'Configured service'} />
              <Fact label="Application mode" value={import.meta.env.MODE} />
              <Fact label="Time display" value="UTC" />
              {!USE_MOCKS && <Fact label="Configured service URL" value={BASE_URL} mono />}
            </dl>
            {USE_MOCKS && (
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
                <p className="text-[11px] text-muted-foreground">Reload the frontend to reset in-memory mock scenario changes.</p>
                <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                  <RotateCcw /> Reload mock scenarios
                </Button>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </PageContainer>
  )
}

function SectionTitle({ icon: Icon, children }: { icon: ComponentType<{ className?: string }>; children: ReactNode }) {
  return <span className="inline-flex items-center gap-2"><Icon className="size-4 text-primary" />{children}</span>
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-muted-foreground">{label}</dt>
      <dd className={mono ? 'mt-0.5 break-all font-mono text-xs text-foreground/90' : 'mt-0.5 text-[13px] text-foreground/90'}>{value}</dd>
    </div>
  )
}