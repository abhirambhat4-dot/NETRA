import type * as React from 'react'
import { useState } from 'react'
import { Bell, Monitor, RotateCcw, ShieldCheck, UserRound } from 'lucide-react'
import { toast } from 'sonner'
import { PageContainer, PageHeader, Panel, SelectFilter, ToneBadge } from '@/components/netra'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { cn } from '@/lib/utils'
import { BASE_URL, USE_MOCKS } from '@/services/http'

/** Mock settings — values live in component state only (no backend yet). */
export function SettingsPage() {
  const [name, setName] = useState('Admin')
  const [email, setEmail] = useState('admin@netra.local')
  const [security, setSecurity] = useState({ mfa: true, dualApproval: false, otpForContainment: true })
  const [timeout, setTimeoutValue] = useState('30')
  const [notify, setNotify] = useState({ critical: true, authorization: true, containment: true, digest: false })
  const [refresh, setRefresh] = useState('30')
  const [density, setDensity] = useState('comfortable')

  const save = (section: string) => toast.success(`${section} saved`, { description: 'Stored locally for this demo session.' })

  return (
    <PageContainer>
      <PageHeader title="Settings" description="Profile, security policy, notifications and platform preferences." />

      <div className="grid items-start gap-4 xl:grid-cols-2">
        <div className="flex flex-col gap-4">
          {/* Profile */}
          <Panel title={<Title icon={UserRound}>Profile</Title>} description="Your identity on the NETRA platform">
            <div className="flex items-center gap-4">
              <Avatar className="size-14 rounded-xl">
                <AvatarFallback className="rounded-xl bg-linear-to-br from-primary/30 to-violet/30 text-base font-semibold">AD</AvatarFallback>
              </Avatar>
              <div>
                <div className="text-sm font-medium">{name}</div>
                <div className="mt-1 flex items-center gap-2">
                  <ToneBadge tone="accent" size="sm">
                    Security Administrator
                  </ToneBadge>
                  <span className="text-[11px] text-muted-foreground">Approver for containment</span>
                </div>
              </div>
            </div>
            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              <Field label="Display name" id="name">
                <Input id="name" value={name} onChange={(e) => setName(e.target.value)} className="h-9" />
              </Field>
              <Field label="Email" id="email">
                <Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="h-9" />
              </Field>
            </div>
            <Footer onSave={() => save('Profile')} />
          </Panel>

          {/* Notifications */}
          <Panel title={<Title icon={Bell}>Notifications</Title>} description="What NETRA alerts you about">
            <div className="divide-y divide-border">
              <Toggle label="Critical incidents" hint="Risk score ≥ 85" checked={notify.critical} onChange={(v) => setNotify((n) => ({ ...n, critical: v }))} />
              <Toggle label="Authorization requests" hint="When a containment needs your approval" checked={notify.authorization} onChange={(v) => setNotify((n) => ({ ...n, authorization: v }))} />
              <Toggle label="Containment results" hint="Execution and verification outcomes" checked={notify.containment} onChange={(v) => setNotify((n) => ({ ...n, containment: v }))} />
              <Toggle label="Daily risk digest" hint="Summary email at 08:00 UTC" checked={notify.digest} onChange={(v) => setNotify((n) => ({ ...n, digest: v }))} />
            </div>
            <Footer onSave={() => save('Notification preferences')} />
          </Panel>

        </div>
        <div className="flex flex-col gap-4">
          {/* Security */}
          <Panel title={<Title icon={ShieldCheck}>Security</Title>} description="Authentication and authorization policy">
            <div className="divide-y divide-border">
              <Toggle
                label="Require multi-factor sign-in"
                hint="Applies to all analyst and approver accounts"
                checked={security.mfa}
                onChange={(v) => setSecurity((s) => ({ ...s, mfa: v }))}
              />
              <Toggle
                label="OTP verification for containment"
                hint="Approver confirms every containment with a one-time password"
                checked={security.otpForContainment}
                onChange={(v) => setSecurity((s) => ({ ...s, otpForContainment: v }))}
              />
              <Toggle
                label="Dual approval for critical assets"
                hint="Two approvers for actions on assets rated critical"
                checked={security.dualApproval}
                onChange={(v) => setSecurity((s) => ({ ...s, dualApproval: v }))}
              />
              <div className="flex items-center justify-between gap-4 py-3">
                <div>
                  <div className="text-[13px] font-medium">Session timeout</div>
                  <div className="text-[11px] text-muted-foreground">Idle sessions are signed out automatically</div>
                </div>
                <SelectFilter
                  label="After"
                  value={timeout}
                  onChange={setTimeoutValue}
                  options={[
                    { value: '15', label: '15 min' },
                    { value: '30', label: '30 min' },
                    { value: '60', label: '60 min' },
                  ]}
                />
              </div>
            </div>
            <Footer onSave={() => save('Security policy')} />
          </Panel>

          {/* System preferences */}
          <Panel title={<Title icon={Monitor}>System preferences</Title>} description="Display and data settings">
            <div className="divide-y divide-border">
              <Row label="Time zone" hint="All timestamps are shown in UTC">
                <span className="font-mono text-xs">UTC</span>
              </Row>
              <Row label="Live refresh" hint="How often dashboards poll for updates">
                <SelectFilter
                  label="Every"
                  value={refresh}
                  onChange={setRefresh}
                  options={[
                    { value: '15', label: '15 s' },
                    { value: '30', label: '30 s' },
                    { value: '60', label: '60 s' },
                  ]}
                />
              </Row>
              <Row label="Table density" hint="Row spacing in lists">
                <SelectFilter
                  label="Density"
                  value={density}
                  onChange={setDensity}
                  options={[
                    { value: 'comfortable', label: 'Comfortable' },
                    { value: 'compact', label: 'Compact' },
                  ]}
                />
              </Row>
              <Row label="Risk bands" hint="Severity thresholds used across NETRA">
                <div className="flex flex-wrap justify-end gap-1.5">
                  <ToneBadge tone="critical" size="sm">≥85</ToneBadge>
                  <ToneBadge tone="high" size="sm">≥65</ToneBadge>
                  <ToneBadge tone="medium" size="sm">≥40</ToneBadge>
                  <ToneBadge tone="low" size="sm">≥15</ToneBadge>
                </div>
              </Row>
              <Row label="Data source" hint={USE_MOCKS ? 'Interconnected mock data (VITE_USE_MOCKS)' : BASE_URL}>
                <ToneBadge tone={USE_MOCKS ? 'medium' : 'low'} size="sm">
                  {USE_MOCKS ? 'Mock' : 'Live API'}
                </ToneBadge>
              </Row>
            </div>
            <div className="mt-4 flex items-center justify-between gap-3 border-t border-border pt-4">
              <p className="text-[11px] text-muted-foreground">Reset restores the demo scenario (authorizations, containment, memory).</p>
              <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                <RotateCcw /> Reset demo data
              </Button>
            </div>
          </Panel>
        </div>
      </div>
    </PageContainer>
  )
}

function Title({ icon: Icon, children }: { icon: React.ComponentType<{ className?: string }>; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2">
      <Icon className="size-4 text-primary" /> {children}
    </span>
  )
}

function Field({ label, id, children }: { label: string; id: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </Label>
      {children}
    </div>
  )
}

function Toggle({ label, hint, checked, onChange }: { label: string; hint: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4 py-3 first:pt-0">
      <div>
        <div className="text-[13px] font-medium">{label}</div>
        <div className="text-[11px] text-muted-foreground">{hint}</div>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </label>
  )
}

function Row({ label, hint, children }: { label: string; hint: string; children: React.ReactNode }) {
  return (
    <div className={cn('flex items-center justify-between gap-4 py-3 first:pt-0')}>
      <div className="min-w-0">
        <div className="text-[13px] font-medium">{label}</div>
        <div className="truncate text-[11px] text-muted-foreground">{hint}</div>
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  )
}

function Footer({ onSave }: { onSave: () => void }) {
  return (
    <div className="mt-4 flex justify-end border-t border-border pt-4">
      <Button size="sm" onClick={onSave}>
        Save changes
      </Button>
    </div>
  )
}
