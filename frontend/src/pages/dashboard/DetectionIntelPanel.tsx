import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import type { EventsPageItem, SystemComponentHealth, TechniqueObservation } from '@/api/types'
import { StatusDot } from '@/components/netra'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ROUTES } from '@/lib/navigation'
import { EventFeed } from './EventFeed'
import { HealthSummary } from './HealthSummary'
import { TechniqueList } from './TechniqueList'

type Tab = 'attack' | 'events' | 'health'

interface Props {
  techniques?: TechniqueObservation[] | null
  events?: EventsPageItem[]
  health?: SystemComponentHealth[]
}

/**
 * Secondary analytics for the Command Center, grouped behind tabs so they
 * support — rather than compete with — posture, threats and incidents.
 */
export function DetectionIntelPanel({ techniques, events, health }: Props) {
  const [tab, setTab] = useState<Tab>('attack')
  const tactics = new Set((techniques ?? []).map((t) => t.technique.tactic)).size
  const healthy = health?.length ? health.every((c) => c.status === 'HEALTHY') : null

  const meta: Record<Tab, { description: string; link: { to: string; label: string } }> = {
    attack: {
      description: techniques ? `${techniques.length} techniques across ${tactics} tactics · last 7 days` : 'Observed ATT&CK techniques',
      link: { to: ROUTES.threatIntelligence, label: 'Threat intelligence' },
    },
    events: {
      description: 'Latest detections from Suricata, ML detector and threat intelligence',
      link: { to: ROUTES.events, label: 'Event stream' },
    },
    health: {
      description: 'NETRA pipeline components',
      link: { to: ROUTES.settings, label: 'System settings' },
    },
  }

  return (
    <section className="surface-panel flex h-full min-w-0 flex-col rounded-xl">
      <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)} className="flex flex-1 flex-col gap-0">
        <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3 px-5 pt-4.5 pb-3">
          <div className="min-w-0">
            <h2 className="text-[15px] font-semibold tracking-tight">Detection intelligence</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">{meta[tab].description}</p>
          </div>
          <TabsList className="h-8 bg-foreground/4">
            <TabsTrigger value="attack" className="px-2.5 text-xs">
              ATT&CK
            </TabsTrigger>
            <TabsTrigger value="events" className="px-2.5 text-xs">
              Events
            </TabsTrigger>
            <TabsTrigger value="health" className="gap-1.5 px-2.5 text-xs">
              {healthy !== null && <StatusDot tone={healthy ? 'low' : 'medium'} size="sm" />}
              Health
            </TabsTrigger>
          </TabsList>
        </header>

        <div className="flex-1 border-t border-border">
          <TabsContent value="attack" className="motion-safe:animate-in motion-safe:fade-in-0">
            <TechniqueList techniques={techniques} />
          </TabsContent>
          <TabsContent value="events" className="px-5 pt-4 pb-2 motion-safe:animate-in motion-safe:fade-in-0">
            <EventFeed events={events?.slice(0, 6)} />
          </TabsContent>
          <TabsContent value="health" className="px-5 pt-4 pb-2 motion-safe:animate-in motion-safe:fade-in-0">
            <HealthSummary health={health} />
          </TabsContent>
        </div>

        <footer className="flex justify-end border-t border-border px-5 py-2.5">
          <Link to={meta[tab].link.to} className="inline-flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-primary">
            {meta[tab].link.label} <ArrowRight className="size-3.5" />
          </Link>
        </footer>
      </Tabs>
    </section>
  )
}
