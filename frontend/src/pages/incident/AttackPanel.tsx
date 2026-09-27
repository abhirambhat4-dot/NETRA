import type { IncidentDetail, ThreatIndicator } from '@/api/types'
import { Panel } from '@/components/netra'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { detectionSourceMeta } from '@/lib/sources'
import { AssetContext, IntelMatches, TechniqueContext } from './ContextPanel'
import { BehaviourEvidence } from './EvidencePanel'

/**
 * ATTACK / BEHAVIOUR — what happened and the context around it, one view at a
 * time: behaviour first, then asset exposure, ATT&CK mapping and intel.
 */
export function AttackPanel({ detail: d, indicators }: { detail: IncidentDetail; indicators: ThreatIndicator[] }) {
  const src = detectionSourceMeta[d.incident.detectionSource]
  const tabs = [
    { value: 'behaviour', label: 'Behaviour' },
    { value: 'asset', label: 'Asset & exposure' },
    { value: 'attack', label: d.mitreTechnique ? `ATT&CK ${d.mitreTechnique.id}` : 'ATT&CK' },
    { value: 'intel', label: `Threat intel${indicators.length ? ` · ${indicators.length}` : ''}` },
  ]

  return (
    <Panel
      title="Attack & behaviour"
      description="Detection evidence and the context around it"
      actions={
        <span className="hidden items-center gap-1.5 rounded-md border border-border px-2 py-1 text-[11px] text-foreground/85 sm:inline-flex">
          <src.icon className="size-3.5" /> {src.label}
        </span>
      }
    >
      <Tabs defaultValue="behaviour" className="gap-4">
        <div className="-mx-1 overflow-x-auto px-1">
          <TabsList variant="line" className="justify-start gap-0 border-b border-border pb-px">
            {tabs.map((t) => (
              <TabsTrigger key={t.value} value={t.value} className="flex-none px-2.5 text-xs">
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value="behaviour" className="motion-safe:animate-in motion-safe:fade-in-0">
          <BehaviourEvidence detail={d} />
        </TabsContent>
        <TabsContent value="asset" className="motion-safe:animate-in motion-safe:fade-in-0">
          <AssetContext detail={d} />
        </TabsContent>
        <TabsContent value="attack" className="motion-safe:animate-in motion-safe:fade-in-0">
          <TechniqueContext detail={d} />
        </TabsContent>
        <TabsContent value="intel" className="motion-safe:animate-in motion-safe:fade-in-0">
          <IntelMatches indicators={indicators} />
        </TabsContent>
      </Tabs>
    </Panel>
  )
}
