import type { LucideIcon } from 'lucide-react'
import { BrainCircuit, Gauge, Layers, Radar, ShieldCheck, UserCheck } from 'lucide-react'
import type { WorkflowStage } from '@/api/types'

/** NETRA workflow stages: Detect → Understand → Prioritise → Verify → Contain → Learn */
export const STAGE_ORDER: WorkflowStage[] = ['DETECT', 'UNDERSTAND', 'PRIORITISE', 'VERIFY', 'CONTAIN', 'LEARN']

export const stageMeta: Record<WorkflowStage, { label: string; icon: LucideIcon }> = {
  DETECT: { label: 'Detect', icon: Radar },
  UNDERSTAND: { label: 'Understand', icon: Layers },
  PRIORITISE: { label: 'Prioritise', icon: Gauge },
  VERIFY: { label: 'Verify', icon: UserCheck },
  CONTAIN: { label: 'Contain', icon: ShieldCheck },
  LEARN: { label: 'Learn', icon: BrainCircuit },
}
