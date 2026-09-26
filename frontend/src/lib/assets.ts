import type { LucideIcon } from 'lucide-react'
import { Database, Globe, Monitor, Network, Server } from 'lucide-react'
import type { AssetCriticality, AssetType } from '@/api/types'
import type { Tone } from './tones'

export const ASSET_ICON: Record<AssetType, LucideIcon> = {
  DATABASE: Database,
  SERVER: Server,
  WEB_APPLICATION: Globe,
  WORKSTATION: Monitor,
  NETWORK_DEVICE: Network,
}

export const CRITICALITY_TONE: Record<AssetCriticality, Tone> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
}

export const ASSET_TYPE_LABEL: Record<AssetType, string> = {
  DATABASE: 'Database',
  SERVER: 'Server',
  WEB_APPLICATION: 'Web app',
  WORKSTATION: 'Workstation',
  NETWORK_DEVICE: 'Network',
}
