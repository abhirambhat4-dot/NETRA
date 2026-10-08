import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  BrainCircuit,
  Crosshair,
  LayoutDashboard,
  RadioTower,
  Server,
  Settings,
  ShieldAlert,
} from 'lucide-react'
import type { Params } from 'react-router-dom'

export const ROUTES = {
  home: '/',
  login: '/login',
  register: '/register',
  forgotPassword: '/forgot-password',
  resetPassword: '/reset-password',
  briefing: '/briefing',
  dashboard: '/dashboard',
  events: '/events',
  incidents: '/incidents',
  incident: (id: string) => `/incidents/${id}`,
  assets: '/assets',
  threatIntelligence: '/threat-intelligence',
  cyberMemory: '/cyber-memory',
  settings: '/settings',
  collector: '/collector',
} as const

export interface NavItem {
  label: string
  to: string
  icon: LucideIcon
  /** Show the live active-incident count next to this item. */
  badge?: 'activeIncidents'
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Intake',
    items: [{ label: 'Live Event Collector', to: ROUTES.collector, icon: RadioTower }],
  },
  {
    label: 'Operations',
    items: [
      { label: 'Command Center', to: ROUTES.dashboard, icon: LayoutDashboard },
      { label: 'Security Events', to: ROUTES.events, icon: Activity },
      { label: 'Incidents', to: ROUTES.incidents, icon: ShieldAlert, badge: 'activeIncidents' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { label: 'Assets', to: ROUTES.assets, icon: Server },
      { label: 'Threat Intelligence', to: ROUTES.threatIntelligence, icon: Crosshair },
    ],
  },
  {
    label: 'Knowledge',
    items: [{ label: 'Cyber Memory', to: ROUTES.cyberMemory, icon: BrainCircuit }],
  },
  {
    label: 'System',
    items: [{ label: 'Settings', to: ROUTES.settings, icon: Settings }],
  },
]

/** Attached to routes via `handle`; the header builds the breadcrumb from it. */
export interface RouteHandle {
  crumb: string | ((params: Params) => string)
}

export function isRouteHandle(value: unknown): value is RouteHandle {
  return typeof value === 'object' && value !== null && 'crumb' in value
}
