import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  BrainCircuit,
  ClipboardCheck,
  Crosshair,
  FileUp,
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
  commandHome: '/home',
  liveTracking: '/live',
  securityWorkspace: '/workspace',
  dashboard: '/dashboard',
  events: '/events',
  incidents: '/incidents',
  incident: (id: string) => `/incidents/${id}`,
  assets: '/assets',
  assessments: '/assessments',
  threatIntelligence: '/threat-intelligence',
  cyberMemory: '/cyber-memory',
  settings: '/settings',
  collector: '/collector',
  imports: '/imports',
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
    items: [
      { label: 'Live Event Collector', to: ROUTES.collector, icon: RadioTower },
      { label: 'Dataset Import', to: ROUTES.imports, icon: FileUp },
    ],
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
      { label: 'Security Assessment', to: ROUTES.assessments, icon: ClipboardCheck },
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

/**
 * Intake items hidden on a workspace landing page: Live Tracking is about live collection, Security
 * Workspace about uploaded datasets, so each hides the other's intake. Routes stay registered.
 */
const CONTEXT_HIDDEN: Readonly<Record<string, readonly string[]>> = {
  [ROUTES.liveTracking]: [ROUTES.imports],
  [ROUTES.securityWorkspace]: [ROUTES.collector],
}

/** Sidebar groups for the current path; every route other than /live and /workspace gets NAV_GROUPS unchanged. */
export function navGroupsForPath(pathname: string): NavGroup[] {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  const hidden = CONTEXT_HIDDEN[path]
  if (!hidden) return NAV_GROUPS
  return NAV_GROUPS
    .map((group) => ({ ...group, items: group.items.filter((item) => !hidden.includes(item.to)) }))
    .filter((group) => group.items.length > 0)
}

/** Attached to routes via `handle`; the header builds the breadcrumb from it. */
export interface RouteHandle {
  crumb: string | ((params: Params) => string)
}

export function isRouteHandle(value: unknown): value is RouteHandle {
  return typeof value === 'object' && value !== null && 'crumb' in value
}
