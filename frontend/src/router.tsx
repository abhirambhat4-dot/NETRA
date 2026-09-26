import type * as React from 'react'
import { Navigate, createBrowserRouter } from 'react-router-dom'
import { AppLayout } from '@/layouts/AppLayout'
import { ROUTES, type RouteHandle } from '@/lib/navigation'
import { LoginPage } from '@/pages/LoginPage'
import { NotFoundPage } from '@/pages/NotFoundPage'

const handle = (h: RouteHandle) => h

// Pages are code-split: each route loads its own chunk on first visit.
const page =
  <K extends string>(load: () => Promise<Record<K, React.ComponentType>>, name: K) =>
  () =>
    load().then((m) => ({ Component: m[name] }))

export const router = createBrowserRouter([
  { path: ROUTES.login, element: <LoginPage /> },
  {
    element: <AppLayout />,
    hydrateFallbackElement: <div className="min-h-svh bg-background" />,
    children: [
      { index: true, element: <Navigate to={ROUTES.dashboard} replace /> },
      {
        path: ROUTES.dashboard,
        lazy: page(() => import('@/pages/CommandCenterPage'), 'CommandCenterPage'),
        handle: handle({ crumb: 'Command Center' }),
      },
      {
        path: ROUTES.events,
        lazy: page(() => import('@/pages/SecurityEventsPage'), 'SecurityEventsPage'),
        handle: handle({ crumb: 'Security Events' }),
      },
      {
        path: ROUTES.incidents,
        handle: handle({ crumb: 'Incidents' }),
        children: [
          { index: true, lazy: page(() => import('@/pages/IncidentsPage'), 'IncidentsPage') },
          {
            path: ':id',
            lazy: page(() => import('@/pages/IncidentDetailsPage'), 'IncidentDetailsPage'),
            handle: handle({ crumb: (p) => p.id ?? 'Incident' }),
          },
        ],
      },
      {
        path: ROUTES.assets,
        lazy: page(() => import('@/pages/AssetsPage'), 'AssetsPage'),
        handle: handle({ crumb: 'Assets' }),
      },
      {
        path: ROUTES.threatIntelligence,
        lazy: page(() => import('@/pages/ThreatIntelligencePage'), 'ThreatIntelligencePage'),
        handle: handle({ crumb: 'Threat Intelligence' }),
      },
      {
        path: ROUTES.cyberMemory,
        lazy: page(() => import('@/pages/CyberMemoryPage'), 'CyberMemoryPage'),
        handle: handle({ crumb: 'Cyber Memory' }),
      },
      {
        path: ROUTES.settings,
        lazy: page(() => import('@/pages/SettingsPage'), 'SettingsPage'),
        handle: handle({ crumb: 'Settings' }),
      },
      {
        path: '/design-system',
        lazy: page(() => import('@/pages/DesignSystemPage'), 'DesignSystemPage'),
        handle: handle({ crumb: 'Design System' }),
      },
      {
        path: '*',
        element: <NotFoundPage />,
        handle: handle({ crumb: 'Not Found' }),
      },
    ],
  },
])
