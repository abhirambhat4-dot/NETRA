import type * as React from 'react'
import { Outlet, createBrowserRouter } from 'react-router-dom'
import { RedirectAuthenticated, RequireAuth } from '@/auth/RouteGuards'
import { AppLayout } from '@/layouts/AppLayout'
import { ROUTES, type RouteHandle } from '@/lib/navigation'
import { ForgotPasswordPage } from '@/pages/ForgotPasswordPage'
import { LoginPage } from '@/pages/LoginPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { PublicLandingPage } from '@/pages/PublicLandingPage'
import { RegisterPage } from '@/pages/RegisterPage'
import { ResetPasswordPage } from '@/pages/ResetPasswordPage'

const handle = (h: RouteHandle) => h

// Pages are code-split: each route loads its own chunk on first visit.
const page =
  <K extends string>(load: () => Promise<Record<K, React.ComponentType>>, name: K) =>
  () =>
    load().then((m) => ({ Component: m[name] }))

export const router = createBrowserRouter([
  { path: ROUTES.home, element: <RedirectAuthenticated><PublicLandingPage /></RedirectAuthenticated> },
  { path: ROUTES.login, element: <RedirectAuthenticated><LoginPage /></RedirectAuthenticated> },
  { path: ROUTES.register, element: <RedirectAuthenticated><RegisterPage /></RedirectAuthenticated> },
  { path: ROUTES.forgotPassword, element: <RedirectAuthenticated><ForgotPasswordPage /></RedirectAuthenticated> },
  // Unguarded so an emailed link works even in a browser that is still signed in.
  { path: ROUTES.resetPassword, element: <ResetPasswordPage /> },
  {
    path: ROUTES.briefing,
    element: <RequireAuth><Outlet /></RequireAuth>,
    children: [
      {
        index: true,
        lazy: page(() => import('@/pages/BriefingPage'), 'BriefingPage'),
        hydrateFallbackElement: <div className="min-h-svh bg-background" />,
      },
    ],
  },
  {
    element: <RequireAuth><AppLayout /></RequireAuth>,
    hydrateFallbackElement: <div className="min-h-svh bg-background" />,
    children: [
      {
        path: ROUTES.dashboard,
        lazy: page(() => import('@/pages/CommandCenterPage'), 'CommandCenterPage'),
        handle: handle({ crumb: 'Command Center' }),
      },
      {
        path: ROUTES.collector,
        lazy: page(() => import('@/pages/CollectorPage'), 'CollectorPage'),
        handle: handle({ crumb: 'Live Event Collector' }),
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
